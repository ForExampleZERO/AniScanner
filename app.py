"""
AniScanner v5.0 — Flask backend
Production-hardened improvements over v4.0:
  - SQLite session storage (scanner/db.py)
  - Adaptive concurrency without Semaphore recreation
  - Async DNS in parser (loop.getaddrinfo)
  - Real HTTP/2 requests (h2 library)
  - Extended CDN detection (IP-range + ASN + TLS cipher + headers)
  - Captcha / block-page detection
  - Path testing per port
  - Typed network exceptions (NetworkError / ProtocolError)
  - print → structured logging (scanner/logging_config.py)
  - File logging via ANISCANNER_LOG_FILE env var
"""

import json
import logging
import os
import queue as tq
import time
import threading
import uuid
from collections import defaultdict

from flask import Flask, render_template, request, Response, stream_with_context, jsonify

from scanner.logging_config import setup_logging
from scanner.parser  import parse_input
from scanner.tcp     import tcp_connect_with_retry, tcp_latency, tcp_http_redirect_check
from scanner.tls     import tls_handshake, detect_provider
from scanner.udp     import udp_probe
from scanner.http    import http_probe_all_ports, best_http_result
from scanner.score   import score_ip
from scanner.db      import session_store

# ── Logging ───────────────────────────────────────────────────────────
setup_logging(
    level    = os.environ.get("ANISCANNER_LOG_LEVEL", "INFO"),
    log_file = os.environ.get("ANISCANNER_LOG_FILE"),
)
logger = logging.getLogger("aniscanner.app")

app = Flask(__name__)

VERSION             = "5.0"
MAX_IPS             = 10_000
DEFAULT_CONCURRENCY = 30
DEFAULT_TIMEOUT     = 3.0
SUPPORTED_PORTS     = [80, 443, 8443, 2053, 2083, 2087, 2096]
SESSION_TTL         = 1800
CLEANUP_INTERVAL    = 300
RATE_LIMIT_WINDOW   = 60
RATE_LIMIT_MAX      = 10

# ── Rate limiter ──────────────────────────────────────────────────────
_rate_store: dict[str, list] = defaultdict(list)
_rate_lock  = threading.Lock()


def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_store[ip]) >= RATE_LIMIT_MAX:
            return False
        _rate_store[ip].append(now)
        return True


# ── Session cleanup daemon ────────────────────────────────────────────

def _cleanup_loop():
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            session_store.cleanup_expired(SESSION_TTL)
        except Exception as exc:
            logger.error("Cleanup loop error: %s", exc)


threading.Thread(target=_cleanup_loop, daemon=True, name="session-cleanup").start()


# ── Per-entry scan ────────────────────────────────────────────────────

async def _scan_entry(entry: dict, timeout: float, scan_mode: str, ports: list[int]) -> dict:
    import asyncio
    ip  = entry["ip"]
    sni = entry.get("sni")

    do_tcp = scan_mode in ("TCP", "BOTH")
    do_udp = scan_mode in ("UDP", "BOTH")

    tls_ports   = [p for p in ports if p != 80]
    tcp_results = {}
    best_tcp    = {"ok": False, "skipped": True}

    # ── TCP ───────────────────────────────────────────────────────────
    if do_tcp:
        tasks = {
            port: tcp_connect_with_retry(
                ip, port, timeout,
                retry_count=1, retry_timeout=min(1.0, timeout * 0.4),
            )
            for port in ports
        }
        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for port, result in zip(tasks.keys(), gathered):
            if isinstance(result, Exception):
                result = {"ok": False, "ms": None, "err": "exception", "skipped": False}
            tcp_results[str(port)] = result
            if result.get("ok") and port != 80 and (
                not best_tcp.get("ok") or
                (result.get("ms") or 9999) < (best_tcp.get("ms") or 9999)
            ):
                best_tcp = {**result, "port": port}

        if not best_tcp.get("ok"):
            if tcp_results.get("80", {}).get("ok"):
                best_tcp = {**tcp_results["80"], "port": 80}
            elif tcp_results:
                best_tcp = next(iter(tcp_results.values()))
    else:
        for port in ports:
            tcp_results[str(port)] = {"ok": False, "skipped": True}

    # ── Port-80 HTTP redirect check ───────────────────────────────────
    http_redirect = None
    if do_tcp and 80 in ports:
        try:
            http_redirect = await tcp_http_redirect_check(ip, timeout=min(3.0, timeout))
        except Exception as exc:
            logger.debug("http_redirect_check failed %s: %s", ip, exc)

    # ── Latency multi-probe ───────────────────────────────────────────
    latency_detail  = None
    best_port_lat   = best_tcp.get("port")
    if best_tcp.get("ok") and best_port_lat and best_port_lat != 80:
        try:
            latency_detail = await tcp_latency(ip, best_port_lat, probes=3, timeout=min(2.0, timeout))
        except Exception as exc:
            logger.debug("tcp_latency failed %s:%d — %s", ip, best_port_lat, exc)

    # ── TLS ───────────────────────────────────────────────────────────
    best_port_for_tls = best_tcp.get("port", (tls_ports or [443])[0])
    if best_port_for_tls == 80:
        for p in tls_ports:
            if tcp_results.get(str(p), {}).get("ok"):
                best_port_for_tls = p
                break
        else:
            best_port_for_tls = (tls_ports or [443])[0]

    tls = {"ok": False, "err": "tcp_failed"}
    if do_tcp and best_tcp.get("ok") and best_port_for_tls != 80:
        try:
            tls = await tls_handshake(ip, sni, timeout + 1, port=best_port_for_tls)
        except Exception as exc:
            logger.debug("tls_handshake failed %s:%d — %s", ip, best_port_for_tls, exc)

    # ── UDP ───────────────────────────────────────────────────────────
    udp_results = {}
    best_udp    = None

    if do_udp:
        udp_scan_ports = [p for p in ports if p != 80]
        tasks_udp = {port: udp_probe(ip, port, timeout) for port in udp_scan_ports}
        gathered_udp = await asyncio.gather(*tasks_udp.values(), return_exceptions=True)
        for port, result in zip(tasks_udp.keys(), gathered_udp):
            if isinstance(result, Exception):
                result = {"ok": False, "status": "ERROR", "ms": None, "quic": False, "err": "exception"}
            udp_results[str(port)] = result
            if result.get("ok") and best_udp is None:
                best_udp = {**result, "port": port}
        if best_udp is None and udp_results:
            for port, r in udp_results.items():
                if r.get("status") == "FILTERED":
                    best_udp = {**r, "port": int(port)}
                    break
            if best_udp is None:
                best_udp = next(iter(udp_results.values()))

    # ── HTTP / HTTPS full probe ───────────────────────────────────────
    http_results = {}
    best_http    = None

    any_tcp_open = best_tcp.get("ok") or any(r.get("ok") for r in tcp_results.values())
    if do_tcp and any_tcp_open:
        try:
            http_results = await http_probe_all_ports(
                ip=ip, ports=list(ports), sni=sni,
                timeout=min(timeout + 1, 8.0),
            )
            best_http = best_http_result(http_results)
        except Exception as exc:
            logger.debug("http_probe_all_ports failed %s — %s", ip, exc)

    # ── Provider detection (extended) ─────────────────────────────────
    http_hdrs = best_http.get("headers", {}) if best_http else {}
    provider  = detect_provider(tls, http_headers=http_hdrs, ip=ip)
    score     = score_ip(best_tcp, tls, best_udp, best_http)

    return {
        "ip":            ip,
        "sni":           sni,
        "tcp":           best_tcp,
        "tcp_ports":     tcp_results,
        "tls":           tls,
        "udp":           best_udp,
        "udp_ports":     udp_results,
        "http":          best_http,
        "http_ports":    http_results,
        "latency":       latency_detail,
        "provider":      provider,
        "score":         score,
        "scanned_ports": ports,
        "http_redirect": http_redirect,
    }


# ── Session runner ────────────────────────────────────────────────────

async def _run_session(session_id: str):
    import asyncio

    sess        = session_store.get(session_id)
    if not sess:
        logger.warning("Session %s not found at run time", session_id)
        return

    entries     = sess["entries"]
    timeout     = sess["timeout"]
    scan_mode   = sess["scan_mode"]
    ports       = sess["ports"]
    concurrency = sess["concurrency"]

    error_window = []
    WINDOW_SIZE  = 20
    target_conc  = concurrency

    # ── Adaptive concurrency without Semaphore recreation ────────────
    # We use a token bucket implemented with asyncio.BoundedSemaphore.
    # Adjustment is done by acquiring/releasing extra permits instead of
    # recreating the semaphore, which avoids race conditions.

    sem          = asyncio.BoundedSemaphore(concurrency)
    _conc_lock   = asyncio.Lock()
    _current_conc = [concurrency]   # mutable cell

    async def _adjust_concurrency(new_c: int) -> None:
        async with _conc_lock:
            old_c = _current_conc[0]
            if new_c == old_c:
                return
            if new_c > old_c:
                # Release extra permits
                for _ in range(new_c - old_c):
                    sem.release()
            else:
                # Acquire permits to reduce effective parallelism
                for _ in range(old_c - new_c):
                    try:
                        await asyncio.wait_for(sem.acquire(), timeout=0.1)
                    except asyncio.TimeoutError:
                        break
            _current_conc[0] = new_c
            session_store.set_adaptive_concurrency(session_id, new_c)
            logger.debug("Session %s: concurrency %d → %d", session_id, old_c, new_c)

    async def bounded(entry: dict):
        async with sem:
            if session_store.get_stop_flag(session_id):
                return
            result = await _scan_entry(entry, timeout, scan_mode, ports)
            session_store.append_result(session_id, result)

            # Adaptive logic (error-rate window)
            ok = result.get("tcp", {}).get("ok", False) or result.get("tls", {}).get("ok", False)
            error_window.append(ok)
            if len(error_window) > WINDOW_SIZE:
                error_window.pop(0)
            if len(error_window) == WINDOW_SIZE:
                error_rate = error_window.count(False) / WINDOW_SIZE
                cur = _current_conc[0]
                if error_rate > 0.6 and cur > 5:
                    await _adjust_concurrency(max(5, cur - 5))
                elif error_rate < 0.2 and cur < target_conc:
                    await _adjust_concurrency(min(target_conc, cur + 5))

            # Notify SSE listeners
            for q in session_store.get_listeners(session_id):
                try:
                    q.put_nowait(result)
                except Exception:
                    pass

    await asyncio.gather(*[asyncio.create_task(bounded(e)) for e in entries])

    final_status = "stopped" if session_store.get_stop_flag(session_id) else "done"
    session_store.set_status(session_id, final_status)
    logger.info("Session %s finished with status=%s", session_id, final_status)

    for q in session_store.get_listeners(session_id):
        try:
            q.put_nowait(None)
        except Exception:
            pass


def _thread_runner(session_id: str):
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run_session(session_id))
    except Exception as exc:
        logger.error("Session %s crashed: %s", session_id, exc)
        session_store.set_status(session_id, "done")
    finally:
        loop.close()


# ── Routes ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", version=VERSION, supported_ports=SUPPORTED_PORTS)


@app.route("/api/parse", methods=["POST"])
def api_parse():
    data    = request.get_json(force=True)
    entries = parse_input(data.get("ips", ""))
    return jsonify({"entries": entries, "count": len(entries)})


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    client_ip = (
        request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        .split(",")[0]
        .strip()
    )
    if not _check_rate_limit(client_ip):
        logger.warning("Rate limit hit for %s", client_ip)
        return jsonify({
            "error": "Rate limit exceeded. Max 10 sessions per minute per IP.",
            "retry_after": RATE_LIMIT_WINDOW,
        }), 429

    data        = request.get_json(force=True)
    entries     = data.get("entries", [])
    concurrency = max(1, min(int(data.get("concurrency", DEFAULT_CONCURRENCY)), 200))
    timeout_ms  = max(500, min(int(data.get("timeout", 3000)), 30000))
    scan_mode   = data.get("scan_mode", "TCP")
    ports       = data.get("ports", [443])
    sid         = data.get("session_id")

    ports = [p for p in ports if p in SUPPORTED_PORTS]
    if not ports:
        ports = [443]

    if not entries:
        return jsonify({"error": "Empty list"}), 400
    if len(entries) > MAX_IPS:
        return jsonify({"error": f"Too many IPs. Max {MAX_IPS}."}), 400

    # Resume existing session
    if sid and session_store.exists(sid):
        sess = session_store.get(sid)
        if sess and sess.get("status") == "running":
            return jsonify({"session_id": sid, "resumed": True, "total": sess["total"]})

    sid = str(uuid.uuid4())
    session_store.create(sid, {
        "status":      "running",
        "entries":     entries,
        "concurrency": concurrency,
        "timeout":     timeout_ms / 1000,
        "scan_mode":   scan_mode,
        "ports":       ports,
        "started_at":  time.time(),
    })

    threading.Thread(target=_thread_runner, args=(sid,), daemon=True, name=f"scan-{sid[:8]}").start()
    logger.info("Scan started: session=%s entries=%d ports=%s mode=%s", sid[:8], len(entries), ports, scan_mode)
    return jsonify({"session_id": sid, "total": len(entries)})


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    sid = request.get_json(force=True).get("session_id")
    if sid:
        session_store.set_stop_flag(sid, True)
        session_store.set_status(sid, "stopped")
        logger.info("Scan stopped: session=%s", sid[:8] if sid else "?")
    return jsonify({"ok": True})


@app.route("/api/scan/status")
def api_scan_status():
    sid  = request.args.get("session_id", "")
    sess = session_store.get(sid)
    if not sess:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status":               sess["status"],
        "total":                sess["total"],
        "scanned":              sess["scanned"],
        "scan_mode":            sess["scan_mode"],
        "ports":                sess["ports"],
        "results":              sess["results"],
        "adaptive_concurrency": sess.get("adaptive_concurrency"),
    })


@app.route("/api/scan/stream")
def api_scan_stream():
    sid  = request.args.get("session_id", "")
    sess = session_store.get(sid)
    if not sess:
        return jsonify({"error": "not found"}), 404

    q = tq.Queue()
    session_store.add_listener(sid, q)

    def generate():
        try:
            while True:
                try:
                    item = q.get(timeout=25)
                except tq.Empty:
                    yield ": ping\n\n"
                    continue
                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    break
                yield f"data: {json.dumps({'type': 'result', 'data': item})}\n\n"
        finally:
            session_store.remove_listener(sid, q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    logger.info("🚀 AniScanner %s  →  http://localhost:5000", VERSION)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
