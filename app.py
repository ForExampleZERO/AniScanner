"""
AniScanner v3.0 — Flask backend
Improvements over v2.0:
  - Rate limiting on /api/scan/start (max 10 sessions/IP/minute)
  - Session expiry + background cleanup (TTL = 30 min)
  - CIDR /prefix-size validation is now in parser
  - Adaptive concurrency (auto-reduce when error rate > 60%)
  - HTTPS port-80 redirect check
"""

import json
import time
import threading
import uuid
from collections import defaultdict
from flask import Flask, render_template, request, Response, stream_with_context, jsonify

from scanner.parser import parse_input
from scanner.tcp    import tcp_connect_with_retry, tcp_latency, tcp_http_redirect_check
from scanner.tls    import tls_handshake, detect_provider
from scanner.udp    import udp_probe
from scanner.score  import score_ip

app = Flask(__name__)

VERSION              = "3.0"
MAX_IPS              = 10_000
DEFAULT_CONCURRENCY  = 30
DEFAULT_TIMEOUT      = 3.0
SUPPORTED_PORTS      = [80, 443, 8443, 2053, 2083, 2087, 2096]
SESSION_TTL          = 1800
CLEANUP_INTERVAL     = 300
RATE_LIMIT_WINDOW    = 60
RATE_LIMIT_MAX       = 10


# ── Session store ─────────────────────────────────
SESSIONS: dict[str, dict] = {}
_sessions_lock = threading.Lock()

# ── Rate limiter ──────────────────────────────────
_rate_store: dict[str, list] = defaultdict(list)
_rate_lock = threading.Lock()


def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_store[ip]) >= RATE_LIMIT_MAX:
            return False
        _rate_store[ip].append(now)
        return True


# ── Session cleanup daemon ────────────────────────

def _cleanup_sessions():
    while True:
        time.sleep(CLEANUP_INTERVAL)
        now = time.time()
        expired = []
        with _sessions_lock:
            for sid, sess in list(SESSIONS.items()):
                started = sess.get("started_at", now)
                status  = sess.get("status", "")
                if status in ("done", "stopped") and (now - started) > SESSION_TTL:
                    expired.append(sid)
                elif (now - started) > SESSION_TTL * 2:
                    expired.append(sid)
            for sid in expired:
                for q in list(SESSIONS[sid].get("listeners", [])):
                    try: q.put_nowait(None)
                    except: pass
                del SESSIONS[sid]
        if expired:
            print(f"[cleanup] removed {len(expired)} expired sessions")


threading.Thread(target=_cleanup_sessions, daemon=True).start()


# ── Background scan ───────────────────────────────

async def _scan_entry(entry: dict, timeout: float, scan_mode: str, ports: list[int]) -> dict:
    import asyncio
    ip  = entry["ip"]
    sni = entry.get("sni")

    do_tcp = scan_mode in ("TCP", "BOTH")
    do_udp = scan_mode in ("UDP", "BOTH")

    tls_ports = [p for p in ports if p != 80]

    tcp_results = {}
    best_tcp    = {"ok": False, "skipped": True}

    if do_tcp:
        tasks = {
            port: tcp_connect_with_retry(ip, port, timeout, retry_count=1, retry_timeout=min(1.0, timeout * 0.4))
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

        # fallback: accept port-80 if nothing else open
        if not best_tcp.get("ok"):
            if tcp_results.get("80", {}).get("ok"):
                best_tcp = {**tcp_results["80"], "port": 80}
            elif tcp_results:
                best_tcp = next(iter(tcp_results.values()))
    else:
        for port in ports:
            tcp_results[str(port)] = {"ok": False, "skipped": True}

    # ── Port-80 HTTP redirect check ───────────────
    http_redirect = None
    if do_tcp and 80 in ports:
        http_redirect = await tcp_http_redirect_check(ip, timeout=min(3.0, timeout))

    # ── Multi-probe latency ───────────────────────
    latency_detail = None
    best_port_lat  = best_tcp.get("port")
    if best_tcp.get("ok") and best_port_lat and best_port_lat != 80:
        latency_detail = await tcp_latency(ip, best_port_lat, probes=3, timeout=min(2.0, timeout))

    # ── TLS ───────────────────────────────────────
    best_port_for_tls = best_tcp.get("port", (tls_ports or [443])[0])
    if best_port_for_tls == 80:
        for p in tls_ports:
            if tcp_results.get(str(p), {}).get("ok"):
                best_port_for_tls = p
                break
        else:
            best_port_for_tls = (tls_ports or [443])[0]

    tls = (
        await tls_handshake(ip, sni, timeout + 1, port=best_port_for_tls)
        if do_tcp and best_tcp.get("ok") and best_port_for_tls != 80
        else {"ok": False, "err": "tcp_failed"}
    )

    # ── UDP ───────────────────────────────────────
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
            if best_udp is None and udp_results:
                best_udp = next(iter(udp_results.values()))

    provider = detect_provider(tls)
    score    = score_ip(best_tcp, tls, best_udp)

    return {
        "ip":            ip,
        "sni":           sni,
        "tcp":           best_tcp,
        "tcp_ports":     tcp_results,
        "tls":           tls,
        "udp":           best_udp,
        "udp_ports":     udp_results,
        "latency":       latency_detail,
        "provider":      provider,
        "score":         score,
        "scanned_ports": ports,
        "http_redirect": http_redirect,
    }


async def _run_session(session_id: str):
    import asyncio
    sess        = SESSIONS[session_id]
    entries     = sess["entries"]
    timeout     = sess["timeout"]
    scan_mode   = sess["scan_mode"]
    ports       = sess["ports"]
    concurrency = sess["concurrency"]

    error_window = []
    WINDOW_SIZE  = 20
    sem          = asyncio.Semaphore(concurrency)

    async def bounded(entry):
        nonlocal concurrency, sem
        async with sem:
            if sess["stop_flag"]:
                return
            result = await _scan_entry(entry, timeout, scan_mode, ports)
            sess["results"].append(result)
            sess["scanned"] += 1

            # Adaptive concurrency
            ok = result.get("tcp", {}).get("ok", False) or result.get("tls", {}).get("ok", False)
            error_window.append(ok)
            if len(error_window) > WINDOW_SIZE:
                error_window.pop(0)
            if len(error_window) == WINDOW_SIZE:
                error_rate = error_window.count(False) / WINDOW_SIZE
                target = sess["concurrency"]
                if error_rate > 0.6 and concurrency > 5:
                    new_c = max(5, concurrency - 5)
                    if new_c != concurrency:
                        concurrency = new_c
                        sem = asyncio.Semaphore(concurrency)
                        sess["adaptive_concurrency"] = new_c
                elif error_rate < 0.2 and concurrency < target:
                    new_c = min(target, concurrency + 5)
                    if new_c != concurrency:
                        concurrency = new_c
                        sem = asyncio.Semaphore(concurrency)
                        sess["adaptive_concurrency"] = new_c

            for q in list(sess["listeners"]):
                try:    q.put_nowait(result)
                except: pass

    await asyncio.gather(*[asyncio.create_task(bounded(e)) for e in entries])

    sess["status"] = "stopped" if sess["stop_flag"] else "done"
    for q in list(sess["listeners"]):
        try: q.put_nowait(None)
        except: pass


def _thread_runner(session_id: str):
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_run_session(session_id))
    loop.close()


# ── Routes ────────────────────────────────────────

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
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if not _check_rate_limit(client_ip):
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

    if sid and sid in SESSIONS and SESSIONS[sid]["status"] == "running":
        return jsonify({"session_id": sid, "resumed": True, "total": len(SESSIONS[sid]["entries"])})

    sid = str(uuid.uuid4())
    with _sessions_lock:
        SESSIONS[sid] = {
            "status":               "running",
            "entries":              entries,
            "results":              [],
            "scanned":              0,
            "concurrency":          concurrency,
            "adaptive_concurrency": concurrency,
            "timeout":              timeout_ms / 1000,
            "scan_mode":            scan_mode,
            "ports":                ports,
            "stop_flag":            False,
            "listeners":            [],
            "started_at":           time.time(),
        }

    threading.Thread(target=_thread_runner, args=(sid,), daemon=True).start()
    return jsonify({"session_id": sid, "total": len(entries)})


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    sid = request.get_json(force=True).get("session_id")
    with _sessions_lock:
        sess = SESSIONS.get(sid)
    if sess:
        sess["stop_flag"] = True
        sess["status"]    = "stopped"
    return jsonify({"ok": True})


@app.route("/api/scan/status")
def api_scan_status():
    sid = request.args.get("session_id", "")
    with _sessions_lock:
        sess = SESSIONS.get(sid)
    if not sess:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status":               sess["status"],
        "total":                len(sess["entries"]),
        "scanned":              sess["scanned"],
        "scan_mode":            sess["scan_mode"],
        "ports":                sess["ports"],
        "results":              sess["results"],
        "adaptive_concurrency": sess.get("adaptive_concurrency"),
    })


@app.route("/api/scan/stream")
def api_scan_stream():
    import queue as tq
    sid = request.args.get("session_id", "")
    with _sessions_lock:
        sess = SESSIONS.get(sid)
    if not sess:
        return jsonify({"error": "not found"}), 404

    q = tq.Queue()
    sess["listeners"].append(q)

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
            try: sess["listeners"].remove(q)
            except: pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    print(f"🚀 AniScanner {VERSION}  →  http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
