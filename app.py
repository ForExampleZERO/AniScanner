import json
import time
import threading
import uuid
from flask import Flask, render_template, request, Response, stream_with_context, jsonify

from scanner.parser import parse_input
from scanner.tcp    import tcp_connect
from scanner.tls    import tls_handshake, detect_provider
from scanner.udp    import udp_probe
from scanner.score  import score_ip

app = Flask(__name__)

VERSION             = "1.0"
MAX_IPS             = 10_000
DEFAULT_CONCURRENCY = 30
DEFAULT_TIMEOUT     = 3.0

# ── Session store ─────────────────────────────────
# Survives browser refresh/close as long as Termux runs
SESSIONS: dict[str, dict] = {}


# ── Background scan ───────────────────────────────

async def _scan_entry(entry: dict, timeout: float, scan_mode: str) -> dict:
    import asyncio
    ip  = entry["ip"]
    sni = entry.get("sni")

    do_tcp = scan_mode in ("TCP", "BOTH")
    do_udp = scan_mode in ("UDP", "BOTH")

    tcp = await tcp_connect(ip, 443, timeout)     if do_tcp else {"ok": False, "skipped": True}
    tls = await tls_handshake(ip, sni, timeout+1) if do_tcp and tcp["ok"] else {"ok": False, "err": "tcp_failed"}
    udp = await udp_probe(ip, 443, timeout)        if do_udp else None

    provider = detect_provider(tls)
    score    = score_ip(tcp, tls, udp)

    return {
        "ip":       ip,
        "sni":      sni,
        "tcp":      tcp,
        "tls":      tls,
        "udp":      udp,
        "provider": provider,
        "score":    score,
    }


async def _run_session(session_id: str):
    import asyncio
    sess        = SESSIONS[session_id]
    entries     = sess["entries"]
    concurrency = sess["concurrency"]
    timeout     = sess["timeout"]
    scan_mode   = sess["scan_mode"]
    sem         = asyncio.Semaphore(concurrency)

    async def bounded(entry):
        async with sem:
            if sess["stop_flag"]:
                return
            result = await _scan_entry(entry, timeout, scan_mode)
            sess["results"].append(result)
            sess["scanned"] += 1
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
    return render_template("index.html", version=VERSION)


@app.route("/api/parse", methods=["POST"])
def api_parse():
    data    = request.get_json(force=True)
    entries = parse_input(data.get("ips", ""))
    return jsonify({"entries": entries, "count": len(entries)})


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    data        = request.get_json(force=True)
    entries     = data.get("entries", [])
    concurrency = int(data.get("concurrency", DEFAULT_CONCURRENCY))
    timeout_ms  = int(data.get("timeout",     3000))
    scan_mode   = data.get("scan_mode", "TCP")
    sid         = data.get("session_id")

    if not entries:
        return jsonify({"error": "Empty list"}), 400

    # Resume existing session
    if sid and sid in SESSIONS and SESSIONS[sid]["status"] == "running":
        return jsonify({"session_id": sid, "resumed": True, "total": len(SESSIONS[sid]["entries"])})

    sid = str(uuid.uuid4())
    SESSIONS[sid] = {
        "status":      "running",
        "entries":     entries,
        "results":     [],
        "scanned":     0,
        "concurrency": concurrency,
        "timeout":     timeout_ms / 1000,
        "scan_mode":   scan_mode,
        "stop_flag":   False,
        "listeners":   [],
        "started_at":  time.time(),
    }

    threading.Thread(target=_thread_runner, args=(sid,), daemon=True).start()
    return jsonify({"session_id": sid, "total": len(entries)})


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    sid  = request.get_json(force=True).get("session_id")
    sess = SESSIONS.get(sid)
    if sess:
        sess["stop_flag"] = True
        sess["status"]    = "stopped"
    return jsonify({"ok": True})


@app.route("/api/scan/status")
def api_scan_status():
    sid  = request.args.get("session_id", "")
    sess = SESSIONS.get(sid)
    if not sess:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status":    sess["status"],
        "total":     len(sess["entries"]),
        "scanned":   sess["scanned"],
        "scan_mode": sess["scan_mode"],
        "results":   sess["results"],
    })


@app.route("/api/scan/stream")
def api_scan_stream():
    import queue as tq
    sid  = request.args.get("session_id", "")
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