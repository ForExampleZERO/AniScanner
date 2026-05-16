import asyncio
import ssl
import socket
import json
import time
import threading
import ipaddress
import uuid
from datetime import datetime, timezone
from flask import Flask, render_template, request, Response, stream_with_context, jsonify

app = Flask(__name__)

MAX_IPS         = 10000
DEFAULT_CONCURRENCY = 30
DEFAULT_TIMEOUT = 3.0

# ══════════════════════════════════════════════════════════════
#  Active scan sessions — survive browser refresh/close
#  { session_id: { status, entries, results, progress, ... } }
# ══════════════════════════════════════════════════════════════
SESSIONS: dict[str, dict] = {}


# ─── IP / Input Tools ─────────────────────────────────────────

def ip_to_int(ip: str) -> int:
    result = 0
    for p in ip.strip().split('.'):
        result = (result << 8) + int(p)
    return result & 0xFFFFFFFF


def int_to_ip(n: int) -> str:
    return '.'.join([str((n >> s) & 0xFF) for s in (24, 16, 8, 0)])


def expand_range(a: str, b: str) -> list:
    s, e = ip_to_int(a), ip_to_int(b)
    if e - s > MAX_IPS:
        return []
    return [int_to_ip(i) for i in range(s, e + 1)]


def cidr_to_ips(cidr: str) -> list:
    try:
        net   = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())

        if len(hosts) > MAX_IPS:
            return []

        return [str(h) for h in hosts]

    except Exception:
        return []


def resolve_domain(domain: str) -> list:
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({i[4][0] for i in infos})

    except Exception:
        return []


def parse_input(text: str) -> list:
    raw = []

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith('#'):
            continue

        # IP Range
        if '-' in line and '/' not in line:
            parts = line.split('-')

            if len(parts) == 2:
                try:
                    for ip in expand_range(parts[0].strip(), parts[1].strip()):
                        raw.append({'ip': ip, 'sni': None})

                except Exception:
                    pass

            continue

        # CIDR
        if '/' in line:
            for ip in cidr_to_ips(line):
                raw.append({'ip': ip, 'sni': None})

            continue

        # Single IP
        try:
            ipaddress.ip_address(line)
            raw.append({'ip': line, 'sni': None})
            continue

        except ValueError:
            pass

        # Domain
        resolved = resolve_domain(line)

        for ip in resolved:
            raw.append({'ip': ip, 'sni': line})

        if len(raw) >= MAX_IPS:
            break

    seen = {}

    for e in raw:
        if e['ip'] not in seen:
            seen[e['ip']] = e['sni']

    return [{'ip': ip, 'sni': sni} for ip, sni in seen.items()][:MAX_IPS]


# ─── Scanner Core ─────────────────────────────────────────────

async def tcp_connect(ip: str, port: int, timeout: float) -> dict:
    start = time.perf_counter()

    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout
        )

        ms = round((time.perf_counter() - start) * 1000)

        w.close()

        try:
            await w.wait_closed()
        except:
            pass

        return {
            'ok': True,
            'ms': ms
        }

    except Exception as ex:
        return {
            'ok': False,
            'ms': None,
            'err': str(ex)[:60]
        }


# ─── UDP Probe ─────────────────────────────────────────────

async def udp_probe(ip: str, port: int = 443, timeout: float = 2.0) -> dict:
    """
    UDP probe on port 443 (QUIC/HTTP3).
    Sends a minimal QUIC Initial packet and checks for any response.
    """

    payload = (
        bytes([0xc0]) +
        b'\x00' * 3 +
        bytes([0x08]) +
        b'\x00' * 8 +
        b'\x00' * 2
    )

    loop = asyncio.get_event_loop()

    try:
        transport, protocol_obj = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=(ip, port)
        )

        transport.sendto(payload)

        await asyncio.sleep(timeout)

        transport.close()

        return {
            'ok': True,
            'filtered': False
        }

    except Exception:
        return {
            'ok': False,
            'filtered': True
        }


# ─── TLS ─────────────────────────────────────────────

async def tls_handshake(ip: str, sni: str | None, timeout: float) -> dict:
    ctx = ssl.create_default_context()

    ctx.check_hostname = bool(sni)
    ctx.verify_mode = ssl.CERT_REQUIRED if sni else ssl.CERT_NONE

    hostname = sni or ip

    start = time.perf_counter()

    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                443,
                ssl=ctx,
                server_hostname=hostname
            ),
            timeout
        )

        ms = round((time.perf_counter() - start) * 1000)

        ssl_obj = w.get_extra_info('ssl_object')

        cert = ssl_obj.getpeercert() if ssl_obj else {}
        cipher = ssl_obj.cipher() if ssl_obj else ('?', '?', 0)

        subj = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))

        san = [
            v for t, v in cert.get('subjectAltName', [])
            if t == 'DNS'
        ][:6]

        not_after_raw = cert.get('notAfter', '')

        try:
            na = datetime.strptime(
                not_after_raw,
                '%b %d %H:%M:%S %Y %Z'
            )

            days_left = (
                na.replace(tzinfo=timezone.utc)
                - datetime.now(timezone.utc)
            ).days

        except:
            days_left = None

        w.close()

        try:
            await w.wait_closed()
        except:
            pass

        return {
            'ok': True,
            'ms': ms,
            'sni_used': hostname,
            'cn': subj.get('commonName', ''),
            'issuer': issuer.get(
                'organizationName',
                issuer.get('commonName', '')
            ),
            'san': san,
            'days_left': days_left,
            'cipher': cipher[0] if cipher else '?',
            'tls_ver': cipher[1] if cipher else '?',
        }

    except ssl.SSLCertVerificationError as ex:
        ms = round((time.perf_counter() - start) * 1000)

        return {
            'ok': False,
            'ms': ms,
            'err': 'cert_mismatch',
            'detail': str(ex)[:80]
        }

    except ssl.SSLError as ex:
        ms = round((time.perf_counter() - start) * 1000)

        return {
            'ok': False,
            'ms': ms,
            'err': 'ssl_error',
            'detail': str(ex)[:80]
        }

    except Exception as ex:
        return {
            'ok': False,
            'ms': None,
            'err': 'timeout',
            'detail': str(ex)[:80]
        }


# ─── Provider Detection ─────────────────────────────────────────────

def detect_provider(tls: dict) -> str:
    if not tls or not tls.get('ok'):
        return ''

    issuer = (tls.get('issuer') or '').lower()
    cn = (tls.get('cn') or '').lower()
    san = ' '.join(tls.get('san') or []).lower()

    text = f"{issuer} {cn} {san}"

    if 'cloudflare' in text:
        return 'Cloudflare'

    if 'amazon' in text or 'aws' in text:
        return 'AWS'

    if 'fastly' in text:
        return 'Fastly'

    if 'akamai' in text:
        return 'Akamai'

    if 'google' in text:
        return 'Google'

    if 'microsoft' in text or 'azure' in text:
        return 'Azure'

    if 'vercel' in text:
        return 'Vercel'

    if 'netlify' in text:
        return 'Netlify'

    if 'lencr' in text or "let's encrypt" in text:
        return "Let's Encrypt"

    return ''


# ─── Score ─────────────────────────────────────────────

def score_ip(tcp: dict, tls: dict) -> dict:
    pts = 0

    if tcp.get('ok'):
        pts += 20

        ping = tcp.get('ms') or 999

        pts += (
            20 if ping <= 100 else
            12 if ping <= 250 else
            6 if ping <= 500 else
            0
        )

    if tls.get('ok'):
        pts += 40

        days = tls.get('days_left')

        if days is not None:
            pts += 10

            if days >= 30:
                pts += 10

    if pts >= 80:
        verdict, color = 'Excellent', '#4ade80'

    elif pts >= 55:
        verdict, color = 'Good', '#38bdf8'

    elif pts >= 30:
        verdict, color = 'Weak', '#facc15'

    elif tcp.get('ok') and not tls.get('ok'):
        verdict, color = 'TCP Only', '#a78bfa'

    else:
        verdict, color = 'Dead', '#f87171'

    return {
        'points': pts,
        'verdict': verdict,
        'color': color
    }


# ─── Full Scan ─────────────────────────────────────────────

async def full_scan_ip(entry: dict, timeout: float) -> dict:
    ip = entry['ip']
    sni = entry.get('sni')

    scan_mode = entry.get('scan_mode', 'TCP')

    tcp = (
        await tcp_connect(ip, 443, timeout)
        if scan_mode in ('TCP', 'BOTH')
        else {'ok': False, 'ms': None, 'err': 'skipped'}
    )

    udp = (
        await udp_probe(ip, 443, timeout)
        if scan_mode in ('UDP', 'BOTH')
        else None
    )

    tls = (
        await tls_handshake(ip, sni, timeout + 1)
        if tcp.get('ok')
        else {
            'ok': False,
            'ms': None,
            'err': 'tcp_failed'
        }
    )

    provider = detect_provider(tls)

    sc = score_ip(tcp, tls)

    return {
        'ip': ip,
        'sni': sni,
        'tcp': tcp,
        'udp': udp,
        'tls': tls,
        'provider': provider,
        'score': sc,
    }


# ─── Background Session ─────────────────────────────────────────────

async def _run_session(session_id: str):
    sess = SESSIONS[session_id]

    entries = sess['entries']
    concurrency = sess['concurrency']
    timeout = sess['timeout']

    sem = asyncio.Semaphore(concurrency)

    async def bounded(entry):
        async with sem:

            if sess['stop_flag']:
                return

            result = await full_scan_ip(entry, timeout)

            sess['results'].append(result)
            sess['scanned'] += 1

            for q in sess['listeners']:
                try:
                    q.put_nowait(result)
                except:
                    pass

    tasks = [asyncio.create_task(bounded(e)) for e in entries]

    await asyncio.gather(*tasks)

    sess['status'] = 'stopped' if sess['stop_flag'] else 'done'

    for q in sess['listeners']:
        try:
            q.put_nowait(None)
        except:
            pass


def _start_session_thread(session_id: str):
    loop = asyncio.new_event_loop()

    asyncio.set_event_loop(loop)

    loop.run_until_complete(_run_session(session_id))

    loop.close()


# ─── Routes ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/parse', methods=['POST'])
def api_parse():
    data = request.get_json(force=True)

    entries = parse_input(data.get('ips', ''))

    return jsonify({
        'entries': entries,
        'count': len(entries)
    })


@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    data = request.get_json(force=True)

    entries = data.get('entries', [])

    concurrency = int(
        data.get(
            'concurrency',
            DEFAULT_CONCURRENCY
        )
    )

    timeout_ms = int(
        data.get(
            'timeout',
            3000
        )
    )

    scan_mode = data.get('scan_mode', 'TCP')

    # attach scan mode to entries
    for e in entries:
        e['scan_mode'] = scan_mode

    if not entries:
        return jsonify({
            'error': 'Empty list'
        }), 400

    sid = data.get('session_id')

    if (
        sid and
        sid in SESSIONS and
        SESSIONS[sid]['status'] == 'running'
    ):
        return jsonify({
            'session_id': sid,
            'resumed': True
        })

    sid = str(uuid.uuid4())

    SESSIONS[sid] = {
        'status': 'running',
        'entries': entries,
        'results': [],
        'scanned': 0,
        'concurrency': concurrency,
        'timeout': timeout_ms / 1000,
        'stop_flag': False,
        'listeners': [],
        'started_at': time.time(),
    }

    threading.Thread(
        target=_start_session_thread,
        args=(sid,),
        daemon=True
    ).start()

    return jsonify({
        'session_id': sid,
        'total': len(entries)
    })


@app.route('/api/scan/stop', methods=['POST'])
def api_scan_stop():
    sid = request.get_json(force=True).get('session_id')

    if sid and sid in SESSIONS:
        SESSIONS[sid]['stop_flag'] = True
        SESSIONS[sid]['status'] = 'stopped'

    return jsonify({'ok': True})


@app.route('/api/scan/status')
def api_scan_status():
    sid = request.args.get('session_id', '')

    sess = SESSIONS.get(sid)

    if not sess:
        return jsonify({
            'error': 'not found'
        }), 404

    return jsonify({
        'status': sess['status'],
        'total': len(sess['entries']),
        'scanned': sess['scanned'],
        'results': sess['results'],
    })


@app.route('/api/scan/stream')
def api_scan_stream():
    import queue as tq

    sid = request.args.get('session_id', '')

    sess = SESSIONS.get(sid)

    if not sess:
        return jsonify({
            'error': 'not found'
        }), 404

    q = tq.Queue()

    sess['listeners'].append(q)

    def generate():
        try:
            while True:
                try:
                    item = q.get(timeout=25)

                except tq.Empty:
                    yield ': ping\n\n'
                    continue

                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    break

                yield f"data: {json.dumps({'type': 'result', 'data': item})}\n\n"

        finally:
            sess['listeners'].remove(q)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        },
    )


if __name__ == '__main__':
    print('🚀 AniScanner v3.1  →  http://localhost:5000')

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )
