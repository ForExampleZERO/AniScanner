"""
scanner/http.py  (v5.0)
Full HTTP/HTTPS probe.

v5.0 additions over v4.0:
  - Real HTTP/2 request via h2 library (ALPN h2 + actual H2 frames)
  - Path testing:  /, /robots.txt, /favicon.ico  (configurable)
  - 403 / 502 body-snippet analysis
  - Captcha / block-page detection heuristics
  - Body inspection (first 4KB) for title + block keywords
  - CDN/WAF detection extended: IP-range + ASN hint passed in
  - All bare except → typed NetworkError / ProtocolError
  - Structured logging (no print)

Returns per-port dict with all v4.0 fields plus:
    body_title      : str | None
    body_snippet    : str | None   (first 200 chars of body)
    captcha         : bool         (captcha/block page detected)
    blocked         : bool         (403/429/503 with block indicators)
    paths_tested    : list[str]
    h2_frames       : bool         (real H2 exchange succeeded)
"""

import asyncio
import logging
import re
import ssl
import time
from urllib.parse import urlparse

logger = logging.getLogger("aniscanner.http")

# ── Custom exceptions ─────────────────────────────────────────────────

class NetworkError(Exception):
    """TCP/TLS-level failure."""

class ProtocolError(Exception):
    """HTTP protocol-level failure."""


# ── Error classifier ──────────────────────────────────────────────────

def _classify(ex: Exception) -> str:
    msg = str(ex).lower()
    if isinstance(ex, asyncio.TimeoutError) or "timed out" in msg:
        return "timeout"
    if isinstance(ex, ssl.SSLCertVerificationError):
        return "cert_mismatch"
    if isinstance(ex, ssl.SSLError):
        return "ssl_error"
    if "refused" in msg:
        return "refused"
    if "unreachable" in msg or "no route" in msg:
        return "unreachable"
    if "name or service" in msg or "nodename" in msg:
        return "dns_error"
    return "unknown"


# ── Security header auditor ───────────────────────────────────────────

_SECURITY_HEADERS = {
    "strict-transport-security": "hsts",
    "content-security-policy":   "csp",
    "x-frame-options":           "x_frame_options",
    "x-content-type-options":    "x_content_type_options",
    "referrer-policy":           "referrer_policy",
    "permissions-policy":        "permissions_policy",
    "x-xss-protection":          "x_xss_protection",
}


def _audit_security(headers: dict) -> dict:
    result = {}
    for header, key in _SECURITY_HEADERS.items():
        val = headers.get(header)
        result[key] = {"present": val is not None, "value": val}
    hsts_val = headers.get("strict-transport-security", "")
    if hsts_val:
        result["hsts"]["max_age"]           = None
        result["hsts"]["include_subdomains"] = "includesubdomains" in hsts_val.lower()
        result["hsts"]["preload"]            = "preload" in hsts_val.lower()
        m = re.search(r"max-age=(\d+)", hsts_val, re.IGNORECASE)
        if m:
            result["hsts"]["max_age"] = int(m.group(1))
    return result


# ── WAF / CDN fingerprinter ───────────────────────────────────────────

_WAF_SIGNATURES = [
    ("Cloudflare",  ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"]),
    ("AWS Shield",  ["x-amz-cf-id", "x-amzn-requestid", "x-amz-id"]),
    ("Akamai",      ["akamai-origin-hop", "x-akamai-transformed", "x-check-cacheable"]),
    ("Fastly",      ["x-fastly-request-id", "fastly-restarts", "x-served-by"]),
    ("Imperva",     ["x-iinfo", "x-cdn-forward", "incap-ses", "visid-incap"]),
    ("Sucuri",      ["x-sucuri-id", "x-sucuri-cache"]),
    ("Vercel",      ["x-vercel-id", "x-vercel-cache"]),
    ("Netlify",     ["x-nf-request-id", "netlify"]),
    ("Azure Front", ["x-azure-ref", "x-msedge-ref"]),
    ("Google",      ["x-goog-backend-id", "x-gfe-request-id"]),
    ("Nginx",       ["nginx"]),
    ("Apache",      ["apache"]),
]

# Cloudflare IP ranges (CIDR prefixes — checked against IP string prefix)
_CF_IP_PREFIXES = [
    "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.", "104.18.",
    "104.19.", "104.20.", "104.21.", "104.22.", "104.24.", "104.25.", "104.26.",
    "104.27.", "108.162.192.", "131.0.72.", "141.101.64.", "141.101.65.",
    "162.158.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
    "172.70.", "172.71.", "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",
    "190.93.240.", "190.93.241.", "190.93.242.", "190.93.243.", "197.234.240.",
    "197.234.241.", "197.234.242.", "197.234.243.", "198.41.128.", "198.41.129.",
    "198.41.192.", "198.41.200.",
]


def _detect_waf(headers: dict, ip: str = "") -> str | None:
    header_str = (
        " ".join(headers.keys()).lower()
        + " "
        + " ".join(str(v) for v in headers.values()).lower()
    )

    # IP-range shortcut for Cloudflare
    if ip and any(ip.startswith(p) for p in _CF_IP_PREFIXES):
        return "Cloudflare"

    for name, signatures in _WAF_SIGNATURES:
        if any(sig in header_str for sig in signatures):
            return name
    return None


# ── Captcha / block detection ─────────────────────────────────────────

_BLOCK_KEYWORDS = [
    "captcha", "recaptcha", "hcaptcha", "cf-turnstile",
    "access denied", "403 forbidden", "bot protection",
    "ddos protection", "checking your browser",
    "please wait", "cloudflare ray id",
    "blocked", "banned", "restricted",
    "just a moment", "enable javascript",
]


def _detect_captcha_or_block(
    status_code: int | None,
    headers: dict,
    body: str,
) -> tuple[bool, bool]:
    """Returns (captcha: bool, blocked: bool)."""
    body_lower = body.lower()

    captcha = any(kw in body_lower for kw in ["captcha", "hcaptcha", "recaptcha", "cf-turnstile"])

    blocked = False
    if status_code in (403, 429, 503, 520, 521, 522, 523, 524, 525, 526):
        blocked = any(kw in body_lower for kw in _BLOCK_KEYWORDS)

    return captcha, blocked


def _extract_title(body: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    return None


# ── HTTP response parser ──────────────────────────────────────────────

def _parse_http_response(raw: str) -> dict:
    lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")
    status_code  = None
    status_text  = None
    http_version = "?"
    headers      = {}
    body_start   = 0

    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                pass
            status_text  = parts[2].strip() if len(parts) > 2 else ""
            http_version = parts[0].upper() if parts[0].startswith("HTTP") else "?"

    for idx, line in enumerate(lines[1:], start=1):
        if not line:
            body_start = idx + 1
            break
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    body = "\r\n".join(lines[body_start:]) if body_start else ""
    return {
        "status_code":  status_code,
        "status_text":  status_text,
        "http_version": http_version,
        "headers":      headers,
        "body":         body,
    }


# ── SSL context builder ───────────────────────────────────────────────

def _make_ssl_ctx(verify: bool = True, sni: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    return ctx


# ── Real HTTP/2 request (h2 library) ─────────────────────────────────

async def _h2_request(
    ip:      str,
    port:    int,
    path:    str       = "/",
    sni:     str | None = None,
    timeout: float     = 5.0,
) -> dict | None:
    """
    Attempt a real HTTP/2 request using the h2 state machine.
    Returns a dict with status_code, headers, body on success, else None.
    """
    try:
        import h2.connection
        import h2.config
        import h2.events
    except ImportError:
        logger.debug("h2 library not installed — skipping real HTTP/2")
        return None

    host_header = sni if sni else ip
    ctx = _make_ssl_ctx(verify=False, sni=sni)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host_header),
            timeout=timeout,
        )
    except Exception as exc:
        logger.debug("H2 TCP connect failed %s:%d — %s", ip, port, exc)
        return None

    ssl_obj = writer.get_extra_info("ssl_object")
    if not ssl_obj or ssl_obj.selected_alpn_protocol() != "h2":
        writer.close()
        return None

    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn   = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    writer.write(conn.data_to_send(65535))

    headers = [
        (":method",    "GET"),
        (":path",      path),
        (":scheme",    "https"),
        (":authority", host_header),
        ("user-agent", "AniScanner/5.0"),
        ("accept",     "*/*"),
    ]

    try:
        conn.send_headers(stream_id=1, headers=headers, end_stream=True)
        writer.write(conn.data_to_send(65535))
        await asyncio.wait_for(writer.drain(), timeout=2.0)
    except Exception as exc:
        logger.debug("H2 send_headers failed: %s", exc)
        writer.close()
        return None

    resp_headers: dict = {}
    body_chunks:  list[bytes] = []
    status_code:  int | None = None

    try:
        while True:
            data = await asyncio.wait_for(reader.read(65535), timeout=timeout)
            if not data:
                break
            events = conn.receive_data(data)
            writer.write(conn.data_to_send(65535))
            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    hd = dict(event.headers)
                    status_code = int(hd.get(b":status", hd.get(":status", 0)))
                    resp_headers = {
                        k.decode() if isinstance(k, bytes) else k:
                        v.decode() if isinstance(v, bytes) else v
                        for k, v in hd.items()
                        if not (k.startswith(b":") if isinstance(k, bytes) else k.startswith(":"))
                    }
                elif isinstance(event, h2.events.DataReceived):
                    body_chunks.append(event.data)
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if sum(len(c) for c in body_chunks) > 16384:
                        break
                elif isinstance(event, h2.events.StreamEnded):
                    break
            if status_code is not None and isinstance(events[-1] if events else None,
                                                       (h2.events.StreamEnded,)):
                break
    except asyncio.TimeoutError:
        pass
    except Exception as exc:
        logger.debug("H2 receive error: %s", exc)

    writer.close()
    body = b"".join(body_chunks).decode("utf-8", errors="ignore")
    if status_code is None:
        return None
    return {"status_code": status_code, "headers": resp_headers, "body": body, "http_version": "HTTP/2"}


# ── Single HTTP/1.1 request ───────────────────────────────────────────

async def _http_request(
    ip:          str,
    port:        int,
    path:        str        = "/",
    use_tls:     bool       = True,
    sni:         str | None = None,
    timeout:     float      = 5.0,
    verify_cert: bool       = True,
) -> dict:
    host_header = sni if sni else ip
    start = time.perf_counter()

    base = {
        "ok": False, "status_code": None, "status_text": None,
        "ttfb_ms": None, "http_version": "?", "server": None,
        "content_type": None, "redirect_url": None, "headers": {},
        "security": {}, "waf": None, "err": None, "body": "",
    }

    try:
        if use_tls:
            ctx = _make_ssl_ctx(verify=verify_cert, sni=sni)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host_header),
                timeout=timeout,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj and ssl_obj.selected_alpn_protocol() == "h2":
                base["http_version"] = "HTTP/2"
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: AniScanner/5.0 (+https://github.com/aniartx)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode())
        try:
            await asyncio.wait_for(writer.drain(), timeout=2.0)
        except asyncio.TimeoutError as exc:
            raise NetworkError("drain timeout") from exc

        try:
            response_bytes = await asyncio.wait_for(reader.read(32768), timeout=timeout)
            ttfb_ms        = round((time.perf_counter() - start) * 1000)
            response_text  = response_bytes.decode("utf-8", errors="ignore")

            parsed = _parse_http_response(response_text)
            h = parsed["headers"]

            if base["http_version"] == "?" and parsed["http_version"] != "?":
                base["http_version"] = parsed["http_version"]

            base.update({
                "ok":           parsed["status_code"] is not None,
                "status_code":  parsed["status_code"],
                "status_text":  parsed["status_text"],
                "ttfb_ms":      ttfb_ms,
                "server":       h.get("server"),
                "content_type": h.get("content-type"),
                "redirect_url": h.get("location"),
                "headers":      h,
                "security":     _audit_security(h),
                "waf":          _detect_waf(h, ip),
                "body":         parsed.get("body", ""),
            })
        except asyncio.TimeoutError:
            base["err"]     = "response_timeout"
            base["ttfb_ms"] = round((time.perf_counter() - start) * 1000)

        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass

    except NetworkError as exc:
        base["err"]     = str(exc)
        base["ttfb_ms"] = round((time.perf_counter() - start) * 1000)
    except Exception as exc:
        base["err"]     = _classify(exc)
        base["ttfb_ms"] = round((time.perf_counter() - start) * 1000)

    return base


# ── 403 / 502 body analysis ───────────────────────────────────────────

def _analyze_error_body(status_code: int | None, body: str) -> dict:
    """Extra analysis for 4xx/5xx responses."""
    result = {
        "body_title":   _extract_title(body),
        "body_snippet": body[:200].strip() if body else None,
    }
    captcha, blocked = _detect_captcha_or_block(status_code, {}, body)
    result["captcha"] = captcha
    result["blocked"] = blocked
    return result


# ── Redirect chain follower ───────────────────────────────────────────

async def _follow_redirects(
    ip: str, port: int, sni: str | None, use_tls: bool,
    timeout: float, max_hops: int = 5,
) -> tuple[dict, list[str]]:
    chain         = []
    current_ip    = ip
    current_port  = port
    current_tls   = use_tls
    current_sni   = sni
    current_path  = "/"

    resp: dict = {}
    for _ in range(max_hops):
        resp = await _http_request(
            ip=current_ip, port=current_port, path=current_path,
            use_tls=current_tls, sni=current_sni,
            timeout=timeout, verify_cert=False,
        )
        code = resp.get("status_code")
        loc  = resp.get("redirect_url")

        if code and 300 <= code < 400 and loc:
            chain.append(loc)
            try:
                parsed       = urlparse(loc)
                if parsed.netloc:
                    current_sni  = parsed.hostname
                    current_tls  = parsed.scheme == "https"
                    current_port = parsed.port or (443 if current_tls else 80)
                    current_path = parsed.path or "/"
                else:
                    current_path = loc
                continue
            except Exception:
                break
        break

    return resp, chain


# ── Path tester ───────────────────────────────────────────────────────

_TEST_PATHS = ["/", "/robots.txt", "/favicon.ico"]


async def _test_paths(
    ip: str, port: int, sni: str | None, use_tls: bool, timeout: float,
) -> dict:
    """Test a few well-known paths, return summary."""
    results = {}
    tasks = {
        path: _http_request(ip, port, path, use_tls, sni, timeout, verify_cert=False)
        for path in _TEST_PATHS
    }
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for path, res in zip(tasks.keys(), gathered):
        if isinstance(res, Exception):
            results[path] = {"ok": False, "status_code": None, "err": str(res)[:60]}
        else:
            results[path] = {"ok": res.get("ok"), "status_code": res.get("status_code")}
    return results


# ── Main HTTP probe ───────────────────────────────────────────────────

async def http_probe(
    ip:               str,
    port:             int         = 443,
    sni:              str | None  = None,
    timeout:          float       = 5.0,
    follow_redirects: bool        = True,
    max_redirects:    int         = 5,
    test_paths:       bool        = True,
    try_h2:           bool        = True,
) -> dict:
    """
    Full HTTP probe for ip:port.

    HTTPS ports: 443, 8443, 2053, 2083, 2087, 2096
    HTTP ports:  80, 8080, 8888

    Extra v5.0:
        h2_frames, body_title, body_snippet, captcha, blocked, paths_tested
    """
    HTTPS_PORTS = {443, 8443, 2053, 2083, 2087, 2096}
    use_tls = port in HTTPS_PORTS

    base = {
        "ok": False, "port": port, "use_tls": use_tls,
        "status_code": None, "status_text": None, "ttfb_ms": None,
        "http_version": "?", "server": None, "content_type": None,
        "redirect_url": None, "redirect_chain": [], "headers": {},
        "security": {}, "waf": None, "err": None,
        # v5.0 additions
        "body_title": None, "body_snippet": None,
        "captcha": False, "blocked": False,
        "paths_tested": {}, "h2_frames": False,
    }

    try:
        # Try real H2 first on TLS ports
        h2_result = None
        if try_h2 and use_tls:
            h2_result = await _h2_request(ip, port, "/", sni, timeout)
            if h2_result:
                base["h2_frames"]    = True
                base["http_version"] = "HTTP/2"
                base["status_code"]  = h2_result["status_code"]
                base["ok"]           = True
                h = h2_result.get("headers", {})
                base["server"]       = h.get("server")
                base["content_type"] = h.get("content-type")
                base["headers"]      = h
                base["security"]     = _audit_security(h)
                base["waf"]          = _detect_waf(h, ip)
                body                 = h2_result.get("body", "")
                base.update(_analyze_error_body(base["status_code"], body))

        # Fall back to HTTP/1.1 (also covers HTTP ports)
        if not h2_result:
            if follow_redirects:
                resp, chain = await _follow_redirects(
                    ip=ip, port=port, sni=sni, use_tls=use_tls,
                    timeout=timeout, max_hops=max_redirects,
                )
                base["redirect_chain"] = chain
            else:
                resp = await _http_request(ip, port, "/", use_tls, sni, timeout, verify_cert=False)

            base.update({k: v for k, v in resp.items() if k in base or k not in base})
            base["ok"] = resp.get("status_code") is not None

            body = resp.get("body", "")
            base.update(_analyze_error_body(base.get("status_code"), body))

            # Enrich WAF with IP hint
            if not base.get("waf"):
                base["waf"] = _detect_waf(base.get("headers", {}), ip)

        # Path testing (async, non-blocking)
        if test_paths and base["ok"]:
            try:
                base["paths_tested"] = await asyncio.wait_for(
                    _test_paths(ip, port, sni, use_tls, min(timeout, 3.0)),
                    timeout=timeout,
                )
            except Exception as exc:
                logger.debug("Path testing failed for %s:%d — %s", ip, port, exc)

    except Exception as exc:
        logger.debug("http_probe unexpected error %s:%d — %s", ip, port, exc)
        base["err"] = _classify(exc)

    return base


# ── Multi-port HTTP probe ─────────────────────────────────────────────

async def http_probe_all_ports(
    ip:      str,
    ports:   list[int],
    sni:     str | None = None,
    timeout: float      = 4.0,
) -> dict:
    tasks = {
        port: http_probe(ip, port, sni, timeout, follow_redirects=True)
        for port in ports
    }
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)

    results = {}
    for port, result in zip(tasks.keys(), gathered):
        if isinstance(result, Exception):
            logger.debug("http_probe_all_ports exception port %d: %s", port, result)
            results[str(port)] = {
                "ok": False, "port": port, "err": "exception",
                "status_code": None, "ttfb_ms": None,
            }
        else:
            results[str(port)] = result

    return results


# ── Best HTTP result selector ─────────────────────────────────────────

def best_http_result(http_ports: dict) -> dict | None:
    if not http_ports:
        return None

    HTTPS_PORTS = {443, 8443, 2053, 2083, 2087, 2096}

    # H2 success first
    for port_str, r in http_ports.items():
        if r.get("ok") and r.get("h2_frames") and int(port_str) in HTTPS_PORTS:
            return r
    # Successful HTTPS
    for port_str, r in http_ports.items():
        if r.get("ok") and int(port_str) in HTTPS_PORTS:
            return r
    # Any successful
    for r in http_ports.values():
        if r.get("ok"):
            return r
    # Any with status code
    for r in http_ports.values():
        if r.get("status_code") is not None:
            return r

    return list(http_ports.values())[0] if http_ports else None


# ── Status category helper ────────────────────────────────────────────

def status_category(code: int | None) -> str:
    if code is None:         return "no_response"
    if 100 <= code < 200:    return "informational"
    if 200 <= code < 300:    return "success"
    if 300 <= code < 400:    return "redirect"
    if 400 <= code < 500:    return "client_error"
    if 500 <= code < 600:    return "server_error"
    return "unknown"
