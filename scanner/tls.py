"""
scanner/tls.py
Full TLS handshake probe with certificate inspection and SNI validation.

Returns rich data:
    ok        : bool
    ms        : int          — TLS handshake RTT
    sni_used  : str
    cn        : str          — certificate Common Name
    issuer    : str
    san       : list[str]    — Subject Alternative Names (DNS)
    days_left : int | None   — days until cert expiry
    tls_ver   : str          — e.g. "TLSv1.3"
    cipher    : str          — cipher suite name
    err       : str | None   — error category
"""

import asyncio
import ssl
import time
from datetime import datetime, timezone


# ── Error classifier ──────────────────────────────

def _classify_ssl(ex: Exception) -> str:
    if isinstance(ex, ssl.SSLCertVerificationError): return "cert_mismatch"
    if isinstance(ex, ssl.SSLError):
        msg = str(ex).lower()
        if "handshake"    in msg: return "handshake_failed"
        if "protocol"     in msg: return "protocol_error"
        if "certificate"  in msg: return "cert_error"
        return "ssl_error"
    if isinstance(ex, asyncio.TimeoutError):         return "timeout"
    if "refused" in str(ex).lower():                return "refused"
    return "unknown"


# ── Cert parser ───────────────────────────────────

def _parse_cert(cert: dict) -> dict:
    subj   = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer",  []))
    san    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    # Expiry
    not_after_raw = cert.get("notAfter", "")
    days_left = None
    try:
        na = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z")
        days_left = (na.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    except Exception:
        pass

    return {
        "cn":        subj.get("commonName", ""),
        "issuer":    issuer.get("organizationName", issuer.get("commonName", "")),
        "san":       san[:8],
        "days_left": days_left,
        "country":   issuer.get("countryName", ""),
    }


# ── Core probe ────────────────────────────────────

async def tls_handshake(
    ip:      str,
    sni:     str | None = None,
    timeout: float      = 4.0,
    port:    int        = 443,
) -> dict:
    """
    Perform a full TLS handshake.

    - If SNI is given: validates certificate against SNI hostname.
    - If no SNI:       disables cert verification (raw IP probe).

    Distinguishes between:
        cert_mismatch  — TLS works but cert doesn't match SNI
        handshake_failed — TLS layer rejected
        timeout        — no response within timeout
    """
    hostname   = sni if sni else ip
    verify     = bool(sni)

    ctx                = ssl.create_default_context()
    ctx.check_hostname = verify
    ctx.verify_mode    = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE

    # Allow older TLS for maximum coverage
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=hostname),
            timeout=timeout,
        )
        ms = round((time.perf_counter() - start) * 1000)

        ssl_obj = writer.get_extra_info("ssl_object")
        cert    = ssl_obj.getpeercert() if ssl_obj else {}
        cipher  = ssl_obj.cipher()      if ssl_obj else ("?", "?", 0)

        cert_data = _parse_cert(cert)

        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass

        return {
            "ok":       True,
            "ms":       ms,
            "sni_used": hostname,
            "tls_ver":  cipher[1] if cipher else "?",
            "cipher":   cipher[0] if cipher else "?",
            "err":      None,
            **cert_data,
        }

    except ssl.SSLCertVerificationError as ex:
        ms = round((time.perf_counter() - start) * 1000)
        return {
            "ok": False, "ms": ms,
            "sni_used": hostname,
            "err": "cert_mismatch",
            "detail": str(ex)[:120],
            "cn": "", "issuer": "", "san": [], "days_left": None,
            "tls_ver": "?", "cipher": "?",
        }

    except Exception as ex:
        ms = round((time.perf_counter() - start) * 1000)
        return {
            "ok": False, "ms": ms,
            "sni_used": hostname,
            "err": _classify_ssl(ex),
            "detail": str(ex)[:120],
            "cn": "", "issuer": "", "san": [], "days_left": None,
            "tls_ver": "?", "cipher": "?",
        }


# ── Provider / CDN detector ───────────────────────

_CDN_SIGNATURES = [
    ("Cloudflare",    ["cloudflare"]),
    ("AWS",           ["amazon", "aws", "cloudfront"]),
    ("Fastly",        ["fastly"]),
    ("Akamai",        ["akamai"]),
    ("Google",        ["google", "gts", "goog"]),
    ("Azure",         ["microsoft", "azure"]),
    ("Vercel",        ["vercel"]),
    ("Netlify",       ["netlify"]),
    ("Let's Encrypt", ["let's encrypt", "lencr"]),
    ("DigiCert",      ["digicert"]),
    ("Sectigo",       ["sectigo", "comodo"]),
    ("ZeroSSL",       ["zerossl"]),
]

def detect_provider(tls: dict) -> str:
    if not tls or not tls.get("ok"):
        return ""
    haystack = " ".join([
        (tls.get("issuer") or ""),
        (tls.get("cn")     or ""),
        " ".join(tls.get("san") or []),
    ]).lower()

    for name, keywords in _CDN_SIGNATURES:
        if any(k in haystack for k in keywords):
            return name
    return ""
