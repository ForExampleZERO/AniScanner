"""
scanner/tls.py  (v5.0)
Full TLS handshake probe + extended CDN/provider detection.

v5.0 additions:
  - CDN detection: IP-range check, ASN hint, TLS fingerprint, headers
  - Structured logging (no print)
  - Typed exceptions in caller-visible errors
"""

import asyncio
import logging
import ssl
import time
from datetime import datetime, timezone

logger = logging.getLogger("aniscanner.tls")


# ── Error classifier ──────────────────────────────────────────────────

def _classify_ssl(ex: Exception) -> str:
    if isinstance(ex, ssl.SSLCertVerificationError): return "cert_mismatch"
    if isinstance(ex, ssl.SSLError):
        msg = str(ex).lower()
        if "handshake"   in msg: return "handshake_failed"
        if "protocol"    in msg: return "protocol_error"
        if "certificate" in msg: return "cert_error"
        return "ssl_error"
    if isinstance(ex, asyncio.TimeoutError): return "timeout"
    if "refused" in str(ex).lower():         return "refused"
    return "unknown"


# ── Cert parser ───────────────────────────────────────────────────────

def _parse_cert(cert: dict) -> dict:
    subj   = dict(x[0] for x in cert.get("subject",  []))
    issuer = dict(x[0] for x in cert.get("issuer",   []))
    san    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    days_left = None
    not_after_raw = cert.get("notAfter", "")
    try:
        na = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z")
        days_left = (na.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
    except Exception:
        pass

    return {
        "cn":        subj.get("commonName",       ""),
        "issuer":    issuer.get("organizationName", issuer.get("commonName", "")),
        "san":       san[:8],
        "days_left": days_left,
        "country":   issuer.get("countryName", ""),
    }


# ── Core probe ────────────────────────────────────────────────────────

async def tls_handshake(
    ip:      str,
    sni:     str | None = None,
    timeout: float      = 4.0,
    port:    int        = 443,
) -> dict:
    hostname = sni if sni else ip
    verify   = bool(sni)

    ctx                = ssl.create_default_context()
    ctx.check_hostname = verify
    ctx.verify_mode    = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

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
        alpn    = ssl_obj.selected_alpn_protocol() if ssl_obj else None

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
            "alpn":     alpn,
            "err":      None,
            **cert_data,
        }

    except ssl.SSLCertVerificationError as ex:
        ms = round((time.perf_counter() - start) * 1000)
        return {
            "ok": False, "ms": ms, "sni_used": hostname,
            "err": "cert_mismatch", "detail": str(ex)[:120],
            "cn": "", "issuer": "", "san": [], "days_left": None,
            "tls_ver": "?", "cipher": "?", "alpn": None,
        }

    except (asyncio.TimeoutError, OSError, ssl.SSLError) as ex:
        ms = round((time.perf_counter() - start) * 1000)
        return {
            "ok": False, "ms": ms, "sni_used": hostname,
            "err": _classify_ssl(ex), "detail": str(ex)[:120],
            "cn": "", "issuer": "", "san": [], "days_left": None,
            "tls_ver": "?", "cipher": "?", "alpn": None,
        }

    except Exception as ex:
        ms = round((time.perf_counter() - start) * 1000)
        logger.debug("tls_handshake unexpected error %s:%d — %s", ip, port, ex)
        return {
            "ok": False, "ms": ms, "sni_used": hostname,
            "err": "unknown", "detail": str(ex)[:120],
            "cn": "", "issuer": "", "san": [], "days_left": None,
            "tls_ver": "?", "cipher": "?", "alpn": None,
        }


# ── Extended CDN / provider detector ─────────────────────────────────

# Cert-issuer / SAN keywords
_CDN_CERT_SIGNATURES = [
    ("Cloudflare",    ["cloudflare"]),
    ("AWS",           ["amazon", "aws", "cloudfront"]),
    ("Fastly",        ["fastly"]),
    ("Akamai",        ["akamai"]),
    ("Google",        ["google", "gts", "goog"]),
    ("Azure",         ["microsoft", "azure"]),
    ("Vercel",        ["vercel"]),
    ("Netlify",       ["netlify"]),
    ("Let's Encrypt", ["let's encrypt", "lencr"]),
    ("DigiCert",      [  "digicert"]),
    ("Sectigo",       ["sectigo", "comodo"]),
    ("ZeroSSL",       ["zerossl"]),
]

# IP prefix → provider
_IP_PREFIX_MAP: list[tuple[str, str]] = [
    # Cloudflare
    ("104.16.", "Cloudflare"), ("104.17.", "Cloudflare"), ("104.18.", "Cloudflare"),
    ("104.19.", "Cloudflare"), ("104.20.", "Cloudflare"), ("104.21.", "Cloudflare"),
    ("172.64.",  "Cloudflare"), ("172.65.", "Cloudflare"), ("172.66.", "Cloudflare"),
    ("172.67.",  "Cloudflare"), ("162.158.", "Cloudflare"), ("190.93.24", "Cloudflare"),
    # AWS CloudFront
    ("13.32.",  "AWS"), ("13.35.", "AWS"), ("52.85.", "AWS"), ("99.84.", "AWS"),
    ("205.251.", "AWS"), ("216.137.", "AWS"),
    # Google
    ("142.250.", "Google"), ("172.217.", "Google"), ("216.58.", "Google"),
    ("64.233.",  "Google"), ("74.125.", "Google"),
    # Azure Front Door
    ("13.107.",  "Azure"), ("23.96.", "Azure"), ("40.112.", "Azure"),
    # Fastly
    ("151.101.", "Fastly"), ("199.232.", "Fastly"),
    # Akamai
    ("23.32.",   "Akamai"), ("23.64.", "Akamai"), ("23.192.", "Akamai"),
    ("96.6.",    "Akamai"), ("184.24.", "Akamai"),
]

# TLS cipher fingerprint hints
_CIPHER_CDN_HINTS: list[tuple[str, str]] = [
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "Cloudflare"),  # CF preferred cipher
    ("ECDHE-RSA-CHACHA20-POLY1305",   "Cloudflare"),
]


def detect_provider(tls: dict, http_headers: dict | None = None, ip: str = "") -> str:
    """
    Extended provider detection using:
      1. IP prefix ranges
      2. TLS cipher fingerprint
      3. Cert issuer / SAN / CN
      4. HTTP response headers (if passed in)
    """
    if not tls:
        # IP-range check even without TLS
        if ip:
            for prefix, provider in _IP_PREFIX_MAP:
                if ip.startswith(prefix):
                    return provider
        return ""

    # 1. IP-range check (most authoritative)
    if ip:
        for prefix, provider in _IP_PREFIX_MAP:
            if ip.startswith(prefix):
                return provider

    # 2. TLS cipher fingerprint
    cipher = tls.get("cipher") or ""
    for cipherstr, provider in _CIPHER_CDN_HINTS:
        if cipherstr in cipher:
            return provider

    # 3. Cert-based detection
    if tls.get("ok"):
        haystack = " ".join([
            tls.get("issuer") or "",
            tls.get("cn")     or "",
            " ".join(tls.get("san") or []),
        ]).lower()
        for name, keywords in _CDN_CERT_SIGNATURES:
            if any(k in haystack for k in keywords):
                return name

    # 4. HTTP header hints
    if http_headers:
        from scanner.http import _detect_waf
        waf = _detect_waf(http_headers, ip)
        if waf:
            return waf

    return ""
