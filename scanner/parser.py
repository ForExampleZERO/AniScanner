"""
scanner/parser.py  (v3.0)
Input parser: accepts IPs, ranges, CIDR blocks, and hostnames.
Returns a deduplicated list of {ip, sni} dicts.

v3.0 additions:
  - CIDR hard cap: prefix < 16 (>65 534 hosts) is rejected with an error hint
  - TTL-aware DNS cache (default TTL = 60 s)
  - Stricter IP-octet validation (rejects 999.0.0.1 etc.)
"""

import ipaddress
import socket
import re
import time
import threading

MAX_IPS      = 10_000
CIDR_MIN_PREFIX = 16       # /8 .. /15 would yield >65 534 hosts — rejected
DNS_CACHE_TTL   = 60       # seconds

# Basic IPv4 pattern (strict: each octet 0-255 checked by ipaddress below)
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# ── DNS cache ─────────────────────────────────────
_dns_cache: dict[str, tuple[list[str], float]] = {}
_dns_lock = threading.Lock()


def _ip_to_int(ip: str) -> int:
    result = 0
    for p in ip.strip().split("."):
        result = (result << 8) + int(p)
    return result & 0xFFFFFFFF


def _int_to_ip(n: int) -> str:
    return ".".join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))


def _is_valid_ipv4(ip: str) -> bool:
    """Strict IPv4 validation — rejects octets > 255."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False


def _expand_range(start: str, end: str) -> list[str]:
    if not (_is_valid_ipv4(start) and _is_valid_ipv4(end)):
        return []
    s, e = _ip_to_int(start), _ip_to_int(end)
    if e < s or (e - s) > MAX_IPS:
        return []
    return [_int_to_ip(i) for i in range(s, e + 1)]


def _cidr_to_ips(cidr: str) -> list[str]:
    """
    Expand a CIDR block to a list of host IPs.
    Hard-rejects prefixes smaller than CIDR_MIN_PREFIX (/16).
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        # Reject /0 .. /15 — too large (>65 534 hosts)
        if net.prefixlen < CIDR_MIN_PREFIX:
            return []   # silently skip; UI warns before sending
        hosts = list(net.hosts())
        if len(hosts) > MAX_IPS:
            return []
        return [str(h) for h in hosts]
    except Exception:
        return []


def _resolve(hostname: str) -> list[str]:
    """DNS A-record lookup with TTL-aware in-process cache."""
    now = time.monotonic()
    with _dns_lock:
        cached = _dns_cache.get(hostname)
        if cached:
            ips, expires = cached
            if now < expires:
                return ips

    # Cache miss — do the lookup outside the lock
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips   = list({i[4][0] for i in infos})
    except Exception:
        ips = []

    with _dns_lock:
        _dns_cache[hostname] = (ips, now + DNS_CACHE_TTL)

    return ips


def parse_input(text: str) -> list[dict]:
    """
    Accepts (one per line, comments with #):
        Single IP:   1.2.3.4
        Range:       1.2.3.1-1.2.3.50
        CIDR:        1.2.3.0/24  (max prefix = /16)
        Hostname:    cloudflare.com   → resolved + kept as SNI hint
        IP#SNI:      1.2.3.4#example.com  → explicit SNI override

    Returns: [{"ip": "...", "sni": "..." | None}, ...]  (deduplicated, max MAX_IPS)
    """
    raw: list[dict] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Explicit SNI override: ip#sni
        explicit_sni = None
        if "#" in line and not line.startswith("#"):
            parts = line.split("#", 1)
            line, explicit_sni = parts[0].strip(), parts[1].strip()

        # IP range  a.b.c.d-e.f.g.h
        if re.match(r"^\d[\d.]*-\d[\d.]*$", line):
            parts = line.split("-", 1)
            for ip in _expand_range(parts[0].strip(), parts[1].strip()):
                raw.append({"ip": ip, "sni": explicit_sni})
            if len(raw) >= MAX_IPS:
                break
            continue

        # CIDR block
        if "/" in line:
            for ip in _cidr_to_ips(line):
                raw.append({"ip": ip, "sni": explicit_sni})
            if len(raw) >= MAX_IPS:
                break
            continue

        # Plain IPv4 (strict validation)
        if _IPV4_RE.match(line) and _is_valid_ipv4(line):
            raw.append({"ip": line, "sni": explicit_sni})
            continue

        # Hostname / domain → resolve + keep as SNI
        resolved = _resolve(line)
        for ip in resolved:
            raw.append({"ip": ip, "sni": explicit_sni or line})

        if len(raw) >= MAX_IPS:
            break

    # Deduplicate by IP (preserve first occurrence)
    seen:   dict[str, str | None] = {}
    result: list[dict]            = []
    for entry in raw:
        ip = entry["ip"]
        if ip not in seen:
            seen[ip] = entry["sni"]
            result.append({"ip": ip, "sni": entry["sni"]})

    return result[:MAX_IPS]
