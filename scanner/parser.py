"""
scanner/parser.py  (v5.0)
Input parser: accepts IPs, ranges, CIDR blocks, and hostnames.
Returns a deduplicated list of {ip, sni} dicts.

v5.0 changes:
  - Async DNS via loop.getaddrinfo() — no more blocking socket.getaddrinfo()
  - _cidr_to_ips → generator/iterator (memory-safe for large CIDRs)
  - TTL-aware async DNS cache
  - Structured logging (no bare print)
"""

import asyncio
import ipaddress
import re
import time
import threading
import logging

logger = logging.getLogger("aniscanner.parser")

MAX_IPS         = 10_000
CIDR_MIN_PREFIX = 16        # /0../15 → rejected (> 65 534 hosts)
DNS_CACHE_TTL   = 60        # seconds

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# ── DNS cache ──────────────────────────────────────────────────────────
_dns_cache: dict[str, tuple[list[str], float]] = {}
_dns_lock = threading.Lock()


# ── IP helpers ─────────────────────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    result = 0
    for p in ip.strip().split("."):
        result = (result << 8) + int(p)
    return result & 0xFFFFFFFF


def _int_to_ip(n: int) -> str:
    return ".".join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))


def _is_valid_ipv4(ip: str) -> bool:
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


def _cidr_to_ips(cidr: str):
    """
    Generator — yields host IPs one at a time.
    Memory-safe: never builds list(net.hosts()) for large CIDRs.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen < CIDR_MIN_PREFIX:
            logger.debug("CIDR %s rejected: /%d < /%d", cidr, net.prefixlen, CIDR_MIN_PREFIX)
            return
        count = 0
        for host in net.hosts():
            if count >= MAX_IPS:
                logger.debug("CIDR %s truncated at %d", cidr, MAX_IPS)
                return
            yield str(host)
            count += 1
    except Exception as exc:
        logger.debug("CIDR parse error %s: %s", cidr, exc)


# ── Async DNS ──────────────────────────────────────────────────────────

async def _resolve_async(hostname: str) -> list[str]:
    """Non-blocking DNS lookup via loop.getaddrinfo()."""
    now = time.monotonic()
    with _dns_lock:
        cached = _dns_cache.get(hostname)
        if cached:
            ips, expires = cached
            if now < expires:
                return ips

    try:
        loop  = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(hostname, None, family=2)  # AF_INET
        ips   = list({i[4][0] for i in infos})
    except OSError as exc:
        logger.debug("DNS lookup failed for %s: %s", hostname, exc)
        ips = []
    except Exception as exc:
        logger.warning("Unexpected DNS error for %s: %s", hostname, exc)
        ips = []

    with _dns_lock:
        _dns_cache[hostname] = (ips, now + DNS_CACHE_TTL)
    return ips


def _resolve_sync(hostname: str) -> list[str]:
    """Sync fallback (used by /api/parse — not in event loop)."""
    now = time.monotonic()
    with _dns_lock:
        cached = _dns_cache.get(hostname)
        if cached:
            ips, expires = cached
            if now < expires:
                return ips
    try:
        loop = asyncio.new_event_loop()
        ips  = loop.run_until_complete(_resolve_async(hostname))
        loop.close()
    except Exception as exc:
        logger.warning("sync DNS wrapper failed for %s: %s", hostname, exc)
        ips = []
    return ips


# ── Sync parse_input ───────────────────────────────────────────────────

def parse_input(text: str) -> list[dict]:
    """
    Accepts (one per line, comments with #):
        Single IP:   1.2.3.4
        Range:       1.2.3.1-1.2.3.50
        CIDR:        1.2.3.0/24
        Hostname:    example.com   → resolved + kept as SNI
        IP#SNI:      1.2.3.4#example.com

    Returns: [{"ip": "...", "sni": "..." | None}, ...]
    """
    raw: list[dict] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        explicit_sni = None
        if "#" in line and not line.startswith("#"):
            parts = line.split("#", 1)
            line, explicit_sni = parts[0].strip(), parts[1].strip()

        if re.match(r"^\d[\d.]*-\d[\d.]*$", line):
            parts = line.split("-", 1)
            for ip in _expand_range(parts[0].strip(), parts[1].strip()):
                raw.append({"ip": ip, "sni": explicit_sni})
            if len(raw) >= MAX_IPS:
                break
            continue

        if "/" in line:
            for ip in _cidr_to_ips(line):
                raw.append({"ip": ip, "sni": explicit_sni})
                if len(raw) >= MAX_IPS:
                    break
            if len(raw) >= MAX_IPS:
                break
            continue

        if _IPV4_RE.match(line) and _is_valid_ipv4(line):
            raw.append({"ip": line, "sni": explicit_sni})
            continue

        resolved = _resolve_sync(line)
        for ip in resolved:
            raw.append({"ip": ip, "sni": explicit_sni or line})

        if len(raw) >= MAX_IPS:
            break

    seen:   dict[str, str | None] = {}
    result: list[dict]            = []
    for entry in raw:
        ip = entry["ip"]
        if ip not in seen:
            seen[ip] = entry["sni"]
            result.append({"ip": ip, "sni": entry["sni"]})

    return result[:MAX_IPS]


# ── Async parse_input ──────────────────────────────────────────────────

async def parse_input_async(text: str) -> list[dict]:
    """Async variant — resolves all hostnames concurrently."""
    pre_raw:         list[dict]                      = []
    hostname_tasks:  list[tuple[str, str | None]]    = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        explicit_sni = None
        if "#" in line and not line.startswith("#"):
            parts = line.split("#", 1)
            line, explicit_sni = parts[0].strip(), parts[1].strip()

        if re.match(r"^\d[\d.]*-\d[\d.]*$", line):
            parts = line.split("-", 1)
            for ip in _expand_range(parts[0].strip(), parts[1].strip()):
                pre_raw.append({"ip": ip, "sni": explicit_sni})
            continue

        if "/" in line:
            for ip in _cidr_to_ips(line):
                pre_raw.append({"ip": ip, "sni": explicit_sni})
            continue

        if _IPV4_RE.match(line) and _is_valid_ipv4(line):
            pre_raw.append({"ip": line, "sni": explicit_sni})
            continue

        hostname_tasks.append((line, explicit_sni))

    raw = list(pre_raw)

    if hostname_tasks:
        resolved_lists = await asyncio.gather(
            *[_resolve_async(h) for h, _ in hostname_tasks],
            return_exceptions=True,
        )
        for (hostname, explicit_sni), ips in zip(hostname_tasks, resolved_lists):
            if isinstance(ips, Exception):
                logger.debug("Async resolve failed for %s: %s", hostname, ips)
                continue
            for ip in ips:
                raw.append({"ip": ip, "sni": explicit_sni or hostname})

    seen:   dict[str, str | None] = {}
    result: list[dict]            = []
    for entry in raw:
        ip = entry["ip"]
        if ip not in seen:
            seen[ip] = entry["sni"]
            result.append({"ip": ip, "sni": entry["sni"]})

    return result[:MAX_IPS]
