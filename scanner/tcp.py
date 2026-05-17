"""
scanner/tcp.py  (v3.0)
TCP connect probe with retry logic and accurate latency.
v3.0: added tcp_http_redirect_check for port-80 HTTP→HTTPS detection.

Returns:
    ok      : bool   — connection succeeded
    ms      : int    — round-trip time in milliseconds
    err     : str    — error category (timeout / refused / unreachable / unknown)
    skipped : bool   — probe was skipped per scan_mode
"""

import asyncio
import time


# ── Error classifier ──────────────────────────────

def _classify(ex: Exception) -> str:
    msg = str(ex).lower()
    if "timed out"   in msg or isinstance(ex, asyncio.TimeoutError): return "timeout"
    if "refused"     in msg: return "refused"
    if "unreachable" in msg or "no route" in msg:                     return "unreachable"
    if "network"     in msg: return "network"
    return "unknown"


# ── Core probe ────────────────────────────────────

async def tcp_connect(
    ip:      str,
    port:    int   = 443,
    timeout: float = 3.0,
) -> dict:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        ms = round((time.perf_counter() - start) * 1000)
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass
        return {"ok": True, "ms": ms, "err": None, "skipped": False}
    except Exception as ex:
        return {
            "ok":      False,
            "ms":      round((time.perf_counter() - start) * 1000),
            "err":     _classify(ex),
            "skipped": False,
        }


# ── Retry probe ───────────────────────────────────

async def tcp_connect_with_retry(
    ip:            str,
    port:          int   = 443,
    timeout:       float = 3.0,
    retry_count:   int   = 1,
    retry_timeout: float = 1.0,
) -> dict:
    result = await tcp_connect(ip, port, timeout)
    if result["ok"]:
        return result
    if result["err"] == "timeout" and retry_count > 0:
        for _ in range(retry_count):
            retry = await tcp_connect(ip, port, retry_timeout)
            if retry["ok"]:
                return retry
            if retry["err"] != "timeout":
                return retry
    return result


# ── Latency sampler ───────────────────────────────

async def tcp_latency(
    ip:      str,
    port:    int   = 443,
    probes:  int   = 3,
    timeout: float = 2.0,
) -> dict:
    times = []
    for _ in range(probes):
        r = await tcp_connect(ip, port, timeout)
        if r["ok"]:
            times.append(r["ms"])
        await asyncio.sleep(0.05)

    if not times:
        return {"ok": False, "min": None, "avg": None, "max": None, "loss": 100}

    loss = round((1 - len(times) / probes) * 100)
    return {
        "ok":   True,
        "min":  min(times),
        "avg":  round(sum(times) / len(times)),
        "max":  max(times),
        "loss": loss,
    }


# ── HTTP→HTTPS redirect check (port 80) ──────────

async def tcp_http_redirect_check(
    ip:      str,
    port:    int   = 80,
    timeout: float = 3.0,
) -> dict:
    """
    Connect to port 80, send a minimal HTTP/1.1 GET, and check if the
    server responds with a 3xx redirect to https://.

    Returns:
        open        : bool  — port 80 is open
        redirects   : bool  — server returned a Location: https:// header
        location    : str   — raw Location header value (if any)
        status_code : int   — HTTP status code (if any)
        ms          : int   — TCP connect time
    """
    start = time.perf_counter()
    result = {
        "open":        False,
        "redirects":   False,
        "location":    None,
        "status_code": None,
        "ms":          None,
    }

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        ms = round((time.perf_counter() - start) * 1000)
        result["open"] = True
        result["ms"]   = ms

        # Send minimal HTTP GET
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(request.encode())
        await asyncio.wait_for(writer.drain(), timeout=2.0)

        # Read response headers (up to 4KB)
        try:
            response_bytes = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            response = response_bytes.decode("utf-8", errors="ignore")
            lines = response.split("\r\n")

            # Parse status line
            if lines:
                parts = lines[0].split(" ", 2)
                if len(parts) >= 2:
                    try:
                        result["status_code"] = int(parts[1])
                    except ValueError:
                        pass

            # Parse Location header
            for line in lines[1:]:
                if line.lower().startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
                    result["location"] = loc
                    if loc.lower().startswith("https://"):
                        result["redirects"] = True
                    break

        except Exception:
            pass

        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass

    except Exception as ex:
        result["ms"] = round((time.perf_counter() - start) * 1000)

    return result
