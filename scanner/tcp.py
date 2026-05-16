"""
scanner/tcp.py
Professional TCP connect probe for port 443.

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
    """
    Attempt a full TCP three-way handshake to ip:port.
    Measures time from SYN to ACK (connection established).
    """
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        ms = round((time.perf_counter() - start) * 1000)

        # Graceful close — don't linger
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


# ── Latency sampler (3-probe median) ─────────────

async def tcp_latency(
    ip:      str,
    port:    int   = 443,
    probes:  int   = 3,
    timeout: float = 2.0,
) -> dict:
    """
    Run `probes` TCP connects and return min/avg/max latency.
    Used by the scoring layer for a more accurate measurement.
    """
    times = []
    for _ in range(probes):
        r = await tcp_connect(ip, port, timeout)
        if r["ok"]:
            times.append(r["ms"])
        await asyncio.sleep(0.05)   # small gap between probes

    if not times:
        return {"ok": False, "min": None, "avg": None, "max": None, "loss": 100}

    loss = round((1 - len(times) / probes) * 100)
    return {
        "ok":  True,
        "min": min(times),
        "avg": round(sum(times) / len(times)),
        "max": max(times),
        "loss": loss,
    }
