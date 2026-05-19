"""
scanner/udp.py
UDP probe for port 443 — targets QUIC / HTTP3.

Strategy
--------
1. Send a crafted QUIC Initial packet (RFC 9000 §17.2.2).
   A QUIC-capable server will reply with its own Initial or a Retry.
2. If we get ANY bytes back within timeout → OPEN.
3. If we get an ICMP Port-Unreachable → CLOSED  (Linux: ConnectionRefusedError).
4. Silence within timeout            → FILTERED (firewall drops, most common).

Returns
-------
    ok       : bool   — received a valid response
    status   : str    — OPEN | FILTERED | CLOSED | ERROR
    ms       : int | None
    quic     : bool   — response looks like a QUIC packet
"""

import asyncio
import os
import time


# ── QUIC Initial packet builder ───────────────────

def _build_quic_initial(dst_ip: str, dst_port: int) -> bytes:
    """
    Minimal QUIC Initial packet per RFC 9000.
    Enough to trigger a server response without completing the handshake.

    Layout (simplified):
        1 byte  Header Form=1 | Fixed=1 | Type=0x00 | Reserved | PKT# Len
        4 bytes Version (QUIC v1 = 0x00000001)
        1 byte  DCID length
        8 bytes DCID  (random)
        1 byte  SCID length (0 = no SCID)
        1 byte  Token length (0)
        2 bytes Packet length (padded to 1200 to avoid amplification filter)
        4 bytes Packet number
        payload (zeros, padded)
    """
    dcid    = os.urandom(8)
    version = b"\x00\x00\x00\x01"   # QUIC v1

    header  = (
        bytes([0xc0])   # Long header, Initial
        + version
        + bytes([len(dcid)]) + dcid
        + bytes([0x00])   # SCID len = 0
        + bytes([0x00])   # Token len = 0
    )

    # Total target = 1200 bytes (RFC minimum to avoid server dropping)
    payload_len = 1200 - len(header) - 4   # 4 = packet number field
    payload_len = max(payload_len, 16)

    # Variable-length int encoding for length field (2-byte form)
    pkt_len = (4 + payload_len) | 0x4000    # 2-byte VLI
    header += pkt_len.to_bytes(2, "big")
    header += b"\x00\x00\x00\x01"           # packet number = 1
    header += b"\x00" * payload_len

    return header


# ── Async UDP datagram protocol ───────────────────

class _UDPProber(asyncio.DatagramProtocol):
    def __init__(self):
        self.response   = None
        self.received   = asyncio.Event()
        self.transport  = None
        self.error      = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.response = data
        self.received.set()

    def error_received(self, exc):
        self.error = exc
        self.received.set()

    def connection_lost(self, exc):
        self.received.set()


# ── Core probe ────────────────────────────────────

async def udp_probe(
    ip:      str,
    port:    int   = 443,
    timeout: float = 2.5,
) -> dict:
    """
    Send a QUIC Initial packet and wait for a response.
    """
    payload = _build_quic_initial(ip, port)
    start   = time.perf_counter()

    loop = asyncio.get_event_loop()
    prober = _UDPProber()

    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: prober,
            remote_addr=(ip, port),
        )
    except Exception as ex:
        return {
            "ok":     False,
            "status": "ERROR",
            "ms":     None,
            "quic":   False,
            "err":    str(ex)[:80],
        }

    try:
        transport.sendto(payload)

        try:
            await asyncio.wait_for(prober.received.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

        ms = round((time.perf_counter() - start) * 1000)

        # ICMP port unreachable arrives as ConnectionRefusedError via error_received
        if prober.error is not None:
            if isinstance(prober.error, ConnectionRefusedError):
                return {"ok": False, "status": "CLOSED", "ms": ms, "quic": False, "err": "icmp_unreachable"}
            return {"ok": False, "status": "ERROR",  "ms": ms, "quic": False, "err": str(prober.error)[:60]}

        if prober.response is None:
            return {"ok": False, "status": "FILTERED", "ms": ms, "quic": False, "err": None}

        # Check if response looks like QUIC (long header bit set)
        quic = bool(prober.response) and (prober.response[0] & 0x80) != 0

        return {"ok": True, "status": "OPEN", "ms": ms, "quic": quic, "err": None}

    finally:
        try: transport.close()
        except: pass
