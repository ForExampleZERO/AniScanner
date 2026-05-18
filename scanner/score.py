"""
scanner/score.py
Scoring and verdict engine.

Score breakdown (max 100):
    TCP OK          +20
    TCP latency     +20  (≤100ms→20, ≤250→12, ≤500→6, else 0)
    TLS OK          +35
    Cert valid      +10  (cert present + days_left ≥ 30)
    UDP OPEN        +10  (bonus, QUIC support)
    Cert fresh      +5   (days_left ≥ 90)

Verdict:
    90–100  Excellent
    70–89   Good
    45–69   Fair
    20–44   Weak
    <20     Dead
"""


def score_ip(tcp: dict, tls: dict, udp: dict | None = None) -> dict:
    pts = 0

    # ── TCP ───────────────────────────────────────
    if tcp and tcp.get("ok"):
        pts += 20
        ms = tcp.get("ms") or 9999
        if   ms <= 100: pts += 20
        elif ms <= 250: pts += 12
        elif ms <= 500: pts += 6

    # ── TLS ───────────────────────────────────────
    if tls and tls.get("ok"):
        pts += 35
        days = tls.get("days_left")
        if days is not None and days >= 0:
            pts += 5              # cert present & not expired
            if days >= 30:  pts += 5
            if days >= 90:  pts += 5

    # ── UDP / QUIC ────────────────────────────────
    if udp and udp.get("ok"):
        pts += 10

    # ── Verdict ───────────────────────────────────
    tcp_ok = bool(tcp and tcp.get("ok"))
    tls_ok = bool(tls and tls.get("ok"))
    udp_ok = bool(udp and udp.get("ok"))

    if pts >= 90:
        verdict, color = "Excellent", "#4ade80"
    elif pts >= 70:
        verdict, color = "Good",      "#38bdf8"
    elif pts >= 45:
        verdict, color = "Fair",      "#a78bfa"
    elif pts >= 20:
        if tcp_ok and not tls_ok:
            verdict, color = "TCP Only", "#facc15"
        elif udp_ok and not tcp_ok:
            verdict, color = "UDP Only", "#fb923c"
        else:
            verdict, color = "Weak",     "#facc15"
    else:
        verdict, color = "Dead",      "#f87171"

    # Extra label overrides
    if tls and tls.get("err") == "cert_mismatch":
        verdict = "Mismatch"
        color   = "#fb923c"

    return {
        "points":  pts,
        "verdict": verdict,
        "color":   color,
    }
