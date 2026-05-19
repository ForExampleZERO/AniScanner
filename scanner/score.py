"""
scanner/score.py  (v4.0)
Scoring and verdict engine — now includes HTTP probe results.

Score breakdown (max 100):
    TCP OK          +20
    TCP latency     +20  (≤100ms→20, ≤250→12, ≤500→6, else 0)
    TLS OK          +20
    Cert valid      +10  (cert present + days_left ≥ 30)
    HTTP OK (2xx)   +15  (HTTP responded with 2xx)
    HTTP fast       +5   (TTFB ≤ 300ms)
    UDP OPEN        +5   (bonus, QUIC support)
    Cert fresh      +5   (days_left ≥ 90)

Verdict:
    90–100  Excellent
    70–89   Good
    45–69   Fair
    20–44   Weak
    <20     Dead
"""


def score_ip(
    tcp: dict,
    tls: dict,
    udp: dict | None = None,
    http: dict | None = None,
) -> dict:
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
        pts += 20
        days = tls.get("days_left")
        if days is not None and days >= 0:
            pts += 5              # cert present & not expired
            if days >= 30:  pts += 5
            if days >= 90:  pts += 5

    # ── HTTP ──────────────────────────────────────
    if http and http.get("ok") and http.get("status_code"):
        code = http["status_code"]
        if 200 <= code < 300:
            pts += 15             # 2xx success
        elif 300 <= code < 400:
            pts += 8              # redirect still responds
        elif code in (401, 403, 405):
            pts += 8              # auth/forbidden = server is alive
        elif 400 <= code < 500:
            pts += 4              # other 4xx = responds but error
        elif 500 <= code < 600:
            pts += 2              # 5xx = server error, but alive
        # TTFB bonus
        ttfb = http.get("ttfb_ms")
        if ttfb and ttfb <= 300:
            pts += 5

    # ── UDP / QUIC ────────────────────────────────
    if udp and udp.get("ok"):
        pts += 5

    pts = min(pts, 100)

    # ── Verdict ───────────────────────────────────
    tcp_ok  = bool(tcp  and tcp.get("ok"))
    tls_ok  = bool(tls  and tls.get("ok"))
    udp_ok  = bool(udp  and udp.get("ok"))
    http_ok = bool(http and http.get("ok") and http.get("status_code"))

    if pts >= 90:
        verdict, color = "Excellent", "#4ade80"
    elif pts >= 70:
        verdict, color = "Good",      "#38bdf8"
    elif pts >= 45:
        verdict, color = "Fair",      "#a78bfa"
    elif pts >= 20:
        if tcp_ok and not tls_ok and not http_ok:
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
