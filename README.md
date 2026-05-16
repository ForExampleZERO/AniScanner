# AniScanner v1.0

> Professional Port 443 Scanner — TCP · TLS · SNI · QUIC · Scoring

[![Telegram](https://img.shields.io/badge/Telegram-@aniartx-blue?logo=telegram)](https://t.me/aniartx)

---

## Features

- **TCP Connect** — full 3-way handshake, measures latency
- **TLS Handshake** — full TLS probe with SNI support, cipher & version detection
- **Certificate Inspection** — CN, Issuer, SAN, days until expiry
- **UDP / QUIC Probe** — sends a crafted QUIC Initial packet, detects OPEN / FILTERED / CLOSED
- **CDN Detection** — Cloudflare, AWS, Fastly, Akamai, Google, Azure, Vercel, Netlify, and more
- **Smart Scoring** — 0–100 score based on TCP, TLS, latency, cert validity, QUIC support
- **Background Sessions** — scan survives browser refresh/close (Termux stays alive)
- **Bilingual UI** — English / Persian (FA) with one click
- **Dynamic Columns** — TCP/UDP columns auto-hide based on selected scan mode
- **Export** — Simple (IP list) or Advanced (full CSV-like data)

## Input Formats

```
1.1.1.1                   # single IP
8.8.8.8-8.8.8.50         # IP range
192.168.1.0/24            # CIDR block
cloudflare.com            # domain (resolved to IPs, kept as SNI)
1.2.3.4#example.com       # IP with explicit SNI override
```

## Project Structure

```
AniScanner/
├── app.py                # Flask app + session manager
├── requirements.txt
├── README.md
│
├── scanner/
│   ├── tcp.py            # TCP connect probe + latency sampler
│   ├── tls.py            # TLS handshake + cert parser + CDN detector
│   ├── udp.py            # UDP/QUIC probe (RFC 9000 Initial packet)
│   ├── parser.py         # Input parser (IP/range/CIDR/domain)
│   └── score.py          # Scoring engine + verdict
│
├── templates/
│   └── index.html
│
└── static/
    ├── css/style.css
    ├── js/app.js
    ├── icons/            # SVG icons (Lucide)
    └── logo/logo.png
```

## Installation (Termux)

```bash
pkg install python
pip install flask

git clone https://github.com/ForExampleZERO/AniScanner
cd AniScanner

python app.py
```

Then open in your browser: `http://localhost:5000`

## Icons

Place the following SVG files in `static/icons/`:
- `activity.svg` — from the provided icons.zip
- `tcp.svg`, `udp.svg`, `both.svg` — custom icons for scan mode selector

Place your logo at `static/logo/logo.png`.

## Verdict Scale

| Score | Verdict   |
|-------|-----------|
| 90–100 | Excellent |
| 70–89  | Good      |
| 45–69  | Fair      |
| 20–44  | Weak / TCP Only / UDP Only |
| < 20   | Dead      |

---

**@aniartx** · [t.me/aniartx](https://t.me/aniartx)
