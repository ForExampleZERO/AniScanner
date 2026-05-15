```markdown
# 🔍 AniScanner

**AniScanner** is a powerful tool for scanning port 443 (HTTPS) and checking SNI (Server Name Indication). It supports uploading JSON/TXT files, IP ranges, CIDRs, domains, and custom `IP:SNI` format. The scan runs in the background using a Python Flask server, so closing the browser does **not** stop the scan.

![AniScanner Demo](https://via.placeholder.com/800x400?text=AniScanner+Screenshot) <!-- You can add a real screenshot later -->

## ✨ Features

- Scan port 443 using WebSocket/TLS handshake (fast and accurate)
- Supports:
  - Single IPs
  - Domains (auto-resolve)
  - `IP:SNI` (custom SNI)
  - IP ranges (e.g., `192.168.1.1-192.168.1.10`)
  - CIDR notation (e.g., `23.44.229.0/24`, IPv6 CIDRs are sampled)
- Upload **JSON** or **TXT** files (auto‑detect format)
- Download results in two modes:
  - **Simple**: one IP per line
  - **Advanced**: `IP (SNI) - Ping: Xms, Status: OPEN`
- Live logs of successful/failed scans in the browser
- Progress indicator in terminal (every 10%)
- Stop scan at any time
- Results persist even if browser is closed

## 🛠️ Installation & Run (Termux / Linux)

### Prerequisites
- Python 3.10+
- pip

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/ForExampleZERO/ApiScanner.git
   cd ApiScanner
```

1. Install dependencies
   ```bash
   pip install flask websockets
   ```
2. Run the server
   ```bash
   python main.py
   ```
3. Open in browser
   · On the same device: http://localhost:5000
   · On another device in the same network: http://<your-ip>:5000

📁 Project Structure

```
ApiScanner/
├── main.py                 # Flask backend + scanner logic
├── templates/
│   └── index.html          # Frontend UI
├── static/
│   ├── css/
│   │   └── style.css       # Styles (separated from HTML)
│   └── icons/
│       └── logo.png        # Optional logo
├── README.md
└── requirements.txt        # Flask, websockets
```

🧪 How to Use

1. Enter targets manually (one per line) in the textarea:
   · cloudflare.com
   · 1.1.1.1
   · 8.8.8.8:google.com (custom SNI)
   · 192.168.1.1-192.168.1.10 (range)
   · 23.44.229.0/24 (CIDR)
2. Or upload a JSON/TXT file containing the same format.
3. Adjust Concurrency (number of parallel scans) and Timeout (ms) according to your device/internet speed.
4. Click Start Scan.
5. Watch live logs and metrics.
6. After scan finishes, click Download Results and choose Simple (only IPs) or Advanced (with SNI and ping).

📦 JSON File Example

```json
[
  "23.44.229.0/24",
  "1.1.1.1",
  "google.com",
  "8.8.8.8:cloudflare.com"
]
```

🖼️ Logo & Styling

· Place logo.png in static/icons/ to display it in the header.
· CSS is separated in static/css/style.css.

📢 Telegram Channel

For updates and support: @aniartx

📄 License

MIT License – Free for personal and commercial use.

---

Version 1.0 | Made with ❤️ by AniArtX

```
