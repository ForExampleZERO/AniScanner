import asyncio
import ssl
import time
from flask import Flask, render_template, request, jsonify, send_file
import ipaddress
from io import BytesIO
import socket
import concurrent.futures
import logging
import json

# غیرفعال کردن لاگ‌های پیش‌فرض Flask
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# تنظیم لاگ سفارشی برای نمایش فقط خطاها
app = Flask(__name__)               # ← ابتدا app را بسازید

import os

@app.route('/logo.png')
def logo():
    logo_path = os.path.join(os.path.dirname(__file__), 'logo.png')
    if os.path.exists(logo_path):
        return send_file(logo_path, mimetype='image/png')
    else:
        return '', 404

# غیرفعال کردن لاگ درخواست‌های Flask
app.logger.disabled = True

# حالا error handler را تعریف کنید
@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    print("="*50)
    print("ERROR OCCURRED:")
    traceback.print_exc()
    print("="*50)
    return jsonify({'error': str(e)}), 500

# بقیه کدهای کلاس Scanner و توابع... (بدون تغییر)

class Scanner:
    def __init__(self):
        self.scanning = False
        self.stop_requested = False
        self.targets = []
        self.results = []
        self.scanned_count = 0
        self.success_count = 0
        self.fail_count = 0
        self.concurrency = 10
        self.timeout_ms = 2000
        self.tasks = []
        self.queue = None
        self.loop = None
        self.last_logged_percent = -1
        self.recent_success = []
        self.recent_fail = []

scanner = Scanner()

_ssl_context = ssl.create_default_context()
_ssl_context.check_hostname = False
_ssl_context.verify_mode = ssl.CERT_NONE

def ip_to_int(ip):
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def int_to_ip(num):
    return f"{(num >> 24) & 0xff}.{(num >> 16) & 0xff}.{(num >> 8) & 0xff}.{num & 0xff}"

def expand_range(start_ip, end_ip):
    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    return [int_to_ip(i) for i in range(start, end+1)]

def cidr_to_ips(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        # تشخیص IPv6
        if net.version == 6:
            # فقط یک آی‌پی نمونه (اولین host) برگردان
            hosts = list(net.hosts())
            if hosts:
                return [str(hosts[0])]
            else:
                # اگر host وجود نداشت (مثل /128)، خود شبکه را برگردان
                return [str(net.network_address)]
        else:
            # IPv4: همه آی‌پی‌ها را برگردان (اگر تعداد زیاد است می‌توان محدود کرد)
            return [str(ip) for ip in net.hosts()]
    except Exception as e:
        print(f"[ERROR] CIDR {cidr}: {e}")
        return []

async def reverse_dns(ip, timeout=1.0):
    loop = asyncio.get_running_loop()
    try:
        with concurrent.futures.ThreadPoolExecutor() as pool:
            result = await asyncio.wait_for(
                loop.run_in_executor(pool, socket.gethostbyaddr, ip),
                timeout=timeout
            )
            return result[0]
    except:
        return None

def parse_target_line(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    if ':' in line and not line.startswith('['):
        parts = line.split(':', 1)
        maybe_ip = parts[0].strip()
        sni = parts[1].strip()
        try:
            ipaddress.ip_address(maybe_ip)
            return {'ip': maybe_ip, 'sni': sni}
        except:
            return None

    if '-' in line:
        ips = expand_range(*line.split('-'))
        return [{'ip': ip, 'sni': ip} for ip in ips]

    if '/' in line:
        try:
            ips = cidr_to_ips(line)
            return [{'ip': ip, 'sni': ip} for ip in ips]
        except:
            return None

    try:
        ipaddress.ip_address(line)
        return {'ip': line, 'sni': line}
    except:
        return {'ip': None, 'sni': line}

def parse_input_to_targets(text):
    lines = text.splitlines()
    all_targets = []
    for line in lines:
        parsed = parse_target_line(line)
        if parsed is None:
            continue
        if isinstance(parsed, list):
            all_targets.extend(parsed)
        else:
            all_targets.append(parsed)
    return all_targets

def extract_ips_from_json(data):
    """استخراج آی‌پی‌ها و CIDRها از داده JSON (حتی تو در تو)"""
    targets = []
    
    if isinstance(data, dict):
        # جستجو در تمام مقادیر دیکشنری
        for key, value in data.items():
            targets.extend(extract_ips_from_json(value))
    elif isinstance(data, list):
        # جستجو در آیتم‌های لیست
        for item in data:
            targets.extend(extract_ips_from_json(item))
    elif isinstance(data, str):
        # اگر رشته است، بررسی کنیم شبیه IP/CIDR/دامنه است
        data = data.strip().strip('"')
        if data and not data.startswith('#'):
            # حذف کامنت‌های JSON (چیزهایی که شبیه توضیحات هستن)
            if data.startswith('//') or data.startswith('/*'):
                return targets
            parsed = parse_target_line(data)
            if parsed:
                if isinstance(parsed, list):
                    targets.extend(parsed)
                else:
                    targets.append(parsed)
    return targets

def detect_and_parse_file(content, filename):
    """تشخیص خودکار فرمت فایل (TXT یا JSON) و استخراج آی‌پی‌ها"""
    content = content.strip()
    
    # تلاش برای پارس به عنوان JSON
    try:
        json_data = json.loads(content)
        print(f"[INFO] Detected JSON format in {filename}")
        targets = extract_ips_from_json(json_data)
        if targets:
            return targets
    except (json.JSONDecodeError, ValueError):
        pass
    
    # اگر JSON نبود، به عنوان متن ساده پردازش کن
    print(f"[INFO] Detected TXT format in {filename}")
    return parse_input_to_targets(content)

def parse_multiple_files(files_content):
    """پردازش چند فایل با فرمت‌های مختلف"""
    all_targets = []
    for filename, content in files_content:
        targets = detect_and_parse_file(content, filename)
        all_targets.extend(targets)
        print(f"[INFO] Extracted {len(targets)} targets from {filename}")
    return all_targets

async def resolve_sni(sni):
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(sni, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except:
        pass
    return None

async def test_ip_sni_fast(ip, sni, timeout_ms):
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=_ssl_context, server_hostname=sni),
            timeout=timeout_ms / 1000.0
        )
        writer.close()
        await writer.wait_closed()
        ping = int((time.perf_counter() - start) * 1000)
        return True, ping
    except Exception:
        return False, None

async def log_progress():
    if scanner.total_targets == 0:
        return
    percent = int((scanner.scanned_count / scanner.total_targets) * 100)
    current_step = percent // 10
    
    if current_step > scanner.last_logged_percent and percent > 0:
        scanner.last_logged_percent = current_step
        if percent <= 100:
            print(f"[PROGRESS] {percent}% ({scanner.scanned_count}/{scanner.total_targets})")

async def worker(worker_id):
    global scanner
    while scanner.scanning and not scanner.stop_requested:
        try:
            target = await asyncio.wait_for(scanner.queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        if target is None:
            break

        ip_to_use = target['ip']
        sni = target['sni']

        if ip_to_use is None:
            ip_to_use = await resolve_sni(sni)
            if not ip_to_use:
                scanner.scanned_count += 1
                scanner.fail_count += 1
                scanner.recent_fail.append({"ip": sni, "sni": sni})
                await log_progress()
                scanner.queue.task_done()
                continue
        else:
            if sni == ip_to_use:
                domain = await reverse_dns(ip_to_use, timeout=1.0)
                if domain:
                    sni = domain

        success, ping = await test_ip_sni_fast(ip_to_use, sni, scanner.timeout_ms)
        scanner.scanned_count += 1
        
        if success:
            scanner.success_count += 1
            scanner.results.append({"ip": ip_to_use, "sni": sni, "ping": ping})
            scanner.recent_success.append({"ip": ip_to_use, "sni": sni, "ping": ping})
            print(f"[SUCCESS] {sni} -> {ip_to_use} ({ping}ms)")
        else:
            scanner.fail_count += 1
            scanner.recent_fail.append({"ip": ip_to_use, "sni": sni})
        
        if len(scanner.recent_success) > 20:
            scanner.recent_success.pop(0)
        if len(scanner.recent_fail) > 20:
            scanner.recent_fail.pop(0)
        
        await log_progress()
        scanner.queue.task_done()

async def run_scanner_async():
    global scanner
    scanner.queue = asyncio.Queue()
    scanner.total_targets = len(scanner.targets)
    scanner.last_logged_percent = -1
    scanner.recent_success = []
    scanner.recent_fail = []
    
    for target in scanner.targets:
        await scanner.queue.put(target)
    
    print(f"\n[START] Scanning started | Targets: {scanner.total_targets} | Concurrency: {scanner.concurrency} | Timeout: {scanner.timeout_ms}ms\n")
    
    scanner.tasks = []
    for i in range(scanner.concurrency):
        task = asyncio.create_task(worker(i))
        scanner.tasks.append(task)
    
    await scanner.queue.join()
    
    scanner.scanning = False
    for task in scanner.tasks:
        task.cancel()
    await asyncio.gather(*scanner.tasks, return_exceptions=True)
    scanner.tasks = []
    
    print(f"\n[FINISH] Scan completed | Success: {scanner.success_count} | Failed: {scanner.fail_count}\n")

def start_scan_async():
    global scanner
    if scanner.scanning:
        return
    scanner.scanning = True
    scanner.stop_requested = False
    scanner.scanned_count = 0
    scanner.success_count = 0
    scanner.fail_count = 0
    scanner.results = []
    scanner.last_logged_percent = -1
    scanner.recent_success = []
    scanner.recent_fail = []

    def run_in_thread():
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        scanner.loop = new_loop
        new_loop.run_until_complete(run_scanner_async())

    import threading
    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()
    scanner.thread = thread

def stop_scan():
    global scanner
    if not scanner.scanning:
        return
    scanner.stop_requested = True
    scanner.scanning = False
    
    # خالی کردن صف برای آزاد کردن queue.join()
    if scanner.queue:
        try:
            while not scanner.queue.empty():
                scanner.queue.get_nowait()
                scanner.queue.task_done()
        except Exception:
            pass
    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/parse', methods=['POST'])
def api_parse():
    data = request.get_json()
    text = data.get('text', '')
    targets = parse_input_to_targets(text)
    return jsonify({'count': len(targets), 'targets': targets})

@app.route('/api/upload_files', methods=['POST'])
def api_upload_files():
    """پردازش فایل‌های آپلود شده (TXT یا JSON)"""
    files = request.files.getlist('files')
    all_targets = []
    files_content = []
    
    for file in files:
        try:
            content = file.read().decode('utf-8')
            files_content.append((file.filename, content))
        except Exception as e:
            print(f"[ERROR] Failed to read {file.filename}: {e}")
    
    all_targets = parse_multiple_files(files_content)
    
    # حذف تکراری‌ها
    unique_targets = []
    seen = set()
    for t in all_targets:
        key = f"{t.get('ip', '')}:{t.get('sni', '')}"
        if key not in seen:
            seen.add(key)
            unique_targets.append(t)
    
    return jsonify({'count': len(unique_targets), 'targets': unique_targets})

@app.route('/api/load', methods=['POST'])
def api_load():
    global scanner
    data = request.get_json()
    targets = data.get('targets', [])
    scanner.targets = targets
    scanner.scanned_count = 0
    scanner.success_count = 0
    scanner.fail_count = 0
    scanner.results = []
    scanner.last_logged_percent = -1
    scanner.recent_success = []
    scanner.recent_fail = []
    print(f"\n[LOAD] Loaded {len(targets)} targets\n")
    return jsonify({'status': 'ok', 'count': len(targets)})

@app.route('/api/start', methods=['POST'])
def api_start():
    global scanner
    if scanner.scanning:
        return jsonify({'status': 'already scanning'})
    if not scanner.targets:
        return jsonify({'status': 'no targets loaded'})
    data = request.get_json() or {}
    scanner.concurrency = data.get('concurrency', 10)
    scanner.timeout_ms = data.get('timeout', 2000)
    start_scan_async()
    return jsonify({'status': 'started'})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    stop_scan()
    return jsonify({'status': 'stopped'})

@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({
        'scanning': scanner.scanning,
        'total': len(scanner.targets),
        'scanned': scanner.scanned_count,
        'success': scanner.success_count,
        'fail': scanner.fail_count,
        'results': scanner.results[-500:],
        'recent_success': scanner.recent_success[-20:],
        'recent_fail': scanner.recent_fail[-20:],
        'concurrency': scanner.concurrency,
        'timeout': scanner.timeout_ms
    })

@app.route('/api/download', methods=['POST'])
def api_download():
    if not scanner.results:
        return jsonify({'error': 'No results'}), 404
    
    data = request.get_json()
    mode = data.get('mode', 'simple')
    sorted_results = sorted(scanner.results, key=lambda x: x['ping'])
    
    if mode == 'simple':
        lines = [r['ip'] for r in sorted_results]
        filename = 'clean_ips.txt'
    else:
        lines = []
        for r in sorted_results:
            if r['sni'] == r['ip']:
                lines.append(f"{r['ip']} - Ping: {r['ping']}ms, Status: OPEN")
            else:
                lines.append(f"{r['ip']} ({r['sni']}) - Ping: {r['ping']}ms, Status: OPEN")
        filename = 'detailed_results.txt'
    
    # استفاده از newline ویندوز (CRLF) برای سازگاری با Notepad و کپی کردن
    content = "\r\n".join(lines)
    return send_file(
        BytesIO(content.encode('utf-8')),
        as_attachment=True,
        download_name=filename,
        mimetype='text/plain;charset=utf-8'
    )

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🔍 AniScanner Server Started")
    print("📍 Access: http://localhost:5000")
    print("📁 Supports: TXT, JSON (auto-detect)")
    print("="*50 + "\n")
    
    import sys
    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None
    
    error_log = logging.getLogger('error_logger')
    error_log.setLevel(logging.ERROR)
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)