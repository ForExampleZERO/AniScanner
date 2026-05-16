// ══════════════════════════════════════════════════
//  AniScanner v3.2 — Frontend
// ══════════════════════════════════════════════════

const VERSION = 'v3.2';
const MAX_LOG = 300;

// ── i18n ──────────────────────────────────────────
const LANG = {
    en: {
        ready:         'AniScanner Ready.',
        listEmpty:     '⚠ List is empty.',
        stopFirst:     '⚠ Stop the scan first.',
        fileLoaded:    '📁 File loaded.',
        prepared:      n  => `📋 ${n} IPs prepared.`,
        scanStart:     (n,c) => `🚀 Scanning ${n} IPs — concurrency: ${c}`,
        scanStop:      '⏸ Scan stopped.',
        scanDone:      (ok,f) => `🏁 Done | OK: ${ok} | Failed: ${f}`,
        dlDone:        m  => `📥 Downloaded (${m}).`,
        dlEmpty:       '⚠ No successful IPs to export.',
        serverError:   '❌ Server connection error.',
        reconnected:   '🔄 Reconnected — loading results…',
        result:        (ip,ms,v) => `${ip} | ${ms}ms | ${v}`,
        dead:          ip => `✘ ${ip} — Dead`,
        heroDesc:      'Professional Port 443 scanner — TCP connect, TLS handshake, SNI validation, certificate check & smart scoring.',
        inputTitle:    '📂 Input — IP / Range / CIDR / Domain',
        uploadLabel:   'Upload TXT file',
        manualLabel:   'Manual input (one per line: IP, range, CIDR, domain)',
        prepareBtn:    '📋 Prepare & Deduplicate',
        settingsTitle: '⚙ Configuration',
        concLabel:     'Concurrency',
        toLabel:       'Timeout (ms)',
        scanModeLabel: 'Scan Mode',
        startBtn:      '▶ Start Scan',
        stopBtn:       '⏹ Stop Scan',
        dlBtn:         '📥 Export ▾',
        dlSimple:      '📄 Simple — one IP per line',
        dlAdvanced:    '📊 Advanced — IP · SNI · Ping · TLS · Score',
        statTotal:     '🎯 Total',
        statScanned:   '🔄 Scanned',
        statOk:        '✅ OK',
        statFail:      '❌ Failed',
        waiting:       'Waiting for scan…',
        footerTxt:     `⚡ AniScanner ${VERSION} — TCP · TLS · SNI · Cert · Scoring`,
        results:       n => `${n} results`,
    },
    fa: {
        ready:         'AniScanner آماده است.',
        listEmpty:     '⚠ لیست خالی است.',
        stopFirst:     '⚠ ابتدا اسکن را متوقف کنید.',
        fileLoaded:    '📁 فایل بارگذاری شد.',
        prepared:      n  => `📋 ${n} آی‌پی آماده شد.`,
        scanStart:     (n,c) => `🚀 اسکن ${n} IP — همزمانی: ${c}`,
        scanStop:      '⏸ اسکن متوقف شد.',
        scanDone:      (ok,f) => `🏁 پایان | موفق: ${ok} | ناموفق: ${f}`,
        dlDone:        m  => `📥 دانلود شد (${m}).`,
        dlEmpty:       '⚠ هیچ IP موفقی وجود ندارد.',
        serverError:   '❌ خطا در اتصال به سرور.',
        reconnected:   '🔄 اتصال مجدد — در حال بارگذاری…',
        result:        (ip,ms,v) => `${ip} | ${ms}ms | ${v}`,
        dead:          ip => `✘ ${ip} — Dead`,
        heroDesc:      'اسکنر حرفه‌ای پورت ۴۴۳ — تست TCP، TLS Handshake، SNI، اعتبارسنجی گواهی و امتیازدهی هوشمند.',
        inputTitle:    '📂 ورودی — IP / Range / CIDR / Domain',
        uploadLabel:   'آپلود فایل TXT',
        manualLabel:   'ورودی دستی (هر خط: IP یا رنج یا CIDR یا دامنه)',
        prepareBtn:    '📋 آماده‌سازی و حذف تکراری',
        settingsTitle: '⚙ پیکربندی',
        concLabel:     'همزمانی',
        toLabel:       'تایم‌اوت (ms)',
        scanModeLabel: 'حالت اسکن',
        startBtn:      '▶ شروع اسکن',
        stopBtn:       '⏹ توقف اسکن',
        dlBtn:         '📥 دانلود ▾',
        dlSimple:      '📄 ساده — فقط IP',
        dlAdvanced:    '📊 پیشرفته — IP · SNI · Ping · TLS · Score',
        statTotal:     '🎯 کل',
        statScanned:   '🔄 اسکن‌شده',
        statOk:        '✅ موفق',
        statFail:      '❌ ناموفق',
        waiting:       'در انتظار اسکن…',
        footerTxt:     `⚡ AniScanner ${VERSION} — TCP · TLS · SNI · Cert · Scoring`,
        results:       n => `${n} نتیجه`,
    }
};

let currentLang = localStorage.getItem('lang') || 'en';
const t = () => LANG[currentLang];

function applyLang() {
    document.documentElement.lang = currentLang === 'fa' ? 'fa' : 'en';
    document.documentElement.dir  = currentLang === 'fa' ? 'rtl' : 'ltr';
    document.getElementById('langBtn').textContent = currentLang === 'fa' ? '🌐 EN' : '🌐 FA';

    const s = t();
    const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };

    set('heroDesc',      s.heroDesc);
    set('inputTitle',    s.inputTitle);
    set('uploadLabel',   s.uploadLabel);
    set('manualLabel',   s.manualLabel);
    set('parseBtn',      s.prepareBtn);
    set('settingsTitle', s.settingsTitle);
    set('concLabel',     s.concLabel);
    set('toLabel',       s.toLabel);
    set('scanModeLabel', s.scanModeLabel);
    set('downloadBtn',   s.dlBtn);
    set('dlSimpleBtn',   s.dlSimple);
    set('dlAdvBtn',      s.dlAdvanced);
    set('lblTotal',      s.statTotal);
    set('lblScanned',    s.statScanned);
    set('lblOk',         s.statOk);
    set('lblFail',       s.statFail);
    set('waitingTxt',    s.waiting);
    set('footer',        s.footerTxt);

    updateScanButton();
    updateResultCount();
}

document.getElementById('langBtn').addEventListener('click', () => {
    currentLang = currentLang === 'en' ? 'fa' : 'en';
    localStorage.setItem('lang', currentLang);
    applyLang();
});

// ── Scan Mode ─────────────────────────────────────
function getScanMode() {
    return document.querySelector('input[name="scanMode"]:checked')?.value || 'TCP';
}

// Dynamic column visibility based on scan mode
function applyColumnVisibility() {
    const mode     = getScanMode();
    const showTcp  = mode === 'TCP'  || mode === 'BOTH';
    const showUdp  = mode === 'UDP'  || mode === 'BOTH';

    // th + all td in that column
    document.querySelectorAll('.col-tcp').forEach(el => {
        el.style.display = showTcp ? '' : 'none';
    });
    document.querySelectorAll('.col-udp').forEach(el => {
        el.style.display = showUdp ? '' : 'none';
    });
}

document.querySelectorAll('input[name="scanMode"]').forEach(r => {
    r.addEventListener('change', () => {
        applyColumnVisibility();
        refreshTable();   // re-render with correct columns
    });
});

// ── State ─────────────────────────────────────────
let scanning     = false;
let sessionId    = localStorage.getItem('sessionId') || null;
let entries      = [];
let results      = [];
let totalCount   = 0;
let scannedCount = 0;
let successCount = 0;
let failCount    = 0;
let eventSource  = null;

// ── Log ───────────────────────────────────────────
function log(msg, color = '#4ade80') {
    const el = document.getElementById('logArea');
    const d  = document.createElement('div');
    d.innerHTML   = `[${new Date().toLocaleTimeString()}] ${msg}`;
    d.style.color = color;
    el.appendChild(d);
    while (el.children.length > MAX_LOG) el.removeChild(el.firstChild);
    el.scrollTop = el.scrollHeight;
}

// ── Stats ─────────────────────────────────────────
function updateStats() {
    document.getElementById('totalStat').innerText   = totalCount;
    document.getElementById('scannedStat').innerText = scannedCount;
    document.getElementById('successStat').innerText = successCount;
    document.getElementById('failStat').innerText    = failCount;

    const pct  = totalCount ? (scannedCount / totalCount) * 100 : 0;
    const fill = document.getElementById('progressFill');
    fill.style.width = pct + '%';
    fill.innerText   = Math.round(pct) + '%';
}

function updateResultCount() {
    const el = document.getElementById('resultCount');
    if (el) el.textContent = t().results(results.length);
}

// ── Scan Button ───────────────────────────────────
function updateScanButton() {
    const btn = document.getElementById('toggleScanBtn');
    if (scanning) {
        btn.textContent = t().stopBtn;
        btn.className   = 'btn-danger';
    } else {
        btn.textContent = t().startBtn;
        btn.className   = 'btn-success';
    }
}

// ── CDN icons ─────────────────────────────────────
const CDN_ICONS = {
    'Cloudflare':    '☁️',
    'AWS':           '🟠',
    'Fastly':        '⚡',
    'Akamai':        '🔵',
    'Google':        '🔴',
    'Azure':         '🔷',
    'Vercel':        '▲',
    'Netlify':       '🟢',
    "Let's Encrypt": '🔒',
};

// ── Badge helpers ─────────────────────────────────
function tcpBadge(tcp) {
    if (!tcp)        return '<span class="badge badge-fail">—</span>';
    if (tcp.ok)      return '<span class="badge badge-open">OPEN</span>';
    if (tcp.err?.includes('timeout') || tcp.err?.includes('timed'))
                     return '<span class="badge badge-timeout">T/O</span>';
    return           '<span class="badge badge-closed">CLOSED</span>';
}

function udpBadge(udp) {
    // UDP is harder to verify; backend marks open/filtered/closed
    if (!udp) return '<span class="badge badge-fail">—</span>';
    if (udp.ok)       return '<span class="badge badge-open">OPEN</span>';
    if (udp.filtered) return '<span class="badge badge-filtered">FILTERED</span>';
    return            '<span class="badge badge-closed">CLOSED</span>';
}

function sniBadge(tls) {
    if (!tls) return '<span class="badge badge-fail">—</span>';
    if (tls.ok) return '<span class="badge badge-ok">OK</span>';
    if (tls.err === 'cert_mismatch') return '<span class="badge badge-mismatch">MISMATCH</span>';
    return '<span class="badge badge-fail">FAIL</span>';
}

function certCell(tls) {
    if (!tls?.ok || !tls.cn) return '<span style="color:var(--muted)">—</span>';
    const days    = tls.days_left;
    const daysStr = days !== null && days !== undefined
        ? `<div class="cert-days ${days < 30 ? 'cert-warn' : ''}">${days}d left</div>`
        : '';
    const cn = tls.cn.length > 22 ? tls.cn.slice(0,20)+'…' : tls.cn;
    return `<div class="cert-cn">${cn}</div>${daysStr}`;
}

function scoreCell(sc) {
    if (!sc) return '<span style="color:var(--muted)">—</span>';
    const cls = sc.points >= 80 ? 'score-excellent'
              : sc.points >= 55 ? 'score-good'
              : sc.points >= 30 ? 'score-weak'
              :                   'score-dead';
    return `<span class="${cls}">${sc.points}</span>`;
}

function pingCell(tcp) {
    if (!tcp?.ok) return '<span style="color:var(--muted)">T/O</span>';
    return `<span class="ping-val">${tcp.ms}ms</span>`;
}

function latencyCell(tls) {
    if (!tls?.ms) return '<span style="color:var(--muted)">—</span>';
    return `<span class="ping-val">${tls.ms}ms</span>`;
}

function lossCell(sc) {
    // approximate loss from score
    if (!sc) return '<span style="color:var(--muted)">—</span>';
    const loss = sc.points >= 80 ? '0%'
               : sc.points >= 55 ? '2%'
               : sc.points >= 30 ? '8%'
               :                   '100%';
    const cls  = sc.points >= 55 ? 'loss-ok' : 'loss-bad';
    return `<span class="${cls}">${loss}</span>`;
}

function cdnCell(provider) {
    if (!provider) return '<span style="color:var(--muted)">—</span>';
    const icon = CDN_ICONS[provider] || '🌐';
    return `<span class="cdn-badge">${icon} ${provider}</span>`;
}

function tlsVerCell(tls) {
    if (!tls?.tls_ver) return '<span style="color:var(--muted)">—</span>';
    return `<span class="tls-pill">${tls.tls_ver}</span>`;
}

// ── Table Refresh ─────────────────────────────────
let tableTimer = null;
function scheduleTableRefresh() {
    if (tableTimer) return;
    tableTimer = setTimeout(() => { refreshTable(); tableTimer = null; }, 400);
}

function refreshTable() {
    const mode    = getScanMode();
    const showTcp = mode === 'TCP'  || mode === 'BOTH';
    const showUdp = mode === 'UDP'  || mode === 'BOTH';

    const sorted = [...results].sort((a, b) => (b.score?.points||0) - (a.score?.points||0));
    const tbody  = document.querySelector('#resultTable tbody');
    tbody.innerHTML = '';

    sorted.forEach((r, i) => {
        const row = tbody.insertRow();
        const tcp = r.tcp || {};
        const tls = r.tls || {};
        const udp = r.udp || null;
        const sc  = r.score || {};

        // #
        const c0 = row.insertCell(0);
        c0.textContent = i + 1;

        // IP
        const c1 = row.insertCell(1);
        c1.textContent = r.ip;
        c1.style.fontWeight = '600';
        c1.style.color = '#c5d5f0';

        // Ping
        row.insertCell(2).innerHTML = pingCell(tcp);

        // TCP (conditional)
        const cTcp = row.insertCell(3);
        cTcp.className   = 'col-tcp';
        cTcp.innerHTML   = tcpBadge(tcp);
        cTcp.style.display = showTcp ? '' : 'none';

        // UDP (conditional)
        const cUdp = row.insertCell(4);
        cUdp.className   = 'col-udp';
        cUdp.innerHTML   = udpBadge(udp);
        cUdp.style.display = showUdp ? '' : 'none';

        // TLS Version
        row.insertCell(5).innerHTML = tlsVerCell(tls);

        // SNI
        row.insertCell(6).innerHTML = sniBadge(tls);

        // Cert
        row.insertCell(7).innerHTML = certCell(tls);

        // CDN
        row.insertCell(8).innerHTML = cdnCell(r.provider);

        // ASN (from backend — fallback to —)
        const cAsn = row.insertCell(9);
        cAsn.textContent = r.asn || '—';
        cAsn.style.color = '#3a5070';
        cAsn.style.fontFamily = 'monospace';

        // Provider (ISP)
        const cProv = row.insertCell(10);
        cProv.textContent = r.isp || r.provider || '—';
        cProv.style.color = '#4b6a90';

        // Latency (TLS RTT)
        row.insertCell(11).innerHTML = latencyCell(tls);

        // Loss (estimated)
        row.insertCell(12).innerHTML = lossCell(sc);

        // Score
        row.insertCell(13).innerHTML = scoreCell(sc);
    });

    // sync header column visibility
    applyColumnVisibility();
    updateResultCount();
}

// ── Prepare ───────────────────────────────────────
async function prepareList() {
    if (scanning) { log(t().stopFirst, '#facc15'); return []; }
    const text = document.getElementById('ipListInput').value;
    if (!text.trim()) { log(t().listEmpty, '#facc15'); return []; }

    try {
        const resp = await fetch('/api/parse', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ ips: text }),
        });
        const data = await resp.json();
        entries = data.entries;

        document.getElementById('ipListInput').value =
            entries.map(e => e.sni ? `${e.ip}  # ${e.sni}` : e.ip).join('\n');

        scannedCount = successCount = failCount = 0;
        totalCount   = entries.length;
        updateStats();
        document.getElementById('progressFill').style.width = '0%';
        document.getElementById('waitingState').style.display = 'flex';
        document.querySelector('#resultTable tbody').innerHTML = '';
        updateResultCount();
        log(t().prepared(entries.length), '#38bdf8');
        return entries;
    } catch (e) {
        log(t().serverError, '#ef4444');
        return [];
    }
}

// ── SSE ───────────────────────────────────────────
function connectStream(sid) {
    if (eventSource) eventSource.close();
    eventSource = new EventSource(`/api/scan/stream?session_id=${sid}`);

    eventSource.onmessage = e => {
        const msg = JSON.parse(e.data);
        if (msg.type === 'result') {
            const r = msg.data;
            scannedCount++;
            if (r.tcp?.ok || r.tls?.ok) {
                successCount++;
                results.push(r);
                log(t().result(r.ip, r.tcp?.ms ?? '?', r.score?.verdict || ''), r.score?.color || '#4ade80');
                scheduleTableRefresh();
            } else {
                failCount++;
                log(t().dead(r.ip), '#f87171');
            }
            updateStats();
        } else if (msg.type === 'done') {
            finishScan();
        }
    };
}

// ── Start ─────────────────────────────────────────
async function startScan(list) {
    if (scanning || !list.length) return;

    const concurrency = parseInt(document.getElementById('concurrency').value);
    const timeout     = parseInt(document.getElementById('timeout').value);
    const scan_mode   = getScanMode();

    try {
        const resp = await fetch('/api/scan/start', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ entries: list, concurrency, timeout, scan_mode, session_id: sessionId }),
        });
        const data = await resp.json();
        sessionId  = data.session_id;
        localStorage.setItem('sessionId', sessionId);

        scanning     = true;
        results      = [];
        scannedCount = successCount = failCount = 0;
        totalCount   = list.length;

        document.getElementById('waitingState').style.display = 'none';
        updateStats(); refreshTable(); updateScanButton();
        document.getElementById('parseBtn').disabled = true;

        log(t().scanStart(list.length, concurrency), '#38bdf8');
        connectStream(sessionId);
    } catch (e) {
        log(t().serverError, '#ef4444');
    }
}

// ── Stop / Finish ─────────────────────────────────
async function stopScan() {
    if (!scanning) return;
    scanning = false;
    if (eventSource) { eventSource.close(); eventSource = null; }
    if (sessionId) {
        await fetch('/api/scan/stop', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ session_id: sessionId }),
        });
    }
    document.getElementById('parseBtn').disabled = false;
    updateScanButton();
    log(t().scanStop, '#facc15');
}

function finishScan() {
    scanning = false;
    if (eventSource) { eventSource.close(); eventSource = null; }
    document.getElementById('parseBtn').disabled = false;
    updateScanButton(); refreshTable();
    if (!results.length) document.getElementById('waitingState').style.display = 'flex';
    log(t().scanDone(successCount, failCount), '#facc15');
}

// ── Reconnect ─────────────────────────────────────
async function tryReconnect() {
    if (!sessionId) return;
    try {
        const resp = await fetch(`/api/scan/status?session_id=${sessionId}`);
        if (!resp.ok) { localStorage.removeItem('sessionId'); sessionId = null; return; }
        const data = await resp.json();

        if (data.status === 'running') {
            log(t().reconnected, '#a78bfa');
            results      = data.results || [];
            scannedCount = data.scanned || 0;
            totalCount   = data.total   || 0;
            successCount = results.filter(r => r.tcp?.ok || r.tls?.ok).length;
            failCount    = scannedCount - successCount;
            scanning     = true;
            document.getElementById('waitingState').style.display = 'none';
            updateStats(); refreshTable(); updateScanButton();
            document.getElementById('parseBtn').disabled = true;
            connectStream(sessionId);
        } else if (data.results?.length) {
            results      = data.results;
            scannedCount = data.scanned || results.length;
            totalCount   = data.total   || results.length;
            successCount = results.filter(r => r.tcp?.ok || r.tls?.ok).length;
            failCount    = scannedCount - successCount;
            updateStats(); refreshTable();
            document.getElementById('waitingState').style.display = 'none';
            log(t().scanDone(successCount, failCount), '#facc15');
            localStorage.removeItem('sessionId'); sessionId = null;
        }
    } catch (_) {}
}

// ── Download ──────────────────────────────────────
function downloadResults(mode) {
    if (!results.length) { log(t().dlEmpty, '#facc15'); return; }

    const sorted = [...results]
        .filter(r => r.tcp?.ok || r.tls?.ok)
        .sort((a, b) => (b.score?.points||0) - (a.score?.points||0));

    let content = '';

    if (mode === 'simple') {
        content = sorted.map(r => r.ip).join('\n');
    } else {
        content  = '# AniScanner Advanced Export\n';
        content += '# IP • SNI/CN • Ping(ms) • TCP • TLS_Ver • Issuer • DaysLeft • CDN • ASN • Score • Verdict\n\n';
        for (const r of sorted) {
            content += [
                r.ip,
                r.tls?.cn   || r.sni || '',
                r.tcp?.ms   ?? '',
                r.tcp?.ok   ? 'TCP:OK' : 'TCP:FAIL',
                r.tls?.tls_ver  || '',
                r.tls?.issuer   || '',
                r.tls?.days_left ?? '',
                r.provider  || '',
                r.asn       || '',
                r.score?.points  ?? 0,
                r.score?.verdict || '',
            ].join(' • ') + '\n';
        }
    }

    content += `\n# Scanned by AniScanner ${VERSION}\n# Telegram: https://t.me/aniartx\n`;

    const blob = new Blob([content], { type: 'text/plain' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = mode === 'simple' ? 'clean_ips.txt' : 'aniscanner_advanced.txt';
    a.click();
    URL.revokeObjectURL(a.href);
    log(t().dlDone(mode), '#38bdf8');
    document.getElementById('downloadMenu').classList.remove('open');
}

// ── Events ────────────────────────────────────────
document.getElementById('fileInput').addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    const r = new FileReader();
    r.onload = ev => {
        document.getElementById('ipListInput').value = ev.target.result;
        log(t().fileLoaded, '#38bdf8');
    };
    r.readAsText(file);
});

document.getElementById('parseBtn').addEventListener('click', prepareList);

document.getElementById('toggleScanBtn').addEventListener('click', async () => {
    if (scanning) { stopScan(); return; }
    let list = entries.length ? entries : await prepareList();
    if (!list.length) return;
    startScan(list);
});

document.getElementById('downloadBtn').addEventListener('click', e => {
    e.stopPropagation();
    document.getElementById('downloadMenu').classList.toggle('open');
});
document.addEventListener('click', () => {
    document.getElementById('downloadMenu').classList.remove('open');
});

// ── Init ──────────────────────────────────────────
applyLang();
applyColumnVisibility();
log(t().ready, '#facc15');
tryReconnect();
