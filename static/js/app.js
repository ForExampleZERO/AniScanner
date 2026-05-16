/* ═══════════════════════════════════════════════
   AniScanner v1.0 — Frontend Logic
═══════════════════════════════════════════════ */

'use strict';

const VERSION = '1.0';

// ── i18n ──────────────────────────────────────────
const LANG = {
    en: {
        heroDesc:      'TCP · TLS · SNI · Certificate · QUIC · Scoring',
        inputTitle:    'Input — IP / Range / CIDR / Domain',
        uploadLabel:   'Upload TXT file',
        manualLabel:   'Manual entry (IP · range · CIDR · domain)',
        prepareBtn:    'Prepare & Deduplicate',
        settingsTitle: 'Configuration',
        concLabel:     'Concurrency',
        toLabel:       'Timeout (ms)',
        scanModeLabel: 'Scan Mode',
        startBtn:      'Start Scan',
        stopBtn:       'Stop Scan',
        dlBtn:         'Export Results',
        dlSimple:      'Simple — one IP per line',
        dlAdv:         'Advanced — full data',
        lblTotal:      'Total',
        lblScanned:    'Scanned',
        lblOk:         'Online',
        lblFail:       'Dead',
        resultsTitle:  'Scan Results',
        waiting:       'Waiting for scan…',
        footer:        `AniScanner v${VERSION} — TCP · TLS · SNI · QUIC · Scoring | @aniartx`,
        results:       n => `${n} result${n !== 1 ? 's' : ''}`,
        progressReady: 'Ready',
        progressScan:  (s, t) => `Scanning ${s} / ${t}`,
        progressDone:  'Complete',
        listEmpty:     '⚠ List is empty.',
        stopFirst:     '⚠ Stop the scan first.',
        fileLoaded:    '📁 File loaded.',
        prepared:      n => `📋 ${n} IPs prepared.`,
        scanStart:     (n, c) => `Scanning ${n} IPs — concurrency: ${c}`,
        scanStop:      'Scan stopped.',
        scanDone:      (ok, f) => `Done — Online: ${ok} | Dead: ${f}`,
        dlDone:        m => `Downloaded (${m}).`,
        dlEmpty:       '⚠ No successful IPs to export.',
        serverErr:     '❌ Server connection error.',
        reconnected:   '🔄 Reconnected — loading results…',
        langBtn:       'FA',
    },
    fa: {
        heroDesc:      'TCP · TLS · SNI · Certificate · QUIC · Scoring',
        inputTitle:    'ورودی — IP · رنج · CIDR · دامنه',
        uploadLabel:   'آپلود فایل TXT',
        manualLabel:   'ورودی دستی (هر خط: IP یا رنج یا CIDR یا دامنه)',
        prepareBtn:    'آماده‌سازی و حذف تکراری',
        settingsTitle: 'پیکربندی',
        concLabel:     'همزمانی',
        toLabel:       'تایم‌اوت (ms)',
        scanModeLabel: 'حالت اسکن',
        startBtn:      'شروع اسکن',
        stopBtn:       'توقف اسکن',
        dlBtn:         'خروجی نتایج',
        dlSimple:      'ساده — فقط IP',
        dlAdv:         'پیشرفته — همه داده‌ها',
        lblTotal:      'کل',
        lblScanned:    'اسکن‌شده',
        lblOk:         'آنلاین',
        lblFail:       'مرده',
        resultsTitle:  'نتایج اسکن',
        waiting:       'در انتظار اسکن…',
        footer:        `AniScanner v${VERSION} — TCP · TLS · SNI · QUIC · Scoring | @aniartx`,
        results:       n => `${n} نتیجه`,
        progressReady: 'آماده',
        progressScan:  (s, t) => `اسکن ${s} از ${t}`,
        progressDone:  'تمام شد',
        listEmpty:     '⚠ لیست خالی است.',
        stopFirst:     '⚠ ابتدا اسکن را متوقف کنید.',
        fileLoaded:    '📁 فایل بارگذاری شد.',
        prepared:      n => `📋 ${n} آی‌پی آماده شد.`,
        scanStart:     (n, c) => `اسکن ${n} IP — همزمانی: ${c}`,
        scanStop:      'اسکن متوقف شد.',
        scanDone:      (ok, f) => `پایان — آنلاین: ${ok} | مرده: ${f}`,
        dlDone:        m => `دانلود شد (${m}).`,
        dlEmpty:       '⚠ هیچ IP موفقی وجود ندارد.',
        serverErr:     '❌ خطا در اتصال به سرور.',
        reconnected:   '🔄 اتصال مجدد — بارگذاری نتایج…',
        langBtn:       'EN',
    },
};

let currentLang = localStorage.getItem('ani_lang') || 'en';
const t = () => LANG[currentLang];

function $id(id) { return document.getElementById(id); }

function setText(id, txt) {
    const el = $id(id);
    if (el) el.textContent = txt;
}

function applyLang() {
    const s = t();
    document.documentElement.lang = currentLang === 'fa' ? 'fa' : 'en';
    document.documentElement.dir  = currentLang === 'fa' ? 'rtl' : 'ltr';

    setText('heroDesc',      s.heroDesc);
    setText('inputTitle',    s.inputTitle);
    setText('uploadLabel',   s.uploadLabel);
    setText('manualLabel',   s.manualLabel);
    setText('prepareBtnTxt', s.prepareBtn);
    setText('settingsTitle', s.settingsTitle);
    setText('concLabel',     s.concLabel);
    setText('toLabel',       s.toLabel);
    setText('scanModeLabel', s.scanModeLabel);
    setText('dlBtnTxt',      s.dlBtn);
    setText('dlSimpleBtn',   s.dlSimple);
    setText('dlAdvBtn',      s.dlAdv);
    setText('lblTotal',      s.lblTotal);
    setText('lblScanned',    s.lblScanned);
    setText('lblOk',         s.lblOk);
    setText('lblFail',       s.lblFail);
    setText('resultsTitle',  s.resultsTitle);
    setText('waitingTxt',    s.waiting);
    setText('footer',        s.footer);
    setText('langBtnTxt',    s.langBtn);

    updateScanButton();
    updateResultCount();
    updateProgressLabel();
}

$id('langBtn').addEventListener('click', () => {
    currentLang = currentLang === 'en' ? 'fa' : 'en';
    localStorage.setItem('ani_lang', currentLang);
    applyLang();
});

// ── State ─────────────────────────────────────────
let scanning     = false;
let sessionId    = localStorage.getItem('ani_session') || null;
let entries      = [];
let results      = [];
let totalCount   = 0;
let scannedCount = 0;
let successCount = 0;
let failCount    = 0;
let evtSource    = null;
let scanState    = 'idle';   // idle | running | done | stopped

// ── Scan button ───────────────────────────────────
function updateScanButton() {
    const btn     = $id('toggleScanBtn');
    const iconEl  = $id('scanBtnIcon');
    const txtEl   = $id('scanBtnTxt');
    if (!btn) return;

    if (scanning) {
        btn.className = 'btn btn-danger';
        if (iconEl) iconEl.innerHTML = '<rect x="6" y="6" width="12" height="12" rx="2"/>';
        if (txtEl)  txtEl.textContent = t().stopBtn;
    } else {
        btn.className = 'btn btn-success';
        if (iconEl) iconEl.innerHTML = '<polygon points="5 3 19 12 5 21 5 3"/>';
        if (txtEl)  txtEl.textContent = t().startBtn;
    }
}

// ── Stats ─────────────────────────────────────────
function updateStats() {
    setText('totalStat',   String(totalCount));
    setText('scannedStat', String(scannedCount));
    setText('successStat', String(successCount));
    setText('failStat',    String(failCount));

    const pct  = totalCount ? (scannedCount / totalCount) * 100 : 0;
    const bar  = $id('progressBar');
    const pctEl = $id('progressPct');
    if (bar)   bar.style.width = pct + '%';
    if (pctEl) pctEl.textContent = Math.round(pct) + '%';
    updateProgressLabel();
}

function updateProgressLabel() {
    const el = $id('progressLabel');
    if (!el) return;
    if (scanState === 'idle')    el.textContent = t().progressReady;
    else if (scanState === 'running') el.textContent = t().progressScan(scannedCount, totalCount);
    else el.textContent = t().progressDone;
}

function updateResultCount() {
    const el = $id('resultCount');
    if (el) el.textContent = t().results(results.length);
}

// ── Scan mode → column visibility ─────────────────
function getScanMode() {
    return document.querySelector('input[name="scanMode"]:checked')?.value || 'TCP';
}

function applyColumns() {
    const mode    = getScanMode();
    const showTcp = mode === 'TCP'  || mode === 'BOTH';
    const showUdp = mode === 'UDP'  || mode === 'BOTH';
    document.querySelectorAll('.col-tcp').forEach(el => el.style.display = showTcp ? '' : 'none');
    document.querySelectorAll('.col-udp').forEach(el => el.style.display = showUdp ? '' : 'none');
}

document.querySelectorAll('input[name="scanMode"]').forEach(r =>
    r.addEventListener('change', () => { applyColumns(); refreshTable(); })
);

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
    'DigiCert':      '🛡',
    'Sectigo':       '🔐',
    'ZeroSSL':       '🔑',
};

// ── Cell renderers ────────────────────────────────

function pingHtml(tcp) {
    if (!tcp?.ok) return '<span class="badge badge-dash">—</span>';
    const ms  = tcp.ms;
    const cls = ms <= 100 ? 'ping-good' : ms <= 300 ? 'ping-ok' : ms <= 600 ? 'ping-bad' : 'ping-dead';
    return `<span class="${cls}">${ms}ms</span>`;
}

function tcpHtml(tcp) {
    if (!tcp || tcp.skipped) return '<span class="badge badge-dash">—</span>';
    if (tcp.ok)  return '<span class="badge badge-open">OPEN</span>';
    const err = tcp.err || '';
    if (err === 'timeout')   return '<span class="badge badge-timeout">T/O</span>';
    if (err === 'refused')   return '<span class="badge badge-closed">REFUSED</span>';
    return '<span class="badge badge-closed">CLOSED</span>';
}

function udpHtml(udp) {
    if (!udp) return '<span class="badge badge-dash">—</span>';
    if (udp.status === 'OPEN')     return `<span class="badge badge-open">${udp.quic ? 'QUIC' : 'OPEN'}</span>`;
    if (udp.status === 'FILTERED') return '<span class="badge badge-filtered">FILTERED</span>';
    if (udp.status === 'CLOSED')   return '<span class="badge badge-closed">CLOSED</span>';
    return '<span class="badge badge-dash">—</span>';
}

function tlsVerHtml(tls) {
    if (!tls?.tls_ver || tls.tls_ver === '?') return '<span class="badge badge-dash">—</span>';
    return `<span class="tls-pill">${tls.tls_ver}</span>`;
}

function sniHtml(tls) {
    if (!tls) return '<span class="badge badge-dash">—</span>';
    if (tls.ok)                       return '<span class="badge badge-ok">OK</span>';
    if (tls.err === 'cert_mismatch')  return '<span class="badge badge-mismatch">MISMATCH</span>';
    if (tls.err === 'tcp_failed')     return '<span class="badge badge-dash">—</span>';
    return '<span class="badge badge-fail">FAIL</span>';
}

function certHtml(tls) {
    if (!tls?.ok || !tls.cn) return '<span class="badge badge-dash">—</span>';
    const days    = tls.days_left;
    const cn      = tls.cn.length > 24 ? tls.cn.slice(0, 22) + '…' : tls.cn;
    const daysStr = days !== null && days !== undefined
        ? `<div class="cert-days ${days < 30 ? 'cert-expiring' : ''}">${days}d left</div>`
        : '';
    return `<div class="cert-wrap"><div class="cert-cn" title="${tls.cn}">${cn}</div>${daysStr}</div>`;
}

function cdnHtml(provider) {
    if (!provider) return '<span class="badge badge-dash">—</span>';
    const icon = CDN_ICONS[provider] || '🌐';
    return `<span class="cdn-tag">${icon} ${provider}</span>`;
}

function latencyHtml(tls) {
    if (!tls?.ms) return '<span class="badge badge-dash">—</span>';
    const ms  = tls.ms;
    const cls = ms <= 100 ? 'ping-good' : ms <= 300 ? 'ping-ok' : ms <= 600 ? 'ping-bad' : 'ping-dead';
    return `<span class="${cls}">${ms}ms</span>`;
}

function scoreHtml(sc) {
    if (!sc) return '<span class="badge badge-dash">—</span>';
    return `<span class="score-val" style="color:${sc.color}">${sc.points}</span>`;
}

function verdictHtml(sc) {
    if (!sc) return '';
    return `<span class="verdict-badge" style="background:${sc.color}18;color:${sc.color};border:1px solid ${sc.color}30">${sc.verdict}</span>`;
}

// ── Table ─────────────────────────────────────────
let tableTimer = null;
function scheduleRefresh() {
    if (tableTimer) return;
    tableTimer = setTimeout(() => { refreshTable(); tableTimer = null; }, 350);
}

function refreshTable() {
    const mode    = getScanMode();
    const showTcp = mode === 'TCP'  || mode === 'BOTH';
    const showUdp = mode === 'UDP'  || mode === 'BOTH';

    const sorted = [...results].sort((a, b) => (b.score?.points || 0) - (a.score?.points || 0));
    const tbody  = document.querySelector('#resultTable tbody');
    tbody.innerHTML = '';

    sorted.forEach((r, i) => {
        const row = tbody.insertRow();
        const tcp = r.tcp  || {};
        const tls = r.tls  || {};
        const udp = r.udp  || null;
        const sc  = r.score || {};

        // #
        row.insertCell(0).textContent = i + 1;

        // IP
        const ipTd = row.insertCell(1);
        ipTd.className   = 'td-ip';
        ipTd.textContent = r.ip;

        // Ping
        row.insertCell(2).innerHTML = pingHtml(tcp);

        // TCP
        const tcpTd = row.insertCell(3);
        tcpTd.className = 'col-tcp';
        tcpTd.innerHTML = tcpHtml(tcp);
        tcpTd.style.display = showTcp ? '' : 'none';

        // UDP
        const udpTd = row.insertCell(4);
        udpTd.className = 'col-udp';
        udpTd.innerHTML = udpHtml(udp);
        udpTd.style.display = showUdp ? '' : 'none';

        // TLS version
        row.insertCell(5).innerHTML = tlsVerHtml(tls);

        // SNI
        row.insertCell(6).innerHTML = sniHtml(tls);

        // Certificate
        row.insertCell(7).innerHTML = certHtml(tls);

        // CDN
        row.insertCell(8).innerHTML = cdnHtml(r.provider);

        // Latency (TLS RTT)
        row.insertCell(9).innerHTML = latencyHtml(tls);

        // Score
        row.insertCell(10).innerHTML = scoreHtml(sc);

        // Verdict
        row.insertCell(11).innerHTML = verdictHtml(sc);
    });

    applyColumns();
    updateResultCount();
}

// ── Prepare list ──────────────────────────────────
async function prepareList() {
    if (scanning) { showToast(t().stopFirst, 'warn'); return []; }
    const text = $id('ipListInput').value.trim();
    if (!text) { showToast(t().listEmpty, 'warn'); return []; }

    try {
        const resp = await fetch('/api/parse', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ ips: text }),
        });
        const data = await resp.json();
        entries = data.entries;

        $id('ipListInput').value =
            entries.map(e => e.sni ? `${e.ip}  # ${e.sni}` : e.ip).join('\n');

        scannedCount = successCount = failCount = 0;
        totalCount   = entries.length;
        scanState    = 'idle';
        updateStats();
        $id('progressBar').style.width = '0%';
        $id('waitingState').style.display = 'flex';
        document.querySelector('#resultTable tbody').innerHTML = '';
        updateResultCount();
        showToast(t().prepared(entries.length), 'info');
        return entries;
    } catch {
        showToast(t().serverErr, 'error');
        return [];
    }
}

// ── SSE stream ────────────────────────────────────
function connectStream(sid) {
    if (evtSource) evtSource.close();
    evtSource = new EventSource(`/api/scan/stream?session_id=${sid}`);

    evtSource.onmessage = e => {
        const msg = JSON.parse(e.data);
        if (msg.type === 'result') {
            const r = msg.data;
            scannedCount++;
            const alive = r.tcp?.ok || r.tls?.ok || r.udp?.ok;
            if (alive) {
                successCount++;
                results.push(r);
                scheduleRefresh();
            } else {
                failCount++;
            }
            updateStats();
        } else if (msg.type === 'done') {
            finishScan();
        }
    };

    evtSource.onerror = () => { /* SSE auto-reconnects */ };
}

// ── Start scan ────────────────────────────────────
async function startScan(list) {
    if (scanning || !list.length) return;

    const concurrency = parseInt($id('concurrency').value) || 30;
    const timeout     = parseInt($id('timeout').value)     || 3000;
    const scan_mode   = getScanMode();

    try {
        const resp = await fetch('/api/scan/start', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ entries: list, concurrency, timeout, scan_mode, session_id: sessionId }),
        });
        const data = await resp.json();
        sessionId = data.session_id;
        localStorage.setItem('ani_session', sessionId);

        scanning     = true;
        results      = [];
        scannedCount = successCount = failCount = 0;
        totalCount   = list.length;
        scanState    = 'running';

        $id('waitingState').style.display = 'none';
        $id('parseBtn').disabled = true;
        updateStats(); refreshTable(); updateScanButton();

        showToast(t().scanStart(list.length, concurrency), 'info');
        connectStream(sessionId);
    } catch {
        showToast(t().serverErr, 'error');
    }
}

// ── Stop / Finish ─────────────────────────────────
async function stopScan() {
    if (!scanning) return;
    scanning  = false;
    scanState = 'stopped';
    if (evtSource) { evtSource.close(); evtSource = null; }
    if (sessionId) {
        await fetch('/api/scan/stop', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ session_id: sessionId }),
        });
    }
    $id('parseBtn').disabled = false;
    updateScanButton();
    updateProgressLabel();
    showToast(t().scanStop, 'warn');
}

function finishScan() {
    scanning  = false;
    scanState = 'done';
    if (evtSource) { evtSource.close(); evtSource = null; }
    $id('parseBtn').disabled = false;
    updateScanButton(); refreshTable();
    if (!results.length) $id('waitingState').style.display = 'flex';
    updateProgressLabel();
    showToast(t().scanDone(successCount, failCount), 'success');
}

// ── Reconnect on page load ─────────────────────────
async function tryReconnect() {
    if (!sessionId) return;
    try {
        const resp = await fetch(`/api/scan/status?session_id=${sessionId}`);
        if (!resp.ok) { localStorage.removeItem('ani_session'); sessionId = null; return; }
        const data = await resp.json();

        results      = data.results || [];
        scannedCount = data.scanned || 0;
        totalCount   = data.total   || 0;
        successCount = results.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok).length;
        failCount    = scannedCount - successCount;

        if (data.status === 'running') {
            showToast(t().reconnected, 'info');
            scanning  = true;
            scanState = 'running';
            $id('waitingState').style.display = 'none';
            $id('parseBtn').disabled = true;
            updateStats(); refreshTable(); updateScanButton();
            connectStream(sessionId);
        } else if (results.length) {
            scanState = 'done';
            $id('waitingState').style.display = 'none';
            updateStats(); refreshTable();
            showToast(t().scanDone(successCount, failCount), 'success');
            localStorage.removeItem('ani_session'); sessionId = null;
        } else {
            localStorage.removeItem('ani_session'); sessionId = null;
        }
    } catch { /* server not ready */ }
}

// ── Download ──────────────────────────────────────
function downloadResults(mode) {
    const alive = results.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok);
    if (!alive.length) { showToast(t().dlEmpty, 'warn'); return; }

    const sorted = [...alive].sort((a, b) => (b.score?.points || 0) - (a.score?.points || 0));
    let content  = '';

    if (mode === 'simple') {
        content = sorted.map(r => r.ip).join('\n');
    } else {
        content  = '# AniScanner Advanced Export\n';
        content += '# IP • SNI/CN • Ping(ms) • TCP • UDP • TLS_Ver • Issuer • DaysLeft • CDN • Score • Verdict\n\n';
        for (const r of sorted) {
            content += [
                r.ip,
                r.tls?.cn   || r.sni || '',
                r.tcp?.ms   ?? '',
                r.tcp?.ok   ? 'TCP:OK'     : 'TCP:FAIL',
                r.udp?.status || 'N/A',
                r.tls?.tls_ver   || '',
                r.tls?.issuer    || '',
                r.tls?.days_left ?? '',
                r.provider  || '',
                r.score?.points  ?? 0,
                r.score?.verdict || '',
            ].join(' • ') + '\n';
        }
    }

    content += `\n# Scanned by AniScanner v${VERSION}\n# Telegram: https://t.me/aniartx\n`;

    const blob = new Blob([content], { type: 'text/plain' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = mode === 'simple' ? 'clean_ips.txt' : 'aniscanner_full.txt';
    a.click();
    URL.revokeObjectURL(a.href);
    showToast(t().dlDone(mode), 'success');
    $id('downloadMenu').classList.remove('open');
}

// ── Toast notifications ───────────────────────────
function showToast(msg, type = 'info') {
    // Simple status line — update progress label area
    const el = $id('progressLabel');
    if (!el) return;
    const colors = { info: '#38bdf8', success: '#34d399', warn: '#fbbf24', error: '#f87171' };
    const prev   = el.style.color;
    el.style.color = colors[type] || colors.info;
    el.textContent = msg;
    setTimeout(() => {
        el.style.color = prev;
        updateProgressLabel();
    }, 3500);
}

// ── Events ────────────────────────────────────────
$id('fileInput').addEventListener('change', e => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
        $id('ipListInput').value = ev.target.result;
        showToast(t().fileLoaded, 'info');
    };
    reader.readAsText(file);
});

$id('parseBtn').addEventListener('click', prepareList);

$id('toggleScanBtn').addEventListener('click', async () => {
    if (scanning) { stopScan(); return; }
    let list = entries.length ? entries : await prepareList();
    if (!list.length) return;
    startScan(list);
});

$id('downloadBtn').addEventListener('click', e => {
    e.stopPropagation();
    $id('downloadMenu').classList.toggle('open');
});

document.addEventListener('click', () => $id('downloadMenu').classList.remove('open'));

// ── Init ──────────────────────────────────────────
applyLang();
applyColumns();
tryReconnect();
