/* ═══════════════════════════════════════════════
   AniScanner v3.0 — Frontend Logic
   Features: Virtual scroll · Web Worker sort/filter
             Filtered export · Port selector
             TCP/UDP/QUIC dot-status columns
             History/sessions · Copy IP · Score histogram
             Dark/Light theme · Cloudflare IP import
═══════════════════════════════════════════════ */

'use strict';

const VERSION = '3.0';

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
        portsLabel:    'Ports to Scan',
        startBtn:      'Start Scan',
        stopBtn:       'Stop Scan',
        dlBtn:         'Export Results',
        dlSimple:      'Simple — one IP per line',
        dlAdv:         'Advanced — full data',
        dlFiltered:    'Filtered — current view',
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
        historyBtn:    'History',
        themeBtn:      'Theme',
        cfImportBtn:   'Import Cloudflare IPs',
        cfImporting:   '⬇ Fetching Cloudflare IPs…',
        cfImportDone:  n => `✅ Imported ${n} Cloudflare IPs`,
        cfImportErr:   '❌ Failed to fetch Cloudflare IPs',
        historyEmpty:  'No scan history yet.',
        historyLoad:   '📂 Loaded from history.',
        copyIp:        '📋 Copied!',
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
        portsLabel:    'پورت‌های اسکن',
        startBtn:      'شروع اسکن',
        stopBtn:       'توقف اسکن',
        dlBtn:         'خروجی نتایج',
        dlSimple:      'ساده — فقط IP',
        dlAdv:         'پیشرفته — همه داده‌ها',
        dlFiltered:    'فیلترشده — نمای فعلی',
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
        historyBtn:    'تاریخچه',
        themeBtn:      'پوسته',
        cfImportBtn:   'ایمپورت IP‌های Cloudflare',
        cfImporting:   '⬇ دریافت IP‌های Cloudflare…',
        cfImportDone:  n => `✅ ${n} آی‌پی کلودفلر ایمپورت شد`,
        cfImportErr:   '❌ خطا در دریافت IP‌های Cloudflare',
        historyEmpty:  'هنوز تاریخچه‌ای وجود ندارد.',
        historyLoad:   '📂 از تاریخچه بارگذاری شد.',
        copyIp:        '📋 کپی شد!',
    },
};

let currentLang = localStorage.getItem('ani_lang') || 'en';
const t = () => LANG[currentLang];

function $id(id) { return document.getElementById(id); }
function setText(id, txt) { const el = $id(id); if (el) el.textContent = txt; }

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
    setText('portsLabel',    s.portsLabel);
    setText('dlBtnTxt',      s.dlBtn);
    setText('dlSimpleBtn',   s.dlSimple);
    setText('dlAdvBtn',      s.dlAdv);
    setText('dlFilteredBtn', s.dlFiltered);
    setText('lblTotal',      s.lblTotal);
    setText('lblScanned',    s.lblScanned);
    setText('lblOk',         s.lblOk);
    setText('lblFail',       s.lblFail);
    setText('resultsTitle',  s.resultsTitle);
    setText('waitingTxt',    s.waiting);
    setText('footer',        s.footer);
    setText('langBtnTxt',    s.langBtn);
    updateScanButton();
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
let results      = [];       // ALL raw results
let filteredSorted = [];     // result after filter+sort (for virtual scroll)
let totalCount   = 0;
let scannedCount = 0;
let successCount = 0;
let failCount    = 0;
let evtSource    = null;
let scanState    = 'idle';

// ── Sorting ───────────────────────────────────────
let currentSort = { key: 'score', asc: false };

// ── Filter ────────────────────────────────────────
let activeFilter = 'all';
let sortByPing   = false;

// ── Virtual Scroll ───────────────────────────────
const ROW_HEIGHT   = 40;   // px per row (must match CSS)
const BUFFER_ROWS  = 10;   // rows above/below viewport to pre-render
let vsScrollTop    = 0;
let vsContainerH   = 400;
let vsRafPending   = false;

// ── Web Worker (inline blob) ──────────────────────
const WORKER_SRC = `
'use strict';

function ipToNumber(ip) {
    return (ip || '0.0.0.0').split('.').map(Number)
        .reduce((acc, o) => (acc << 8) + o, 0) >>> 0;
}

function getSortValue(r, key) {
    switch (key) {
        case 'ip':      return ipToNumber(r.ip);
        case 'ping':    return r.tcp?.ms ?? 999999;
        case 'tcp':     return r.tcp?.ok ? 1 : 0;
        case 'udp':     return r.udp?.ok ? 1 : 0;
        case 'tls_ver': return r.tls?.tls_ver || '';
        case 'sni':     return (r.tls?.cn || r.sni || '').toLowerCase();
        case 'cdn':     return (r.provider || '').toLowerCase();
        case 'latency': return r.latency?.avg ?? r.tls?.ms ?? 999999;
        case 'score':   return r.score?.points ?? 0;
        case 'verdict': return (r.score?.verdict || '').toLowerCase();
        default:        return '';
    }
}

function applyFilter(list, filter) {
    switch (filter) {
        case 'online': return list.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok);
        case 'dead':   return list.filter(r => !r.tcp?.ok && !r.tls?.ok && !r.udp?.ok);
        case 'tcp':    return list.filter(r => r.tcp?.ok);
        case 'udp':    return list.filter(r => r.udp?.ok);
        case 'sni':    return list.filter(r => r.tls?.ok);
        case 'cdn':    return list.filter(r => !!r.provider);
        case 'all':
        default:       return list.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok);
    }
}

self.onmessage = function(e) {
    const { results, filter, sortKey, sortAsc, sortByPing } = e.data;
    let filtered = applyFilter(results, filter);

    filtered.sort((a, b) => {
        const av = getSortValue(a, sortKey);
        const bv = getSortValue(b, sortKey);
        let cmp = 0;
        if (typeof av === 'number' && typeof bv === 'number') cmp = av - bv;
        else cmp = String(av).localeCompare(String(bv));
        if (sortKey === 'score') cmp *= -1;
        if (['tcp','udp'].includes(sortKey)) cmp *= -1;
        return sortAsc ? cmp : -cmp;
    });

    self.postMessage({ filtered });
};
`;

let sortWorker = null;
let workerBusy = false;
let workerPending = null;

function getWorker() {
    if (!sortWorker) {
        const blob = new Blob([WORKER_SRC], { type: 'application/javascript' });
        sortWorker = new Worker(URL.createObjectURL(blob));
        sortWorker.onmessage = e => {
            filteredSorted = e.data.filtered;
            workerBusy = false;
            renderVirtualTable();
            updateFilterCount();
            // If another sort was queued, run it now
            if (workerPending) {
                const pending = workerPending;
                workerPending = null;
                dispatchSort(pending);
            }
        };
    }
    return sortWorker;
}

function dispatchSort(payload) {
    if (workerBusy) { workerPending = payload; return; }
    workerBusy = true;
    getWorker().postMessage(payload);
}

function triggerSort() {
    dispatchSort({
        results,
        filter:     activeFilter,
        sortKey:    sortByPing ? 'ping' : currentSort.key,
        sortAsc:    sortByPing ? true   : currentSort.asc,
        sortByPing,
    });
}

// ── Scan mode → column visibility ─────────────────
function getScanMode() {
    return document.querySelector('input[name="scanMode"]:checked')?.value || 'TCP';
}

function getSelectedPorts() {
    const checked = document.querySelectorAll('input[name="scanPort"]:checked');
    const ports = Array.from(checked).map(cb => parseInt(cb.value)).filter(Boolean);
    return ports.length ? ports : [443];
}

function applyColumns() {
    const mode    = getScanMode();
    const showTcp = mode === 'TCP'  || mode === 'BOTH';
    const showUdp = mode === 'UDP'  || mode === 'BOTH';
    document.querySelectorAll('.col-tcp').forEach(el => el.style.display = showTcp ? '' : 'none');
    document.querySelectorAll('.col-udp').forEach(el => el.style.display = showUdp ? '' : 'none');
}

document.querySelectorAll('input[name="scanMode"]').forEach(r =>
    r.addEventListener('change', () => { applyColumns(); triggerSort(); })
);

// Port checkbox styling
document.querySelectorAll('.port-option input').forEach(cb => {
    cb.addEventListener('change', function() {
        this.closest('.port-option').classList.toggle('checked', this.checked);
    });
});

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

// ── Status dot helper ──────────────────────────────
// green=open, yellow=filtered, red=closed/dead
function statusDot(state) {
    // state: 'open' | 'filtered' | 'closed' | 'skip'
    const colors = { open: '#4ade80', filtered: '#facc15', closed: '#f87171', skip: '#4b5563' };
    const c = colors[state] || colors.skip;
    return `<span class="status-dot" style="background:${c}" title="${state}"></span>`;
}

// ── Cell renderers ────────────────────────────────

function pingHtml(tcp, latency) {
    // Prefer multi-probe avg latency if available
    const ms = latency?.avg ?? tcp?.ms ?? null;
    if (!tcp?.ok || ms === null) return '<span class="badge badge-dash">—</span>';
    const cls = ms <= 100 ? 'ping-good' : ms <= 300 ? 'ping-ok' : ms <= 600 ? 'ping-bad' : 'ping-dead';
    const detail = latency ? `min:${latency.min} avg:${latency.avg} max:${latency.max}` : '';
    return `<span class="${cls}" title="${detail}">${ms}ms</span>`;
}

function tcpDotsHtml(tcp, tcpPorts, scannedPorts) {
    if (!scannedPorts || !scannedPorts.length) {
        // fallback single
        if (!tcp || tcp.skipped) return '<span class="badge badge-dash">—</span>';
        if (tcp.ok) return statusDot('open') + ' <span class="badge badge-open">OPEN</span>';
        const err = tcp.err || '';
        if (err === 'timeout') return statusDot('filtered') + ' <span class="badge badge-timeout">T/O</span>';
        if (err === 'refused') return statusDot('closed') + ' <span class="badge badge-closed">REFUSED</span>';
        return statusDot('closed') + ' <span class="badge badge-closed">CLOSED</span>';
    }

    let html = '<div class="port-dots">';
    for (const port of scannedPorts) {
        const r = tcpPorts?.[String(port)];
        let state = 'skip';
        let label = '';
        if (r && !r.skipped) {
            if (r.ok) { state = 'open'; label = `${port}: ${r.ms}ms`; }
            else if (r.err === 'timeout') { state = 'filtered'; label = `${port}: timeout`; }
            else { state = 'closed'; label = `${port}: ${r.err || 'closed'}`; }
        }
        html += `<span class="port-dot-wrap" title="${label}">${statusDot(state)}<span class="port-num">${port}</span></span>`;
    }
    html += '</div>';
    return html;
}

function udpDotsHtml(udp, udpPorts, scannedPorts) {
    if (!scannedPorts || !scannedPorts.length) {
        if (!udp) return '<span class="badge badge-dash">—</span>';
        if (udp.status === 'OPEN')     return statusDot('open')     + ` <span class="badge badge-open">${udp.quic ? 'QUIC' : 'OPEN'}</span>`;
        if (udp.status === 'FILTERED') return statusDot('filtered') + ' <span class="badge badge-filtered">FILTERED</span>';
        if (udp.status === 'CLOSED')   return statusDot('closed')   + ' <span class="badge badge-closed">CLOSED</span>';
        return '<span class="badge badge-dash">—</span>';
    }

    let html = '<div class="port-dots">';
    for (const port of scannedPorts) {
        const r = udpPorts?.[String(port)];
        let state = 'skip';
        let label = '';
        if (r) {
            if (r.status === 'OPEN')     { state = 'open';     label = `${port}: QUIC/OPEN ${r.ms}ms`; }
            else if (r.status === 'FILTERED') { state = 'filtered'; label = `${port}: filtered`; }
            else if (r.status === 'CLOSED')   { state = 'closed';   label = `${port}: closed`; }
            else { state = 'skip'; label = `${port}: error`; }
        }
        html += `<span class="port-dot-wrap" title="${label}">${statusDot(state)}<span class="port-num">${port}</span></span>`;
    }
    html += '</div>';
    return html;
}

function tlsVerHtml(tls) {
    if (!tls?.tls_ver || tls.tls_ver === '?') return '<span class="badge badge-dash">—</span>';
    return `<span class="tls-pill">${tls.tls_ver}</span>`;
}

function sniHtml(tls) {
    if (!tls) return '<span class="badge badge-dash">—</span>';
    if (tls.ok)                      return '<span class="badge badge-ok">OK</span>';
    if (tls.err === 'cert_mismatch') return '<span class="badge badge-mismatch">MISMATCH</span>';
    if (tls.err === 'tcp_failed')    return '<span class="badge badge-dash">—</span>';
    return '<span class="badge badge-fail">FAIL</span>';
}

function certHtml(tls) {
    if (!tls?.ok || !tls.cn) return '<span class="badge badge-dash">—</span>';
    const days = tls.days_left;
    const cn   = tls.cn.length > 24 ? tls.cn.slice(0, 22) + '…' : tls.cn;
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

function latencyHtml(tls, latency) {
    // Show multi-probe latency if available, else TLS RTT
    const ms = latency?.avg ?? tls?.ms ?? null;
    if (!ms) return '<span class="badge badge-dash">—</span>';
    const cls = ms <= 100 ? 'ping-good' : ms <= 300 ? 'ping-ok' : ms <= 600 ? 'ping-bad' : 'ping-dead';
    const detail = latency ? `min:${latency.min} avg:${latency.avg} max:${latency.max}` : '';
    return `<span class="${cls}" title="${detail}">${ms}ms</span>`;
}

function scoreHtml(sc) {
    if (!sc) return '<span class="badge badge-dash">—</span>';
    return `<span class="score-val" style="color:${sc.color}">${sc.points}</span>`;
}

function verdictHtml(sc) {
    if (!sc) return '';
    return `<span class="verdict-badge" style="background:${sc.color}18;color:${sc.color};border:1px solid ${sc.color}30">${sc.verdict}</span>`;
}

// ── Row builder ───────────────────────────────────
function buildRow(r, i, showTcp, showUdp) {
    const tcp  = r.tcp  || {};
    const tls  = r.tls  || {};
    const sc   = r.score || {};

    const tr = document.createElement('tr');
    tr.style.height = ROW_HEIGHT + 'px';

    function td(html, cls) {
        const cell = document.createElement('td');
        if (cls) cell.className = cls;
        cell.innerHTML = html;
        return cell;
    }

    tr.appendChild(td(String(i + 1)));

    const ipTd = document.createElement('td');
    ipTd.className   = 'td-ip tbl-ip';
    ipTd.textContent = r.ip;
    ipTd.title       = '📋 Click to copy';
    ipTd.addEventListener('click', e => { e.stopPropagation(); copyIpToClipboard(r.ip); });
    tr.appendChild(ipTd);

    tr.appendChild(td(pingHtml(tcp, r.latency)));

    const tcpTd = td(tcpDotsHtml(tcp, r.tcp_ports, r.scanned_ports), 'col-tcp');
    tcpTd.style.display = showTcp ? '' : 'none';
    tr.appendChild(tcpTd);

    const udpTd = td(udpDotsHtml(r.udp, r.udp_ports, r.scanned_ports), 'col-udp');
    udpTd.style.display = showUdp ? '' : 'none';
    tr.appendChild(udpTd);

    tr.appendChild(td(tlsVerHtml(tls)));
    tr.appendChild(td(sniHtml(tls)));
    tr.appendChild(td(certHtml(tls)));
    tr.appendChild(td(cdnHtml(r.provider)));
    tr.appendChild(td(latencyHtml(tls, r.latency)));
    tr.appendChild(td(scoreHtml(sc)));
    tr.appendChild(td(verdictHtml(sc)));

    return tr;
}

// ── Virtual Scroll ────────────────────────────────
function renderVirtualTable() {
    const wrap   = $id('tableWrap');
    const tbody  = $id('resultBody');
    if (!wrap || !tbody) return;

    const total  = filteredSorted.length;
    if (total === 0) {
        tbody.innerHTML = '';
        // spacer clean
        const spacerT = $id('vsSpacerTop');
        const spacerB = $id('vsSpacerBot');
        if (spacerT) spacerT.style.height = '0px';
        if (spacerB) spacerB.style.height = '0px';
        const aliveTotal = results.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok).length;
        $id('waitingState').style.display = aliveTotal === 0 ? 'flex' : 'none';
        return;
    }

    $id('waitingState').style.display = 'none';

    const mode    = getScanMode();
    const showTcp = mode === 'TCP'  || mode === 'BOTH';
    const showUdp = mode === 'UDP'  || mode === 'BOTH';

    vsContainerH = wrap.clientHeight || 400;
    const scrollTop   = wrap.scrollTop;
    const startIdx    = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - BUFFER_ROWS);
    const visibleRows = Math.ceil(vsContainerH / ROW_HEIGHT);
    const endIdx      = Math.min(total - 1, startIdx + visibleRows + BUFFER_ROWS * 2);

    // Spacers
    let spacerT = $id('vsSpacerTop');
    let spacerB = $id('vsSpacerBot');
    if (!spacerT) {
        spacerT = document.createElement('tr');
        spacerT.id = 'vsSpacerTop';
        tbody.prepend(spacerT);
    }
    if (!spacerB) {
        spacerB = document.createElement('tr');
        spacerB.id = 'vsSpacerBot';
        tbody.append(spacerB);
    }

    spacerT.style.height = (startIdx * ROW_HEIGHT) + 'px';
    spacerB.style.height = ((total - 1 - endIdx) * ROW_HEIGHT) + 'px';

    // Remove existing data rows
    Array.from(tbody.querySelectorAll('tr[data-vs]')).forEach(r => r.remove());

    const frag = document.createDocumentFragment();
    for (let i = startIdx; i <= endIdx; i++) {
        const row = buildRow(filteredSorted[i], i, showTcp, showUdp);
        row.setAttribute('data-vs', i);
        frag.appendChild(row);
    }

    // Insert after spacerTop
    spacerT.after(frag);
}

function scheduleVsRender() {
    if (vsRafPending) return;
    vsRafPending = true;
    requestAnimationFrame(() => {
        vsRafPending = false;
        renderVirtualTable();
    });
}

// Scroll listener
document.addEventListener('DOMContentLoaded', () => {
    const wrap = $id('tableWrap');
    if (wrap) wrap.addEventListener('scroll', scheduleVsRender, { passive: true });
});

// Debounced refresh (used during streaming)
let tableTimer = null;
function scheduleRefresh() {
    if (tableTimer) return;
    tableTimer = setTimeout(() => { tableTimer = null; triggerSort(); }, 350);
}

// ── Filter counts ─────────────────────────────────
function updateFilterCount() {
    const counts = {
        all:    results.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok).length,
        online: results.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok).length,
        dead:   results.filter(r => !r.tcp?.ok && !r.tls?.ok && !r.udp?.ok).length,
        tcp:    results.filter(r => r.tcp?.ok).length,
        udp:    results.filter(r => r.udp?.ok).length,
        sni:    results.filter(r => r.tls?.ok).length,
        cdn:    results.filter(r => !!r.provider).length,
    };
    Object.keys(counts).forEach(f => {
        const el = document.querySelector(`.filter-btn[data-filter="${f}"] .filter-count`);
        if (el) el.textContent = counts[f];
    });
}

// ── Sort controls ─────────────────────────────────
function setSort(key) {
    if (currentSort.key === key) {
        currentSort.asc = !currentSort.asc;
    } else {
        currentSort.key = key;
        currentSort.asc = !['score'].includes(key);
    }
    document.querySelectorAll('th.sortable').forEach(th => th.classList.remove('active', 'desc'));
    const activeTh = document.querySelector(`[onclick="setSort('${key}')"]`);
    if (activeTh) {
        activeTh.classList.add('active');
        if (!currentSort.asc) activeTh.classList.add('desc');
    }
    triggerSort();
}

// ── Scan button ───────────────────────────────────
function updateScanButton() {
    const btn    = $id('toggleScanBtn');
    const iconEl = $id('scanBtnIcon');
    const txtEl  = $id('scanBtnTxt');
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
    const pct   = totalCount ? (scannedCount / totalCount) * 100 : 0;
    const bar   = $id('progressBar');
    const pctEl = $id('progressPct');
    if (bar)   bar.style.width = pct + '%';
    if (pctEl) pctEl.textContent = Math.round(pct) + '%';
    updateProgressLabel();
}

function updateProgressLabel() {
    const el = $id('progressLabel');
    if (!el) return;
    if (scanState === 'idle')         el.textContent = t().progressReady;
    else if (scanState === 'running') el.textContent = t().progressScan(scannedCount, totalCount);
    else                              el.textContent = t().progressDone;
}

// ── Prepare list ──────────────────────────────────
async function prepareList() {
    if (scanning) { showToast(t().stopFirst, 'warn'); return []; }
    const text = $id('ipListInput').value.trim();
    if (!text)  { showToast(t().listEmpty, 'warn'); return []; }
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
        results      = [];
        filteredSorted = [];
        updateStats();
        $id('progressBar').style.width = '0%';
        $id('waitingState').style.display = 'flex';
        const tbody = $id('resultBody');
        if (tbody) tbody.innerHTML = '';
        updateFilterCount();
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
            if (alive) successCount++; else failCount++;
            results.push(r);
            updateFilterCount();
            scheduleRefresh();
            updateStats();
        } else if (msg.type === 'done') {
            finishScan();
        }
    };
    evtSource.onerror = () => {};
}

// ── Start scan ────────────────────────────────────
async function startScan(list) {
    if (scanning || !list.length) return;
    const concurrency = parseInt($id('concurrency').value) || 30;
    const timeout     = parseInt($id('timeout').value)     || 3000;
    const scan_mode   = getScanMode();
    const ports       = getSelectedPorts();
    try {
        const resp = await fetch('/api/scan/start', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ entries: list, concurrency, timeout, scan_mode, ports, session_id: sessionId }),
        });
        const data = await resp.json();
        sessionId = data.session_id;
        localStorage.setItem('ani_session', sessionId);
        SESSIONS_ports = ports;
        SESSIONS_mode  = scan_mode;
        scanning     = true;
        results      = [];
        filteredSorted = [];
        scannedCount = successCount = failCount = 0;
        totalCount   = list.length;
        scanState    = 'running';
        $id('waitingState').style.display = 'none';
        $id('parseBtn').disabled = true;
        updateStats(); triggerSort(); updateScanButton();
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
    updateScanButton(); updateProgressLabel();
    showToast(t().scanStop, 'warn');
}

function finishScan() {
    scanning  = false;
    scanState = 'done';
    if (evtSource) { evtSource.close(); evtSource = null; }
    $id('parseBtn').disabled = false;
    updateScanButton(); triggerSort();
    const aliveCount = results.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok).length;
    if (!aliveCount) $id('waitingState').style.display = 'flex';
    updateProgressLabel();
    showToast(t().scanDone(successCount, failCount), 'success');
    // v3.0: save to IndexedDB history + render histogram
    saveToHistory({
        total:     results.length,
        online:    aliveCount,
        results:   results,
        ports:     SESSIONS_ports || [],
        scan_mode: SESSIONS_mode  || 'TCP',
    });
    renderHistogram();
}

// v3.0: track last scan mode/ports for history saving
let SESSIONS_ports = [];
let SESSIONS_mode  = 'TCP';

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
            updateStats(); triggerSort(); updateScanButton();
            connectStream(sessionId);
        } else if (successCount > 0) {
            scanState = 'done';
            $id('waitingState').style.display = 'none';
            updateStats(); triggerSort();
            showToast(t().scanDone(successCount, failCount), 'success');
            localStorage.removeItem('ani_session'); sessionId = null;
        } else {
            localStorage.removeItem('ani_session'); sessionId = null;
        }
    } catch {}
}

// ── Download ──────────────────────────────────────
function downloadResults(mode) {
    // 'filtered' mode exports whatever is in the current filtered view
    const sourceList = mode === 'filtered'
        ? filteredSorted
        : results.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok);

    if (!sourceList.length) { showToast(t().dlEmpty, 'warn'); return; }

    const sorted = mode === 'filtered'
        ? sourceList
        : [...sourceList].sort((a, b) => (b.score?.points || 0) - (a.score?.points || 0));

    const CRLF  = '\r\n';
    let content = '';

    if (mode === 'simple') {
        content = sorted.map(r => r.ip).join(CRLF) + CRLF;
    } else {
        content  = '# AniScanner Advanced Export' + CRLF;
        content += '# IP • SNI/CN • Ping(ms) • Latency(avg) • TCP • UDP • TLS_Ver • Issuer • DaysLeft • CDN • Score • Verdict' + CRLF + CRLF;
        for (const r of sorted) {
            content += [
                r.ip,
                r.tls?.cn   || r.sni || '',
                r.tcp?.ms   ?? '',
                r.latency?.avg ?? '',
                r.tcp?.ok   ? 'TCP:OK'     : 'TCP:FAIL',
                r.udp?.status || 'N/A',
                r.tls?.tls_ver   || '',
                r.tls?.issuer    || '',
                r.tls?.days_left ?? '',
                r.provider  || '',
                r.score?.points  ?? 0,
                r.score?.verdict || '',
            ].join(' • ') + CRLF;
        }
    }

    content += CRLF + `# Scanned by AniScanner v${VERSION}` + CRLF + `# Telegram: https://t.me/aniartx` + CRLF;

    const BOM  = '\uFEFF';
    const blob = new Blob([BOM + content], { type: 'text/plain;charset=utf-8' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = mode === 'simple' ? 'clean_ips.txt' : mode === 'filtered' ? 'filtered_ips.txt' : 'aniscanner_full.txt';
    a.click();
    URL.revokeObjectURL(a.href);
    showToast(t().dlDone(mode), 'success');
    $id('downloadMenu').classList.remove('open');
}

// ── Toast notifications ───────────────────────────
function showToast(msg, type = 'info') {
    const el = $id('progressLabel');
    if (!el) return;
    const colors = { info: '#38bdf8', success: '#34d399', warn: '#fbbf24', error: '#f87171' };
    el.style.color = colors[type] || colors.info;
    el.textContent = msg;
    setTimeout(() => { el.style.color = ''; updateProgressLabel(); }, 3500);
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

// ── Filter handlers ───────────────────────────────
function setFilter(f) {
    activeFilter = f;
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === f);
    });
    triggerSort();
}

function toggleSortByPing() {
    sortByPing = !sortByPing;
    const cb = $id('sortByPingCb');
    if (cb) cb.checked = sortByPing;
    triggerSort();
}

// expose globally
window.setFilter        = setFilter;
window.toggleSortByPing = toggleSortByPing;
window.setSort          = setSort;
window.downloadResults  = downloadResults;



// ══════════════════════════════════════════════════
// v3.0 — New Features
// ══════════════════════════════════════════════════

// ── Dark / Light Theme ────────────────────────────
let currentTheme = localStorage.getItem('ani_theme') || 'dark';

function applyTheme(theme) {
    currentTheme = theme;
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ani_theme', theme);
    const btn = $id('themeBtn');
    if (btn) btn.textContent = theme === 'dark' ? '☀️' : '🌙';
}

function toggleTheme() {
    applyTheme(currentTheme === 'dark' ? 'light' : 'dark');
}

window.toggleTheme = toggleTheme;

// ── Copy IP on row click ──────────────────────────
function copyIpToClipboard(ip) {
    if (!ip) return;
    navigator.clipboard.writeText(ip).then(() => {
        showToast(t().copyIp + ' ' + ip, 'success');
    }).catch(() => {
        // fallback
        const ta = document.createElement('textarea');
        ta.value = ip;
        ta.style.position = 'fixed';
        ta.style.opacity  = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast(t().copyIp + ' ' + ip, 'success');
    });
}

window.copyIpToClipboard = copyIpToClipboard;

// ── Score Histogram ───────────────────────────────
function renderHistogram() {
    const container = $id('histogramContainer');
    if (!container) return;
    if (!results.length) { container.innerHTML = ''; return; }

    const BUCKETS = [
        { label: '0–19',  min: 0,  max: 19,  color: '#f87171' },
        { label: '20–44', min: 20, max: 44,  color: '#facc15' },
        { label: '45–69', min: 45, max: 69,  color: '#a78bfa' },
        { label: '70–89', min: 70, max: 89,  color: '#38bdf8' },
        { label: '90–100',min: 90, max: 100, color: '#4ade80' },
    ];

    const counts = BUCKETS.map(b =>
        results.filter(r => {
            const p = r.score?.points ?? 0;
            return p >= b.min && p <= b.max;
        }).length
    );
    const maxCount = Math.max(...counts, 1);

    container.innerHTML = `
        <div class="histogram" title="Score Distribution">
            ${BUCKETS.map((b, i) => `
                <div class="hist-bar-wrap" title="${b.label}: ${counts[i]}">
                    <div class="hist-bar" style="height:${Math.round((counts[i]/maxCount)*60)}px;background:${b.color}"></div>
                    <div class="hist-count">${counts[i]}</div>
                    <div class="hist-label">${b.label}</div>
                </div>
            `).join('')}
        </div>`;
}

window.renderHistogram = renderHistogram;

// ── Scan History (IndexedDB) ──────────────────────
const DB_NAME    = 'AniScannerDB';
const DB_VERSION = 1;
const STORE_NAME = 'scan_history';
let   _db        = null;

function openDB() {
    return new Promise((resolve, reject) => {
        if (_db) { resolve(_db); return; }
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = e => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                const store = db.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
                store.createIndex('started_at', 'started_at', { unique: false });
            }
        };
        req.onsuccess = e => { _db = e.target.result; resolve(_db); };
        req.onerror   = e => reject(e.target.error);
    });
}

async function saveToHistory(scanData) {
    try {
        const db    = await openDB();
        const tx    = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        store.add({
            started_at:  Date.now(),
            total:       scanData.total,
            online:      scanData.online,
            results:     scanData.results,
            ports:       scanData.ports,
            scan_mode:   scanData.scan_mode,
        });
    } catch (e) {
        console.warn('[history] save failed', e);
    }
}

async function loadHistory() {
    try {
        const db    = await openDB();
        const tx    = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const all   = await new Promise((res, rej) => {
            const req = store.getAll();
            req.onsuccess = e => res(e.target.result);
            req.onerror   = e => rej(e.target.error);
        });
        return all.sort((a, b) => b.started_at - a.started_at).slice(0, 20);
    } catch (e) {
        return [];
    }
}

async function showHistoryModal() {
    const modal = $id('historyModal');
    if (!modal) return;
    const list = await loadHistory();
    const body = $id('historyList');
    if (!body) return;

    if (!list.length) {
        body.innerHTML = `<p class="history-empty">${t().historyEmpty}</p>`;
    } else {
        body.innerHTML = list.map(item => {
            const d = new Date(item.started_at);
            const dateStr = d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
            return `
                <div class="history-item" data-id="${item.id}" onclick="loadHistoryItem(${item.id})">
                    <span class="hist-date">${dateStr}</span>
                    <span class="hist-total">${item.total} IPs</span>
                    <span class="hist-online" style="color:#4ade80">${item.online} online</span>
                    <span class="hist-mode">${item.scan_mode || 'TCP'}</span>
                </div>`;
        }).join('');
    }
    modal.style.display = 'flex';
}

async function loadHistoryItem(id) {
    try {
        const db    = await openDB();
        const tx    = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const item  = await new Promise((res, rej) => {
            const req = store.get(id);
            req.onsuccess = e => res(e.target.result);
            req.onerror   = e => rej(e.target.error);
        });
        if (!item) return;
        results      = item.results || [];
        filteredSorted = [];
        scannedCount = results.length;
        totalCount   = results.length;
        successCount = results.filter(r => r.tcp?.ok || r.tls?.ok || r.udp?.ok).length;
        failCount    = scannedCount - successCount;
        scanState    = 'done';
        $id('waitingState').style.display = 'none';
        updateStats(); triggerSort(); renderHistogram();
        closeHistoryModal();
        showToast(t().historyLoad, 'info');
    } catch (e) {
        console.warn('[history] load failed', e);
    }
}

function closeHistoryModal() {
    const modal = $id('historyModal');
    if (modal) modal.style.display = 'none';
}

window.showHistoryModal  = showHistoryModal;
window.closeHistoryModal = closeHistoryModal;
window.loadHistoryItem   = loadHistoryItem;

// ── Cloudflare IP Import ──────────────────────────
async function importCloudflareIPs() {
    showToast(t().cfImporting, 'info');
    try {
        const [v4resp, v6resp] = await Promise.all([
            fetch('https://www.cloudflare.com/ips-v4'),
            fetch('https://www.cloudflare.com/ips-v6'),
        ]);
        const v4text = v4resp.ok ? await v4resp.text() : '';
        const v6text = v6resp.ok ? await v6resp.text() : '';
        const combined = [v4text, v6text].join('\n').trim();
        if (!combined) throw new Error('empty');

        const current = $id('ipListInput').value.trim();
        $id('ipListInput').value = current ? current + '\n' + combined : combined;
        const lines = combined.split('\n').filter(Boolean);
        showToast(t().cfImportDone(lines.length), 'success');
    } catch (e) {
        showToast(t().cfImportErr, 'error');
    }
}

window.importCloudflareIPs = importCloudflareIPs;

// Hook: save to history when scan finishes
const _origFinishScan = finishScan;
// We need to patch finishScan — we do it after definition

// ── Init ──────────────────────────────────────────
applyLang();
applyColumns();
applyTheme(currentTheme);
tryReconnect();
