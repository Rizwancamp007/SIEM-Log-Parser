'use strict';
/**
 * ══════════════════════════════════════════════════════════════════
 *  SIEM Console  ·  Frontend Controller  ·  app.js
 *  ─────────────────────────────────────────────────────────────────
 *  WebSocket client, dynamic DOM updates, Chart.js visualisations,
 *  audio alerts, filter/search, and ticker management.
 * ══════════════════════════════════════════════════════════════════
 */

// ── Config ──────────────────────────────────────────────────────────
const WS_URL         = `ws://${location.host}`;
const RECONNECT_MS   = 3000;
const MAX_LOG_LINES  = 120;    // Green terminal lines to keep in DOM
const MAX_ALERT_CARDS = 60;   // Alert cards to keep in the feed panel
const MAX_TABLE_ROWS  = 200;  // Rows to keep in the filterable table

// ── State ────────────────────────────────────────────────────────────
let ws            = null;
let wsConnected   = false;
let audioEnabled  = false;
let audioCtx      = null;

// Alert store (newest first)
let allAlerts = [];

// Chart buckets
const CHART_BUCKET_MINUTES = 30;
const buckets = Array.from({ length: CHART_BUCKET_MINUTES }, () => 0);
let   bucketTs = Date.now();

const typeCounts = {};   // { attackType: count }
const sevCounts  = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };

// Ticker items array
let tickerItems = ['SIEM Monitoring Active'];

// ── DOM Refs ─────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

const elWsDot      = $('ws-dot');
const elWsLabel    = $('ws-label');
const elWsStatus   = $('ws-status');
const elStatLines  = $('stat-lines');
const elStatAlerts = $('stat-alerts');
const elStatCrit   = $('stat-critical');
const elStatIps    = $('stat-ips');
const elBarLines   = $('bar-lines');
const elBarAlerts  = $('bar-alerts');
const elBarCrit    = $('bar-critical');
const elBarIps     = $('bar-ips');
const elLogBadge   = $('log-count-badge');
const elAlertBadge = $('alert-count-badge');
const elLogTerm    = $('log-terminal');
const elAlertFeed  = $('alert-feed');
const elAlertTbody = $('alert-tbody');
const elTickerTrack = $('ticker-track');
const elBtnAudio   = $('btn-audio');
const elBtnClear   = $('btn-clear');
const elFilterInput = $('filter-input');
const elFilterSev   = $('filter-severity');
const elClock       = $('clock');
const elCardAlerts  = $('card-alerts');

// ── Clock ─────────────────────────────────────────────────────────────
function updateClock() {
  elClock.textContent = new Date().toUTCString().replace('GMT', 'UTC');
}
updateClock();
setInterval(updateClock, 1000);

// ── Bucket timer — rotate every 60 s ─────────────────────────────────
setInterval(() => {
  buckets.shift();
  buckets.push(0);
  bucketTs = Date.now();
  chartTimeline.update();
}, 60_000);

// ── Audio ─────────────────────────────────────────────────────────────
function initAudio() {
  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  }
}

function playCriticalBeep() {
  if (!audioEnabled || !audioCtx) return;
  try {
    const osc  = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    osc.type      = 'square';
    osc.frequency.setValueAtTime(880, audioCtx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.15);
    gain.gain.setValueAtTime(0.3, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.35);

    osc.start(audioCtx.currentTime);
    osc.stop(audioCtx.currentTime + 0.35);
  } catch (e) { /* silently ignore audio errors */ }
}

elBtnAudio.addEventListener('click', () => {
  audioEnabled = !audioEnabled;
  if (audioEnabled) initAudio();
  elBtnAudio.textContent = audioEnabled ? '🔊 Audio ON' : '🔇 Audio OFF';
  elBtnAudio.classList.toggle('active', audioEnabled);
});

// ── Clear ─────────────────────────────────────────────────────────────
elBtnClear.addEventListener('click', async () => {
  if (!confirm('Clear all alerts and reset the log? This will truncate auth.log.')) return;
  try {
    await fetch('/api/clear');
  } catch { /* ws CLEAR message handles it */ }
});

// ── Ticker ────────────────────────────────────────────────────────────
function addTickerItem(text, isThreat = false) {
  tickerItems.push(text);
  if (tickerItems.length > 40) tickerItems.shift();
  renderTicker();
}

function renderTicker() {
  // Duplicate items so the animation loops seamlessly
  const items = [...tickerItems, ...tickerItems];
  elTickerTrack.innerHTML = items
    .map((t, i) => `<span class="ticker-item ${t.includes('|') ? 'threat' : ''}">${escHtml(t)}</span>`)
    .join('');
  // Adjust animation duration based on content length
  const total = tickerItems.join(' ⸺ ').length;
  elTickerTrack.style.animationDuration = Math.max(20, total * 0.25) + 's';
}

// ── Log Terminal ──────────────────────────────────────────────────────
function addLogLine(text, isThreat = false) {
  const p = document.createElement('p');
  p.className = `log-line${isThreat ? ' threat' : ''}`;
  p.textContent = text;
  elLogTerm.appendChild(p);

  // Trim overflow
  while (elLogTerm.children.length > MAX_LOG_LINES) {
    elLogTerm.removeChild(elLogTerm.firstChild);
  }
  elLogTerm.scrollTop = elLogTerm.scrollHeight;
  elLogBadge.textContent = `${elLogTerm.children.length} lines`;
}

// ── Alert Cards ───────────────────────────────────────────────────────
function addAlertCard(alert) {
  // Remove placeholder if present
  const placeholder = elAlertFeed.querySelector('.no-alerts-msg');
  if (placeholder) placeholder.remove();

  const div = document.createElement('div');
  div.className = `alert-card ${alert.severity} new`;
  div.innerHTML = `
    <div class="alert-card-top">
      <span class="sev-badge ${alert.severity}">${escHtml(alert.severity)}</span>
      <span class="alert-type">${escHtml(alert.attackType)}</span>
      <span class="alert-time">${formatTime(alert.timestamp)}</span>
    </div>
    <div class="alert-ip">⚡ ${escHtml(alert.attackerIp)}</div>
    <div class="alert-payload">${escHtml(alert.targetPayload)}</div>
  `;
  elAlertFeed.prepend(div);

  // Trim overflow
  while (elAlertFeed.children.length > MAX_ALERT_CARDS) {
    elAlertFeed.removeChild(elAlertFeed.lastChild);
  }
  elAlertBadge.textContent = `${elAlertFeed.children.length} alerts`;

  // Flash parent metric card
  elCardAlerts.classList.remove('flash');
  void elCardAlerts.offsetWidth;   // reflow
  elCardAlerts.classList.add('flash');
  setTimeout(() => elCardAlerts.classList.remove('flash'), 900);
}

// ── Alert Table ───────────────────────────────────────────────────────
function renderTable() {
  const query  = elFilterInput.value.toLowerCase();
  const sevFlt = elFilterSev.value;

  const filtered = allAlerts.filter((a) => {
    if (sevFlt && a.severity !== sevFlt) return false;
    if (query) {
      const haystack = `${a.attackerIp} ${a.attackType} ${a.targetPayload}`.toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  }).slice(0, MAX_TABLE_ROWS);

  if (filtered.length === 0) {
    elAlertTbody.innerHTML = '<tr><td colspan="5" class="empty-row">No matching alerts.</td></tr>';
    return;
  }

  elAlertTbody.innerHTML = filtered.map((a) => `
    <tr>
      <td><span class="chip ${a.severity}">${escHtml(a.severity)}</span></td>
      <td>${escHtml(formatTime(a.timestamp))}</td>
      <td>${escHtml(a.attackType)}</td>
      <td>${escHtml(a.attackerIp)}</td>
      <td>${escHtml(a.targetPayload.slice(0, 180))}${a.targetPayload.length > 180 ? '…' : ''}</td>
    </tr>
  `).join('');
}

elFilterInput.addEventListener('input',  renderTable);
elFilterSev.addEventListener('change', renderTable);

// ── Stats Counters ────────────────────────────────────────────────────
function updateStats(s) {
  animateCount(elStatLines,  s.totalLines);
  animateCount(elStatAlerts, s.totalAlerts);
  animateCount(elStatCrit,   s.criticalCount);
  animateCount(elStatIps,    s.uniqueIps);

  // Progress bars (max 100% at 500 events)
  const pct = (n) => Math.min(100, (n / 500) * 100) + '%';
  elBarLines.style.width  = pct(s.totalLines);
  elBarAlerts.style.width = pct(s.totalAlerts);
  elBarCrit.style.width   = pct(s.criticalCount * 5);
  elBarIps.style.width    = pct(s.uniqueIps * 8);
}

const counters = new WeakMap();
function animateCount(el, target) {
  const start = parseInt(el.textContent.replace(/,/g, '')) || 0;
  if (start === target) return;
  const step = Math.ceil(Math.abs(target - start) / 20);
  let current = start;
  const tick = () => {
    current = current < target ? Math.min(current + step, target)
                               : Math.max(current - step, target);
    el.textContent = current.toLocaleString();
    if (current !== target) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

// ── Charts ─────────────────────────────────────────────────────────────
const chartDefaults = {
  color:     '#5a7090',
  font:      { family: "'Share Tech Mono', monospace", size: 10 },
};
Chart.defaults.color     = chartDefaults.color;
Chart.defaults.font      = chartDefaults.font;
Chart.defaults.borderColor = 'rgba(0,240,255,0.08)';

// Severity Doughnut
const ctxSev = $('chart-severity').getContext('2d');
const chartSeverity = new Chart(ctxSev, {
  type: 'doughnut',
  data: {
    labels: ['Critical', 'High', 'Medium'],
    datasets: [{
      data: [0, 0, 0],
      backgroundColor: ['rgba(255,0,85,0.75)', 'rgba(255,170,0,0.75)', 'rgba(168,85,247,0.75)'],
      borderColor:     ['#ff0055', '#ffaa00', '#a855f7'],
      borderWidth:     2,
      hoverOffset:     8,
    }],
  },
  options: {
    cutout:    '70%',
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#5a7090', padding: 10, font: { size: 10 } },
      },
      tooltip: {
        callbacks: {
          label: (ctx) => ` ${ctx.label}: ${ctx.raw} events`,
        },
      },
    },
  },
});

// Timeline Line Chart
const timeLabels = Array.from({ length: CHART_BUCKET_MINUTES }, (_, i) => {
  const d = new Date(Date.now() - (CHART_BUCKET_MINUTES - 1 - i) * 60_000);
  return `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`;
});

const ctxTl = $('chart-timeline').getContext('2d');
const chartTimeline = new Chart(ctxTl, {
  type: 'line',
  data: {
    labels: timeLabels,
    datasets: [{
      label:           'Alerts / min',
      data:            [...buckets],
      borderColor:     '#00f0ff',
      backgroundColor: 'rgba(0, 240, 255, 0.08)',
      borderWidth:     2,
      pointRadius:     2,
      pointBackgroundColor: '#00f0ff',
      fill:            true,
      tension:         0.4,
    }],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
    scales: {
      x: {
        ticks: { maxRotation: 0, maxTicksLimit: 8 },
        grid:  { color: 'rgba(0,240,255,0.06)' },
      },
      y: {
        beginAtZero: true,
        ticks: { stepSize: 1 },
        grid:  { color: 'rgba(0,240,255,0.06)' },
      },
    },
    plugins: { legend: { display: false } },
  },
});

// Top Attack Types Bar
const ctxTypes = $('chart-types').getContext('2d');
const chartTypes = new Chart(ctxTypes, {
  type: 'bar',
  data: {
    labels:   [],
    datasets: [{
      label:            'Events',
      data:             [],
      backgroundColor:  'rgba(0,240,255,0.18)',
      borderColor:      '#00f0ff',
      borderWidth:      1.5,
      borderRadius:     4,
      hoverBackgroundColor: 'rgba(0,240,255,0.4)',
    }],
  },
  options: {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
    scales: {
      x: {
        beginAtZero: true,
        ticks: { stepSize: 1 },
        grid:  { color: 'rgba(0,240,255,0.06)' },
      },
      y: { grid: { display: false } },
    },
    plugins: { legend: { display: false } },
  },
});

function updateCharts() {
  // Severity doughnut
  chartSeverity.data.datasets[0].data = [sevCounts.CRITICAL, sevCounts.HIGH, sevCounts.MEDIUM];
  chartSeverity.update();

  // Timeline (live bucket)
  chartTimeline.data.datasets[0].data = [...buckets];
  chartTimeline.update();

  // Top types bar
  const sorted = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  chartTypes.data.labels                  = sorted.map((e) => e[0]);
  chartTypes.data.datasets[0].data        = sorted.map((e) => e[1]);
  chartTypes.update();
}

// ── Incoming Alert Handler ────────────────────────────────────────────
function handleAlert(alert) {
  allAlerts.unshift(alert);
  if (allAlerts.length > 500) allAlerts.pop();

  // Update counters
  sevCounts[alert.severity] = (sevCounts[alert.severity] || 0) + 1;
  typeCounts[alert.attackType] = (typeCounts[alert.attackType] || 0) + 1;
  buckets[buckets.length - 1]++;

  // UI updates
  addAlertCard(alert);
  addLogLine(`[THREAT] ${alert.severity} | ${alert.attackType} | ${alert.attackerIp}`, true);
  addTickerItem(`${alert.severity} | ${alert.attackType} | IP: ${alert.attackerIp}`, true);
  renderTable();
  updateCharts();

  if (alert.severity === 'CRITICAL') playCriticalBeep();
}

// ── Snapshot Handler ──────────────────────────────────────────────────
function handleSnapshot(payload) {
  allAlerts = payload.alerts || [];

  // Rebuild severity / type buckets from history
  allAlerts.forEach((a) => {
    sevCounts[a.severity] = (sevCounts[a.severity] || 0) + 1;
    typeCounts[a.attackType] = (typeCounts[a.attackType] || 0) + 1;
  });

  // Show last 20 alert cards
  elAlertFeed.innerHTML = '';
  allAlerts.slice(0, 20).forEach((a) => addAlertCard(a));

  // Show last 40 log lines
  elLogTerm.innerHTML = '';
  (payload.logLines || []).slice(-40).forEach((l) => addLogLine(l.line || l));

  updateStats(payload.stats);
  updateCharts();
  renderTable();
}

// ── WebSocket ─────────────────────────────────────────────────────────
function connectWS() {
  elWsLabel.textContent  = 'Connecting…';
  elWsDot.className      = 'ws-dot';
  elWsStatus.className   = 'ws-status';

  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    wsConnected        = true;
    elWsDot.className  = 'ws-dot connected';
    elWsLabel.textContent = 'Connected';
    elWsStatus.className  = 'ws-status connected';
    console.log('[WS] Connected');
  };

  ws.onmessage = (evt) => {
    let msg;
    try { msg = JSON.parse(evt.data); } catch { return; }

    switch (msg.type) {
      case 'SNAPSHOT':
        handleSnapshot(msg.payload);
        break;
      case 'ALERT':
        handleAlert(msg.payload);
        break;
      case 'LOG_LINE':
        addLogLine(msg.payload.line || msg.payload);
        break;
      case 'STATS':
        updateStats(msg.payload);
        break;
      case 'CLEAR':
        allAlerts = [];
        Object.keys(sevCounts).forEach((k)  => (sevCounts[k]  = 0));
        Object.keys(typeCounts).forEach((k) => (typeCounts[k] = 0));
        buckets.fill(0);
        elAlertFeed.innerHTML = '<p class="no-alerts-msg">Alerts cleared.</p>';
        elLogTerm.innerHTML   = '<p class="log-line muted">[SIEM] Log cleared.</p>';
        elAlertTbody.innerHTML = '<tr><td colspan="5" class="empty-row">Awaiting threat data…</td></tr>';
        updateStats({ totalLines: 0, totalAlerts: 0, criticalCount: 0, highCount: 0, mediumCount: 0, uniqueIps: 0 });
        updateCharts();
        break;
    }
  };

  ws.onclose = () => {
    wsConnected           = false;
    elWsDot.className     = 'ws-dot error';
    elWsLabel.textContent = `Reconnecting in ${RECONNECT_MS / 1000}s…`;
    elWsStatus.className  = 'ws-status';
    console.warn('[WS] Disconnected — retrying…');
    setTimeout(connectWS, RECONNECT_MS);
  };

  ws.onerror = (err) => {
    console.error('[WS] Error', err);
    ws.close();
  };
}

// ── Utility ───────────────────────────────────────────────────────────
function escHtml(str = '') {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatTime(iso) {
  try {
    const d = new Date(iso);
    return `${String(d.getUTCHours()).padStart(2,'0')}:${String(d.getUTCMinutes()).padStart(2,'0')}:${String(d.getUTCSeconds()).padStart(2,'0')} UTC`;
  } catch {
    return iso;
  }
}

// ── Boot ──────────────────────────────────────────────────────────────
connectWS();
