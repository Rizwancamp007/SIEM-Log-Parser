'use strict';

/**
 * ══════════════════════════════════════════════════════════════════
 *  SIEM Log Parser  ·  Backend Broker  ·  server.js
 *  ─────────────────────────────────────────────────────────────────
 *  Express HTTP server  +  WebSocket broadcaster  +  Chokidar watcher
 *  Port: 5000
 * ══════════════════════════════════════════════════════════════════
 */

const express   = require('express');
const http      = require('http');
const WebSocket = require('ws');
const chokidar  = require('chokidar');
const fs        = require('fs');
const path      = require('path');
const { parseLine } = require('./parser');

// ── Constants ────────────────────────────────────────────────────────
const PORT      = process.env.PORT || 5000;
const LOG_FILE  = path.join(__dirname, 'logs', 'auth.log');
const MAX_HISTORY    = 200;   // In-memory circular alert store
const MAX_LOG_LINES  = 300;   // Green ticker lines kept in memory

// ── Application Setup ────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── In-Memory State ──────────────────────────────────────────────────
let alertHistory  = [];    // Array of parsed alert objects (newest first)
let logLineBuffer = [];    // Raw lines for the green log ticker
let stats = {
  totalLines:     0,
  totalAlerts:    0,
  criticalCount:  0,
  highCount:      0,
  mediumCount:    0,
  uniqueIps:      new Set(),
};

// ── Utility Functions ────────────────────────────────────────────────

function broadcast(data) {
  const payload = JSON.stringify(data);
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

function pushAlert(alert) {
  alertHistory.unshift(alert);
  if (alertHistory.length > MAX_HISTORY) alertHistory.pop();

  stats.totalAlerts++;
  stats.uniqueIps.add(alert.attackerIp);
  if (alert.severity === 'CRITICAL') stats.criticalCount++;
  else if (alert.severity === 'HIGH') stats.highCount++;
  else if (alert.severity === 'MEDIUM') stats.mediumCount++;

  broadcast({ type: 'ALERT', payload: alert });
  broadcast({ type: 'STATS', payload: getStats() });
}

function pushLogLine(line) {
  logLineBuffer.push({ ts: new Date().toISOString(), line: line.trim() });
  if (logLineBuffer.length > MAX_LOG_LINES) logLineBuffer.shift();
  stats.totalLines++;
  broadcast({ type: 'LOG_LINE', payload: { ts: new Date().toISOString(), line: line.trim() } });
}

function getStats() {
  return {
    totalLines:    stats.totalLines,
    totalAlerts:   stats.totalAlerts,
    criticalCount: stats.criticalCount,
    highCount:     stats.highCount,
    mediumCount:   stats.mediumCount,
    uniqueIps:     stats.uniqueIps.size,
  };
}

// ── File Watcher ─────────────────────────────────────────────────────

// Ensure the log file exists
if (!fs.existsSync(LOG_FILE)) {
  fs.writeFileSync(LOG_FILE, '', 'utf8');
  console.log(`[SIEM] Created log file: ${LOG_FILE}`);
}

let lastSize = fs.statSync(LOG_FILE).size;

const watcher = chokidar.watch(LOG_FILE, {
  persistent:    true,
  usePolling:    false,
  awaitWriteFinish: false,
});

watcher.on('change', (filePath) => {
  try {
    const stat    = fs.statSync(filePath);
    const newSize = stat.size;

    if (newSize < lastSize) {
      // File was truncated/rotated — reset position
      lastSize = 0;
    }

    const diff = newSize - lastSize;
    if (diff <= 0) return;

    // Read only the newly appended bytes
    const buf = Buffer.alloc(diff);
    const fd  = fs.openSync(filePath, 'r');
    fs.readSync(fd, buf, 0, diff, lastSize);
    fs.closeSync(fd);
    lastSize = newSize;

    const newContent = buf.toString('utf8');
    const lines      = newContent.split('\n').filter((l) => l.trim().length > 0);

    lines.forEach((line) => {
      pushLogLine(line);
      const alert = parseLine(line);
      if (alert) {
        pushAlert(alert);
        console.log(`[ALERT] ${alert.severity} | ${alert.attackType} | ${alert.attackerIp}`);
      }
    });
  } catch (err) {
    console.error('[WATCHER ERROR]', err.message);
  }
});

watcher.on('error', (err) => console.error('[CHOKIDAR ERROR]', err));
console.log(`[SIEM] Watching: ${LOG_FILE}`);

// ── WebSocket Handshake ──────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  console.log(`[WS] Client connected: ${clientIp}`);

  // Send snapshot on connect
  ws.send(JSON.stringify({ type: 'SNAPSHOT', payload: {
    alerts:   alertHistory.slice(0, 50),
    logLines: logLineBuffer.slice(-100),
    stats:    getStats(),
  }}));

  ws.on('error', (err) => console.error('[WS CLIENT ERROR]', err.message));
  ws.on('close',  () => console.log(`[WS] Client disconnected: ${clientIp}`));
});

// ── REST API ─────────────────────────────────────────────────────────
app.get('/api/history', (_req, res) => {
  res.json({ alerts: alertHistory.slice(0, 50), stats: getStats() });
});

app.get('/api/stats', (_req, res) => {
  res.json(getStats());
});

app.get('/api/clear', (_req, res) => {
  alertHistory  = [];
  logLineBuffer = [];
  stats = { totalLines: 0, totalAlerts: 0, criticalCount: 0, highCount: 0, mediumCount: 0, uniqueIps: new Set() };
  lastSize = 0;
  fs.writeFileSync(LOG_FILE, '', 'utf8');
  broadcast({ type: 'CLEAR' });
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║   SIEM Dashboard → http://localhost:${PORT}  ║`);
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});
