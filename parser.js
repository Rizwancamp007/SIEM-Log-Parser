'use strict';

/**
 * ══════════════════════════════════════════════════════════════════
 *  SIEM Log Parser  ·  Threat Signature Engine  ·  parser.js
 *  ─────────────────────────────────────────────────────────────────
 *  Analyses a single raw log line against the built-in regex
 *  signature database and returns a structured alert object, or
 *  null when the line is benign.
 * ══════════════════════════════════════════════════════════════════
 */

// ── Signature Database ──────────────────────────────────────────────
const SIGNATURES = [
  {
    id:         'SQLi',
    attackType: 'SQL Injection',
    severity:   'CRITICAL',
    pattern:    /(UNION\s+SELECT|SELECT\s+.+\s+FROM|UNION\s+ALL\s+SELECT|'\s*OR\s*'?\d+'?\s*=\s*'?\d+'?|1=1--|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM)/i,
    extract:    (line) => extractIp(line),
  },
  {
    id:         'XSS',
    attackType: 'Cross-Site Scripting',
    severity:   'HIGH',
    pattern:    /(<script[\s>]|<\/script>|javascript\s*:|onerror\s*=|onload\s*=|<svg\s+on|<img\s+on|alert\s*\(|document\.cookie)/i,
    extract:    (line) => extractIp(line),
  },
  {
    id:         'LFI',
    attackType: 'Path Traversal / LFI',
    severity:   'HIGH',
    pattern:    /(\.\.\/\.\.\/|\.\.\\\.\.\\|etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini|proc\/self\/environ)/i,
    extract:    (line) => extractIp(line),
  },
  {
    id:         'BRUTE',
    attackType: 'SSH Brute Force',
    severity:   'HIGH',
    pattern:    /Failed\s+password\s+for\s+(invalid\s+user\s+)?(\w+)\s+from\s+([\d.]+)/i,
    extract:    (line) => {
      const m = line.match(/from\s+([\d.]+)/i);
      return m ? m[1] : extractIp(line);
    },
  },
  {
    id:         'CMD_INJECT',
    attackType: 'Command Injection',
    severity:   'CRITICAL',
    pattern:    /(\||;|`|\$\()\s*(ls|cat|whoami|id|uname|wget|curl|bash|sh|nc|nmap|chmod|rm\s+-rf)/i,
    extract:    (line) => extractIp(line),
  },
  {
    id:         'SCANNER',
    attackType: 'Port / Vulnerability Scan',
    severity:   'MEDIUM',
    pattern:    /(Nmap|masscan|nikto|nessus|openvas|zap|dirb|gobuster|hydra|sqlmap)/i,
    extract:    (line) => extractIp(line),
  },
];

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Tries to pull the first IPv4 address out of a log line.
 */
function extractIp(line) {
  const m = line.match(/\b(\d{1,3}\.){3}\d{1,3}\b/);
  return m ? m[0] : 'unknown';
}

/**
 * Truncates a payload string to keep alert objects lean.
 */
function truncate(str, max = 220) {
  return str.length > max ? str.slice(0, max) + '…' : str;
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Analyse one raw log line.
 *
 * @param   {string} rawLog  – A single line from auth.log / web access log.
 * @returns {Object|null}    – Structured alert object, or null if benign.
 */
function parseLine(rawLog) {
  if (!rawLog || !rawLog.trim()) return null;

  for (const sig of SIGNATURES) {
    if (sig.pattern.test(rawLog)) {
      return {
        id:            `${sig.id}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp:     new Date().toISOString(),
        severity:      sig.severity,
        attackType:    sig.attackType,
        attackerIp:    sig.extract(rawLog),
        targetPayload: truncate(rawLog.trim()),
        rawLog:        truncate(rawLog, 512),
      };
    }
  }

  return null;   // benign line — caller treats it as a green ticker event
}

module.exports = { parseLine, SIGNATURES };
