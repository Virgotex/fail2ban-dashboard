/**
 * fail2banClient.js
 * Communicates with the local Fail2Ban daemon via its Unix socket.
 * Uses fail2ban-client commands via child_process as the most reliable
 * cross-distro method (works on Ubuntu, Debian, Arch, etc.)
 *
 * SECURITY: All IP inputs are validated before reaching this module.
 * Commands are constructed as arrays (never string interpolation) to
 * prevent any shell injection risk.
 */

const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const zlib = require('zlib');

const LOG_PATH      = process.env.FAIL2BAN_LOG   || '/var/log/fail2ban.log';
const LOG_MAX_LINES = parseInt(process.env.LOG_MAX_LINES || '500', 10);
// Read at most this many bytes from the end of a log file. Defends against
// pathologically large logs starving the process — fail2ban.log grows fast on
// noisy boxes. 2 MB is ~10k average lines, well above LOG_MAX_LINES.
const LOG_MAX_BYTES  = parseInt(process.env.LOG_MAX_BYTES  || String(2 * 1024 * 1024), 10);
const AUTH_MAX_BYTES = parseInt(process.env.AUTH_MAX_BYTES || String(5 * 1024 * 1024), 10);
// History budget for the features that look backwards in time — the 7-day
// trend, per-jail totals and an IP's timeline. These span rotated files, and a
// busy host writes well past LOG_MAX_BYTES in a week, so they get their own
// (larger) ceiling. Read at most once per LOG_CACHE_TTL_MS.
const HISTORY_MAX_BYTES = parseInt(process.env.HISTORY_MAX_BYTES || String(16 * 1024 * 1024), 10);
// Use sudo so the process doesn't need to run as root.
// The sudoers rule in docs/SECURITY.md scopes this to fail2ban-client only.
const USE_SUDO = process.env.USE_SUDO !== 'false';

// ─── Log reading ──────────────────────────────────────────────────────────
// Reads are always bounded to the tail: fail2ban.log grows fast on a noisy box
// and the agent must not starve the host it's monitoring. Where a line is
// sliced through by the byte budget, the first line read is a fragment and gets
// dropped.
//
// logrotate moves history out from under us. Minutes after a rotation the live
// fail2ban.log holds a handful of lines, so everything derived from it — the
// 7-day trend, per-jail totals, an IP's history — reads as zero while the bans
// that produced it sit in fail2ban.log.1. Include the rotated siblings too,
// newest first, until `maxBytes` is spent.
//
// `sinceMs`, when given, drops archives whose last write predates it: a file
// not touched since then holds nothing inside the window, so decompressing it
// would be pure waste.
//
// Returns [{ file, gz, size, takeBytes }] OLDEST FIRST, so a caller that walks
// them in order sees lines chronologically.
function logSources(filePath, maxBytes, sinceMs = 0) {
  const statOf = f => { try { return fs.statSync(f); } catch { return null; } };
  const liveStat = statOf(filePath);
  if (!liveStat) return [];

  const dir  = path.dirname(filePath);
  const base = path.basename(filePath);

  // logrotate produces either numeric suffixes (fail2ban.log.1[.gz]) or dates
  // (fail2ban.log-20260816[.gz]) depending on `dateext`. Ordering by mtime
  // covers both without having to parse either convention.
  let rotated = [];
  try {
    rotated = fs.readdirSync(dir)
      .filter(n => n !== base && (n.startsWith(`${base}.`) || n.startsWith(`${base}-`)))
      .map((n) => { const file = path.join(dir, n); return { file, st: statOf(file) }; })
      .filter(x => x.st && x.st.isFile() && x.st.mtimeMs >= sinceMs)
      .sort((a, b) => b.st.mtimeMs - a.st.mtimeMs);
  } catch { /* directory unreadable — the live file alone is still useful */ }

  const chosen = [];
  let budget = maxBytes;
  for (const { file, st } of [{ file: filePath, st: liveStat }, ...rotated]) {
    if (budget <= 0) break;
    const gz = /\.gz$/.test(file);
    // takeBytes is what's left of the budget when this file is reached, so an
    // oversized file is tail-sliced rather than read whole.
    chosen.push({ file, gz, size: st.size, takeBytes: budget });
    // Text compresses ~10x; charging a gzipped log at 10x its on-disk size
    // stops one archive from consuming an unbounded amount of the budget.
    budget -= gz ? st.size * 10 : st.size;
  }
  return chosen.reverse();
}

// Feed every line of `filePath` plus as much rotated history as `maxBytes`
// allows to `onLine`, oldest first. A single unreadable or truncated archive is
// skipped rather than failing the whole read.
async function readLines(filePath, maxBytes, onLine, sinceMs = 0) {
  for (const src of logSources(filePath, maxBytes, sinceMs)) {
    // gzip isn't seekable, so an archive is read whole; only plain files can be
    // tail-sliced. Sizes come from logSources — no second stat per file.
    const start = src.gz ? 0 : Math.max(0, src.size - src.takeBytes);
    const input = src.gz
      ? fs.createReadStream(src.file).pipe(zlib.createGunzip())
      : fs.createReadStream(src.file, { encoding: 'utf8', start });

    await new Promise((resolve) => {
      const rl = readline.createInterface({ input, crlfDelay: Infinity });
      let dropFirst = start > 0;
      rl.on('line', (line) => {
        if (dropFirst) { dropFirst = false; return; }
        onLine(line);
      });
      rl.on('close', resolve);
      rl.on('error', resolve);
      input.on('error', resolve);
    });
  }
}

// ─── Strict IP/CIDR validator ──────────────────────────────────────────────
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const IPV6_RE = /^[0-9a-fA-F:]{2,39}(\/\d{1,3})?$/;

function validateIP(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  if (IPV4_RE.test(trimmed)) {
    const parts = trimmed.split('/')[0].split('.');
    return parts.every(p => parseInt(p, 10) <= 255);
  }
  return IPV6_RE.test(trimmed);
}

// ─── Jail name validator (alphanumeric + hyphens only) ────────────────────
function validateJailName(name) {
  return /^[a-zA-Z0-9_-]{1,64}$/.test(name);
}

// ─── Promisified execFile wrapper ─────────────────────────────────────────
// Args are always an array — never concatenated into a shell string.
// If USE_SUDO=true, prepends ['sudo', 'fail2ban-client']; otherwise just 'fail2ban-client'.
function runCommand(args) {
  const bin  = USE_SUDO ? 'sudo' : 'fail2ban-client';
  const argv = USE_SUDO ? ['fail2ban-client', ...args] : args;
  return new Promise((resolve, reject) => {
    // maxBuffer guards against a jail with thousands of banned IPs overflowing
    // the default 1 MB stdout cap on `status <jail>`.
    execFile(bin, argv, { timeout: 10000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(stderr || err.message));
        return;
      }
      resolve(stdout.trim());
    });
  });
}

// ─── Public API ───────────────────────────────────────────────────────────

/**
 * Ping the fail2ban daemon to check if it's running.
 */
async function ping() {
  try {
    const out = await runCommand(['ping']);
    return { ok: out === 'Server replied: pong', raw: out };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/**
 * Get all configured jail names.
 */
async function getJails() {
  const out = await runCommand(['status']);
  // Output: "|- Number of jail:	N\n`- Jail list: jail1, jail2"
  const match = out.match(/Jail list:\s+(.+)/);
  if (!match) return [];
  return match[1].split(',').map(j => j.trim()).filter(Boolean);
}

/**
 * Get detailed status for a specific jail.
 */
async function getJailStatus(jailName) {
  if (!validateJailName(jailName)) throw new Error('Invalid jail name');
  const out = await runCommand(['status', jailName]);

  const parse = (re) => {
    const m = out.match(re);
    return m ? m[1].trim() : null;
  };

  const bannedStr = parse(/Currently banned:\s+(\d+)/);
  const totalStr  = parse(/Total banned:\s+(\d+)/);
  const fileStr   = parse(/File list:\s+(.+)/);
  const ipStr     = parse(/Banned IP list:\s+(.*)/);

  return {
    name:          jailName,
    currentlyBanned: parseInt(bannedStr || '0', 10),
    totalBanned:    parseInt(totalStr  || '0', 10),
    logFiles:       fileStr ? fileStr.split(' ').filter(Boolean) : [],
    bannedIPs:      ipStr   ? ipStr.split(' ').filter(Boolean)   : [],
  };
}

/**
 * Get status for all jails in parallel.
 */
async function getAllJailStatuses() {
  const jails = await getJails();
  const results = await Promise.allSettled(jails.map(j => getJailStatus(j)));
  return results
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value);
}

/**
 * Ban an IP in a specific jail.
 * IP is strictly validated before the command is built.
 */
async function banIP(jailName, ip) {
  if (!validateJailName(jailName)) throw new Error('Invalid jail name');
  if (!validateIP(ip)) throw new Error('Invalid IP address');
  const out = await runCommand(['set', jailName, 'banip', ip]);
  return { success: true, output: out };
}

/**
 * Unban an IP in a specific jail.
 */
async function unbanIP(jailName, ip) {
  if (!validateJailName(jailName)) throw new Error('Invalid jail name');
  if (!validateIP(ip)) throw new Error('Invalid IP address');
  const out = await runCommand(['set', jailName, 'unbanip', ip]);
  return { success: true, output: out };
}

/**
 * Check if a specific IP is currently banned in a jail.
 */
async function isIPBanned(jailName, ip) {
  if (!validateJailName(jailName)) throw new Error('Invalid jail name');
  if (!validateIP(ip)) throw new Error('Invalid IP address');
  const status = await getJailStatus(jailName);
  return status.bannedIPs.includes(ip);
}

/**
 * Read and parse the fail2ban log file.
 * Returns up to LOG_MAX_LINES recent lines, newest first.
 */
async function getLogs(filterText = '', level = '') {
  if (!fs.existsSync(LOG_PATH)) return [];

  const lines = [];
  // Hoisted out of the per-line callback: this runs over every line of a
  // multi-megabyte window, so lowercasing the (constant) filter per line — or
  // the line itself when nothing needs it — is pure waste.
  const ft = filterText.toLowerCase();
  // fail2ban writes "NOTICE  [sshd] Ban 1.2.3.4" — the event follows the jail,
  // it isn't a "[ban]" tag. Matching "[ban]" filtered out every line.
  const levelNeedle = { BAN: '] ban ', UNBAN: '] unban ', WARNING: 'warning' }[level] || '';
  const needsLower  = Boolean(ft || levelNeedle);

  // Spans rotated files: right after a rotation the live log may hold only a
  // few lines, and "recent activity" that stops at the rotation boundary is
  // indistinguishable from a quiet server.
  await readLines(LOG_PATH, LOG_MAX_BYTES, (line) => {
    if (!line.trim()) return;

    if (needsLower) {
      const lower = line.toLowerCase();
      if (ft && !lower.includes(ft)) return;
      if (levelNeedle && !lower.includes(levelNeedle)) return;
    }

    // Parse line: "2024-05-12 09:14:22,123 fail2ban.actions [1234]: NOTICE [sshd] Ban …"
    const m = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+\S+\s+\[(\d+)\]:\s+(WARNING|NOTICE|INFO|DEBUG|ERROR|CRITICAL)\s+(.*)/);
    if (m) {
      lines.push({
        timestamp: m[1],
        pid:       m[2],
        level:     m[3],
        message:   m[4],
        raw:       line,
      });
    } else {
      lines.push({ timestamp: null, level: 'INFO', message: line, raw: line });
    }
  });

  return lines.slice(-LOG_MAX_LINES).reverse();
}

/**
 * Get global fail2ban config values that are readable via fail2ban-client.
 */
async function getGlobalConfig() {
  const [loglevel, logtarget, dbpurgeage] = await Promise.all([
    runCommand(['get', 'loglevel']).catch(() => 'unknown'),
    runCommand(['get', 'logtarget']).catch(() => 'unknown'),
    runCommand(['get', 'dbpurgeage']).catch(() => 'unknown'),
  ]);
  return { loglevel, logtarget, dbpurgeage };
}

/**
 * Parse the fail2ban log to produce chart-ready report data, covering the last
 * 7 days — which is what the UI labels these as, and what bounds the read:
 *   - bans per day
 *   - bans per jail
 *   - recent ban events with IP + jail
 *
 * Rotated and gzipped logs are included; archives untouched since the window
 * opened are skipped unread.
 *
 * This is all derived from YOUR actual log file — zero mock data.
 */
async function getReports() {
  if (!fs.existsSync(LOG_PATH)) {
    return { dailyBans: [], byJail: [], recentBans: [] };
  }

  // We'll count bans per day (last 7 days) and per jail
  const dailyMap  = {};   // 'YYYY-MM-DD' -> count
  const jailMap   = {};   // jailName -> count
  const recentBans = [];  // [{timestamp, jail, ip}]

  // Build the last-7-days date keys so days with zero bans still appear
  const today = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    dailyMap[key] = 0;
  }

  // Matches lines like:
  // 2025-05-12 09:14:22,123 fail2ban.actions [1234]: NOTICE  [sshd] Ban 185.220.101.45
  const BAN_RE = /^(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2},\d+\s+\S+\s+\[\d+\]:\s+\w+\s+\[([^\]]+)\] Ban ([\d.:a-fA-F]+)/;

  // HISTORY_MAX_BYTES, not LOG_MAX_BYTES: a seven-day trend has to be able to
  // see seven days, which on a busy host is more than the live-log budget and,
  // after a rotation, is not in the live log at all. Archives untouched since
  // the window opened are skipped, so a long retention policy costs nothing
  // here — byJail is "all time" within what that leaves.
  const windowStart = Date.parse(`${Object.keys(dailyMap)[0]}T00:00:00Z`);
  await readLines(LOG_PATH, HISTORY_MAX_BYTES, (line) => {
    const m = line.match(BAN_RE);
    if (!m) return;

    const [, dateStr, jail, ip] = m;

    // Per-jail totals (all time in the window we read)
    jailMap[jail] = (jailMap[jail] || 0) + 1;

    // Per-day (only last 7 days)
    if (Object.prototype.hasOwnProperty.call(dailyMap, dateStr)) {
      dailyMap[dateStr]++;
    }

    // Collect every ban in the window; we slice the newest 50 at the end.
    // (Capping here would keep the *oldest* 50 in the tail window, not the
    // most recent — the opposite of what "recent bans" should show.)
    recentBans.push({ date: dateStr, jail, ip });
  }, windowStart);

  const dailyBans = Object.entries(dailyMap).map(([date, bans]) => ({
    // Short label like "Mon" or "12/05"
    day: new Date(date + 'T12:00:00').toLocaleDateString('en-GB', { weekday: 'short' }),
    date,
    bans,
  }));

  const byJail = Object.entries(jailMap)
    .map(([name, bans]) => ({ name, bans }))
    .sort((a, b) => b.bans - a.bans);

  // Newest 50, most-recent first.
  return { dailyBans, byJail, recentBans: recentBans.slice(-50).reverse() };
}

/**
 * Scrape the fail2ban log for every line mentioning a specific IP.
 * Returns a full timeline of what that IP did: which jails it hit,
 * how many attempts, when it was banned/unbanned, and all raw log lines.
 *
 * Also reads the system auth logs (if readable) for deeper context —
 * e.g. what usernames the IP tried, what ports it hit.
 */
async function getIPDetails(ip) {
  if (!validateIP(ip)) throw new Error('Invalid IP address');

  // Logs to scan — fail2ban.log first, then auth/syslog if readable
  const LOG_PATHS = [
    LOG_PATH,
    '/var/log/auth.log',
    '/var/log/secure',          // RHEL/CentOS equivalent
    '/var/log/syslog',
  ].filter(p => {
    try { fs.accessSync(p, fs.constants.R_OK); return true; } catch { return false; }
  });

  const timeline   = [];   // all events in order
  const jailsHit   = {};   // jailName -> { bans, unbans, attempts }
  const usernames  = new Set();
  const ports      = new Set();
  let   firstSeen  = null;
  let   lastSeen   = null;

  // Patterns we look for in log lines mentioning this IP
  // Escape the IP for use in regex (dots)
  const escapedIP = ip.replace(/\./g, '\\.');

  // fail2ban log patterns
  const F2B_BAN    = new RegExp(`\\[([^\\]]+)\\] Ban ${escapedIP}`);
  const F2B_UNBAN  = new RegExp(`\\[([^\\]]+)\\] Unban ${escapedIP}`);
  const F2B_FOUND  = new RegExp(`\\[([^\\]]+)\\] Found ${escapedIP}`);
  // Auth log patterns
  const AUTH_USER  = /(?:Invalid user|Failed password for(?:\s+invalid user)?)\s+(\S+)\s+from/;
  const AUTH_PORT  = /port\s+(\d+)/;
  const AUTH_METH  = /(?:ssh2|publickey|password|keyboard-interactive)/i;

  // The agent's own HTTP access log reaches syslog via journald, so
  // investigating an IP logs a request containing that IP — which would then
  // come back as "evidence" about it. Drop our own API traffic.
  const SELF_NOISE = /"(?:GET|POST|PUT|PATCH|DELETE)\s+\/api\//;

  for (const logPath of LOG_PATHS) {
    const isFail2ban = logPath === LOG_PATH;

    // Spans rotated/gzipped files: a ban from before the last rotation is
    // exactly the history an investigation is for.
    await readLines(logPath, isFail2ban ? HISTORY_MAX_BYTES : AUTH_MAX_BYTES, (line) => {
      if (!line.includes(ip)) return;  // fast pre-filter
      if (SELF_NOISE.test(line)) return;

      // Extract timestamp
      let timestamp = null;
      const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
      if (tsMatch) timestamp = tsMatch[1];
      // Auth log format: "May 12 09:14:22"
      const authTs = line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
      if (!timestamp && authTs) timestamp = authTs[1];

      if (timestamp) {
        if (!firstSeen) firstSeen = timestamp;
        lastSeen = timestamp;
      }

      if (isFail2ban) {
        let type = 'info';
        let jail = null;
        let detail = '';

        const banMatch   = line.match(F2B_BAN);
        const unbanMatch = line.match(F2B_UNBAN);
        const foundMatch = line.match(F2B_FOUND);

        if (banMatch) {
          type  = 'ban';
          jail  = banMatch[1];
          detail = `Banned in jail [${jail}]`;
          jailsHit[jail] = jailsHit[jail] || { bans: 0, unbans: 0, attempts: 0 };
          jailsHit[jail].bans++;
        } else if (unbanMatch) {
          type   = 'unban';
          jail   = unbanMatch[1];
          detail = `Unbanned from jail [${jail}]`;
          jailsHit[jail] = jailsHit[jail] || { bans: 0, unbans: 0, attempts: 0 };
          jailsHit[jail].unbans++;
        } else if (foundMatch) {
          type   = 'attempt';
          jail   = foundMatch[1];
          detail = `Trigger detected in jail [${jail}]`;
          jailsHit[jail] = jailsHit[jail] || { bans: 0, unbans: 0, attempts: 0 };
          jailsHit[jail].attempts++;
        } else {
          detail = line.replace(/^\S+\s+\S+\s+\[\d+\]:\s+\w+\s+/, '').trim();
        }

        timeline.push({ timestamp, type, source: 'fail2ban', jail, detail, raw: line });

      } else {
        // Auth/syslog line
        const userMatch = line.match(AUTH_USER);
        const portMatch = line.match(AUTH_PORT);
        const methMatch = line.match(AUTH_METH);

        if (userMatch) usernames.add(userMatch[1]);
        if (portMatch) ports.add(portMatch[1]);

        let detail = line.replace(/^\w+\s+\d+\s+\S+\s+\S+:\s+/, '').trim();
        // Truncate very long lines
        if (detail.length > 200) detail = detail.slice(0, 200) + '…';

        timeline.push({
          timestamp,
          type: line.toLowerCase().includes('failed') || line.toLowerCase().includes('invalid') ? 'attempt' : 'info',
          source: path.basename(logPath),
          jail: null,
          detail,
          raw: line,
          method: methMatch ? methMatch[0] : null,
        });
      }
    });
  }

  // Sort timeline by timestamp (oldest first)
  timeline.sort((a, b) => {
    if (!a.timestamp) return 1;
    if (!b.timestamp) return -1;
    return a.timestamp.localeCompare(b.timestamp);
  });

  const totalBans     = Object.values(jailsHit).reduce((s, j) => s + j.bans,     0);
  const totalAttempts = Object.values(jailsHit).reduce((s, j) => s + j.attempts, 0);
  const isRecurring   = totalBans > 1;

  return {
    ip,
    summary: {
      firstSeen,
      lastSeen,
      totalBans,
      totalAttempts,
      isRecurring,
      jailCount: Object.keys(jailsHit).length,
      triedUsernames: [...usernames].slice(0, 50),
      triedPorts:     [...ports].slice(0, 20),
    },
    jailsHit: Object.entries(jailsHit).map(([name, stats]) => ({ name, ...stats })),
    timeline: timeline.slice(-200), // cap at 200 events
  };
}

module.exports = {
  ping,
  getJails,
  getJailStatus,
  getAllJailStatuses,
  banIP,
  unbanIP,
  isIPBanned,
  getLogs,
  getGlobalConfig,
  getReports,
  getIPDetails,
  validateIP,
  validateJailName,
};
