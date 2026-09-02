/**
 * Tests for the log-derived half of the agent: getLogs, getReports and
 * getIPDetails.
 *
 * These read real files from a temp fixture directory rather than mocking `fs`,
 * because every bug this suite exists to prevent was about what is actually on
 * disk: logrotate having moved the history into fail2ban.log.1, an archive being
 * gzipped, a byte budget slicing a line in half. Mocking the filesystem would
 * have mocked away the bugs.
 *
 * No fail2ban daemon is involved — nothing here shells out to fail2ban-client.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

// The module reads its paths from the environment at require time, so this has
// to be set before the require below.
const FIXTURES = fs.mkdtempSync(path.join(os.tmpdir(), 'f2b-test-'));
const LOG = path.join(FIXTURES, 'fail2ban.log');
const AUTH = path.join(FIXTURES, 'auth.log');
process.env.FAIL2BAN_LOG = LOG;
process.env.AUTH_LOG_PATHS = AUTH;

const f2b = require('../src/fail2banClient');

test.after(() => fs.rmSync(FIXTURES, { recursive: true, force: true }));

// ─── Fixture helpers ──────────────────────────────────────────────────────

/** A fail2ban.log line. `event` is e.g. 'Ban 1.2.3.4' or 'Found 1.2.3.4'. */
function line(date, time, jail, event, level = 'NOTICE') {
  const logger = event.startsWith('Found') ? 'fail2ban.filter ' : 'fail2ban.actions';
  return `${date} ${time},123 ${logger}        [4242]: ${level}  [${jail}] ${event}`;
}

/** Write files into the fixture dir; `{ name: contents }`. Clears old ones. */
function writeLogs(files) {
  for (const name of fs.readdirSync(FIXTURES)) fs.rmSync(path.join(FIXTURES, name));
  for (const [name, contents] of Object.entries(files)) {
    const target = path.join(FIXTURES, name);
    if (name.endsWith('.gz')) fs.writeFileSync(target, zlib.gzipSync(contents));
    else fs.writeFileSync(target, contents);
  }
}

/** logrotate ordering is inferred from mtime, so fixtures must set it. */
function setMtime(name, isoish) {
  const t = new Date(isoish);
  fs.utimesSync(path.join(FIXTURES, name), t, t);
}

/**
 * 'YYYY-MM-DD' for N days before today — report assertions must not go stale.
 * LOCAL date parts, matching what fail2ban stamps its lines with. Using
 * toISOString() here would have agreed with the UTC bug it is meant to catch.
 */
function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  const p = x => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

// ─── Rotation: the bug that made every log-derived view read zero ─────────

test('getReports counts bans across the live log, .1 and a gzipped .2', async () => {
  writeLogs({
    'fail2ban.log':      line(daysAgo(0), '06:00:00', 'sshd',  'Ban 10.0.0.9') + '\n',
    'fail2ban.log.1':    line(daysAgo(1), '03:00:00', 'sshd',  'Ban 10.0.0.3') + '\n' +
                         line(daysAgo(1), '04:00:00', 'sshd',  'Unban 10.0.0.3') + '\n',
    'fail2ban.log.2.gz': line(daysAgo(2), '01:00:00', 'nginx', 'Ban 10.0.0.2') + '\n',
  });
  setMtime('fail2ban.log.2.gz', `${daysAgo(2)}T02:00:00Z`);
  setMtime('fail2ban.log.1', `${daysAgo(1)}T05:00:00Z`);

  const r = await f2b.getReports();

  assert.deepEqual(r.byJail, [{ name: 'sshd', bans: 2 }, { name: 'nginx', bans: 1 }],
    'bans from rotated and gzipped archives must be counted, sorted by volume');
  assert.equal(r.recentBans.length, 3, 'Unban lines are not bans');
  assert.equal(r.recentBans[0].ip, '10.0.0.9', 'recentBans is newest-first');
  assert.equal(r.recentBans.at(-1).ip, '10.0.0.2', 'oldest archive ends up last');

  const nonZero = r.dailyBans.filter(d => d.bans > 0).map(d => `${d.date}=${d.bans}`);
  assert.deepEqual(nonZero, [`${daysAgo(2)}=1`, `${daysAgo(1)}=1`, `${daysAgo(0)}=1`]);
});

test('getReports skips archives older than the 7-day window', async () => {
  writeLogs({
    'fail2ban.log':      line(daysAgo(0), '06:00:00', 'sshd', 'Ban 10.0.0.9') + '\n',
    'fail2ban.log.9.gz': line('2020-01-01', '01:00:00', 'ancient', 'Ban 10.0.0.1') + '\n',
  });
  setMtime('fail2ban.log.9.gz', '2020-01-01T02:00:00Z');

  const r = await f2b.getReports();
  assert.deepEqual(r.byJail, [{ name: 'sshd', bans: 1 }],
    'an archive untouched since before the window holds nothing in it — do not read it');
});

test('getReports zero-fills all seven days and stays chronological', async () => {
  writeLogs({ 'fail2ban.log': '' });
  const r = await f2b.getReports();

  assert.equal(r.dailyBans.length, 7);
  assert.equal(r.dailyBans.at(-1).date, daysAgo(0), 'today is last');
  assert.equal(r.dailyBans[0].date, daysAgo(6), 'the window opens 6 days back');
  assert.ok(r.dailyBans.every(d => d.bans === 0));
  assert.deepEqual(r.byJail, []);
  assert.deepEqual(r.recentBans, []);
});

test('getReports returns empty rather than throwing when the log is absent', async () => {
  writeLogs({});                                   // no fail2ban.log at all
  const r = await f2b.getReports();
  assert.deepEqual(r, { dailyBans: [], byJail: [], recentBans: [] });
});

test('getReports caps recentBans at the 50 NEWEST bans', async () => {
  const rows = [];
  for (let i = 0; i < 60; i++) {
    rows.push(line(daysAgo(0), `06:${String(i).padStart(2, '0')}:00`, 'sshd', `Ban 10.0.0.${i}`));
  }
  writeLogs({ 'fail2ban.log': rows.join('\n') + '\n' });

  const r = await f2b.getReports();
  assert.equal(r.recentBans.length, 50);
  assert.equal(r.recentBans[0].ip, '10.0.0.59', 'newest first, not the oldest 50');
  assert.equal(r.recentBans.at(-1).ip, '10.0.0.10');
});

test('getReports buckets days in the host timezone, not UTC', async () => {
  // The trend was keyed with toISOString(), i.e. UTC, while fail2ban stamps its
  // lines in local time. For most of the world, for part of every day, that put
  // today's bans in no bucket at all and they vanished from the chart.
  const original = process.env.TZ;
  try {
    // Kiritimati (UTC+14) and Midway (UTC-11) between them straddle every hour
    // of the UTC day, so one of them always disagrees with UTC about the date —
    // whatever time this suite happens to run.
    for (const tz of ['UTC', 'Pacific/Kiritimati', 'Pacific/Midway', 'Asia/Kolkata']) {
      process.env.TZ = tz;
      const today = daysAgo(0);                     // local date, in this tz
      writeLogs({ 'fail2ban.log': line(today, '00:30:00', 'sshd', 'Ban 10.0.0.9') + '\n' });

      const r = await f2b.getReports();
      assert.equal(r.dailyBans.at(-1).date, today, `${tz}: today must be the last bucket`);
      assert.equal(r.dailyBans.at(-1).bans, 1, `${tz}: today's ban must be counted`);
      assert.equal(r.dailyBans.reduce((s, d) => s + d.bans, 0), 1,
        `${tz}: counted exactly once, in the right bucket`);
    }
  } finally {
    if (original === undefined) delete process.env.TZ; else process.env.TZ = original;
  }
});

// ─── getLogs: filters and rotation ────────────────────────────────────────

test('getLogs level=BAN matches real fail2ban ban lines', async () => {
  writeLogs({
    'fail2ban.log':
      line(daysAgo(0), '06:00:00', 'sshd', 'Ban 10.0.0.9') + '\n' +
      line(daysAgo(0), '06:01:00', 'sshd', 'Unban 10.0.0.9') + '\n' +
      line(daysAgo(0), '06:02:00', 'sshd', 'Found 10.0.0.9', 'INFO') + '\n',
  });

  // fail2ban writes "NOTICE [sshd] Ban 1.2.3.4"; matching a "[ban]" tag found
  // nothing, ever, which made this filter silently useless.
  const bans = await f2b.getLogs('', 'BAN');
  assert.equal(bans.length, 1);
  assert.match(bans[0].message, /Ban 10\.0\.0\.9/);
  assert.doesNotMatch(bans[0].message, /Unban/, 'Unban must not satisfy the BAN filter');

  const unbans = await f2b.getLogs('', 'UNBAN');
  assert.equal(unbans.length, 1);
  assert.match(unbans[0].message, /Unban/);
});

test('getLogs parses fields, spans rotation, and returns newest-first', async () => {
  writeLogs({
    'fail2ban.log':   line(daysAgo(0), '06:00:00', 'sshd', 'Ban 10.0.0.9') + '\n',
    'fail2ban.log.1': line(daysAgo(1), '03:00:00', 'sshd', 'Ban 10.0.0.3') + '\n',
  });
  setMtime('fail2ban.log.1', `${daysAgo(1)}T05:00:00Z`);

  const logs = await f2b.getLogs();
  assert.equal(logs.length, 2, 'a freshly rotated log must not look like a quiet server');
  assert.equal(logs[0].timestamp, `${daysAgo(0)} 06:00:00`, 'newest first');
  assert.equal(logs[0].level, 'NOTICE');
  assert.equal(logs[0].pid, '4242');
  assert.match(logs[0].message, /\[sshd\] Ban 10\.0\.0\.9/);
});

test('getLogs text filter is case-insensitive and applied across rotations', async () => {
  writeLogs({
    'fail2ban.log':   line(daysAgo(0), '06:00:00', 'SSHD',  'Ban 10.0.0.9') + '\n',
    'fail2ban.log.1': line(daysAgo(1), '03:00:00', 'nginx', 'Ban 10.0.0.3') + '\n',
  });
  setMtime('fail2ban.log.1', `${daysAgo(1)}T05:00:00Z`);

  assert.equal((await f2b.getLogs('sshd')).length, 1);
  assert.equal((await f2b.getLogs('10.0.0.3')).length, 1, 'archives are searched too');
  assert.equal((await f2b.getLogs('no-such-text')).length, 0);
});

test('getLogs keeps unparseable lines rather than dropping them', async () => {
  writeLogs({ 'fail2ban.log': 'this is not a fail2ban formatted line\n\n' });
  const logs = await f2b.getLogs();
  assert.equal(logs.length, 1, 'blank lines skipped, unknown lines kept');
  assert.equal(logs[0].timestamp, null);
  assert.equal(logs[0].raw, 'this is not a fail2ban formatted line');
});

test('getLogs drops the fragment when the byte budget slices a line', async () => {
  const good = line(daysAgo(0), '06:00:00', 'sshd', 'Ban 10.0.0.9');
  writeLogs({ 'fail2ban.log': 'X'.repeat(500) + '\n' + good + '\n' });

  // Budget lands mid-way through the padding line, so the first line read is a
  // partial one and must not be reported as a log entry.
  const previous = process.env.LOG_MAX_BYTES;
  process.env.LOG_MAX_BYTES = String(good.length + 20);
  delete require.cache[require.resolve('../src/fail2banClient')];
  const fresh = require('../src/fail2banClient');
  try {
    const logs = await fresh.getLogs();
    assert.equal(logs.length, 1, 'only the whole line survives');
    assert.match(logs[0].raw, /Ban 10\.0\.0\.9/);
  } finally {
    if (previous === undefined) delete process.env.LOG_MAX_BYTES;
    else process.env.LOG_MAX_BYTES = previous;
    delete require.cache[require.resolve('../src/fail2banClient')];
  }
});

// ─── getIPDetails ─────────────────────────────────────────────────────────

test('getIPDetails finds a ban that happened before the last rotation', async () => {
  writeLogs({
    'fail2ban.log':   line(daysAgo(0), '06:00:00', 'sshd', 'Found 10.0.0.3', 'INFO') + '\n',
    'fail2ban.log.1': line(daysAgo(1), '03:00:00', 'sshd', 'Ban 10.0.0.3') + '\n' +
                      line(daysAgo(1), '04:00:00', 'sshd', 'Unban 10.0.0.3') + '\n',
  });
  setMtime('fail2ban.log.1', `${daysAgo(1)}T05:00:00Z`);

  const d = await f2b.getIPDetails('10.0.0.3');
  assert.equal(d.summary.totalBans, 1, 'a currently-banned IP must not report zero bans');
  assert.equal(d.summary.totalAttempts, 1);
  assert.equal(d.summary.jailCount, 1);
  assert.deepEqual(d.jailsHit, [{ name: 'sshd', bans: 1, unbans: 1, attempts: 1 }],
    'the ban and unban come from the archive, the Found from the live log');
  assert.equal(d.summary.isRecurring, false, 'one ban is not recurring');
});

test('getIPDetails flags a repeat offender as recurring', async () => {
  writeLogs({
    'fail2ban.log':
      line(daysAgo(1), '01:00:00', 'sshd',  'Ban 10.0.0.7') + '\n' +
      line(daysAgo(0), '02:00:00', 'nginx', 'Ban 10.0.0.7') + '\n',
  });

  const d = await f2b.getIPDetails('10.0.0.7');
  assert.equal(d.summary.totalBans, 2);
  assert.equal(d.summary.jailCount, 2, 'both jails are attributed');
  assert.equal(d.summary.isRecurring, true);
});

test('getIPDetails ignores the agent\'s own API traffic', async () => {
  // The agent's HTTP access log reaches syslog, so investigating an IP writes a
  // line containing that IP — which came back as "evidence" about it.
  writeLogs({
    'fail2ban.log': line(daysAgo(0), '06:00:00', 'sshd', 'Ban 10.0.0.5') + '\n',
    'auth.log':
      'Aug 17 06:00:01 host node[123]: 127.0.0.1 - - [17/Aug/2026:06:00:01 +0000] ' +
      '"GET /api/ip/10.0.0.5/details HTTP/1.1" 200 197 "-" "node"\n',
  });

  const d = await f2b.getIPDetails('10.0.0.5');
  assert.equal(d.timeline.length, 1, 'our own request log is not evidence about the IP');
  assert.equal(d.timeline[0].source, 'fail2ban');
});

test('getIPDetails harvests usernames and ports from the auth log', async () => {
  writeLogs({
    'fail2ban.log': line(daysAgo(0), '06:00:00', 'sshd', 'Ban 10.0.0.6') + '\n',
    'auth.log':
      'Aug 17 05:59:00 host sshd[1]: Invalid user admin from 10.0.0.6 port 40001\n' +
      'Aug 17 05:59:30 host sshd[1]: Failed password for root from 10.0.0.6 port 40002 ssh2\n' +
      'Aug 17 05:59:31 host sshd[1]: Failed password for invalid user oracle from 10.0.0.6 port 40003 ssh2\n' +
      'Aug 17 05:59:40 host sshd[1]: Failed password for root from 10.9.9.9 port 40004 ssh2\n',
  });

  const d = await f2b.getIPDetails('10.0.0.6');
  assert.deepEqual(d.summary.triedUsernames.sort(), ['admin', 'oracle', 'root']);
  assert.deepEqual(d.summary.triedPorts.sort(), ['40001', '40002', '40003'],
    'another IP\'s port must not be attributed to this one');
});

test('getIPDetails timeline is chronological across both log formats', async () => {
  // fail2ban writes "2026-08-25 10:00:00", syslog writes "Aug 25 09:00:00".
  // Compared as strings, digits sort before letters, so every auth-log event
  // landed after every fail2ban one however early it happened — and the
  // 200-event cap then kept the auth noise and sliced the bans away.
  const today = new Date();
  const mon = today.toLocaleString('en-US', { month: 'short' });
  const day = String(today.getDate()).padStart(2, ' ');

  writeLogs({
    'fail2ban.log':
      line(daysAgo(0), '09:30:00', 'sshd', 'Ban 10.0.0.8') + '\n' +
      line(daysAgo(0), '09:40:00', 'sshd', 'Unban 10.0.0.8') + '\n',
    'auth.log':
      `${mon} ${day} 09:00:00 host sshd[1]: Invalid user admin from 10.0.0.8 port 40001\n` +
      `${mon} ${day} 09:35:00 host sshd[1]: Failed password for root from 10.0.0.8 port 40002 ssh2\n`,
  });

  const d = await f2b.getIPDetails('10.0.0.8');
  assert.equal(d.timeline.length, 4);
  assert.deepEqual(d.timeline.map(e => e.timestamp.slice(-8)),
    ['09:00:00', '09:30:00', '09:35:00', '09:40:00'],
    'events interleave by real time, not by which file they came from');

  // The activity window must span the whole thing, not stop at whichever file
  // was read last.
  assert.match(d.summary.firstSeen, /09:00:00$/);
  assert.match(d.summary.lastSeen,  /09:40:00$/);
});

test('timestampToMs understands both log formats and rejects the rest', () => {
  const iso = f2b.timestampToMs('2026-08-25 10:00:00');
  assert.equal(iso, new Date(2026, 7, 25, 10, 0, 0).getTime(), 'fail2ban format, parsed as local');

  // Syslog carries no year: assume the current one...
  const now = new Date(2026, 7, 25, 12, 0, 0).getTime();
  assert.equal(f2b.timestampToMs('Aug 25 10:00:00', now),
    new Date(2026, 7, 25, 10, 0, 0).getTime());
  // ...unless that would date the event in the future, which is what a December
  // archive read in January looks like.
  const january = new Date(2026, 0, 3, 12, 0, 0).getTime();
  assert.equal(f2b.timestampToMs('Dec 28 23:00:00', january),
    new Date(2025, 11, 28, 23, 0, 0).getTime(), 'a December line in January is last year');

  for (const bad of [null, '', 'not a timestamp', 'Foo 25 10:00:00', '2026-08-25']) {
    assert.equal(f2b.timestampToMs(bad), null, `${JSON.stringify(bad)} is not a timestamp`);
  }
});

test('getIPDetails rejects anything that is not an IP', async () => {
  writeLogs({ 'fail2ban.log': '' });
  for (const bad of ['not-an-ip', '1.2.3.4; rm -rf /', '999.1.1.1', '']) {
    await assert.rejects(() => f2b.getIPDetails(bad), /Invalid IP address/,
      `must reject ${JSON.stringify(bad)}`);
  }
});

// ─── Validators — the guard in front of every fail2ban-client call ────────

test('validateIP accepts real addresses and CIDRs, rejects the rest', () => {
  for (const ok of ['1.2.3.4', '10.0.0.0/8', '255.255.255.255', '0.0.0.0/0',
                    '::1', '2001:db8::1', '2001:db8::/32', 'fe80::1/128',
                    ' 1.2.3.4 ' /* trimmed */]) {
    assert.equal(f2b.validateIP(ok), true, `${ok} should be valid`);
  }
  for (const bad of ['256.1.1.1', '1.2.3.4.5', '1.2.3', 'localhost', '1.2.3.4 && id',
                     '', null, undefined, '../../etc/passwd',
                     // A hand-rolled IPv6 regex used to wave these through.
                     ':::', '::::', '1:2:3:4:5:6:7:8:9', 'gggg::1', '2001:db8::/129',
                     '10.0.0.0/33', '10.0.0.0/8/8', '10.0.0.0/', '10.0.0.0/x']) {
    assert.equal(f2b.validateIP(bad), false, `${JSON.stringify(bad)} should be invalid`);
  }
});

test('validateJailName allows only jail-shaped names', () => {
  for (const ok of ['sshd', 'nginx-botsearch', 'my_jail', 'a']) {
    assert.equal(f2b.validateJailName(ok), true, `${ok} should be valid`);
  }
  for (const bad of ['', 'has space', 'semi;colon', '../etc', 'x'.repeat(65), 'quote"']) {
    assert.equal(f2b.validateJailName(bad), false, `${JSON.stringify(bad)} should be invalid`);
  }
});
