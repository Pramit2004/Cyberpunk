// db.js — SQLite database for incidents, targets, logs
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, '../n3xus.db'));

// ── Schema ──────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS incidents (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    title     TEXT NOT NULL,
    severity  TEXT DEFAULT 'medium',
    status    TEXT DEFAULT 'open',
    ip        TEXT,
    country   TEXT,
    city      TEXT,
    lat       REAL,
    lon       REAL,
    type      TEXT DEFAULT 'intrusion',
    notes     TEXT DEFAULT '',
    created   INTEGER DEFAULT (strftime('%s','now')),
    updated   INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS ip_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip        TEXT,
    country   TEXT,
    city      TEXT,
    lat       REAL,
    lon       REAL,
    isp       TEXT,
    threat    INTEGER DEFAULT 0,
    ts        INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    level     TEXT DEFAULT 'info',
    message   TEXT,
    ip        TEXT,
    ts        INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS watched_ips (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip        TEXT UNIQUE,
    label     TEXT,
    added     INTEGER DEFAULT (strftime('%s','now'))
  );
`);

// ── Incidents ────────────────────────────────────────
const incidents = {
  all: () => db.prepare(`SELECT * FROM incidents ORDER BY created DESC LIMIT 100`).all(),
  get: (id) => db.prepare(`SELECT * FROM incidents WHERE id = ?`).get(id),
  create: (data) => {
    const stmt = db.prepare(`
      INSERT INTO incidents (title, severity, status, ip, country, city, lat, lon, type, notes)
      VALUES (@title, @severity, @status, @ip, @country, @city, @lat, @lon, @type, @notes)
    `);
    const result = stmt.run(data);
    return incidents.get(result.lastInsertRowid);
  },
  update: (id, data) => {
    const fields = Object.keys(data).map(k => `${k} = @${k}`).join(', ');
    db.prepare(`UPDATE incidents SET ${fields}, updated = strftime('%s','now') WHERE id = @id`)
      .run({ ...data, id });
    return incidents.get(id);
  },
  delete: (id) => db.prepare(`DELETE FROM incidents WHERE id = ?`).run(id),
  stats: () => db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open,
      SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN created > strftime('%s','now') - 86400 THEN 1 ELSE 0 END) as last24h
    FROM incidents
  `).get()
};

// ── IP Log ───────────────────────────────────────────
const ipLog = {
  add: (data) => db.prepare(`
    INSERT INTO ip_log (ip, country, city, lat, lon, isp, threat)
    VALUES (@ip, @country, @city, @lat, @lon, @isp, @threat)
  `).run(data),
  recent: (n = 50) => db.prepare(`SELECT * FROM ip_log ORDER BY ts DESC LIMIT ?`).all(n),
  threats: () => db.prepare(`SELECT * FROM ip_log WHERE threat = 1 ORDER BY ts DESC LIMIT 30`).all(),
  unique: () => db.prepare(`SELECT COUNT(DISTINCT ip) as count FROM ip_log`).get()
};

// ── Activity Log ─────────────────────────────────────
const actLog = {
  add: (level, message, ip = '') => db.prepare(`
    INSERT INTO activity_log (level, message, ip) VALUES (?, ?, ?)
  `).run(level, message, ip),
  recent: (n = 60) => db.prepare(`SELECT * FROM activity_log ORDER BY ts DESC LIMIT ?`).all(n)
};

// ── Watched IPs ──────────────────────────────────────
const watchedIPs = {
  all: () => db.prepare(`SELECT * FROM watched_ips ORDER BY added DESC`).all(),
  add: (ip, label = '') => {
    try {
      db.prepare(`INSERT INTO watched_ips (ip, label) VALUES (?, ?)`).run(ip, label);
      return true;
    } catch(e) { return false; }
  },
  remove: (ip) => db.prepare(`DELETE FROM watched_ips WHERE ip = ?`).run(ip)
};

// ── Seed demo data ───────────────────────────────────
function seedIfEmpty() {
  const count = db.prepare(`SELECT COUNT(*) as n FROM incidents`).get();
  if(count.n > 0) return;

  const demo = [
    { title:'Brute-force SSH attempt', severity:'high', status:'open', ip:'185.220.101.45', country:'Germany', city:'Frankfurt', lat:50.11, lon:8.68, type:'intrusion', notes:'Multiple failed login attempts on port 22' },
    { title:'SQL Injection detected', severity:'critical', status:'investigating', ip:'103.21.244.0', country:'China', city:'Beijing', lat:39.90, lon:116.40, type:'injection', notes:'Attempted UNION SELECT on login endpoint' },
    { title:'Malware C2 Beacon', severity:'critical', status:'open', ip:'45.33.32.156', country:'United States', city:'Fremont', lat:37.54, lon:-121.96, type:'malware', notes:'Outbound beacon every 60s to known C2 host' },
    { title:'DDoS SYN flood', severity:'high', status:'mitigated', ip:'194.165.16.11', country:'Russia', city:'Moscow', lat:55.75, lon:37.61, type:'ddos', notes:'Rate limited at edge. 40k req/s peak' },
    { title:'Phishing email campaign', severity:'medium', status:'closed', ip:'91.108.4.0', country:'Netherlands', city:'Amsterdam', lat:52.37, lon:4.89, type:'phishing', notes:'Spoofed internal HR domain' },
    { title:'Unauthorized API access', severity:'medium', status:'open', ip:'202.14.43.0', country:'Japan', city:'Tokyo', lat:35.68, lon:139.69, type:'unauthorized', notes:'Valid token used from anomalous geo' },
  ];

  demo.forEach(d => incidents.create(d));

  const logs = [
    ['alert', 'INTRUSION DETECTED — SSH brute force Node-7-Alpha', '185.220.101.45'],
    ['warn',  'Anomalous outbound traffic detected — port 8443', '10.0.0.15'],
    ['info',  'Firewall rule #8821 updated by admin', ''],
    ['alert', 'SQL injection pattern blocked — login endpoint', '103.21.244.0'],
    ['info',  'Threat signature DB updated to v4.8.2', ''],
    ['warn',  'SSL certificate expiry — 3 days remaining', ''],
    ['info',  'VPN tunnel established — Agent-07', '10.10.0.1'],
    ['alert', 'C2 beacon detected — malware quarantined', '45.33.32.156'],
    ['info',  'Backup integrity verified OK', ''],
    ['warn',  'Unusual DNS queries from internal host', '192.168.1.42'],
  ];
  logs.forEach(([l, m, ip]) => actLog.add(l, m, ip));
}

seedIfEmpty();

module.exports = { incidents, ipLog, actLog, watchedIPs };
