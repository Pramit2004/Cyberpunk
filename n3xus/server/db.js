// db.js — SQLite database (production mode, no seed)

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
`);

// ── Incidents ────────────────────────────────────────
const incidents = {
  all: () => db.prepare(`SELECT * FROM incidents ORDER BY created DESC LIMIT 100`).all(),
  create: (data) => {
    const stmt = db.prepare(`
      INSERT INTO incidents (title, severity, status, ip, country, city, lat, lon, type, notes)
      VALUES (@title, @severity, @status, @ip, @country, @city, @lat, @lon, @type, @notes)
    `);
    const result = stmt.run(data);
    return db.prepare(`SELECT * FROM incidents WHERE id = ?`).get(result.lastInsertRowid);
  },
  stats: () => db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open,
      SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high
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
  unique: () => db.prepare(`SELECT COUNT(DISTINCT ip) as count FROM ip_log`).get()
};

// ── Activity Log ─────────────────────────────────────
const actLog = {
  add: (level, message, ip = '') => db.prepare(`
    INSERT INTO activity_log (level, message, ip) VALUES (?, ?, ?)
  `).run(level, message, ip),
  recent: (n = 60) => db.prepare(`SELECT * FROM activity_log ORDER BY ts DESC LIMIT ?`).all(n)
};

module.exports = { incidents, ipLog, actLog };