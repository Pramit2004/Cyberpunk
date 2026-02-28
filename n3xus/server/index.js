const express = require('express');
const http = require('http');
const ws = require('ws');
const path = require('path');
const cors = require('cors');

const { incidents, ipLog, actLog } = require('./db');
const { lookupIP } = require('./geo');

const app = express();
const server = http.createServer(app);
const wss = new ws.WebSocketServer({ server });

const PORT = process.env.PORT || 3000;

app.set('trust proxy', true);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ── Broadcast ───────────────────────────────────────
function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === ws.WebSocket.OPEN) {
      client.send(msg);
    }
  });
}

// ── Helper to get real IP ───────────────────────────
function getIP(req) {
  let ip =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket.remoteAddress ||
    '';

  if (ip.startsWith('::ffff:')) {
    ip = ip.replace('::ffff:', '');
  }

  return ip;
}

// ── Visitor Logging ─────────────────────────────────
app.use(async (req, res, next) => {
  const ip = getIP(req);
  if (!ip) return next();

  try {
    const geo = await lookupIP(ip);
    if (!geo) return next();

    ipLog.add({
      ip: geo.ip,
      country: geo.country,
      city: geo.city,
      lat: geo.lat,
      lon: geo.lon,
      isp: geo.isp,
      threat: 0
    });

    actLog.add('info', `Request: ${req.method} ${req.path}`, geo.ip);

    broadcast({ type: 'visitor', data: geo });

  } catch (err) {
    console.error('Geo lookup failed:', err.message);
  }

  next();
});

// ── Attack Detection ────────────────────────────────
const suspiciousPatterns = [
  'union select',
  'or 1=1',
  '<script>',
  '../',
  'wp-admin',
  '.env',
  'etc/passwd'
];

app.use(async (req, res, next) => {
  const payload = (JSON.stringify(req.query) + JSON.stringify(req.body)).toLowerCase();

  for (const pattern of suspiciousPatterns) {
    if (payload.includes(pattern)) {

      const ip = getIP(req);
      const geo = await lookupIP(ip);

      actLog.add('alert', `Attack detected: ${pattern}`, ip);

      incidents.create({
        title: `Attack pattern: ${pattern}`,
        severity: 'high',
        status: 'open',
        ip: geo?.ip || ip,
        country: geo?.country || '',
        city: geo?.city || '',
        lat: geo?.lat || 0,
        lon: geo?.lon || 0,
        type: 'injection',
        notes: 'Auto-detected malicious payload'
      });

      broadcast({
        type: 'attack',
        data: { ip, pattern }
      });

      break;
    }
  }

  next();
});

// ── API ──────────────────────────────────────────────
app.get('/api/incidents', (req, res) => {
  res.json(incidents.all());
});

app.get('/api/logs', (req, res) => {
  res.json(actLog.recent(100));
});

app.get('/api/ips', (req, res) => {
  res.json(ipLog.recent(50));
});

app.get('/api/stats', (req, res) => {
  res.json({
    ...incidents.stats(),
    unique_ips: ipLog.unique().count,
    clients: wss.clients.size
  });
});

// ── WebSocket ───────────────────────────────────────
wss.on('connection', socket => {
  socket.send(JSON.stringify({
    type: 'init',
    data: {
      incidents: incidents.all(),
      logs: actLog.recent(50),
      ips: ipLog.recent(50),
      stats: incidents.stats()
    }
  }));
});

// ── Start ───────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`N3XUS running on port ${PORT}`);
});