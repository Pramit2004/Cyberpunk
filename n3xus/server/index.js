// index.js — N3XUS Server
// Express REST API + WebSocket live feed
const express  = require('express');
const http     = require('http');
const ws       = require('ws');
const path     = require('path');
const cors     = require('cors');

const { incidents, ipLog, actLog, watchedIPs } = require('./db');
const { lookupIP }        = require('./geo');
const { generateEvent, getStats } = require('./threats');

const app    = express();
const server = http.createServer(app);
const wss    = new ws.WebSocketServer({ server });

const PORT = process.env.PORT || 3000;

// ── Middleware ───────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ── WebSocket broadcast ──────────────────────────────
function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(client => {
    if(client.readyState === ws.WebSocket.OPEN) client.send(msg);
  });
}

wss.on('connection', (socket) => {
  console.log('[ws] Client connected. Total:', wss.clients.size);

  // Send initial snapshot
  socket.send(JSON.stringify({
    type: 'init',
    data: {
      incidents: incidents.all(),
      recentIPs: ipLog.recent(30),
      logs:      actLog.recent(30),
      stats:     incidents.stats(),
      watched:   watchedIPs.all(),
    }
  }));

  socket.on('close', () => console.log('[ws] Client disconnected'));
  socket.on('error', (e) => console.error('[ws] Error:', e.message));
});

// ── REST API ─────────────────────────────────────────

// Incidents
app.get('/api/incidents', (req, res) => {
  res.json(incidents.all());
});

app.post('/api/incidents', (req, res) => {
  try {
    const inc = incidents.create({
      title:    req.body.title    || 'Untitled Incident',
      severity: req.body.severity || 'medium',
      status:   req.body.status   || 'open',
      ip:       req.body.ip       || '',
      country:  req.body.country  || '',
      city:     req.body.city     || '',
      lat:      parseFloat(req.body.lat)  || 0,
      lon:      parseFloat(req.body.lon)  || 0,
      type:     req.body.type     || 'intrusion',
      notes:    req.body.notes    || '',
    });
    actLog.add('info', `Incident created: ${inc.title}`, inc.ip);
    broadcast({ type: 'incident_created', data: inc });
    res.json(inc);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/incidents/:id', (req, res) => {
  try {
    const allowed = ['title','severity','status','notes','type'];
    const updates = {};
    allowed.forEach(k => { if(req.body[k] !== undefined) updates[k] = req.body[k]; });
    const inc = incidents.update(req.params.id, updates);
    actLog.add('info', `Incident #${inc.id} updated: status=${inc.status}`);
    broadcast({ type: 'incident_updated', data: inc });
    res.json(inc);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/incidents/:id', (req, res) => {
  incidents.delete(req.params.id);
  broadcast({ type: 'incident_deleted', data: { id: parseInt(req.params.id) } });
  res.json({ ok: true });
});

// IP Lookup
app.get('/api/lookup/:ip', async (req, res) => {
  try {
    const result = await lookupIP(req.params.ip);
    ipLog.add({ ...result, threat: 0 });
    actLog.add('info', `Manual IP lookup: ${req.params.ip} → ${result.city}, ${result.country}`, req.params.ip);
    broadcast({ type: 'ip_lookup', data: result });
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Logs
app.get('/api/logs', (req, res) => {
  res.json(actLog.recent(100));
});

// Threat IPs
app.get('/api/threats', (req, res) => {
  res.json(ipLog.threats());
});

// Recent IPs
app.get('/api/ips', (req, res) => {
  res.json(ipLog.recent(50));
});

// Stats
app.get('/api/stats', (req, res) => {
  res.json({
    ...incidents.stats(),
    unique_ips: ipLog.unique().count,
    clients: wss.clients.size,
  });
});

// Watched IPs
app.get('/api/watched', (req, res) => res.json(watchedIPs.all()));
app.post('/api/watched', (req, res) => {
  watchedIPs.add(req.body.ip, req.body.label || '');
  res.json({ ok: true });
});
app.delete('/api/watched/:ip', (req, res) => {
  watchedIPs.remove(req.params.ip);
  res.json({ ok: true });
});

// Manual threat event trigger (for testing)
app.post('/api/trigger', async (req, res) => {
  const event = await generateEvent(broadcast);
  res.json(event?.data || { error: 'Failed' });
});

// ── Live threat feed (auto-generate events) ──────────
let threatInterval;
function startThreatFeed() {
  // Generate event every 8-20 seconds
  function scheduleNext() {
    const delay = 8000 + Math.random() * 12000;
    threatInterval = setTimeout(async () => {
      await generateEvent(broadcast);
      scheduleNext();
    }, delay);
  }
  scheduleNext();
  console.log('[threats] Live feed started');
}

// ── Start ─────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════╗
║   N3XUS CYBER INTELLIGENCE SYSTEM     ║
║   Server: http://localhost:${PORT}        ║
║   WebSocket: ws://localhost:${PORT}       ║
╚═══════════════════════════════════════╝
  `);
  startThreatFeed();
});

server.on('error', (e) => {
  if(e.code === 'EADDRINUSE') console.error(`[error] Port ${PORT} in use. Try PORT=3001 node server/index.js`);
  else console.error('[error]', e);
});
