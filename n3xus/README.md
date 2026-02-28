# N3XUS // CYBER DEFENSE GRID

Real-time cybersecurity intelligence dashboard with live IP geolocation,
WebSocket threat feed, and incident management.

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Start the server
npm start

# 3. Open your browser
open http://localhost:3000
```

## What's Running

| Component | Description |
|-----------|-------------|
| Express server | REST API on port 3000 |
| WebSocket | Live threat push feed |
| SQLite DB | Incidents, IP logs, activity |
| ip-api.com | Free IP geolocation (no key needed) |
| Threat engine | Auto-generates events every 8-20s |

## API Endpoints

```
GET  /api/incidents         — All incidents
POST /api/incidents         — Create incident
PATCH /api/incidents/:id    — Update incident
DELETE /api/incidents/:id   — Delete incident

GET  /api/lookup/:ip        — Geolocate an IP address
GET  /api/logs              — Activity log (last 100)
GET  /api/threats           — Flagged threat IPs
GET  /api/stats             — Dashboard stats
POST /api/trigger           — Manually trigger a threat event (testing)

GET  /api/watched           — Watched IP list
POST /api/watched           — Add IP to watch list
DELETE /api/watched/:ip     — Remove from watch list
```

## WebSocket Events (ws://localhost:3000)

```json
{ "type": "init",             "data": { incidents, logs, stats } }
{ "type": "threat_event",     "data": { ip, type, severity, city, lat, lon, ... } }
{ "type": "incident_created", "data": { ...incident } }
{ "type": "incident_updated", "data": { ...incident } }
{ "type": "incident_deleted", "data": { id } }
{ "type": "ip_lookup",        "data": { ip, city, country, lat, lon, isp } }
```

## Rate Limits

ip-api.com (free tier): 45 requests/minute — the server respects this automatically.

## Customization

- Edit `server/threats.js` to change threat types and event frequency
- Edit `server/db.js` to modify the schema or seed data
- Edit `public/index.html` for frontend changes

## Tech Stack

- **Backend**: Node.js, Express, ws, better-sqlite3
- **Geolocation**: ip-api.com (free, no API key)
- **Frontend**: Vanilla JS, Canvas API
- **Database**: SQLite (file: n3xus.db)
