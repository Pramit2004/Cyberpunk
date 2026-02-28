// // threats.js — Live threat event engine
// const { lookupIP, randomPublicIP } = require('./geo');
// const { ipLog, actLog, incidents } = require('./db');

// const THREAT_TYPES = ['intrusion','malware','ddos','phishing','injection','exfil','recon','ransomware','c2-beacon','bruteforce'];
// const SEVERITIES   = ['low','medium','high','critical'];
// const SEV_WEIGHTS  = [0.25, 0.40, 0.25, 0.10]; // weighted random

// const EVENT_MESSAGES = {
//   intrusion:   (ip, city) => `Unauthorized access attempt from ${city} [${ip}]`,
//   malware:     (ip, city) => `Malware beacon detected — origin: ${city} [${ip}]`,
//   ddos:        (ip, city) => `DDoS SYN flood from ${city} — ${randInt(10,80)}k req/s`,
//   phishing:    (ip, city) => `Phishing email traced to ${city} [${ip}]`,
//   injection:   (ip, city) => `SQL/XSS injection attempt from ${ip} (${city})`,
//   exfil:       (ip, city) => `Data exfiltration attempt blocked — ${city} [${ip}]`,
//   recon:       (ip, city) => `Port scan detected from ${city} [${ip}]`,
//   ransomware:  (ip, city) => `Ransomware signature matched — ${city} [${ip}]`,
//   'c2-beacon': (ip, city) => `C2 command-and-control beacon: ${ip} (${city})`,
//   bruteforce:  (ip, city) => `Brute-force SSH/RDP from ${ip} (${city})`,
// };

// function weightedSeverity() {
//   const r = Math.random();
//   let acc = 0;
//   for(let i = 0; i < SEVERITIES.length; i++){
//     acc += SEV_WEIGHTS[i];
//     if(r < acc) return SEVERITIES[i];
//   }
//   return 'medium';
// }

// function randInt(min, max){ return Math.floor(Math.random()*(max-min+1))+min; }
// function randItem(arr){ return arr[Math.floor(Math.random()*arr.length)]; }

// // Generate a live threat event and broadcast to WS clients
// async function generateEvent(broadcast) {
//   try {
//     const ip       = randomPublicIP();
//     const type     = randItem(THREAT_TYPES);
//     const severity = weightedSeverity();
//     const geoData  = await lookupIP(ip);

//     const { country, city, lat, lon, isp } = geoData;
//     const msgFn = EVENT_MESSAGES[type] || EVENT_MESSAGES.intrusion;
//     const message = msgFn(ip, city);
//     const level = severity === 'critical' || severity === 'high' ? 'alert' :
//                   severity === 'medium' ? 'warn' : 'info';

//     // Store in DB
//     ipLog.add({ ip, country, city, lat, lon, isp, threat: level === 'alert' ? 1 : 0 });
//     actLog.add(level, message, ip);

//     // Auto-create incident for high/critical
//     let incident = null;
//     if(severity === 'critical' || (severity === 'high' && Math.random() > 0.5)){
//       incident = incidents.create({
//         title: message.slice(0, 80),
//         severity,
//         status: 'open',
//         ip, country, city, lat, lon, type,
//         notes: `Auto-detected. ISP: ${isp}`
//       });
//     }

//     const event = {
//       type: 'threat_event',
//       data: {
//         id:       Date.now(),
//         ip, type, severity, message, level,
//         country,  city, lat, lon, isp,
//         ts:       Math.floor(Date.now()/1000),
//         incident: incident ? incident.id : null,
//       }
//     };

//     if(broadcast) broadcast(event);
//     return event;

//   } catch(e) {
//     console.error('[threats] generateEvent error:', e.message);
//   }
// }

// // Stats snapshot for dashboard
// function getStats() {
//   const inc = incidents.stats();
//   const recent = ipLog.recent(10);
//   const logs = actLog.recent(20);
//   return { incidents: inc, recentIPs: recent, logs };
// }

// module.exports = { generateEvent, getStats, randItem, randInt };
