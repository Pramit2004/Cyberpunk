// geo.js — IP Geolocation using ip-api.com (free, 45 req/min, no key needed)
const fetch = require('node-fetch');

const cache = new Map();
const CACHE_TTL = 1000 * 60 * 60; // 1 hour

// Known threat IPs (demo list — in production connect to AbuseIPDB)
const KNOWN_THREATS = new Set([
  '185.220.101.45', '103.21.244.0', '45.33.32.156',
  '194.165.16.11', '91.108.4.0', '202.14.43.0',
]);

async function lookupIP(ip) {

  if(cache.has(ip)) {
    const entry = cache.get(ip);
    if(Date.now() - entry.ts < CACHE_TTL) return entry.data;
  }

  if(isPrivate(ip)) {
    return { ip, country: 'Internal', city: 'LAN', lat: 0, lon: 0, isp: 'Private', threat: false, org: 'Internal Network', countryCode: 'XX' };
  }

  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,lat,lon,isp,org,query`);
    const data = await res.json();

    console.log("IP API RESPONSE:", data);

    if(data.status !== 'success') throw new Error('Lookup failed');

    const result = {
      ip:          data.query,
      country:     data.country || 'Unknown',
      countryCode: data.countryCode || '??',
      city:        data.city || 'Unknown',
      lat:         data.lat || 0,
      lon:         data.lon || 0,
      isp:         data.isp || 'Unknown',
      org:         data.org || '',
      threat:      KNOWN_THREATS.has(ip),
    };

    cache.set(ip, { ts: Date.now(), data: result });
    return result;

  } catch(e) {
    const fallback = {
      ip, country: 'Unknown', countryCode: '??',
      city: 'Unknown', lat: 0, lon: 0, isp: 'Unknown', org: '', threat: false
    };
    cache.set(ip, { ts: Date.now(), data: fallback });
    return fallback;
  }
}

// Batch lookup (respects rate limit)
async function lookupBatch(ips, onResult) {
  const unique = [...new Set(ips.filter(ip => ip && !isPrivate(ip)))];
  for(const ip of unique) {
    const result = await lookupIP(ip);
    if(onResult) onResult(result);
    await sleep(4000); // ip-api.com: 45 req/min = 1 req/1.33s
  }
}

function isPrivate(ip) {
  return /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1|localhost)/i.test(ip);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// Generate a realistic fake IP (for demo mode)
function randomPublicIP() {
  const pools = [
    () => `${rand(1,223)}.${rand(0,255)}.${rand(0,255)}.${rand(1,254)}`,
  ];
  let ip;
  do { ip = pools[0](); } while(isPrivate(ip));
  return ip;
}

function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

module.exports = { lookupIP, lookupBatch, isPrivate, randomPublicIP };
