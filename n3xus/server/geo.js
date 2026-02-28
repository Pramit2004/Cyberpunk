const fetch = require('node-fetch');

const cache = new Map();
const CACHE_TTL = 1000 * 60 * 60;

async function lookupIP(ip) {
  if (!ip) return null;

  if (cache.has(ip)) {
    const entry = cache.get(ip);
    if (Date.now() - entry.ts < CACHE_TTL) return entry.data;
  }

  if (isPrivate(ip)) {
    return {
      ip,
      country: 'Internal',
      city: 'LAN',
      lat: 0,
      lon: 0,
      isp: 'Private',
      threat: false
    };
  }

  try {
    const res = await fetch(`http://ip-api.com/json/${ip}`);
    const data = await res.json();

    if (data.status !== 'success') throw new Error();

    const result = {
      ip: data.query,
      country: data.country,
      city: data.city,
      lat: data.lat,
      lon: data.lon,
      isp: data.isp,
      threat: false
    };

    cache.set(ip, { ts: Date.now(), data: result });
    return result;

  } catch {
    return {
      ip,
      country: 'Unknown',
      city: 'Unknown',
      lat: 0,
      lon: 0,
      isp: 'Unknown',
      threat: false
    };
  }
}

function isPrivate(ip) {
  return /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1|localhost)/i.test(ip);
}

module.exports = { lookupIP };