const net = require('net');

const refang = (s) =>
  s.trim().replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)|\[dot\]/gi, '.').replace(/\[:\]/g, ':');

function classify(v) {
  if (/^https?:\/\/\S+$/i.test(v)) return 'url';
  if (net.isIP(v)) return 'ip';
  if (/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(v)) return 'hash';
  if (/^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$/i.test(v)) return 'domain';
  return null;
}

const isPrivate = (ip) =>
  /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(ip) || /^(::1|fc|fd|fe80)/i.test(ip);

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  // The key comes from the visitor's browser, is used for this one request and is never stored or logged.
  const key = String(req.headers['x-vt-key'] || '').trim();
  if (!/^[a-f0-9]{64}$/i.test(key))
    return res.status(401).json({ error: 'That does not look like a VirusTotal API key (64 characters).', badKey: true });

  const raw = String((req.body && req.body.indicator) || '');
  const value = refang(raw);
  const type = classify(value);

  // Nothing below here reaches VirusTotal, so invalid/private rows cost no quota.
  if (!type) return res.json({ status: 'invalid', value, queried: false });
  if (type === 'ip' && isPrivate(value)) return res.json({ status: 'private', value, type, queried: false });

  const path = {
    ip: `ip_addresses/${value}`,
    domain: `domains/${value.toLowerCase()}`,
    hash: `files/${value.toLowerCase()}`,
    url: `urls/${Buffer.from(value).toString('base64url')}`,
  }[type];

  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
      headers: { 'x-apikey': key },
      signal: AbortSignal.timeout(9000),
    });
    if (r.status === 404) return res.json({ status: 'notfound', value, type, queried: true });
    if (r.status === 429) return res.status(429).json({ error: 'VirusTotal rate limit hit' });
    if (r.status === 401 || r.status === 403) return res.status(401).json({ error: 'VirusTotal rejected that API key.', badKey: true });
    if (!r.ok) return res.status(502).json({ error: `VirusTotal returned HTTP ${r.status}` });
    const s = (await r.json()).data.attributes.last_analysis_stats || {};
    const total = Object.values(s).reduce((a, b) => a + b, 0);
    res.json({
      status: 'ok', value, type, queried: true,
      malicious: s.malicious || 0, suspicious: s.suspicious || 0, total,
      link: `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`,
    });
  } catch (e) {
    res.status(502).json({ error: 'VirusTotal request failed: ' + (e.message || e) });
  }
};
