const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DATA_FILE = path.join(__dirname, "..", "data", "uptime.json");
const CHECK_INTERVAL = 60000; // 60 seconds
const MAX_CONTENT_BODY = 1024 * 1024; // 1MB cap for content monitoring
const MAX_CONTENT_HISTORY = 200; // per endpoint

let config = { endpoints: [], checks: {}, contentHistory: {} };
let checkTimer = null;

function load() {
  try {
    if (fs.existsSync(DATA_FILE)) config = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch {}
  if (!config.endpoints) config.endpoints = [];
  if (!config.checks) config.checks = {};
  if (!config.contentHistory) config.contentHistory = {};
}

function save() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(config, null, 2), "utf8");
  } catch (e) { console.error("[UPTIME] save:", e.message); }
}

function addEndpoint(ep) {
  const id = ep.id || crypto.randomUUID();
  const endpoint = {
    id, name: ep.name, url: ep.url,
    interval: ep.interval || 60,
    expectedStatus: ep.expectedStatus || 200,
    created: new Date().toISOString()
  };
  if (ep.contentMonitor) endpoint.contentMonitor = ep.contentMonitor;
  config.endpoints.push(endpoint);
  config.checks[id] = [];
  save();
  return id;
}

function updateEndpoint(id, updates) {
  const ep = config.endpoints.find(e => e.id === id);
  if (!ep) return false;
  if (updates.name !== undefined) ep.name = updates.name;
  if (updates.url !== undefined) ep.url = updates.url;
  if (updates.interval !== undefined) ep.interval = updates.interval;
  if (updates.expectedStatus !== undefined) ep.expectedStatus = updates.expectedStatus;
  if (updates.contentMonitor !== undefined) ep.contentMonitor = updates.contentMonitor;
  save();
  return true;
}

function removeEndpoint(id) {
  config.endpoints = config.endpoints.filter(e => e.id !== id);
  delete config.checks[id];
  delete config.contentHistory[id];
  save();
}

function getEndpoints() { return config.endpoints; }

function getChecks(id, days = 30) {
  const since = Date.now() - days * 24 * 60 * 60 * 1000;
  return (config.checks[id] || []).filter(c => c.ts >= since);
}

function getUptimePercent(id, hours = 24) {
  const since = Date.now() - hours * 60 * 60 * 1000;
  const checks = (config.checks[id] || []).filter(c => c.ts >= since);
  if (checks.length === 0) return null;
  const up = checks.filter(c => c.ok).length;
  return Math.round((up / checks.length) * 10000) / 100;
}

function getContentHistory(id) {
  return config.contentHistory[id] || [];
}

// ── Content monitoring helpers ──────────────────────────────────────────

function hashContent(str) {
  return crypto.createHash('md5').update(str).digest('hex').substring(0, 16);
}

function stripHtml(html) {
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractBySelector(html, selector) {
  let pattern;
  if (selector.startsWith('#')) {
    const id = selector.substring(1);
    pattern = new RegExp('<[^>]+id=["\']' + escapeRegex(id) + '["\'][^>]*>([\\s\\S]*?)<\\/[^>]+>', 'i');
  } else if (selector.startsWith('.')) {
    const cls = selector.substring(1);
    pattern = new RegExp('<[^>]+class=["\'][^"\']*\\b' + escapeRegex(cls) + '\\b[^"\']*["\'][^>]*>([\\s\\S]*?)<\\/[^>]+>', 'i');
  } else {
    pattern = new RegExp('<' + escapeRegex(selector) + '[^>]*>([\\s\\S]*?)<\\/' + escapeRegex(selector) + '>', 'i');
  }
  const match = html.match(pattern);
  return match ? stripHtml(match[1]) : null;
}

function processContentCheck(ep, entry, body) {
  const cm = ep.contentMonitor;
  if (!cm || !cm.enabled) return;

  let content;
  if (cm.selector) {
    content = extractBySelector(body, cm.selector) || stripHtml(body);
  } else if (cm.mode === 'text') {
    content = stripHtml(body);
  } else {
    content = body;
  }

  entry.contentHash = hashContent(content);
  entry.contentSize = body.length;

  // Find previous check with content hash
  const prevChecks = config.checks[ep.id] || [];
  const lastWithContent = [...prevChecks].reverse().find(c => c.contentHash);
  if (lastWithContent) {
    entry.contentChanged = entry.contentHash !== lastWithContent.contentHash;
  } else {
    entry.contentChanged = false; // first check — baseline
  }

  // Keyword checks
  const lowerContent = content.toLowerCase();
  if (cm.keywords && cm.keywords.length) {
    entry.keywordHits = cm.keywords.map(kw => ({
      word: kw, found: lowerContent.includes(kw.toLowerCase())
    }));
  }
  if (cm.forbidden && cm.forbidden.length) {
    entry.forbiddenHits = cm.forbidden.map(kw => ({
      word: kw, found: lowerContent.includes(kw.toLowerCase())
    }));
  }

  // Store content change event
  if (entry.contentChanged) {
    if (!config.contentHistory[ep.id]) config.contentHistory[ep.id] = [];
    config.contentHistory[ep.id].push({
      ts: entry.ts,
      hash: entry.contentHash,
      prevHash: lastWithContent ? lastWithContent.contentHash : null,
      size: body.length,
      snippet: content.substring(0, 300)
    });
    if (config.contentHistory[ep.id].length > MAX_CONTENT_HISTORY) {
      config.contentHistory[ep.id] = config.contentHistory[ep.id].slice(-MAX_CONTENT_HISTORY);
    }

    // Notify on content change
    try {
      const { pushNotification } = require('../routes/notification-center');
      pushNotification('uptime', ep.name + ' content changed',
        'Content at ' + ep.url + ' has changed. Size: ' + body.length + ' bytes.', 'warning');
    } catch (e) {}
  }

  // Notify on keyword issues
  const missingKeywords = (entry.keywordHits || []).filter(k => !k.found);
  const foundForbidden = (entry.forbiddenHits || []).filter(k => k.found);
  if (missingKeywords.length || foundForbidden.length) {
    try {
      const { pushNotification } = require('../routes/notification-center');
      const issues = [];
      if (missingKeywords.length) issues.push('Missing: ' + missingKeywords.map(k => k.word).join(', '));
      if (foundForbidden.length) issues.push('Forbidden found: ' + foundForbidden.map(k => k.word).join(', '));
      pushNotification('uptime', ep.name + ' keyword alert',
        ep.url + ' — ' + issues.join('. '), 'critical');
    } catch (e) {}
  }
}

// Track last known state per endpoint for transition alerts
const lastState = {};

async function checkAll() {
  for (const ep of config.endpoints) {
    const entry = { ts: Date.now(), ok: false, latency: -1 };
    try {
      const start = Date.now();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      const res = await fetch(ep.url, { signal: controller.signal });
      clearTimeout(timeout);
      entry.latency = Date.now() - start;
      entry.status = res.status;
      entry.ok = res.status === (ep.expectedStatus || 200);

      // Content monitoring — read body when enabled and response is OK
      if (ep.contentMonitor && ep.contentMonitor.enabled && entry.ok) {
        try {
          const body = await res.text();
          const capped = body.length > MAX_CONTENT_BODY ? body.substring(0, MAX_CONTENT_BODY) : body;
          processContentCheck(ep, entry, capped);
        } catch (e) {
          entry.contentError = e.message;
        }
      }
    } catch (e) {
      entry.error = e.message;
    }
    if (!config.checks[ep.id]) config.checks[ep.id] = [];
    config.checks[ep.id].push(entry);
    // Keep 30 days (1 check/min = 43200 entries max)
    if (config.checks[ep.id].length > 43200) config.checks[ep.id] = config.checks[ep.id].slice(-43200);

    // Notify on state transitions (up→down or down→up)
    const wasOk = lastState[ep.id];
    if (wasOk !== undefined && wasOk !== entry.ok) {
      try {
        const { pushNotification } = require('../routes/notification-center');
        if (!entry.ok) {
          pushNotification('uptime', ep.name + ' is DOWN', 'Endpoint ' + ep.url + ' returned ' + (entry.status || 'error') + (entry.error ? ': ' + entry.error : '') + '. Latency: ' + entry.latency + 'ms', 'critical');
        } else {
          pushNotification('uptime', ep.name + ' is back UP', 'Endpoint ' + ep.url + ' recovered. Status: ' + entry.status + ', Latency: ' + entry.latency + 'ms', 'info');
        }
      } catch (e) { console.error('[UPTIME] notify error:', e.message); }
    }
    lastState[ep.id] = entry.ok;
  }
  save();
}

// One-off content check for a specific endpoint (manual trigger)
async function checkContent(id) {
  const ep = config.endpoints.find(e => e.id === id);
  if (!ep) return { error: 'Endpoint not found' };
  if (!ep.contentMonitor || !ep.contentMonitor.enabled) return { error: 'Content monitoring not enabled' };

  const entry = { ts: Date.now(), ok: false, latency: -1 };
  try {
    const start = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    const res = await fetch(ep.url, { signal: controller.signal });
    clearTimeout(timeout);
    entry.latency = Date.now() - start;
    entry.status = res.status;
    entry.ok = res.status === (ep.expectedStatus || 200);

    if (entry.ok) {
      const body = await res.text();
      const capped = body.length > MAX_CONTENT_BODY ? body.substring(0, MAX_CONTENT_BODY) : body;
      processContentCheck(ep, entry, capped);
    }
  } catch (e) {
    entry.error = e.message;
  }

  // Store the check result
  if (!config.checks[ep.id]) config.checks[ep.id] = [];
  config.checks[ep.id].push(entry);
  if (config.checks[ep.id].length > 43200) config.checks[ep.id] = config.checks[ep.id].slice(-43200);
  save();

  return entry;
}

// Scrape a URL and return structured content (for MCP tool / AI)
async function scrapeUrl(url, opts = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  const headers = { 'User-Agent': 'Bulwark/2.1 Monitor' };
  if (opts.userAgent) headers['User-Agent'] = opts.userAgent;

  const res = await fetch(url, { signal: controller.signal, headers });
  clearTimeout(timeout);

  const body = await res.text();
  const capped = body.length > MAX_CONTENT_BODY ? body.substring(0, MAX_CONTENT_BODY) : body;
  const textContent = stripHtml(capped);
  const hash = hashContent(capped);

  const result = {
    url,
    status: res.status,
    contentType: res.headers.get('content-type') || '',
    server: res.headers.get('server') || '',
    contentLength: body.length,
    contentHash: hash,
    textContent: opts.selector ? (extractBySelector(capped, opts.selector) || textContent) : textContent,
    title: (capped.match(/<title[^>]*>([^<]*)<\/title>/i) || [])[1] || '',
    metaDescription: (capped.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i) || [])[1] || '',
    links: (capped.match(/href=["']([^"']+)["']/gi) || []).slice(0, 50).map(m => m.replace(/href=["']|["']/gi, '')),
    headers: {
      server: res.headers.get('server') || '',
      contentType: res.headers.get('content-type') || '',
      cacheControl: res.headers.get('cache-control') || '',
      lastModified: res.headers.get('last-modified') || '',
      xPoweredBy: res.headers.get('x-powered-by') || '',
    }
  };

  // Truncate text for AI consumption
  if (result.textContent.length > 5000) {
    result.textContent = result.textContent.substring(0, 5000) + '...[truncated]';
  }

  return result;
}

function start() {
  load();
  checkAll();
  checkTimer = setInterval(checkAll, CHECK_INTERVAL);
}

function stop() {
  if (checkTimer) clearInterval(checkTimer);
}

module.exports = {
  start, stop, load, save,
  addEndpoint, updateEndpoint, removeEndpoint,
  getEndpoints, getChecks, getUptimePercent,
  getContentHistory, checkContent, scrapeUrl,
  checkAll
};
