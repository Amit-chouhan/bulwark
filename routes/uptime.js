const uptimeStore = require("../lib/uptime-store");

module.exports = function (app, ctx) {
  app.get("/api/uptime", ctx.requireAdmin, (req, res) => {
    const endpoints = uptimeStore.getEndpoints();
    const data = endpoints.map(ep => ({
      ...ep,
      uptime24h: uptimeStore.getUptimePercent(ep.id, 24),
      uptime7d: uptimeStore.getUptimePercent(ep.id, 168),
      uptime30d: uptimeStore.getUptimePercent(ep.id, 720),
      recentChecks: uptimeStore.getChecks(ep.id, 1).slice(-90), // last 90 checks for bar
      contentChanges: uptimeStore.getContentHistory(ep.id).length,
      lastContentChange: (uptimeStore.getContentHistory(ep.id).slice(-1)[0] || {}).ts || null,
    }));
    res.json({ endpoints: data });
  });

  app.get("/api/uptime/history/:id", ctx.requireAdmin, (req, res) => {
    const days = parseInt(req.query.days) || 30;
    const checks = uptimeStore.getChecks(req.params.id, days);
    res.json({ checks });
  });

  app.post("/api/uptime/endpoints", ctx.requireAdmin, (req, res) => {
    const { name, url, interval, expectedStatus, contentMonitor } = req.body;
    if (!name || !url) return res.status(400).json({ error: "name and url required" });
    const id = uptimeStore.addEndpoint({ name, url, interval, expectedStatus, contentMonitor });
    res.json({ success: true, id });
  });

  app.put("/api/uptime/endpoints/:id", ctx.requireAdmin, (req, res) => {
    const { name, url, interval, expectedStatus, contentMonitor } = req.body;
    const ok = uptimeStore.updateEndpoint(req.params.id, { name, url, interval, expectedStatus, contentMonitor });
    if (!ok) return res.status(404).json({ error: "Endpoint not found" });
    res.json({ success: true });
  });

  app.delete("/api/uptime/endpoints/:id", ctx.requireAdmin, (req, res) => {
    uptimeStore.removeEndpoint(req.params.id);
    res.json({ success: true });
  });

  // ── Content monitoring endpoints ──────────────────────────────────────

  app.get("/api/uptime/content/:id", ctx.requireAdmin, (req, res) => {
    const history = uptimeStore.getContentHistory(req.params.id);
    res.json({ history });
  });

  app.post("/api/uptime/content/:id/check", ctx.requireAdmin, async (req, res) => {
    try {
      const result = await uptimeStore.checkContent(req.params.id);
      if (result.error) return res.status(400).json(result);
      res.json({ success: true, check: result });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post("/api/uptime/scrape", ctx.requireAdmin, async (req, res) => {
    try {
      const { url, selector, userAgent } = req.body;
      if (!url) return res.status(400).json({ error: "url required" });
      const result = await uptimeStore.scrapeUrl(url, { selector, userAgent });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post("/api/uptime/content/ai-analyze", ctx.requireAdmin, async (req, res) => {
    try {
      const { endpointId, changes } = req.body;
      const ep = uptimeStore.getEndpoints().find(e => e.id === endpointId);
      if (!ep) return res.status(404).json({ error: "Endpoint not found" });

      const history = uptimeStore.getContentHistory(endpointId).slice(-10);
      const prompt = 'Analyze content changes detected on "' + ep.name + '" (' + ep.url + ').\n\n' +
        'Recent content changes:\n' + history.map(h =>
          '- ' + new Date(h.ts).toISOString() + ': hash ' + h.prevHash + ' → ' + h.hash +
          ', size ' + h.size + ' bytes' + (h.snippet ? ', snippet: "' + h.snippet.substring(0, 100) + '"' : '')
        ).join('\n') +
        '\n\nAre these changes significant? What might have changed? Any concerns (defacement, downtime residue, unexpected updates)? Be specific in 2-3 sentences. No markdown.';

      const response = await fetch('http://localhost:' + (process.env.PORT || 3001) + '/api/db/assistant/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: req.headers.cookie || '' },
        body: JSON.stringify({ message: prompt })
      });
      const data = await response.json();
      res.json({ analysis: data.response || data.error || 'Analysis unavailable' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
};
