const { loadStore, saveStore, encrypt, decrypt, ensureApp } = require("../lib/envvars-store");

module.exports = function (app, ctx) {
  app.get("/api/envvars", ctx.requireAdmin, (req, res) => {
    const store = loadStore();
    const apps = Object.keys(store.apps).map(name => ({
      name, count: Object.keys(store.apps[name].vars || {}).length,
    }));
    res.json({ apps });
  });

  app.get("/api/envvars/:app", ctx.requireAdmin, (req, res) => {
    const store = loadStore();
    const appData = store.apps[req.params.app];
    if (!appData) return res.json({ vars: [] });
    const vars = Object.entries(appData.vars || {}).map(([key, entry]) => ({
      key, value: req.query.reveal === "true" ? decrypt(entry.value) : "••••••••",
      updated: entry.updated, description: entry.description,
    }));
    res.json({ vars });
  });

  app.post("/api/envvars/:app", ctx.requireRole('editor'), (req, res) => {
    const { key, value, description } = req.body;
    if (!key || value === undefined) return res.status(400).json({ error: "key and value required" });
    const store = loadStore();
    const appData = ensureApp(store, req.params.app);
    appData.vars[key] = { value: encrypt(value), description: description || "", updated: new Date().toISOString() };
    appData.history.push({ action: "set", key, by: req.user.user, ts: new Date().toISOString() });
    if (appData.history.length > 50) appData.history = appData.history.slice(-50);
    saveStore(store);
    res.json({ success: true });
  });

  app.delete("/api/envvars/:app/:key", ctx.requireRole('editor'), (req, res) => {
    const store = loadStore();
    const appData = store.apps[req.params.app];
    if (!appData || !appData.vars[req.params.key]) return res.status(404).json({ error: "Not found" });
    delete appData.vars[req.params.key];
    appData.history.push({ action: "delete", key: req.params.key, by: req.user.user, ts: new Date().toISOString() });
    saveStore(store);
    res.json({ success: true });
  });

  app.post("/api/envvars/:app/bulk", ctx.requireRole('editor'), (req, res) => {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: "content required" });
    const store = loadStore();
    const appData = ensureApp(store, req.params.app);
    let count = 0;
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const key = trimmed.substring(0, eq).trim();
      const value = trimmed.substring(eq + 1).trim().replace(/^["']|["']$/g, "");
      appData.vars[key] = { value: encrypt(value), updated: new Date().toISOString(), description: "" };
      count++;
    }
    appData.history.push({ action: "bulk_import", count, by: req.user.user, ts: new Date().toISOString() });
    saveStore(store);
    res.json({ success: true, imported: count });
  });

  app.get("/api/envvars/:app/history", ctx.requireAdmin, (req, res) => {
    const store = loadStore();
    const appData = store.apps[req.params.app];
    res.json({ history: appData?.history || [] });
  });
};
