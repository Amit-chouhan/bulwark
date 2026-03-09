const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { buildHealthUrl, normalizeRemoteOrigin } = require("../lib/remote-targets");

const AGENTS_FILE = path.join(__dirname, "..", "data", "agents.json");
const MASK = "****";

function loadAgents() {
  try { if (fs.existsSync(AGENTS_FILE)) return JSON.parse(fs.readFileSync(AGENTS_FILE, "utf8")); } catch {}
  return { agents: [] };
}

function saveAgents(data) {
  fs.mkdirSync(path.dirname(AGENTS_FILE), { recursive: true });
  fs.writeFileSync(AGENTS_FILE, JSON.stringify(data, null, 2), "utf8");
}

module.exports = function (app, ctx) {
  function allowPrivateTargets() {
    return String(process.env.BULWARK_ALLOW_PRIVATE_TARGETS || "").toLowerCase() === "true";
  }

  function normalizeAgentHost(host) {
    return normalizeRemoteOrigin(host, { allowPrivate: allowPrivateTargets() });
  }

  function maskAgent(agent) {
    return { ...agent, authKey: MASK + (agent.authKey || "").slice(-4) };
  }

  async function fetchAgentHealth(agent, timeoutMs) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers = { Accept: "application/json" };
      if (agent.authKey) headers.Authorization = `Bearer ${agent.authKey}`;
      return await fetch(buildHealthUrl(normalizeAgentHost(agent.host)), {
        signal: controller.signal,
        headers,
      });
    } finally {
      clearTimeout(timeout);
    }
  }

  app.get("/api/multi-server/agents", ctx.requireAdmin, (req, res) => {
    const data = loadAgents();
    res.json({ agents: data.agents.map(maskAgent) });
  });

  app.post("/api/multi-server/agents", ctx.requireAdmin, (req, res) => {
    const { name, host, authKey } = req.body;
    if (!name || !host) return res.status(400).json({ error: "name and host required" });

    let normalizedHost;
    try {
      normalizedHost = normalizeAgentHost(host);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    const data = loadAgents();
    const agent = {
      id: crypto.randomUUID(),
      name: String(name).trim().slice(0, 80),
      host: normalizedHost,
      authKey: authKey ? String(authKey).trim().slice(0, 256) : "",
      status: "unknown",
      created: new Date().toISOString(),
    };
    data.agents.push(agent);
    saveAgents(data);
    res.json({ success: true, agent: maskAgent(agent) });
  });

  app.delete("/api/multi-server/agents/:id", ctx.requireAdmin, (req, res) => {
    const data = loadAgents();
    data.agents = data.agents.filter(a => a.id !== req.params.id);
    saveAgents(data);
    res.json({ success: true });
  });

  app.get("/api/multi-server/agents/:id/health", ctx.requireAdmin, async (req, res) => {
    const data = loadAgents();
    const agent = data.agents.find(a => a.id === req.params.id);
    if (!agent) return res.status(404).json({ error: "Agent not found" });
    try {
      const start = Date.now();
      const r = await fetchAgentHealth(agent, 8000);
      const body = await r.json();
      agent.host = normalizeAgentHost(agent.host);
      agent.status = r.ok ? "healthy" : "unhealthy";
      agent.lastCheck = new Date().toISOString();
      agent.latency = Date.now() - start;
      saveAgents(data);
      res.json({ status: agent.status, latency: agent.latency, data: body });
    } catch (e) {
      agent.status = "unreachable";
      agent.lastCheck = new Date().toISOString();
      saveAgents(data);
      res.json({ status: "unreachable", error: e.message });
    }
  });

  app.get("/api/multi-server/overview", ctx.requireAdmin, async (req, res) => {
    const data = loadAgents();
    const results = [];
    for (const agent of data.agents) {
      try {
        const start = Date.now();
        const r = await fetchAgentHealth(agent, 5000);
        results.push({
          ...agent,
          authKey: undefined,
          status: r.ok ? "healthy" : "unhealthy",
          latency: Date.now() - start,
        });
      } catch (e) {
        results.push({ ...agent, authKey: undefined, status: "unreachable", latency: -1, error: e.message });
      }
    }
    res.json({ agents: results });
  });
};
