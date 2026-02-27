#!/usr/bin/env node
// =============================================================================
// Chester Dev Monitor — Standalone server control panel for dev ticket pipeline
// Runs on port 3001, completely separate from admin app
//
// Usage:
//   cd dev-monitor && npm install && npm start
//   pm2 start server.js --name "dev-monitor"
//
// Access: http://localhost:3001 or https://dev.autopilotaitech.com:3001
// =============================================================================

const express = require("express");
const http = require("http");
const crypto = require("crypto");
const { Server: SocketServer } = require("socket.io");
const { Pool } = require("pg");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

// ── Config ───────────────────────────────────────────────────────────────────
const PORT = process.env.MONITOR_PORT || 3001;
const DB_URL = process.env.DATABASE_URL || "";
const REPO_DIR = process.env.REPO_DIR || path.resolve(__dirname, "../admin");
const VPS_HOST = process.env.VPS_HOST || "https://admin.autopilotaitech.com";
const AUTH_USER = process.env.MONITOR_USER || "admin";
const AUTH_PASS = process.env.MONITOR_PASS || "";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

// ── Session Store ────────────────────────────────────────────────────────────
const sessions = new Map(); // token -> { user, created, expires }
const SESSION_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours

function createSession(user) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { user, created: Date.now(), expires: Date.now() + SESSION_MAX_AGE });
  return token;
}

function validateSession(token) {
  if (!token) return false;
  const session = sessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expires) {
    sessions.delete(token);
    return false;
  }
  return true;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(";").forEach((c) => {
    const [key, ...val] = c.trim().split("=");
    if (key) cookies[key] = val.join("=");
  });
  return cookies;
}

// ── Database ─────────────────────────────────────────────────────────────────
let pool = null;
if (DB_URL) {
  pool = new Pool({ connectionString: DB_URL, ssl: { rejectUnauthorized: false } });
}

async function dbQuery(sql, params = []) {
  if (!pool) return [];
  try {
    const res = await pool.query(sql, params);
    return res.rows;
  } catch (e) {
    console.error("[DB]", e.message);
    return [];
  }
}

// ── Express App ──────────────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
app.set("trust proxy", 1); // Trust Cloudflare Tunnel proxy
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Authentication ───────────────────────────────────────────────────────────

// Rate limiting for login
const loginAttempts = new Map(); // ip -> { count, firstAttempt }
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW = 15 * 60 * 1000; // 15 minutes

function checkRateLimit(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry) return true;
  if (Date.now() - entry.firstAttempt > LOGIN_WINDOW) {
    loginAttempts.delete(ip);
    return true;
  }
  return entry.count < MAX_LOGIN_ATTEMPTS;
}

function recordFailedLogin(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry) {
    loginAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
  } else {
    entry.count++;
  }
}

// Login page (served without auth)
app.get("/login", (req, res) => {
  const error = req.query.error ? '<div class="error">Invalid credentials</div>' : "";
  const locked = req.query.locked ? '<div class="error">Too many attempts. Try again in 15 minutes.</div>' : "";
  res.send(getLoginHTML(error || locked));
});

// Login handler
app.post("/login", (req, res) => {
  const ip = req.ip || req.socket.remoteAddress;
  if (!checkRateLimit(ip)) {
    console.log(`[AUTH] Rate limited: ${ip}`);
    return res.redirect("/login?locked=1");
  }

  const { username, password } = req.body;
  if (!AUTH_PASS) {
    return res.redirect("/login?error=1");
  }
  if (username === AUTH_USER && password === AUTH_PASS) {
    loginAttempts.delete(ip); // Clear on success
    const token = createSession(username);
    const secure = req.secure || req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
    res.setHeader("Set-Cookie", `monitor_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MAX_AGE / 1000}${secure}`);
    return res.redirect("/");
  }
  recordFailedLogin(ip);
  console.log(`[AUTH] Failed login attempt for user: ${username} from ${ip}`);
  res.redirect("/login?error=1");
});

// Logout
app.get("/logout", (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.monitor_session) sessions.delete(cookies.monitor_session);
  res.setHeader("Set-Cookie", "monitor_session=; Path=/; HttpOnly; Max-Age=0");
  res.redirect("/login");
});

// Health endpoint — always public (for external monitoring)
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), db: !!pool, ts: Date.now() });
});

// Auth middleware — protect everything else
function requireAuth(req, res, next) {
  // Skip auth if no password is set (local dev)
  if (!AUTH_PASS) return next();

  const cookies = parseCookies(req.headers.cookie);
  if (validateSession(cookies.monitor_session)) return next();

  // Check for Bearer token in header (API access)
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ") && validateSession(authHeader.slice(7))) return next();

  if (req.path.startsWith("/api/")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  res.redirect("/login");
}

app.use(requireAuth);

// Static files — served after auth middleware
app.use(express.static(path.join(__dirname, "public")));

// ── Socket.IO ────────────────────────────────────────────────────────────────
const io = new SocketServer(server, {
  cors: { origin: false }, // No CORS — same-origin only
});

// Socket.IO auth middleware
io.use((socket, next) => {
  // Skip auth if no password set
  if (!AUTH_PASS) return next();

  const cookies = parseCookies(socket.handshake.headers.cookie);
  if (validateSession(cookies.monitor_session)) return next();

  // Check auth query param (for programmatic access)
  if (socket.handshake.auth?.token && validateSession(socket.handshake.auth.token)) return next();

  next(new Error("Unauthorized"));
});

// Track active Claude processes
let activeClaudeProc = null;
// Track PTY sessions per socket
const ptyMap = new Map();

// Try to load node-pty (may not compile on Windows easily)
let pty = null;
try {
  pty = require("node-pty");
} catch {
  console.warn("[WARN] node-pty not available — terminal will be disabled");
}

io.on("connection", (socket) => {
  console.log(`[IO] Client connected: ${socket.id}`);

  // Send initial state
  sendInitialState(socket);

  // Terminal input
  socket.on("terminal_input", (data) => {
    const term = ptyMap.get(socket.id);
    if (term) term.write(data);
  });

  // Terminal resize
  socket.on("terminal_resize", ({ cols, rows }) => {
    const term = ptyMap.get(socket.id);
    if (term) {
      try { term.resize(cols, rows); } catch {}
    }
  });

  // Start terminal session
  socket.on("terminal_start", () => {
    if (!pty) {
      socket.emit("terminal_output", "\r\n[ERROR] node-pty not available on this platform.\r\nInstall on Linux: npm rebuild node-pty\r\n");
      return;
    }
    // Kill existing PTY for this socket
    const existing = ptyMap.get(socket.id);
    if (existing) { try { existing.kill(); } catch {} }

    const shell = os.platform() === "win32" ? "powershell.exe" : "bash";
    const term = pty.spawn(shell, [], {
      name: "xterm-256color",
      cols: 120,
      rows: 30,
      cwd: REPO_DIR,
      env: { ...process.env, TERM: "xterm-256color" },
    });

    term.onData((data) => {
      socket.emit("terminal_output", data);
    });

    term.onExit(() => {
      ptyMap.delete(socket.id);
      socket.emit("terminal_output", "\r\n[Session ended]\r\n");
    });

    ptyMap.set(socket.id, term);
  });

  // Claude CLI
  socket.on("claude_run", ({ prompt }) => {
    if (!prompt) return;
    runClaude(prompt);
  });

  socket.on("disconnect", () => {
    const term = ptyMap.get(socket.id);
    if (term) { try { term.kill(); } catch {} }
    ptyMap.delete(socket.id);
    console.log(`[IO] Client disconnected: ${socket.id}`);
  });
});

async function sendInitialState(socket) {
  const [sys, tickets, activity, procs] = await Promise.all([
    getSystemInfo(),
    getTicketSummary(),
    getRecentActivity(),
    getProcessList(),
  ]);
  socket.emit("init", { system: sys, tickets, activity, processes: procs });
}

// ── System Info ──────────────────────────────────────────────────────────────
function getSystemInfo() {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const uptime = os.uptime();
  const loadAvg = os.loadavg();

  // Calculate CPU usage from idle time
  let totalIdle = 0, totalTick = 0;
  for (const cpu of cpus) {
    for (const type in cpu.times) totalTick += cpu.times[type];
    totalIdle += cpu.times.idle;
  }
  const cpuPct = Math.round(100 - (totalIdle / totalTick) * 100);

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    cpuCount: cpus.length,
    cpuModel: cpus[0]?.model || "unknown",
    cpuPct,
    totalMemMB: Math.round(totalMem / 1024 / 1024),
    freeMemMB: Math.round(freeMem / 1024 / 1024),
    usedMemMB: Math.round((totalMem - freeMem) / 1024 / 1024),
    usedMemPct: Math.round(((totalMem - freeMem) / totalMem) * 100),
    uptimeHours: Math.round(uptime / 3600),
    uptimeSecs: Math.round(uptime),
    loadAvg: loadAvg.map((l) => l.toFixed(2)),
    nodeVersion: process.version,
  };
}

// ── Ticket Pipeline ──────────────────────────────────────────────────────────
async function getTicketSummary() {
  const summary = await dbQuery(`
    SELECT fix_status, COUNT(*) as count
    FROM support_tickets
    WHERE fix_status IS NOT NULL
    GROUP BY fix_status
    ORDER BY fix_status
  `);
  const tickets = await dbQuery(`
    SELECT id, subject, issue_type, issue_description, priority, fix_status,
           fix_branch, fix_notes, source, created_at, updated_at,
           target_env, status
    FROM support_tickets
    WHERE target_env = 'dev' OR fix_status IS NOT NULL
    ORDER BY
      CASE fix_status
        WHEN 'pending' THEN 1
        WHEN 'analyzing' THEN 2
        WHEN 'fixing' THEN 3
        WHEN 'testing' THEN 4
        WHEN 'awaiting_approval' THEN 5
        WHEN 'approved' THEN 6
        WHEN 'deployed' THEN 7
        ELSE 8
      END,
      updated_at DESC
    LIMIT 50
  `);
  return { summary, tickets };
}

async function getRecentActivity() {
  return await dbQuery(`
    SELECT id, activity_type, description, created_at, metadata
    FROM chester_activity
    ORDER BY created_at DESC
    LIMIT 30
  `);
}

// ── Process List ─────────────────────────────────────────────────────────────
async function getProcessList() {
  try {
    const result = await execCommand("pm2 jlist");
    const procs = JSON.parse(result.stdout || "[]");
    return procs.map((p) => ({
      name: p.name,
      pm_id: p.pm_id,
      status: p.pm2_env?.status,
      cpu: p.monit?.cpu,
      memory: Math.round((p.monit?.memory || 0) / 1024 / 1024),
      uptime: p.pm2_env?.pm_uptime,
      restarts: p.pm2_env?.restart_time,
      pid: p.pid,
    }));
  } catch {
    return [];
  }
}

// ── Server Health ────────────────────────────────────────────────────────────
async function getServerHealth() {
  const servers = [];

  // Local (this server)
  servers.push({
    name: "AWS Dev Server",
    host: "localhost",
    provider: "aws",
    status: "healthy",
    latency: 0,
    system: getSystemInfo(),
  });

  // VPS Production
  try {
    const start = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`${VPS_HOST}/api/health`, { signal: controller.signal });
    clearTimeout(timeout);
    const data = await res.json();
    servers.push({
      name: "VPS Production",
      host: VPS_HOST,
      provider: "vps",
      status: res.ok ? "healthy" : "unhealthy",
      latency: Date.now() - start,
      commit: data.commit,
      db: data.db,
    });
  } catch (e) {
    servers.push({
      name: "VPS Production",
      host: VPS_HOST,
      provider: "vps",
      status: "unreachable",
      latency: -1,
      error: e.message,
    });
  }

  // Fly.io + other cloud_endpoints from DB
  const endpoints = await dbQuery(`
    SELECT id, name, host, provider, metadata
    FROM cloud_endpoints
    WHERE status = 'active' AND provider NOT IN ('vps', 'aws')
  `);

  for (const ep of endpoints) {
    try {
      const url = ep.host.startsWith("http") ? ep.host : `https://${ep.host}`;
      const start = Date.now();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(`${url}/api/health`, { signal: controller.signal });
      clearTimeout(timeout);
      servers.push({
        name: ep.name,
        host: ep.host,
        provider: ep.provider,
        status: res.ok ? "healthy" : "unhealthy",
        latency: Date.now() - start,
      });
    } catch (e) {
      servers.push({
        name: ep.name,
        host: ep.host,
        provider: ep.provider,
        status: "unreachable",
        latency: -1,
        error: e.message,
      });
    }
  }

  return servers;
}

// ── Claude CLI ───────────────────────────────────────────────────────────────
function runClaude(prompt) {
  if (activeClaudeProc) {
    io.emit("claude_output", "\r\n[ERROR] Claude is already running. Wait for it to finish.\r\n");
    return;
  }

  io.emit("claude_output", `\r\n[STARTING] claude --print "${prompt.substring(0, 80)}..."\r\n\r\n`);

  const child = spawn("claude", ["--print", prompt], {
    cwd: REPO_DIR,
    env: { ...process.env },
    shell: true,
  });

  activeClaudeProc = child;
  let output = "";

  child.stdout.on("data", (data) => {
    const text = data.toString();
    output += text;
    io.emit("claude_output", text);
  });

  child.stderr.on("data", (data) => {
    const text = data.toString();
    output += text;
    io.emit("claude_output", text);
  });

  child.on("close", (code) => {
    activeClaudeProc = null;
    io.emit("claude_done", { code, output, prompt });

    // Log to DB
    dbQuery(
      `INSERT INTO chester_activity (activity_type, description, metadata)
       VALUES ($1, $2, $3)`,
      ["claude_cli", `Claude CLI: ${prompt.substring(0, 100)}`, JSON.stringify({ code, prompt, output_length: output.length })]
    ).catch(() => {});
  });

  child.on("error", (err) => {
    activeClaudeProc = null;
    io.emit("claude_output", `\r\n[ERROR] ${err.message}\r\n`);
    io.emit("claude_done", { code: 1, output: err.message, prompt });
  });
}

// ── API Routes ───────────────────────────────────────────────────────────────
// (Health endpoint is above the auth middleware — always public)

// System metrics
app.get("/api/system", (req, res) => {
  res.json(getSystemInfo());
});

// Tickets
app.get("/api/tickets", async (req, res) => {
  res.json(await getTicketSummary());
});

// Activity log
app.get("/api/activity", async (req, res) => {
  res.json({ activity: await getRecentActivity() });
});

// PM2 process list
app.get("/api/processes", async (req, res) => {
  res.json({ processes: await getProcessList() });
});

// Git status
app.get("/api/git", async (req, res) => {
  try {
    const [branch, log, status, remotes] = await Promise.all([
      execCommand("git branch --show-current", { cwd: REPO_DIR }),
      execCommand("git log --oneline -20", { cwd: REPO_DIR }),
      execCommand("git status --short", { cwd: REPO_DIR }),
      execCommand("git remote -v", { cwd: REPO_DIR }),
    ]);
    res.json({
      branch: branch.stdout.trim(),
      commits: log.stdout.trim().split("\n").filter(Boolean),
      status: status.stdout.trim(),
      remotes: remotes.stdout.trim(),
    });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Server health
app.get("/api/servers", async (req, res) => {
  res.json({ servers: await getServerHealth() });
});

// Logs for a PM2 service
app.get("/api/logs/:service", async (req, res) => {
  const { service } = req.params;
  // Sanitize service name — alphanumeric + hyphens only
  if (!/^[a-zA-Z0-9_-]+$/.test(service)) {
    return res.status(400).json({ error: "Invalid service name" });
  }
  const lines = parseInt(req.query.lines, 10) || 100;
  const safeLines = Math.min(Math.max(lines, 1), 500);
  try {
    const result = await execCommand(
      `pm2 logs ${service} --nostream --lines ${safeLines} 2>&1 || echo 'no logs'`,
      { timeout: 10000 }
    );
    res.json({ lines: result.stdout.split("\n") });
  } catch {
    res.json({ lines: ["No logs available for " + service] });
  }
});

// Run terminal command (sandboxed)
app.post("/api/exec", async (req, res) => {
  const { command } = req.body;
  if (!command) return res.status(400).json({ error: "command required" });

  const allowed = [
    "pm2", "git", "docker", "node", "npm", "curl", "ls", "cat",
    "head", "tail", "grep", "df", "free", "uptime", "whoami", "pwd",
    "claude", "top", "ps", "which", "echo", "date",
  ];
  const cmd = command.trim().split(/\s+/)[0];
  if (!allowed.includes(cmd)) {
    return res.status(403).json({ error: `Command '${cmd}' not allowed` });
  }

  try {
    const result = await execCommand(command, { cwd: REPO_DIR, timeout: 30000 });
    res.json({ stdout: result.stdout, stderr: result.stderr, code: result.code });
  } catch (e) {
    res.json({ stdout: "", stderr: e.message, code: 1 });
  }
});

// Claude CLI — start
app.post("/api/claude/start", (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: "prompt required" });
  if (activeClaudeProc) return res.status(409).json({ error: "Claude is already running" });
  runClaude(prompt);
  res.json({ started: true });
});

// Claude CLI — stop
app.post("/api/claude/stop", (req, res) => {
  if (activeClaudeProc) {
    activeClaudeProc.kill("SIGTERM");
    activeClaudeProc = null;
    io.emit("claude_output", "\r\n[STOPPED] Claude process terminated by user.\r\n");
    res.json({ stopped: true });
  } else {
    res.json({ stopped: false, message: "No Claude process running" });
  }
});

// Ticket actions
app.post("/api/tickets/:id/approve", async (req, res) => {
  const { id } = req.params;
  try {
    await dbQuery(
      `UPDATE support_tickets SET fix_status = 'approved', approved_at = NOW(), updated_at = NOW() WHERE id = $1`,
      [id]
    );
    // Get the ticket's fix branch and push
    const rows = await dbQuery(`SELECT fix_branch FROM support_tickets WHERE id = $1`, [id]);
    if (rows[0]?.fix_branch) {
      const branch = rows[0].fix_branch;
      await execCommand(`git -C ${REPO_DIR} push origin ${branch}`, { timeout: 30000 });
      io.emit("claude_output", `\r\n[DEPLOY] Pushed branch ${branch} to origin\r\n`);
    }
    await dbQuery(
      `INSERT INTO chester_activity (activity_type, description, metadata)
       VALUES ('ticket_approved', $1, $2)`,
      [`Ticket ${id.substring(0, 8)} approved`, JSON.stringify({ ticket_id: id })]
    );
    io.emit("tickets", await getTicketSummary());
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/tickets/:id/reject", async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  try {
    await dbQuery(
      `UPDATE support_tickets SET fix_status = 'fixing', fix_notes = COALESCE(fix_notes, '') || E'\n[REJECTED] ' || $2, updated_at = NOW() WHERE id = $1`,
      [id, reason || "Rejected by user"]
    );
    await dbQuery(
      `INSERT INTO chester_activity (activity_type, description, metadata)
       VALUES ('ticket_rejected', $1, $2)`,
      [`Ticket ${id.substring(0, 8)} rejected`, JSON.stringify({ ticket_id: id, reason })]
    );
    io.emit("tickets", await getTicketSummary());
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Git quick actions
app.post("/api/git/pull", async (req, res) => {
  try {
    const result = await execCommand("git pull origin main", { cwd: REPO_DIR, timeout: 30000 });
    res.json({ stdout: result.stdout, stderr: result.stderr });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/git/push", async (req, res) => {
  try {
    const branch = await execCommand("git branch --show-current", { cwd: REPO_DIR });
    const result = await execCommand(`git push origin ${branch.stdout.trim()}`, { cwd: REPO_DIR, timeout: 30000 });
    res.json({ stdout: result.stdout, stderr: result.stderr, branch: branch.stdout.trim() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PM2 actions
app.post("/api/pm2/:action/:name", async (req, res) => {
  const { action, name } = req.params;
  const allowedActions = ["restart", "stop", "delete"];
  if (!allowedActions.includes(action)) return res.status(400).json({ error: "Invalid action" });
  // Sanitize process name
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    return res.status(400).json({ error: "Invalid process name" });
  }
  try {
    const result = await execCommand(`pm2 ${action} ${name}`, { timeout: 15000 });
    res.json({ stdout: result.stdout, stderr: result.stderr });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Helpers ──────────────────────────────────────────────────────────────────
function execCommand(cmd, opts = {}) {
  return new Promise((resolve, reject) => {
    const shell = os.platform() === "win32" ? "cmd" : "bash";
    const shellFlag = os.platform() === "win32" ? "/c" : "-c";
    const child = spawn(shell, [shellFlag, cmd], {
      cwd: opts.cwd || REPO_DIR,
      timeout: opts.timeout || 15000,
      env: { ...process.env },
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ stdout, stderr, code }));
    child.on("error", reject);
  });
}

// ── Real-time broadcasts ────────────────────────────────────────────────────

// System metrics every 3s
setInterval(() => {
  if (io.engine.clientsCount === 0) return;
  io.emit("metrics", { system: getSystemInfo(), ts: Date.now() });
}, 3000);

// Tickets + activity every 10s
setInterval(async () => {
  if (io.engine.clientsCount === 0) return;
  const [tickets, activity, processes] = await Promise.all([
    getTicketSummary(),
    getRecentActivity(),
    getProcessList(),
  ]);
  io.emit("tickets", tickets);
  io.emit("activity", { activity });
  io.emit("process_list", { processes });
}, 10000);

// Server health every 30s
setInterval(async () => {
  if (io.engine.clientsCount === 0) return;
  const servers = await getServerHealth();
  io.emit("server_health", { servers });
}, 30000);

// ── Login Page HTML ──────────────────────────────────────────────────────────
function getLoginHTML(error = "") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Chester Dev Monitor — Login</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'SF Mono', 'Cascadia Code', monospace; background: #0f1117; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .login-box { background: #1a1d27; border: 1px solid #2a2d37; border-radius: 12px; padding: 40px; width: 380px; max-width: 90vw; }
    h1 { font-size: 18px; color: #22d3ee; text-align: center; margin-bottom: 4px; letter-spacing: 1px; }
    .subtitle { text-align: center; color: #64748b; font-size: 12px; margin-bottom: 28px; }
    label { display: block; font-size: 12px; color: #94a3b8; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
    input { width: 100%; padding: 10px 12px; background: #0f1117; border: 1px solid #2a2d37; border-radius: 6px; color: #e2e8f0; font-family: inherit; font-size: 14px; margin-bottom: 16px; }
    input:focus { outline: none; border-color: #22d3ee; }
    button { width: 100%; padding: 10px; background: #22d3ee; color: #000; border: none; border-radius: 6px; font-family: inherit; font-size: 14px; font-weight: 600; cursor: pointer; }
    button:hover { background: #06b6d4; }
    .error { background: rgba(239,68,68,0.15); color: #ef4444; padding: 8px 12px; border-radius: 6px; font-size: 12px; margin-bottom: 16px; text-align: center; }
    .lock-icon { text-align: center; margin-bottom: 16px; font-size: 32px; opacity: 0.3; }
  </style>
</head>
<body>
  <div class="login-box">
    <div class="lock-icon">&#128274;</div>
    <h1>CHESTER DEV</h1>
    <div class="subtitle">Monitor Control Panel</div>
    ${error}
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autocomplete="username" autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="current-password">
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>`;
}

// ── Cleanup expired sessions every 5 minutes ────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (now > session.expires) sessions.delete(token);
  }
}, 5 * 60 * 1000);

// ── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n  Chester Dev Monitor running on http://0.0.0.0:${PORT}`);
  console.log(`  DB: ${DB_URL ? "connected" : "NOT connected (set DATABASE_URL)"}`);
  console.log(`  Auth: ${AUTH_PASS ? "ENABLED (password set)" : "DISABLED (set MONITOR_PASS)"}`);
  console.log(`  Repo: ${REPO_DIR}`);
  console.log(`  VPS: ${VPS_HOST}`);
  console.log(`  PTY: ${pty ? "available" : "not available (terminal disabled)"}\n`);
});
