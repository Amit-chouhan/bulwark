const net = require("net");

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
]);

function isLoopbackIPv4(host) {
  return /^127\./.test(host);
}

function isPrivateIPv4(host) {
  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  const m = host.match(/^172\.(\d+)\./);
  return !!m && Number(m[1]) >= 16 && Number(m[1]) <= 31;
}

function isBlockedIPv4(host) {
  return isLoopbackIPv4(host) ||
    isPrivateIPv4(host) ||
    /^169\.254\./.test(host) ||
    /^0\./.test(host);
}

function isBlockedIPv6(host) {
  const normalized = host.toLowerCase();
  return normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd");
}

function normalizeRemoteOrigin(input, opts = {}) {
  const raw = String(input || "").trim();
  if (!raw) throw new Error("host is required");

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("host must be a valid http(s) URL");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("host must use http or https");
  }
  if (parsed.username || parsed.password) {
    throw new Error("host must not include embedded credentials");
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("host must be an origin without path, query, or fragment");
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const allowPrivate = !!opts.allowPrivate;
  const ipKind = net.isIP(host);
  if (!allowPrivate) {
    if (BLOCKED_HOSTNAMES.has(host) || host.endsWith(".localhost")) {
      throw new Error("local hostnames are not allowed");
    }
    if (ipKind === 4 && isBlockedIPv4(host)) {
      throw new Error("private or link-local IPv4 targets require explicit opt-in");
    }
    if (ipKind === 6 && isBlockedIPv6(host)) {
      throw new Error("private or link-local IPv6 targets require explicit opt-in");
    }
  }

  parsed.pathname = "";
  parsed.search = "";
  parsed.hash = "";
  return parsed.origin;
}

function buildHealthUrl(origin) {
  return new URL("/api/health", origin).toString();
}

module.exports = {
  buildHealthUrl,
  normalizeRemoteOrigin,
};
