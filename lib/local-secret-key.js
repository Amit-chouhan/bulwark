const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function readSecretFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) return "";
    return fs.readFileSync(filePath, "utf8").trim();
  } catch {
    return "";
  }
}

function writeSecretFile(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value + "\n", { encoding: "utf8", mode: 0o600 });
}

function getManagedSecret({ envNames = [], filePath, legacyValues = [], bytes = 32 }) {
  for (const envName of envNames) {
    if (process.env[envName]) return process.env[envName];
  }

  const stored = readSecretFile(filePath);
  if (stored) return stored;

  const generated = crypto.randomBytes(bytes).toString("hex");
  writeSecretFile(filePath, generated);
  return generated;
}

function getSecretCandidates({ envNames = [], filePath, legacyValues = [] }) {
  const values = [];
  const seen = new Set();

  function add(value) {
    const normalized = String(value || "").trim();
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    values.push(normalized);
  }

  envNames.forEach(name => add(process.env[name]));
  add(readSecretFile(filePath));
  legacyValues.forEach(add);
  return values;
}

module.exports = {
  getManagedSecret,
  getSecretCandidates,
};
