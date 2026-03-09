const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getManagedSecret, getSecretCandidates } = require('./local-secret-key');

const DEFAULT_DATA_FILE = path.join(__dirname, '..', 'data', 'envvars.json');
const ENVVARS_KEY_FILE = path.join(__dirname, '..', 'data', '.envvars-key');

function getDataFile() {
  return process.env.BULWARK_ENVVARS_FILE || DEFAULT_DATA_FILE;
}

function getKey() {
  const raw = getManagedSecret({
    envNames: ['ENCRYPTION_KEY'],
    filePath: ENVVARS_KEY_FILE,
    legacyValues: [process.env.MONITOR_PASS || '', 'dev-monitor-default-key'],
  });
  return crypto.createHash('sha256').update(raw).digest();
}

function getKeyCandidates() {
  return getSecretCandidates({
    envNames: ['ENCRYPTION_KEY'],
    filePath: ENVVARS_KEY_FILE,
    legacyValues: [process.env.MONITOR_PASS || '', 'dev-monitor-default-key'],
  }).map(raw => crypto.createHash('sha256').update(raw).digest());
}

function isEncryptedValue(value) {
  return typeof value === 'string' && /^[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/i.test(value);
}

function encrypt(text) {
  const plain = String(text == null ? '' : text);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  let enc = cipher.update(plain, 'utf8', 'hex');
  enc += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + tag + ':' + enc;
}

function decrypt(data) {
  if (!isEncryptedValue(data)) {
    throw new Error('Invalid encrypted env var payload');
  }
  const [ivHex, tagHex, enc] = data.split(':');
  let lastError = null;
  for (const key of getKeyCandidates()) {
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
      decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
      let dec = decipher.update(enc, 'hex', 'utf8');
      dec += decipher.final('utf8');
      return dec;
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError || new Error('Could not decrypt env var payload');
}

function createEmptyStore() {
  return { apps: {} };
}

function normalizeEntry(entry, now) {
  if (!entry || typeof entry !== 'object') return null;
  const value = entry.value == null ? '' : String(entry.value);
  return {
    value: isEncryptedValue(value) ? value : encrypt(value),
    description: entry.description || '',
    updated: entry.updated || entry.updatedAt || now,
  };
}

function normalizeLegacyVariables(variables, now) {
  const vars = {};
  for (const entry of Array.isArray(variables) ? variables : []) {
    if (!entry || typeof entry.key !== 'string' || !entry.key) continue;
    vars[entry.key] = normalizeEntry(entry, now);
  }
  return vars;
}

function normalizeStore(raw) {
  const now = new Date().toISOString();
  const store = createEmptyStore();

  if (raw && raw.apps && typeof raw.apps === 'object') {
    Object.entries(raw.apps).forEach(([appName, appData]) => {
      const normalizedApp = { vars: {}, history: [] };
      const vars = appData && typeof appData === 'object' ? appData.vars : null;
      Object.entries(vars || {}).forEach(([key, entry]) => {
        const normalized = normalizeEntry(entry, now);
        if (normalized) normalizedApp.vars[key] = normalized;
      });
      if (Array.isArray(appData?.history)) {
        normalizedApp.history = appData.history.slice(-200);
      }
      store.apps[appName] = normalizedApp;
    });
  }

  if (Array.isArray(raw?.variables)) {
    const app = ensureApp(store, 'default');
    Object.assign(app.vars, normalizeLegacyVariables(raw.variables, now));
  }

  return store;
}

function loadStore() {
  try {
    const file = getDataFile();
    if (fs.existsSync(file)) {
      return normalizeStore(JSON.parse(fs.readFileSync(file, 'utf8')));
    }
  } catch {}
  return createEmptyStore();
}

function saveStore(store) {
  const file = getDataFile();
  const normalized = normalizeStore(store);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(normalized, null, 2), 'utf8');
  return normalized;
}

function ensureApp(store, appName) {
  if (!store.apps) store.apps = {};
  if (!store.apps[appName]) store.apps[appName] = { vars: {}, history: [] };
  if (!store.apps[appName].vars) store.apps[appName].vars = {};
  if (!Array.isArray(store.apps[appName].history)) store.apps[appName].history = [];
  return store.apps[appName];
}

module.exports = {
  getDataFile,
  isEncryptedValue,
  encrypt,
  decrypt,
  loadStore,
  saveStore,
  ensureApp,
  normalizeStore,
};
