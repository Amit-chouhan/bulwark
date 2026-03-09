const assert = require("assert");
const { execFileCommand } = require("../lib/exec");
const { buildHealthUrl, normalizeRemoteOrigin } = require("../lib/remote-targets");
const { buildReadOnlySql, classifySql } = require("../lib/sql-safety");

(async function main() {
  assert.equal(buildReadOnlySql("select 1", 25), "select 1 LIMIT 25");
  assert.equal(buildReadOnlySql("SELECT 1 LIMIT 5", 25), "SELECT 1 LIMIT 5");
  assert.equal(buildReadOnlySql("EXPLAIN SELECT 1", 10), "EXPLAIN SELECT 1");
  assert.throws(() => buildReadOnlySql("update users set role = 'admin'", 10), /Only SELECT/);
  assert.throws(() => buildReadOnlySql("select 1; select 2", 10), /Multiple SQL statements/);

  const classification = classifySql("DELETE FROM users");
  assert.equal(classification.isDML, true);
  assert.equal(classification.isDDL, false);

  assert.equal(normalizeRemoteOrigin("https://example.com/"), "https://example.com");
  assert.equal(buildHealthUrl("https://example.com"), "https://example.com/api/health");
  assert.throws(() => normalizeRemoteOrigin("http://localhost"), /not allowed/);
  assert.throws(() => normalizeRemoteOrigin("http://169.254.169.254"), /require explicit opt-in/);
  assert.equal(normalizeRemoteOrigin("http://10.0.0.25", { allowPrivate: true }), "http://10.0.0.25");

  const execResult = await execFileCommand(process.execPath, ["-e", "process.stdout.write(process.argv[1])", "ok"]);
  assert.equal(execResult.code, 0);
  assert.equal(execResult.stdout, "ok");

  console.log("security regression tests passed");
})().catch((err) => {
  console.error(err.stack || err.message || String(err));
  process.exit(1);
});
