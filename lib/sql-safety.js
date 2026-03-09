function classifySql(sql) {
  const trimmed = String(sql || "").trim();
  const upper = trimmed.toUpperCase();
  return {
    trimmed,
    upper,
    isDDL: /^(DROP|TRUNCATE|ALTER|CREATE)\b/i.test(trimmed),
    isDML: /^(INSERT|UPDATE|DELETE|MERGE)\b/i.test(trimmed),
    isReadOnlyCandidate: /^(SELECT|WITH|EXPLAIN)\b/i.test(trimmed),
  };
}

function buildReadOnlySql(sql, limit) {
  const cleaned = String(sql || "").trim().replace(/;\s*$/, "");
  if (!cleaned) throw new Error("SQL query is required");
  if (cleaned.includes(";")) throw new Error("Multiple SQL statements are not allowed.");

  const { upper } = classifySql(cleaned);
  if (!upper.startsWith("SELECT") && !upper.startsWith("WITH") && !upper.startsWith("EXPLAIN")) {
    throw new Error("Only SELECT, WITH, and EXPLAIN queries are allowed.");
  }

  const safeLimit = Math.max(1, Math.min(Number(limit) || 50, 500));
  if (upper.startsWith("SELECT") || upper.startsWith("WITH")) {
    return /\bLIMIT\s+\d+/i.test(cleaned) ? cleaned : cleaned + " LIMIT " + safeLimit;
  }
  return cleaned;
}

async function runReadOnlyQuery(pool, sql) {
  if (!pool?.connect) throw new Error("No direct database pool available");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SET TRANSACTION READ ONLY");
    const result = await client.query(sql);
    await client.query("ROLLBACK");
    return result;
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

module.exports = {
  buildReadOnlySql,
  classifySql,
  runReadOnlyQuery,
};
