// Demo app: decrypt the PostgreSQL credentials from ASTIS at startup, then open a real
// connection and read something basic — mirroring the Java/Go examples.
//
// The plaintext exists only in this process's RAM. By default the credentials are never
// printed (only a sha256 prefix); printing is fail-closed (see plaintextPrintAllowed).

import crypto from "node:crypto";
import fs from "node:fs";
import pg from "pg";
import { fromKubernetes } from "./astis-workload.js";

const env = (k, def) => process.env[k] || def;

// Fail-closed: print the plaintext only if the operator opts in AND declares a
// non-production environment. A deployed pod leaves ASTIS_ENV at "production".
function plaintextPrintAllowed() {
  const e = env("ASTIS_ENV", "production");
  return process.env.ASTIS_DEMO_PRINT_SECRET === "true" && !["production", "prod", ""].includes(e);
}
const sha256Prefix = (buf) => crypto.createHash("sha256").update(buf).digest("hex").slice(0, 12);

async function main() {
  const apiUrl = env("ASTIS_API_URL", "https://api.astis.io");
  // No declared identity (RFC-020 §12.2): the gateway derives it from the API-key
  // binding + the verified SA JWT read from the standard pod mounts.
  console.log(`[astis] RFC-020 workload-secret (Node.js) — api=${apiUrl}`);

  const client = fromKubernetes(apiUrl);

  const user = await client.openSecret(fs.readFileSync(env("ASTIS_DB_USER_ENVELOPE", "/etc/astis-sealed/db-user"), "utf8").trim());
  const pass = await client.openSecret(fs.readFileSync(env("ASTIS_DB_PASS_ENVELOPE", "/etc/astis-sealed/db-password"), "utf8").trim());
  console.log(`[astis] username decrypted (sha256=${sha256Prefix(user)}, ${user.length} bytes)`);
  console.log(`[astis] password decrypted (sha256=${sha256Prefix(pass)}, ${pass.length} bytes) — edge saw only HPKE-sealed blobs`);
  if (plaintextPrintAllowed()) console.log(`  DB_USER=${user} DB_PASSWORD=${pass}`);

  // Connect with the ASTIS-decrypted credentials and read something basic.
  const pool = new pg.Pool({
    host: env("DB_HOST", "db.example.com"),
    port: Number(env("DB_PORT", "5432")),
    database: env("DB_NAME", "postgres"),
    user: user.toString(),
    password: pass.toString(),
    ssl: env("DB_SSLMODE", "prefer") === "disable" ? false : { rejectUnauthorized: false },
    connectionTimeoutMillis: 5000,
  });
  try {
    const r = await pool.query("select version() as v, current_user as u, current_database() as d");
    console.log(`[astis] PostgreSQL connected with ASTIS-decrypted credentials — user=${r.rows[0].u} db=${r.rows[0].d} (${r.rows[0].v})`);
  } catch (e) {
    console.error(`[astis] PostgreSQL connection failed: ${e.message}`);
    process.exitCode = 1;
  }

  console.log("[astis] done — keeping the demo process alive");
  setInterval(() => {}, 1 << 30);
}

main().catch((e) => { console.error(`[astis] FAILED: ${e.message}`); process.exit(1); });
