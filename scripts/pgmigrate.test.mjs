// Proves the PGlite → Postgres copy logic used when moving to managed Postgres:
// every table is copied with jsonb/date/boolean fidelity, foreign keys stay
// intact, and re-running is a safe no-op. Source and target are independent
// in-memory PGlite databases (same SQL the managed-pg path runs).
import { PGlite } from "@electric-sql/pglite";
import { randomUUID } from "node:crypto";
import { SCHEMA, copyAllTables } from "../api/_db.js";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}

const src = new PGlite();
const dst = new PGlite();
await src.waitReady; await dst.waitReady;
await src.exec(SCHEMA); await dst.exec(SCHEMA);
const sQ = (sql, p) => src.query(sql, p).then((r) => r.rows);
const dQ = (sql, p) => dst.query(sql, p).then((r) => r.rows);

const now = new Date().toISOString();
const uId = randomUUID(), oId = randomUUID(), rId = randomUUID(), jId = randomUUID();

try {
  // Seed the source with one row per table, FK-consistent.
  await sQ(`INSERT INTO users (id,email,name,password_hash,created_at,marketing_opt_in,age_confirmed,email_verified) VALUES ($1,$2,$3,$4,$5,true,true,true)`,
    [uId, "copy@codecanic.local", "Copy", "scrypt$65536$8$1$aa$bb", now]);
  await sQ(`INSERT INTO organizations (id,name,slug,plan,created_at) VALUES ($1,$2,$3,'Free',$4)`, [oId, "Copy Org", "copy-org", now]);
  await sQ(`INSERT INTO memberships (id,user_id,organization_id,role,created_at) VALUES ($1,$2,$3,'owner',$4)`, [randomUUID(), uId, oId, now]);
  await sQ(`INSERT INTO sessions (id,user_id,created_at,expires_at) VALUES ($1,$2,$3,$4)`, [randomUUID(), uId, now, now]);
  await sQ(`INSERT INTO connector_creds (id,provider,organization_id,user_id,access_token,token_type,updated_at) VALUES ($1,'GitHub',$2,$3,'enc:v1:tok','bearer',$4)`, [randomUUID(), oId, uId, now]);
  await sQ(`INSERT INTO reports (id,organization_id,source_url,created_at,summary,findings) VALUES ($1,$2,'https://github.com/x/y',$3,$4::jsonb,$5::jsonb)`,
    [rId, oId, now, JSON.stringify({ total: 3, critical: 1 }), JSON.stringify([{ id: "f1", severity: "critical" }])]);
  await sQ(`INSERT INTO auth_tokens (id,user_id,kind,token_hash,expires_at) VALUES ($1,$2,'email_verify',$3,$4)`, [randomUUID(), uId, "hash123", now]);
  await sQ(`INSERT INTO login_attempts (key,count,updated_at) VALUES ($1,3,$2)`, ["1.2.3.4|copy@codecanic.local", now]);
  await sQ(`INSERT INTO jobs (id,type,status,organization_id,user_id,payload,result,attempts,created_at) VALUES ($1,'scan','succeeded',$2,$3,$4::jsonb,$5::jsonb,1,$6)`,
    [jId, oId, uId, JSON.stringify({ sourceUrl: "https://github.com/x/y" }), JSON.stringify({ engine: "real-v1", summary: { total: 3 } }), now]);

  console.log("Copy PGlite → (empty) target");
  const counts = await copyAllTables(sQ, dQ);
  ok("copied 1 user", counts.users === 1);
  ok("copied all 9 tables' rows", Object.values(counts).reduce((a, b) => a + b, 0) === 9, JSON.stringify(counts));

  console.log("\nFidelity in the target");
  const u = (await dQ("SELECT * FROM users WHERE id=$1", [uId]))[0];
  ok("user copied with email + verified flag", u?.email === "copy@codecanic.local" && u.email_verified === true);
  ok("password hash preserved verbatim", u.password_hash === "scrypt$65536$8$1$aa$bb");
  const r = (await dQ("SELECT * FROM reports WHERE id=$1", [rId]))[0];
  ok("report jsonb summary round-trips", r?.summary?.total === 3 && r.summary.critical === 1);
  ok("report jsonb findings round-trips", Array.isArray(r.findings) && r.findings[0].id === "f1");
  const j = (await dQ("SELECT * FROM jobs WHERE id=$1", [jId]))[0];
  ok("job jsonb payload + result round-trip", j?.payload?.sourceUrl?.includes("github") && j.result?.engine === "real-v1");
  const la = (await dQ("SELECT * FROM login_attempts"))[0];
  ok("login_attempts copied (non-uuid PK)", la?.count === 3);

  console.log("\nForeign-key integrity preserved");
  const m = (await dQ("SELECT * FROM memberships WHERE user_id=$1 AND organization_id=$2", [uId, oId]));
  ok("membership references copied user + org", m.length === 1);
  const cred = (await dQ("SELECT * FROM connector_creds WHERE organization_id=$1", [oId]))[0];
  ok("connector credential copied + linked", cred?.provider === "GitHub");

  console.log("\nIdempotence (safe re-run)");
  const counts2 = await copyAllTables(sQ, dQ);
  ok("re-copy reports same source counts", counts2.users === 1);
  ok("target not duplicated", (await dQ("SELECT count(*)::int AS n FROM users"))[0].n === 1);
  ok("reports not duplicated", (await dQ("SELECT count(*)::int AS n FROM reports"))[0].n === 1);
} finally {
  await src.close(); await dst.close();
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
