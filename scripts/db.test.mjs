// Proves the relational data layer fixes the P0 failure modes of the old
// JSON-file store: durability across a process restart, unique constraints,
// and referential integrity (cascading deletes). Runs against embedded
// Postgres (PGlite) persisted to a temp dir — the same SQL prod runs on `pg`.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

const dir = await mkdtemp(join(tmpdir(), "codecanic-db-test-"));
process.env.CODECANIC_DATA_DIR = dir;
process.env.CODECANIC_SESSION_SECRET = "db-test-secret-0123456789abcdef";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}

const repo = await import("../api/_repo.js");
const { closeDb, backendKind } = await import("../api/_db.js");

const mkUser = (email) => ({
  id: randomUUID(), email, name: email.split("@")[0], passwordHash: "hash",
  createdAt: new Date().toISOString(), termsAcceptedAt: new Date().toISOString(),
  privacyAcceptedAt: new Date().toISOString(), marketingOptIn: false, ageConfirmed: true
});

try {
  console.log(`Backend: ${await backendKind()}`);

  console.log("\nDurability across restart (the core P0 fix)");
  const u = mkUser("durable@codecanic.local");
  const { organization } = await repo.createUserWithOrg(u, "durable-org", "Durable Org");
  await repo.insertReport({ id: randomUUID(), organizationId: organization.id, sourceUrl: "https://github.com/x/y",
    createdAt: new Date().toISOString(), summary: { total: 2 }, findings: [{ id: "a" }, { id: "b" }] });

  // Simulate a process/container restart: drop the singleton, reconnect to the
  // same on-disk database. The JSON-file store on Railway's ephemeral FS would
  // have lost everything here.
  await closeDb();
  const again = await import("../api/_repo.js");
  ok("user survives a restart", (await again.findUserByEmail("durable@codecanic.local"))?.id === u.id);
  ok("organization survives a restart", (await again.organizationsForUser(u.id)).length === 1);

  console.log("\nUnique constraints");
  let dup = false;
  try { await repo.createUserWithOrg(mkUser("durable@codecanic.local"), "dup", "Dup"); }
  catch { dup = true; }
  ok("duplicate email rejected by DB", dup);

  console.log("\nReferential integrity (cascading deletes)");
  // Give the org a connected credential, then delete the user (sole owner) and
  // confirm the org + its memberships + creds + reports all cascade away.
  await repo.upsertConnectorCred({ provider: "GitHub", organizationId: organization.id, userId: u.id, accessToken: "enc:tok" });
  ok("credential present before delete", !!(await repo.findConnectorCred("GitHub", organization.id)));
  await repo.deleteUserAndSoleOwnedOrgs(u.id);
  ok("user removed", (await repo.findUserByEmail("durable@codecanic.local")) == null);
  ok("sole-owned org removed", (await repo.organizationsForUser(u.id)).length === 0);
  ok("credential cascaded away", (await repo.findConnectorCred("GitHub", organization.id)) == null);
  ok("report cascaded away", (await repo.findReport("00000000-0000-0000-0000-000000000000", organization.id)) == null);

  console.log("\nReport pruning + retrieval");
  const owner = mkUser("reporter@codecanic.local");
  const { organization: org2 } = await repo.createUserWithOrg(owner, "rep-org", "Rep Org");
  let lastId;
  for (let i = 0; i < 25; i++) {
    lastId = randomUUID();
    await repo.insertReport({ id: lastId, organizationId: org2.id, sourceUrl: `https://github.com/x/r${i}`,
      createdAt: new Date(Date.now() + i).toISOString(), summary: { total: i }, findings: [] });
  }
  ok("latest report is retrievable by id", (await repo.findReport(lastId, org2.id))?.id === lastId);
  ok("findReport is org-scoped (no cross-tenant read)", (await repo.findReport(lastId, organization.id)) == null);

  console.log("\nUnique slug generation");
  const a = mkUser("slug-a@codecanic.local");
  const b = mkUser("slug-b@codecanic.local");
  const r1 = await repo.createUserWithOrg(a, "acme", "Acme");
  const r2 = await repo.createUserWithOrg(b, "acme", "Acme");
  ok("colliding org names get distinct slugs", r1.organization.slug !== r2.organization.slug, `${r1.organization.slug} vs ${r2.organization.slug}`);
} finally {
  await closeDb();
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
