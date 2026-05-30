// Proves the boot-time legacy JSON -> Postgres migration: deploying the
// relational version over an existing JSON-file store must NOT orphan accounts.
// Writes a legacy codecanic.json, boots the DB (triggering migration), and
// asserts the data imported and that re-running is a safe no-op.
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = await mkdtemp(join(tmpdir(), "codecanic-migrate-test-"));
process.env.CODECANIC_DATA_DIR = dir;
process.env.CODECANIC_SESSION_SECRET = "migrate-test-secret-0123456789ab";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}

const U = "11111111-1111-1111-1111-111111111111";
const O = "22222222-2222-2222-2222-222222222222";
await writeFile(join(dir, "codecanic.json"), JSON.stringify({
  users: [{ id: U, email: "legacy@codecanic.local", name: "Legacy", passwordHash: "dead:beef", createdAt: "2026-01-01T00:00:00.000Z", marketingOptIn: false, ageConfirmed: true }],
  organizations: [{ id: O, name: "Legacy Org", slug: "legacy-org", plan: "Free", createdAt: "2026-01-01T00:00:00.000Z" }],
  memberships: [{ id: "33333333-3333-3333-3333-333333333333", userId: U, organizationId: O, role: "owner", createdAt: "2026-01-01T00:00:00.000Z" }],
  sessions: [],
  connectorCreds: [{ id: "44444444-4444-4444-4444-444444444444", provider: "GitHub", organizationId: O, userId: U, accessToken: "enc:v1:tok", tokenType: "bearer", updatedAt: "2026-01-01T00:00:00.000Z" }],
  reports: [{ id: "55555555-5555-5555-5555-555555555555", organizationId: O, sourceUrl: "https://github.com/x/y", createdAt: "2026-01-01T00:00:00.000Z", summary: { total: 1 }, findings: [{ id: "f1" }] }]
}, null, 2));

const repo = await import("../api/_repo.js");       // first access triggers init + migration
const { closeDb } = await import("../api/_db.js");

try {
  console.log("Legacy JSON import");
  const user = await repo.findUserByEmail("legacy@codecanic.local");
  ok("legacy user imported", user?.id === U, `user=${JSON.stringify(user?.email)}`);
  ok("imported user is email-verified (predates the feature)", user?.emailVerified === true);
  ok("legacy org + membership imported", (await repo.organizationsForUser(U)).length === 1);
  ok("legacy connector credential imported", !!(await repo.findConnectorCred("GitHub", O)));
  ok("legacy report imported + retrievable", (await repo.findReport("55555555-5555-5555-5555-555555555555", O))?.id === "55555555-5555-5555-5555-555555555555");

  console.log("\nIdempotence");
  await closeDb();
  const again = await import("../api/_repo.js"); // re-init: tables non-empty → migration skips
  ok("re-boot does not duplicate or error", (await again.findUserByEmail("legacy@codecanic.local"))?.id === U);
} finally {
  await closeDb();
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
