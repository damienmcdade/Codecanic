// Proves the auth-hardening primitives: stronger password hashing with
// transparent upgrade of legacy hashes, DB-backed login lockout (survives
// restarts / works across replicas), and single-use auth tokens for email
// verification + password reset. Runs against embedded Postgres (PGlite).
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, scryptSync, createHash, randomUUID } from "node:crypto";

const dir = await mkdtemp(join(tmpdir(), "codecanic-auth-test-"));
process.env.CODECANIC_DATA_DIR = dir;
process.env.CODECANIC_SESSION_SECRET = "auth-test-secret-0123456789abcdef";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}

const { hashPassword, verifyPassword, passwordNeedsUpgrade } = await import("../api/_auth.js");
const repo = await import("../api/_repo.js");
const { closeDb } = await import("../api/_db.js");
const hashTok = (raw) => createHash("sha256").update(raw).digest("hex");

try {
  console.log("Password hashing (raised scrypt cost, param-encoded)");
  const h = await hashPassword("Correct-Horse-9!");
  ok("hash uses param-encoded scrypt format", h.startsWith("scrypt$65536$8$1$"), h.slice(0, 20));
  ok("correct password verifies", await verifyPassword("Correct-Horse-9!", h));
  ok("wrong password rejected", !(await verifyPassword("wrong", h)));
  ok("new-format hash does NOT need upgrade", passwordNeedsUpgrade(h) === false);

  // Legacy "<salt>:<hash>" produced by Node's default scrypt must still verify.
  const salt = randomBytes(16).toString("hex");
  const legacy = `${salt}:${scryptSync("Legacy-Pass-1!", salt, 64).toString("hex")}`;
  ok("legacy hash still verifies", await verifyPassword("Legacy-Pass-1!", legacy));
  ok("legacy hash flagged for upgrade", passwordNeedsUpgrade(legacy) === true);

  console.log("\nDB-backed login lockout");
  const key = "1.2.3.4|user@x.io";
  let locked = 0;
  for (let i = 0; i < 5; i++) {
    const r = await repo.recordLoginFailure(key, 5, 60_000);
    if (r.lockUntil) locked++;
  }
  ok("locks after 5 failures", locked >= 1);
  ok("loginLockRemaining reports a positive lock", (await repo.loginLockRemaining(key)) > 0);
  await repo.clearLoginFailures(key);
  ok("clearLoginFailures unlocks", (await repo.loginLockRemaining(key)) === 0);

  // Lockout persists across a restart (the in-memory Map never did).
  const key2 = "5.6.7.8|persist@x.io";
  for (let i = 0; i < 5; i++) await repo.recordLoginFailure(key2, 5, 60_000);
  await closeDb();
  const again = await import("../api/_repo.js");
  ok("lockout survives a restart", (await again.loginLockRemaining(key2)) > 0);
  await again.clearLoginFailures(key2);

  console.log("\nAuth tokens (verification + reset, single-use)");
  // Need a real user to satisfy the FK.
  const user = {
    id: randomUUID(), email: "tok@codecanic.local", name: "tok", passwordHash: "x",
    createdAt: new Date().toISOString(), termsAcceptedAt: new Date().toISOString(),
    privacyAcceptedAt: new Date().toISOString(), marketingOptIn: false, ageConfirmed: true, emailVerified: false
  };
  await again.createUserWithOrg(user, "tok-org", "Tok Org");

  const raw = randomBytes(32).toString("base64url");
  await again.createAuthToken({ userId: user.id, kind: "email_verify", tokenHash: hashTok(raw), expiresAt: new Date(Date.now() + 60_000).toISOString() });
  ok("wrong-kind token does not consume", (await again.consumeAuthToken("password_reset", hashTok(raw))) == null);
  ok("valid token consumes to userId", (await again.consumeAuthToken("email_verify", hashTok(raw))) === user.id);
  ok("token is single-use (second consume fails)", (await again.consumeAuthToken("email_verify", hashTok(raw))) == null);

  const expiredRaw = randomBytes(32).toString("base64url");
  await again.createAuthToken({ userId: user.id, kind: "password_reset", tokenHash: hashTok(expiredRaw), expiresAt: new Date(Date.now() - 1000).toISOString() });
  ok("expired token is rejected", (await again.consumeAuthToken("password_reset", hashTok(expiredRaw))) == null);

  console.log("\nEmail verification + password update");
  await again.markEmailVerified(user.id);
  ok("markEmailVerified flips the flag", (await again.findUserByEmail("tok@codecanic.local")).emailVerified === true);
  const newHash = await hashPassword("Brand-New-Pass-1!");
  await again.updateUserPassword(user.id, newHash);
  ok("updateUserPassword persists new hash", (await again.findUserByEmail("tok@codecanic.local")).passwordHash === newHash);
} finally {
  await closeDb();
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
