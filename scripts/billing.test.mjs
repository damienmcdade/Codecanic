// Proves the freemium Pro tier: entitlements, plan changes, the monthly scan
// counter that gates Free, and Stripe webhook signature verification (so a
// forged "you're now Pro" event can't upgrade an org). Stripe API calls are
// prod-only; the signature + plan logic is fully tested offline.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID, createHmac } from "node:crypto";

const dir = await mkdtemp(join(tmpdir(), "codecanic-billing-test-"));
process.env.CODECANIC_DATA_DIR = dir;
process.env.CODECANIC_SESSION_SECRET = "billing-test-secret-0123456789ab";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}

const { entitlements, planFor } = await import("../api/_lib.js");
const repo = await import("../api/_repo.js");
const { verifyStripeSignature } = await import("../api/billing.js");
const { closeDb } = await import("../api/_db.js");

try {
  console.log("Plan entitlements");
  // Sponsor-supported model: no paid tier — Free has UNLIMITED scans (same full
  // feature set as the dormant Pro entry), matching the published Terms/Privacy.
  ok("Free: ads on, unlimited scans (no paid tier)", entitlements("Free").adFree === false && entitlements("Free").monthlyScanLimit === null);
  ok("Pro: ad-free, unlimited scans", entitlements("Pro").adFree === true && entitlements("Pro").monthlyScanLimit === null);
  ok("unknown plan falls back to Free", entitlements("Bogus").plan === "Free");

  const owner = {
    id: randomUUID(), email: "bill@codecanic.local", name: "bill", passwordHash: "x",
    createdAt: new Date().toISOString(), termsAcceptedAt: new Date().toISOString(),
    privacyAcceptedAt: new Date().toISOString(), marketingOptIn: false, ageConfirmed: true, emailVerified: true
  };
  const { organization: org } = await repo.createUserWithOrg(owner, "bill-org", "Bill Org");

  console.log("\nPlan changes");
  ok("new org starts on Free", (await repo.organizationsForUser(owner.id))[0].plan === "Free");
  await repo.setOrgPlan(org.id, "Pro");
  ok("setOrgPlan → Pro", (await repo.organizationsForUser(owner.id))[0].plan === "Pro");
  ok("Pro org is ad-free", entitlements((await repo.organizationsForUser(owner.id))[0].plan).adFree === true);
  await repo.setOrgPlan(org.id, "Free");
  ok("downgrade → Free", (await repo.organizationsForUser(owner.id))[0].plan === "Free");

  console.log("\nMonthly scan counter (analytics only — no longer gates)");
  ok("starts at 0 scans this month", (await repo.countScansThisMonth(org.id)) === 0);
  for (let i = 0; i < 3; i++) await repo.enqueueJob({ type: "scan", organizationId: org.id, userId: owner.id, payload: {} });
  await repo.enqueueJob({ type: "repair", organizationId: org.id, userId: owner.id, payload: {} }); // not counted
  ok("counts only scan jobs this month", (await repo.countScansThisMonth(org.id)) === 3);
  ok("Free has no scan limit (null) — same as Pro", planFor("Free").monthlyScanLimit === null);
  ok("Pro has no limit (null)", planFor("Pro").monthlyScanLimit === null);

  console.log("\nStripe webhook signature verification");
  const secret = "whsec_test_123";
  const body = JSON.stringify({ type: "checkout.session.completed", data: { object: { metadata: { organizationId: org.id } } } });
  const t = Math.floor(Date.now() / 1000);
  const goodSig = `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;
  ok("valid signature verifies", verifyStripeSignature(body, goodSig, secret) === true);
  ok("tampered body is rejected", verifyStripeSignature(body + "x", goodSig, secret) === false);
  ok("wrong secret is rejected", verifyStripeSignature(body, goodSig, "whsec_other") === false);
  ok("missing/garbage header is rejected", verifyStripeSignature(body, "nope", secret) === false);

  // Replay protection: a correctly-signed but stale event (outside the tolerance)
  // is rejected so a captured webhook can't be replayed indefinitely.
  const oldT = t - 3600; // 1h ago
  const oldSig = `t=${oldT},v1=${createHmac("sha256", secret).update(`${oldT}.${body}`).digest("hex")}`;
  ok("stale (replayed) signature is rejected", verifyStripeSignature(body, oldSig, secret) === false);
  ok("stale signature accepted when tolerance disabled", verifyStripeSignature(body, oldSig, secret, 0) === true);
} finally {
  await closeDb();
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
