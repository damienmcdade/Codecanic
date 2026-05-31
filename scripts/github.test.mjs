// Proves the GitHub App (least-privilege) layer: a correctly-signed App JWT
// (verifiable with the keypair), config detection, and graceful fallback to the
// stored OAuth token when the App can't mint an installation token. The live
// installation-token exchange needs a registered App + network (prod only).
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID, generateKeyPairSync, createVerify } from "node:crypto";

const dir = await mkdtemp(join(tmpdir(), "codecanic-gh-test-"));
process.env.CODECANIC_DATA_DIR = dir;
process.env.CODECANIC_SESSION_SECRET = "gh-test-secret-0123456789abcdef01";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}

// Generate an App keypair; store the private key with literal \n (as env vars do).
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = privateKey.export({ type: "pkcs8", format: "pem" });

const repo = await import("../api/_repo.js");
const { encryptSecret } = await import("../api/_crypto.js");
const { closeDb } = await import("../api/_db.js");

try {
  console.log("Config detection");
  const gh1 = await import("../api/_github.js");
  ok("not configured without env", gh1.githubAppConfigured() === false);

  process.env.GITHUB_APP_ID = "654321";
  process.env.GITHUB_APP_PRIVATE_KEY = pem.replace(/\n/g, "\\n"); // escaped, as a real env var would be
  ok("configured once APP_ID + key are set", gh1.githubAppConfigured() === true);

  console.log("\nApp JWT (RS256) is correctly signed");
  const now = Math.floor(Date.now() / 1000);
  const jwt = gh1.appJwt(now);
  const [h, p, s] = jwt.split(".");
  ok("JWT has 3 parts", !!h && !!p && !!s);
  const verified = createVerify("RSA-SHA256").update(`${h}.${p}`).verify(publicKey, Buffer.from(s, "base64url"));
  ok("signature verifies with the App public key", verified === true);
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  ok("payload iss = App ID", payload.iss === "654321");
  ok("payload exp is after iat (short-lived)", payload.exp > payload.iat && payload.exp - payload.iat <= 600);

  console.log("\nToken resolution + fallback (needs a user/org)");
  const owner = {
    id: randomUUID(), email: "gh@codecanic.local", name: "gh", passwordHash: "x",
    createdAt: new Date().toISOString(), termsAcceptedAt: new Date().toISOString(),
    privacyAcceptedAt: new Date().toISOString(), marketingOptIn: false, ageConfirmed: true, emailVerified: true
  };
  const { organization: org } = await repo.createUserWithOrg(owner, "gh-org", "GH Org");

  ok("no connection → hasConnection false", (await gh1.hasConnection("github.com", org.id)) === false);
  ok("no connection → resolveRepoToken null", (await gh1.resolveRepoToken("github.com", org.id)) == null);

  // Add an OAuth credential (the fallback path).
  await repo.upsertConnectorCred({ provider: "GitHub", organizationId: org.id, userId: owner.id, accessToken: encryptSecret("gho_oauthtoken123") });
  ok("OAuth cred → hasConnection true", (await gh1.hasConnection("github.com", org.id)) === true);
  ok("resolveRepoToken returns the OAuth token", (await gh1.resolveRepoToken("github.com", org.id)) === "gho_oauthtoken123");

  // Record an App installation; minting will fail offline → must fall back to OAuth.
  await repo.setGithubInstallation(org.id, "99887766");
  ok("App installation recorded", (await repo.getGithubInstallation(org.id)) === "99887766");
  ok("App installation also satisfies hasConnection", (await gh1.hasConnection("github.com", org.id)) === true);
  ok("token mint fails offline → falls back to OAuth token (no crash)", (await gh1.resolveRepoToken("github.com", org.id)) === "gho_oauthtoken123");

  ok("non-git host → no token", (await gh1.resolveRepoToken("example.com", org.id)) == null);
} finally {
  await closeDb();
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
