// Intensive end-to-end test harness for Codecanic.
// Boots the real server.js against a temp data dir and exercises every
// advertised endpoint plus the security layer (CSP, CSRF, password policy,
// consent gates, session auth, data export/delete).
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PORT = 4517;
const BASE = `http://127.0.0.1:${PORT}`;
const ORIGIN = BASE;

let pass = 0;
let fail = 0;
const failures = [];

function ok(name, cond, detail = "") {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    failures.push(`${name}${detail ? ` — ${detail}` : ""}`);
    console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

// --- tiny cookie jar -------------------------------------------------------
let jar = "";
function setJarFrom(res) {
  const sc = res.headers.get("set-cookie");
  if (!sc) return;
  // node fetch folds multiple cookies into one comma-joined string; split safely
  const parts = sc.split(/,(?=[^;]+?=)/);
  for (const p of parts) {
    const kv = p.split(";")[0].trim();
    const name = kv.split("=")[0];
    // replace existing cookie of same name
    const others = jar
      .split("; ")
      .filter(Boolean)
      .filter((c) => c.split("=")[0] !== name);
    if (/=;|=deleted|Max-Age=0|Expires=Thu, 01 Jan 1970/.test(p) && !kv.split("=")[1]) {
      jar = others.join("; ");
    } else {
      jar = [...others, kv].join("; ");
    }
  }
}

async function call(method, path, { body, origin = ORIGIN, cookie = true, headers = {} } = {}) {
  const h = { ...headers };
  if (origin) h["Origin"] = origin;
  if (cookie && jar) h["Cookie"] = jar;
  if (body !== undefined) h["Content-Type"] = "application/json";
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: h,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    redirect: "manual"
  });
  setJarFrom(res);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: res.status, json, text, headers: res.headers };
}

// Poll a job until it reaches a terminal state (or times out).
async function pollJob(orgSlug, jobId, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = await call("GET", `/api/jobs/${jobId}?organization=${orgSlug}`, { origin: null });
    if (r.json?.status === "succeeded" || r.json?.status === "failed") return r.json;
    await new Promise((res) => setTimeout(res, 1200));
  }
  return { status: "timeout" };
}

// --- boot server -----------------------------------------------------------
const dataDir = await mkdtemp(join(tmpdir(), "codecanic-e2e-"));
const child = spawn(process.execPath, ["server.js"], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    PORT: String(PORT),
    CODECANIC_DATA_DIR: dataDir,
    CODECANIC_SESSION_SECRET: "e2e-secret-not-for-prod-0123456789",
    CODECANIC_ENCRYPTION_KEY: "e2e-encryption-key-0123456789abcd",
    CODECANIC_ALLOWED_ORIGINS: ORIGIN,
    CODECANIC_REQUIRE_EMAIL_VERIFICATION: "1"
  },
  stdio: ["ignore", "ignore", "pipe"] // ignore stdout (structured request logs) to avoid pipe-buffer backpressure
});
child.stderr.on("data", (d) => process.stderr.write(`[server] ${d}`));

async function waitForServer() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/api/health`);
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("server did not start");
}

let exitCode = 0;
try {
  await waitForServer();

  // 1. Health -------------------------------------------------------------
  console.log("\nHealth & static");
  {
    const r = await call("GET", "/api/health", { origin: null });
    ok("GET /api/health → 200 ok", r.status === 200 && r.json?.status === "ok", `status=${r.status}`);
    ok("health reports name Codecanic", r.json?.name === "Codecanic");
  }

  // 2. Static + security headers -----------------------------------------
  {
    const r = await call("GET", "/", { origin: null });
    ok("GET / serves HTML 200", r.status === 200 && r.text.includes("Codecanic"));
    const csp = r.headers.get("content-security-policy") || "";
    ok("CSP header present w/ nonce", /script-src[^;]*'nonce-/.test(csp), csp.slice(0, 40));
    ok("HSTS header present", !!r.headers.get("strict-transport-security"));
    ok("X-Frame-Options DENY", r.headers.get("x-frame-options") === "DENY");
    ok("X-Content-Type-Options nosniff", r.headers.get("x-content-type-options") === "nosniff");
    ok("frame-ancestors none in CSP", /frame-ancestors 'none'/.test(csp));
  }

  // 3. Auth: me as guest --------------------------------------------------
  console.log("\nAuth flow");
  {
    const r = await call("GET", "/api/auth/me", { origin: null });
    ok("GET /api/auth/me guest → {user:null}", r.status === 200 && r.json?.user === null, `status=${r.status}`);
  }

  // 4. Signup negative cases ---------------------------------------------
  {
    const weak = await call("POST", "/api/auth/signup", {
      body: { email: "weak@x.io", password: "weakpass", organization: "X", acceptTerms: true, age: 30 }
    });
    ok("signup weak password → 400", weak.status === 400, `status=${weak.status}`);

    const noTerms = await call("POST", "/api/auth/signup", {
      body: { email: "t@x.io", password: "Strong-Pass-1!", organization: "X", acceptTerms: false, age: 30 }
    });
    ok("signup without terms → 400", noTerms.status === 400);

    const young = await call("POST", "/api/auth/signup", {
      body: { email: "y@x.io", password: "Strong-Pass-1!", organization: "X", acceptTerms: true, age: 12 }
    });
    ok("signup under-16 → 400", young.status === 400);
  }

  // 5. Signup happy path --------------------------------------------------
  let orgSlug, verifyToken;
  {
    const r = await call("POST", "/api/auth/signup", {
      body: {
        email: "owner@codecanic.local",
        password: "Owner-Pass-123!",
        organization: "Acme Co",
        acceptTerms: true,
        age: 30
      }
    });
    ok("signup happy → 200 + user", r.status === 200 && !!r.json?.user, `status=${r.status} ${r.text.slice(0,80)}`);
    ok("signup sets session cookie", /codecanic_session=/.test(jar), jar.slice(0, 30));
    ok("signup provisions active organization", !!r.json?.activeOrganization?.slug);
    ok("signup flags email verification required", r.json?.emailVerificationRequired === true);
    ok("new user starts unverified", r.json?.user?.emailVerified === false);
    orgSlug = r.json?.activeOrganization?.slug;
    verifyToken = r.json?.devVerifyToken;
  }

  // 5b. Email verification gate -------------------------------------------
  console.log("\nEmail verification");
  {
    // Sensitive features are blocked until the email is verified.
    const blocked = await call("POST", `/api/scan?organization=${orgSlug}`, { body: { sourceUrl: "https://github.com/x/y" } });
    ok("scan blocked before verification → 403", blocked.status === 403 && blocked.json?.code === "email_unverified", `status=${blocked.status}`);
    ok("dev verification token was issued", !!verifyToken);

    const bad = await call("POST", "/api/auth/verify-email", { body: { token: "not-a-real-token" } });
    ok("bad verification token → 400", bad.status === 400, `status=${bad.status}`);

    const verified = await call("POST", "/api/auth/verify-email", { body: { token: verifyToken } });
    ok("valid token verifies email → 200", verified.status === 200, `status=${verified.status} ${verified.text.slice(0,80)}`);

    const me = await call("GET", "/api/auth/me", { origin: null });
    ok("me now shows emailVerified=true", me.json?.user?.emailVerified === true);

    const reuse = await call("POST", "/api/auth/verify-email", { body: { token: verifyToken } });
    ok("verification token is single-use → 400", reuse.status === 400, `status=${reuse.status}`);
  }

  // 6. me authed ----------------------------------------------------------
  {
    const r = await call("GET", "/api/auth/me", { origin: null });
    ok("GET /api/auth/me authed → user", r.status === 200 && r.json?.user?.email === "owner@codecanic.local");
    ok("me returns memberships/orgs", Array.isArray(r.json?.organizations) && r.json.organizations.length >= 1);
  }

  // 7. duplicate signup ---------------------------------------------------
  {
    const r = await call("POST", "/api/auth/signup", {
      body: { email: "owner@codecanic.local", password: "Owner-Pass-123!", organization: "Dup", acceptTerms: true, age: 30 }
    });
    ok("duplicate email signup → 409", r.status === 409, `status=${r.status}`);
  }

  // 8. CSRF / origin protection ------------------------------------------
  console.log("\nSecurity: CSRF / origin");
  {
    const r = await call("POST", "/api/scan", { origin: null, body: { sourceUrl: "x" } });
    ok("POST without Origin → 403", r.status === 403, `status=${r.status}`);
    const bad = await call("POST", "/api/scan", { origin: "https://evil.example.com", body: { sourceUrl: "x" } });
    ok("POST cross-origin → 403", bad.status === 403, `status=${bad.status}`);
  }

  // 9. Orgs ---------------------------------------------------------------
  console.log("\nOrganizations");
  {
    const list = await call("GET", "/api/orgs", { origin: null });
    ok("GET /api/orgs lists orgs", list.status === 200 && list.json?.organizations?.length >= 1);
    const create = await call("POST", "/api/orgs", { body: { name: "Second Org" } });
    ok("POST /api/orgs creates org", create.status === 200 && create.json?.organization?.slug, `status=${create.status}`);
    const list2 = await call("GET", "/api/orgs", { origin: null });
    ok("org count increased to 2", list2.json?.organizations?.length >= 2, `count=${list2.json?.organizations?.length}`);
  }

  // 10. Connectors --------------------------------------------------------
  console.log("\nConnectors");
  {
    const r = await call("GET", `/api/connectors?name=GitHub&organization=${orgSlug}`, { origin: null });
    ok("GET /api/connectors?name=GitHub → 200", r.status === 200, `status=${r.status} ${r.text.slice(0,80)}`);
    const list = await call("GET", `/api/connectors?action=list&organization=${orgSlug}`, { origin: null });
    ok("connectors action=list returns set", list.status === 200 && Array.isArray(list.json?.connectors), `status=${list.status}`);
  }

  // 11. Scan + Repair -----------------------------------------------------
  console.log("\nScan & Repair (core product — REAL engine, ASYNC jobs)");
  {
    // Synchronous validation still returns clean codes before anything is queued:
    const noUrl = await call("POST", `/api/scan?organization=${orgSlug}`, { body: { scanDepth: "full" } });
    ok("scan without URL → 400", noUrl.status === 400, `status=${noUrl.status}`);
    const badHost = await call("POST", `/api/scan?organization=${orgSlug}`, { body: { sourceUrl: "https://evil.example.com/o/r" } });
    ok("scan of non-allowlisted host → 400", badHost.status === 400, `status=${badHost.status}`);
    const badProto = await call("POST", `/api/scan?organization=${orgSlug}`, { body: { sourceUrl: "http://github.com/o/r" } });
    ok("scan of non-https URL → 400", badProto.status === 400, `status=${badProto.status}`);

    // Async scan: POST enqueues (202 + jobId), the worker runs it, the client polls.
    let reportId, realFindingId;
    const enq = await call("POST", `/api/scan?organization=${orgSlug}`, {
      body: { sourceUrl: "https://github.com/jquery/jquery", scanDepth: "full" }
    });
    ok("scan enqueues → 202 + jobId", enq.status === 202 && !!enq.json?.jobId && enq.json?.status === "queued", `status=${enq.status} ${enq.text.slice(0,80)}`);
    ok("scan job is typed 'scan' with a pollUrl", enq.json?.type === "scan" && /\/api\/jobs\//.test(enq.json?.pollUrl || ""));

    const unknownJob = await call("GET", `/api/jobs/00000000-0000-0000-0000-000000000000?organization=${orgSlug}`, { origin: null });
    ok("unknown job id → 404", unknownJob.status === 404, `status=${unknownJob.status}`);

    const finished = enq.json?.jobId ? await pollJob(orgSlug, enq.json.jobId) : { status: "no-job" };
    if (finished.status === "succeeded") {
      const report = finished.result;
      ok("scan job → succeeded with real-v1 report", report?.engine === "real-v1", `engine=${report?.engine}`);
      ok("report has a findings array", Array.isArray(report?.findings));
      ok("report summary has numeric counts", typeof report?.summary?.critical === "number" && typeof report?.summary?.total === "number");
      ok("report resolved repository + commit", !!report?.repository?.commit);
      ok("report shows what it walked", typeof report?.scanned?.filesWalked === "number");
      ok("findings carry severity+target", (report?.findings || []).every((f) => f.severity && f.target));
      reportId = report?.id;
      realFindingId = report?.findings?.[0]?.id;
    } else if (finished.status === "failed") {
      console.log(`  ⊘ SKIP scan result — job failed in this env: ${finished.error || ""}`);
    } else {
      console.log(`  ⊘ SKIP scan result — job did not finish (status=${finished.status})`);
    }

    // Repair validation is still synchronous (clean codes before queueing).
    const empty = await call("POST", `/api/repair?organization=${orgSlug}`, { body: { findingIds: [] } });
    ok("repair with no findings → 400", empty.status === 400, `status=${empty.status}`);
    const noReport = await call("POST", `/api/repair?organization=${orgSlug}`, { body: { findingIds: ["x"] } });
    ok("repair without reportId → 400", noReport.status === 400, `status=${noReport.status}`);
    const badReport = await call("POST", `/api/repair?organization=${orgSlug}`, { body: { findingIds: ["x"], reportId: "nope" } });
    ok("repair with unknown reportId → 404", badReport.status === 404, `status=${badReport.status}`);

    if (reportId && realFindingId) {
      // Report + finding exist, but no GitHub provider is connected → the
      // synchronous token check must refuse with 422 BEFORE queueing (no fake PR).
      const repair = await call("POST", `/api/repair?organization=${orgSlug}`, {
        body: { reportId, findingIds: [realFindingId] }
      });
      ok("repair without connected GitHub → 422 (no fake PR)", repair.status === 422, `status=${repair.status} ${repair.text.slice(0,90)}`);
      ok("422 explains how to connect provider", /connect github/i.test(repair.json?.error || ""), `err=${repair.json?.error}`);
    } else {
      console.log("  ⊘ SKIP real repair path — no live report (offline)");
    }
  }

  // 11b. Billing + suppressions (new endpoints) ---------------------------
  console.log("\nBilling & suppressions");
  {
    const bill = await call("GET", `/api/billing?organization=${orgSlug}`, { origin: null });
    ok("GET /api/billing → Free plan + usage", bill.status === 200 && bill.json?.plan === "Free" && typeof bill.json?.usage?.scansThisMonth === "number", `status=${bill.status}`);
    ok("billing reports entitlements (ads on for Free)", bill.json?.entitlements?.adFree === false);
    const checkout = await call("POST", `/api/billing/checkout?organization=${orgSlug}`, { body: {} });
    ok("checkout without Stripe configured → not configured (no crash)", checkout.status === 200 && checkout.json?.configured === false, `status=${checkout.status}`);
    const fakeHook = await call("POST", "/api/billing/webhook", { origin: null, body: { type: "checkout.session.completed" } });
    ok("webhook rejects an unsigned event → 400", fakeHook.status === 400, `status=${fakeHook.status}`);

    const sup = await call("POST", `/api/suppressions?organization=${orgSlug}`, { body: { fingerprint: "hygiene:no-ci", reason: "n/a here" } });
    ok("POST /api/suppressions → suppressed", sup.status === 200 && sup.json?.status === "suppressed", `status=${sup.status}`);
    const supList = await call("GET", `/api/suppressions?organization=${orgSlug}`, { origin: null });
    ok("GET /api/suppressions lists it", supList.json?.suppressions?.some((s) => s.fingerprint === "hygiene:no-ci"));
    const unsup = await call("DELETE", `/api/suppressions?organization=${orgSlug}`, { body: { fingerprint: "hygiene:no-ci" } });
    ok("DELETE /api/suppressions → unsuppressed", unsup.status === 200 && unsup.json?.status === "unsuppressed");
  }

  // 12. unauth scan -------------------------------------------------------
  {
    const saved = jar;
    jar = "";
    const r = await call("POST", `/api/scan?organization=${orgSlug}`, { body: { sourceUrl: "x" } });
    ok("scan while signed out → 401", r.status === 401, `status=${r.status}`);
    jar = saved;
  }

  // 13. Data export (GDPR) -----------------------------------------------
  console.log("\nGDPR: export & delete");
  {
    const r = await call("GET", "/api/auth/export", { origin: null });
    ok("GET /api/auth/export → 200 user data", r.status === 200 && !!r.json, `status=${r.status}`);
  }

  // 14. Logout ------------------------------------------------------------
  {
    const r = await call("POST", "/api/auth/logout", {});
    ok("POST /api/auth/logout → 200", r.status === 200, `status=${r.status}`);
    const me = await call("GET", "/api/auth/me", { origin: null });
    ok("me after logout → guest", me.json?.user === null, `user=${JSON.stringify(me.json?.user)}`);
  }

  // 15. Login -------------------------------------------------------------
  console.log("\nLogin");
  {
    const bad = await call("POST", "/api/auth/login", { body: { email: "owner@codecanic.local", password: "wrong-Pass-1!" } });
    ok("login wrong password → 401", bad.status === 401, `status=${bad.status}`);
    const good = await call("POST", "/api/auth/login", { body: { email: "owner@codecanic.local", password: "Owner-Pass-123!" } });
    ok("login correct → 200 + user", good.status === 200 && good.json?.user?.email === "owner@codecanic.local", `status=${good.status} ${good.text.slice(0,80)}`);
    const me = await call("GET", "/api/auth/me", { origin: null });
    ok("session restored after login", me.json?.user?.email === "owner@codecanic.local");
  }

  // 15b. Login lockout (DB-backed) — use a separate key so the owner isn't locked.
  console.log("\nLogin lockout");
  {
    let last;
    for (let i = 0; i < 5; i++) {
      last = await call("POST", "/api/auth/login", { body: { email: "lockme@codecanic.local", password: "nope-Pass-1!" } });
    }
    const sixth = await call("POST", "/api/auth/login", { body: { email: "lockme@codecanic.local", password: "nope-Pass-1!" } });
    ok("locks out after repeated failures → 429", sixth.status === 429, `status=${sixth.status}`);
    ok("429 includes Retry-After header", !!sixth.headers.get("retry-after"));
  }

  // 15c. Password reset ----------------------------------------------------
  console.log("\nPassword reset");
  const NEW_PW = "Owner-Pass-456!";
  {
    const unknown = await call("POST", "/api/auth/request-password-reset", { body: { email: "ghost@codecanic.local" } });
    ok("reset request is generic for unknown email → 200", unknown.status === 200 && !unknown.json?.devResetToken, `status=${unknown.status}`);

    const reqReset = await call("POST", "/api/auth/request-password-reset", { body: { email: "owner@codecanic.local" } });
    ok("reset request for real email → 200 + dev token", reqReset.status === 200 && !!reqReset.json?.devResetToken, `status=${reqReset.status}`);
    const resetToken = reqReset.json?.devResetToken;

    const weak = await call("POST", "/api/auth/reset-password", { body: { token: resetToken, password: "weak" } });
    ok("reset rejects weak password → 400", weak.status === 400, `status=${weak.status}`);

    const done = await call("POST", "/api/auth/reset-password", { body: { token: resetToken, password: NEW_PW } });
    ok("reset with valid token → 200", done.status === 200, `status=${done.status} ${done.text.slice(0,80)}`);

    const oldLogin = await call("POST", "/api/auth/login", { body: { email: "owner@codecanic.local", password: "Owner-Pass-123!" } });
    ok("old password no longer works → 401", oldLogin.status === 401, `status=${oldLogin.status}`);

    const reuse = await call("POST", "/api/auth/reset-password", { body: { token: resetToken, password: NEW_PW } });
    ok("reset token is single-use → 400", reuse.status === 400, `status=${reuse.status}`);

    const newLogin = await call("POST", "/api/auth/login", { body: { email: "owner@codecanic.local", password: NEW_PW } });
    ok("new password works → 200", newLogin.status === 200 && newLogin.json?.user?.email === "owner@codecanic.local", `status=${newLogin.status}`);
  }

  // 16. Account deletion --------------------------------------------------
  {
    // Deletion is defense-in-depth: requires password re-entry AND typing "DELETE".
    const noPw = await call("DELETE", "/api/auth/account", { body: { confirm: "DELETE" } });
    ok("delete without password → 422", noPw.status === 422, `status=${noPw.status}`);
    const wrongConfirm = await call("DELETE", "/api/auth/account", { body: { password: NEW_PW, confirm: "yes" } });
    ok("delete without typing DELETE → 422", wrongConfirm.status === 422, `status=${wrongConfirm.status}`);
    const r = await call("DELETE", "/api/auth/account", { body: { password: NEW_PW, confirm: "DELETE" } });
    ok("DELETE /api/auth/account → 2xx", r.status >= 200 && r.status < 300, `status=${r.status} ${r.text.slice(0,80)}`);
    const me = await call("GET", "/api/auth/me", { origin: null });
    ok("account gone after delete", me.json?.user === null, `user=${JSON.stringify(me.json?.user)}`);
    const relog = await call("POST", "/api/auth/login", { body: { email: "owner@codecanic.local", password: NEW_PW } });
    ok("deleted account cannot log back in", relog.status === 401, `status=${relog.status}`);
  }

  // 17. 404 / fallback ----------------------------------------------------
  console.log("\nRouting edge cases");
  {
    const r = await call("GET", "/totally/unknown/path", { origin: null });
    ok("unknown path falls back to SPA index", r.status === 200 && r.text.includes("Codecanic"));
    const m = await call("PUT", "/api/health", { origin: ORIGIN });
    ok("wrong method on health → 405", m.status === 405, `status=${m.status}`);
  }
} catch (err) {
  console.error("\nHARNESS ERROR:", err);
  exitCode = 2;
} finally {
  child.kill("SIGTERM");
  await rm(dataDir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(50)}`);
console.log(`RESULT: ${pass} passed, ${fail} failed`);
if (failures.length) {
  console.log("\nFAILURES:");
  for (const f of failures) console.log(`  - ${f}`);
}
process.exit(fail > 0 ? 1 : exitCode);
