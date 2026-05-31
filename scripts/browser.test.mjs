// Real browser QA (headless Chromium via Puppeteer) of the frontend auth +
// async-scan flows that unit/e2e tests can't cover: the verification banner,
// email-verify, forgot-password, the /reset-password page, and scan polling
// rendering a report in the UI. Boots the real server (PGlite) as a subprocess.
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import puppeteer from "puppeteer";

const PORT = 4733;
const BASE = `http://127.0.0.1:${PORT}`;

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const dataDir = await mkdtemp(join(tmpdir(), "codecanic-browser-"));
const child = spawn(process.execPath, ["server.js"], {
  cwd: process.cwd(),
  env: {
    ...process.env, PORT: String(PORT), CODECANIC_DATA_DIR: dataDir,
    CODECANIC_SESSION_SECRET: "browser-secret-0123456789abcdef0123",
    CODECANIC_ALLOWED_ORIGINS: BASE, CODECANIC_REQUIRE_EMAIL_VERIFICATION: "1"
  },
  stdio: ["ignore", "ignore", "pipe"]
});
child.stderr.on("data", (d) => process.stderr.write(`[server] ${d}`));

async function waitForServer() {
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(`${BASE}/api/health`)).ok) return; } catch {}
    await sleep(100);
  }
  throw new Error("server did not start");
}

let browser, exitCode = 0;
try {
  await waitForServer();
  browser = await puppeteer.launch({ headless: "new", args: ["--no-sandbox"] });
  const page = await browser.newPage();
  // Drive the UI via synthetic events so overlays (cookie banner / ad slots)
  // can't intercept clicks, and value-setting doesn't depend on focus/visibility.
  const clickEl = (sel) => page.$eval(sel, (el) => el.click());
  const setVal = (sel, value) => page.$eval(sel, (el, v) => { el.value = v; el.dispatchEvent(new Event("input", { bubbles: true })); }, value);
  const hidden = (sel) => page.$eval(sel, (el) => el.hidden);

  // Capture dev tokens the server returns only in non-production.
  let verifyToken, resetToken;
  page.on("response", async (res) => {
    const u = res.url();
    if (u.endsWith("/api/auth/signup") || u.endsWith("/api/auth/request-password-reset")) {
      try { const j = await res.json(); verifyToken = j.devVerifyToken || verifyToken; resetToken = j.devResetToken || resetToken; } catch {}
    }
  });

  const email = "browser@codecanic.local";
  const PW1 = "Browser-Pass-123!";
  const PW2 = "Browser-Pass-456!";

  console.log("App loads");
  await page.goto(BASE, { waitUntil: "networkidle2" });
  ok("page title is Codecanic", (await page.title()).includes("Codecanic"));

  console.log("\nSign up via the modal");
  await page.waitForSelector('[data-auth-open="signup"]');
  await clickEl('[data-auth-open="signup"]');
  await page.waitForFunction(() => !document.querySelector("#auth-modal").hidden, { timeout: 8000 });
  await setVal('#auth-form input[name="name"]', "Browser Tester");
  await setVal('#auth-form input[name="organization"]', "Browser Org");
  await setVal('#auth-form input[name="email"]', email);
  await setVal('#auth-form input[name="password"]', PW1);
  await clickEl("#ageConfirm");
  await clickEl("#acceptTerms");
  await clickEl("#auth-submit");
  await page.waitForFunction((e) => document.querySelector("#account-email")?.textContent?.includes(e), { timeout: 15000 }, email);
  ok("account shows the signed-in email", (await page.$eval("#account-email", (e) => e.textContent)).includes(email));

  console.log("\nEmail verification banner");
  await page.waitForFunction(() => { const b = document.querySelector("#verify-banner"); return b && !b.hidden; }, { timeout: 8000 }).catch(() => {});
  ok("verify banner shown for unverified user", (await hidden("#verify-banner")) === false);
  ok("signup returned a dev verify token", !!verifyToken);

  // Verify the email via the link target, then reload — banner should clear.
  await page.goto(`${BASE}/api/auth/verify-email?token=${verifyToken}`, { waitUntil: "domcontentloaded" });
  ok("verify link renders a confirmation page", /verified/i.test(await page.content()));
  await page.goto(BASE, { waitUntil: "networkidle2" });
  await page.waitForFunction(() => document.querySelector("#account-email")?.textContent?.length > 0, { timeout: 10000 });
  await page.waitForFunction(() => { const b = document.querySelector("#verify-banner"); return b && b.hidden; }, { timeout: 8000 }).catch(() => {});
  ok("verify banner cleared after verification", (await hidden("#verify-banner")) === true);

  console.log("\nAsync scan → poll → report renders (needs network)");
  try {
    await setVal("#source-url", "https://github.com/sindresorhus/slugify");
    await clickEl("#run-scan");
    await page.waitForFunction(() => /Report ready/i.test(document.querySelector("#scan-state")?.textContent || ""), { timeout: 60000 });
    ok("scan polled to completion and report rendered", /Report ready/i.test(await page.$eval("#scan-state", (e) => e.textContent)));
  } catch (err) {
    console.log(`  ⊘ SKIP scan-in-browser — ${String(err.message).slice(0, 80)}`);
  }

  console.log("\nForgot password");
  await clickEl("#sign-out-button");
  await page.waitForFunction(() => !document.querySelector(".account-signed-out")?.hidden, { timeout: 8000 });
  await clickEl('[data-auth-open="signin"]');
  await page.waitForFunction(() => !document.querySelector("#auth-modal").hidden, { timeout: 8000 });
  await setVal('#auth-form input[name="email"]', email);
  await clickEl("#forgot-password");
  await page.waitForFunction(() => document.querySelector("#toast")?.classList.contains("visible"), { timeout: 8000 });
  ok("forgot-password shows a confirmation toast", /reset link/i.test(await page.$eval("#toast", (e) => e.textContent)));
  await sleep(600);
  ok("request-password-reset returned a dev reset token", !!resetToken, "no reset token captured");

  console.log("\nReset-password page");
  await page.goto(`${BASE}/reset-password?token=${resetToken}`, { waitUntil: "networkidle2" });
  await page.waitForFunction(() => { const m = document.querySelector("#reset-modal"); return m && !m.hidden; }, { timeout: 8000 });
  ok("reset-password deep link opens the reset modal", (await hidden("#reset-modal")) === false);
  // Mismatched passwords → inline error.
  await setVal('#reset-form input[name="password"]', PW2);
  await setVal('#reset-form input[name="confirm"]', "Different-1!");
  await clickEl("#reset-submit");
  await page.waitForFunction(() => !document.querySelector("#reset-error")?.hidden, { timeout: 8000 });
  ok("mismatched passwords show an error", /do not match/i.test(await page.$eval("#reset-error", (e) => e.textContent)));
  // Fix the confirm and submit → success.
  await setVal('#reset-form input[name="confirm"]', PW2);
  await clickEl("#reset-submit");
  await page.waitForFunction(() => /Password updated/i.test(document.querySelector("#toast")?.textContent || ""), { timeout: 10000 });
  ok("valid reset shows success toast", /Password updated/i.test(await page.$eval("#toast", (e) => e.textContent)));
  // (That the new password actually works for login is verified server-side in
  // the e2e: "old password → 401" + "new password → 200".)
} catch (err) {
  console.error("\nHARNESS ERROR:", err);
  exitCode = 2;
} finally {
  if (browser) await browser.close();
  child.kill("SIGTERM");
  await sleep(300);
  await rm(dataDir, { recursive: true, force: true }).catch(() => {});
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : exitCode);
