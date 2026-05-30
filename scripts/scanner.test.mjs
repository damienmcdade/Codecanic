// Proves the v1 scan engine performs REAL detection (not canned output).
// Builds a fixture repo with a known-vulnerable dependency, planted secrets,
// and hygiene problems, then asserts scanDirectory() finds them.
// Network is only needed for the OSV dependency check, which is skipped
// gracefully when unreachable so the suite stays deterministic offline.
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanDirectory, validateGitUrl } from "../api/_scanner.js";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}
function expectThrow(name, fn) {
  try { fn(); ok(name, false, "expected throw"); }
  catch { ok(name, true); }
}

const dir = await mkdtemp(join(tmpdir(), "codecanic-scanner-test-"));

try {
  // --- build a realistic fixture repo --------------------------------------
  await writeFile(join(dir, "package.json"), JSON.stringify({
    name: "fixture-app", version: "1.0.0",
    dependencies: { lodash: "4.17.15" }
  }, null, 2));
  // package-lock with the concrete vulnerable version OSV will flag.
  await writeFile(join(dir, "package-lock.json"), JSON.stringify({
    name: "fixture-app", lockfileVersion: 3, requires: true,
    packages: {
      "": { name: "fixture-app", version: "1.0.0", dependencies: { lodash: "4.17.15" } },
      "node_modules/lodash": { version: "4.17.15" }
    }
  }, null, 2));
  // Planted secrets in source (AWS canonical example key + a GitHub PAT shape).
  await writeFile(join(dir, "config.js"), [
    "export const region = 'us-east-1';",
    "const awsKey = 'AKIAIOSFODNN7EXAMPLE';",
    "const ghToken = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';",
    "export default { awsKey, ghToken };"
  ].join("\n"));
  // Committed environment file (hygiene: must not be in source control).
  await writeFile(join(dir, ".env"), "DB_PASSWORD=\"sup3rSecretValue!42\"\nAPI_TOKEN=\"xpld93kfj38dkfjeu29dk\"\n");
  // tsconfig with strict disabled (hygiene).
  await writeFile(join(dir, "tsconfig.json"), JSON.stringify({
    compilerOptions: { target: "ES2022", strict: false }
  }, null, 2));
  // a secret in an .example file that MUST be ignored (false-positive guard).
  await writeFile(join(dir, ".env.example"), "DB_PASSWORD=\"your-password-here\"\nAWS_KEY=AKIAEXAMPLEEXAMPLE12\n");

  // --- run the engine ------------------------------------------------------
  const report = await scanDirectory(dir, { scanDepth: "full" });
  const byCat = (c) => report.findings.filter((f) => f.category === c);
  const ids = report.findings.map((f) => f.id);

  console.log("\nSecret detection (real regex over real files)");
  ok("detects AWS access key in config.js", ids.some((id) => id.includes("secret:aws-access-key") && id.includes("config.js")));
  ok("detects GitHub PAT in config.js", ids.some((id) => id.includes("secret:github-pat")));
  ok("secret findings are critical", byCat("secret").some((f) => f.severity === "critical"));
  ok("redacts the matched secret (no raw AKIA in output)", !JSON.stringify(report.findings).includes("AKIAIOSFODNN7EXAMPLE"));
  ok("IGNORES secrets in .env.example (no false positive)", !ids.some((id) => id.includes(".env.example")));

  console.log("\nHygiene detection (real file/content checks)");
  ok("flags committed .env file", ids.some((id) => id === "hygiene:committed-env"));
  ok("flags tsconfig strict disabled", ids.some((id) => id === "hygiene:ts-strict"));
  ok("flags missing CI pipeline", ids.some((id) => id === "hygiene:no-ci"));

  console.log("\nDependency SCA (real OSV.dev lookup)");
  if (report.scanned.osv === "ok") {
    const depFindings = byCat("dependency");
    ok("finds known CVE in lodash@4.17.15 via OSV", depFindings.some((f) => /lodash/.test(f.target)), `osv=${report.scanned.osv}`);
    ok("dependency finding cites an OSV/CVE reference", depFindings.length === 0 || depFindings.every((f) => /osv\.dev/.test(f.reference || "")));
  } else {
    console.log(`  ⊘ SKIP — OSV unreachable (${report.scanned.osv}); offline run`);
  }

  console.log("\nReport shape & summary");
  ok("summary.total matches findings length", report.summary.total === report.findings.length);
  ok("summary has numeric critical/warnings", typeof report.summary.critical === "number" && typeof report.summary.warnings === "number");
  ok("findings sorted critical-first", report.findings.length < 2 || report.findings[0].severity === "critical");
  ok("reports scan duration", typeof report.scanned.durationMs === "number");

  console.log("\nURL validation (SSRF safety)");
  ok("accepts a valid github https url", !!validateGitUrl("https://github.com/owner/repo"));
  expectThrow("rejects http (non-https)", () => validateGitUrl("http://github.com/o/r"));
  expectThrow("rejects non-allowlisted host", () => validateGitUrl("https://evil.example.com/o/r"));
  expectThrow("rejects credentials embedded in url", () => validateGitUrl("https://user:pw@github.com/o/r"));
  expectThrow("rejects missing owner/repo", () => validateGitUrl("https://github.com/justowner"));
  expectThrow("rejects internal metadata host", () => validateGitUrl("https://169.254.169.254/latest"));
} finally {
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
