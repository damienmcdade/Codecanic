// Proves the repair engine generates and applies REAL patches (offline).
// Builds a fixture repo + a set of findings (as the scanner would emit them),
// plans repairs, applies them to disk, and asserts the files actually changed.
// The clone/commit/push/PR path (runRepair) is the production integration and
// is not exercised here (needs a GitHub token + writable repo).
import { mkdtemp, mkdir, writeFile, readFile, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { planRepairs, applyPlan, classifyBump, confidenceScore } from "../api/_repair.js";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}
async function exists(p) { try { await access(p); return true; } catch { return false; } }

// Findings shaped exactly like the scanner emits (with remediation blocks).
const findings = [
  { id: "dep:lodash@4.17.15:GHSA-x", category: "dependency", severity: "critical", title: "Vulnerable dependency: lodash", target: "npm · lodash@4.17.15",
    remediation: { kind: "npm-bump-direct", ecosystem: "npm", packageName: "lodash", currentVersion: "4.17.15", fixedVersion: "4.17.21" } },
  { id: "dep:minimist@1.2.0:GHSA-y", category: "dependency", severity: "warning", title: "Vulnerable dependency: minimist", target: "npm · minimist@1.2.0",
    remediation: { kind: "npm-override", ecosystem: "npm", packageName: "minimist", currentVersion: "1.2.0", fixedVersion: "1.2.6" } },
  { id: "hygiene:ts-strict", category: "hygiene", severity: "warning", title: "TypeScript strict mode disabled", target: "tsconfig.json",
    remediation: { kind: "tsconfig-strict", file: "tsconfig.json" } },
  { id: "hygiene:committed-env", category: "hygiene", severity: "critical", title: "Environment file committed", target: ".env",
    remediation: { kind: "gitignore-env", file: ".env" } },
  { id: "hygiene:no-ci", category: "hygiene", severity: "warning", title: "No CI pipeline detected", target: "(repository root)",
    remediation: { kind: "add-ci" } },
  // Manual (no remediation) — must NOT be auto-patched:
  { id: "secret:aws-access-key:config.js:2", category: "secret", severity: "critical", title: "Exposed secret: AWS Access Key ID", target: "config.js:2", fix: "Rotate." },
  { id: "hygiene:key-file", category: "hygiene", severity: "critical", title: "Private key committed", target: "server.pem", fix: "Remove + rotate." }
];

console.log("Planning");
const plan = planRepairs(findings);
const kinds = plan.patches.map((p) => p.kind);
ok("plans an npm-deps patch", kinds.includes("npm-deps"));
ok("plans tsconfig-strict patch", kinds.includes("tsconfig-strict"));
ok("plans gitignore-env patch", kinds.includes("gitignore-env"));
ok("plans add-ci patch", kinds.includes("add-ci"));
const npm = plan.patches.find((p) => p.kind === "npm-deps");
ok("direct dep → bump", npm?.bumps?.lodash === "4.17.21", JSON.stringify(npm?.bumps));
ok("transitive dep → override", npm?.overrides?.minimist === "1.2.6", JSON.stringify(npm?.overrides));
ok("secret is listed as MANUAL (never auto-patched)", plan.manual.some((m) => m.id.startsWith("secret:")));
ok("key-file is listed as MANUAL", plan.manual.some((m) => m.id === "hygiene:key-file"));
ok("manual items carry a human reason", plan.manual.every((m) => typeof m.reason === "string" && m.reason.length > 0));

const dir = await mkdtemp(join(tmpdir(), "codecanic-repair-test-"));
try {
  await writeFile(join(dir, "package.json"), JSON.stringify({
    name: "fix-me", version: "1.0.0",
    dependencies: { lodash: "^4.17.15" }
  }, null, 2));
  await writeFile(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { strict: false } }, null, 2));
  await writeFile(join(dir, ".env"), "SECRET=live-value\n");
  await writeFile(join(dir, ".gitignore"), "node_modules/\n");

  console.log("\nApplying patches to a real tree");
  const applied = await applyPlan(dir, plan);

  const pkg = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
  ok("package.json: lodash bumped to ^4.17.21", pkg.dependencies.lodash === "^4.17.21", pkg.dependencies.lodash);
  ok("package.json: minimist override added", pkg.overrides?.minimist === "^1.2.6", JSON.stringify(pkg.overrides));

  const tsc = JSON.parse(await readFile(join(dir, "tsconfig.json"), "utf8"));
  ok("tsconfig: strict flipped to true", tsc.compilerOptions.strict === true);

  const gi = await readFile(join(dir, ".gitignore"), "utf8");
  ok(".gitignore: .env added", gi.split("\n").includes(".env"));
  ok(".gitignore: preserves existing entries", gi.includes("node_modules/"));
  ok(".env file removed from tree", !(await exists(join(dir, ".env"))));

  ok("CI workflow created", await exists(join(dir, ".github", "workflows", "codecanic-ci.yml")));

  ok("applied.changed lists package.json", applied.changed.includes("package.json"));
  ok("applied.removed lists .env", applied.removed.includes(".env"));
  ok("applied.summary is human-readable", applied.summary.length > 0 && applied.summary.every((s) => typeof s === "string"));

  console.log("\nIdempotence / safety");
  const applied2 = await applyPlan(dir, planRepairs(findings));
  const gi2 = await readFile(join(dir, ".gitignore"), "utf8");
  ok(".gitignore not duplicated on re-run", gi2.split("\n").filter((l) => l.trim() === ".env").length === 1);

  console.log("\nNo auto-fixable findings → no empty work");
  const onlyManual = planRepairs([findings[5]]);
  ok("plan with only secrets has zero patches", onlyManual.patches.length === 0);

  console.log("\nMerge confidence (semver risk signal)");
  ok("patch bump classified patch", classifyBump("4.17.15", "4.17.21") === "patch");
  ok("minor bump classified minor", classifyBump("1.2.0", "1.5.0") === "minor");
  ok("major bump classified major", classifyBump("1.2.0", "2.0.0") === "major");
  ok("non-semver classified unknown", classifyBump("latest", "x") === "unknown");
  const conf = plan.confidence;
  ok("plan exposes per-bump confidence", Array.isArray(conf) && conf.length === 2);
  ok("lodash bump scored patch", conf.find((c) => c.name === "lodash")?.level === "patch", JSON.stringify(conf));
  ok("minimist override scored patch", conf.find((c) => c.name === "minimist")?.level === "patch");
  ok("all-patch plan scores 100", confidenceScore(conf) === 100, String(confidenceScore(conf)));
  ok("a major bump lowers the score", confidenceScore([{ level: "major" }]) === 40);
} finally {
  await rm(dir, { recursive: true, force: true });
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
