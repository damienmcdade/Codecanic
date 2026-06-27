// Codecanic real repair engine (v1).
//
// Turns approved scan findings into an actual pull request: it clones the repo
// with the org's provider token, applies deterministic safe patches, commits,
// pushes a branch, and opens a GitHub PR. Findings that can't be auto-fixed
// safely (secrets, key files) are listed in the PR body as manual action items.
//
// planRepairs()/applyPlan() are pure/IO-light and unit-tested offline; runRepair()
// performs the clone/commit/push/PR and is the production path.
import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm, unlink, mkdir, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname, relative, isAbsolute } from "node:path";
import { createHash } from "node:crypto";
import { validateGitUrl, dirSizeExceeds } from "./_scanner.js";
import { fetchWithTimeout } from "./_http.js";

const CLONE_TIMEOUT_MS = 60_000;
const MAX_CLONE_BYTES = 2_000_000_000; // 2 GB — disk-exhaustion guard (see _scanner.js)
const CLONE_SIZE_POLL_MS = 3_000;
const GIT_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// Planning (pure): findings -> patch operations + manual items
// ---------------------------------------------------------------------------
const CI_WORKFLOW = `name: CI
on:
  push:
    branches: [main, master]
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci || npm install
      - run: npm test --if-present
`;

export function planRepairs(findings = []) {
  const bumps = new Map(); // name -> fixedVersion (direct)
  const overrides = new Map(); // name -> fixedVersion (transitive)
  const froms = new Map(); // name -> currentVersion (for confidence scoring)
  const tsconfigs = new Set();
  const envFiles = new Set();
  let addCi = false;
  const codeReplaces = [];
  const manual = [];

  for (const f of findings) {
    const r = f?.remediation;
    if (!r) {
      manual.push({ id: f.id, title: f.title, target: f.target, fix: f.fix, reason: manualReason(f) });
      continue;
    }
    switch (r.kind) {
      case "npm-bump-direct": bumps.set(r.packageName, pickHigher(bumps.get(r.packageName), r.fixedVersion)); froms.set(r.packageName, r.currentVersion); break;
      case "npm-override": overrides.set(r.packageName, pickHigher(overrides.get(r.packageName), r.fixedVersion)); froms.set(r.packageName, r.currentVersion); break;
      case "tsconfig-strict": tsconfigs.add(r.file); break;
      case "gitignore-env": envFiles.add(r.file); break;
      case "add-ci": addCi = true; break;
      case "code-replace": codeReplaces.push({ file: r.file, line: r.line, search: r.search, replace: r.replace, title: f.title }); break;
      default: manual.push({ id: f.id, title: f.title, target: f.target, fix: f.fix, reason: "no automated remediation" });
    }
  }

  const patches = [];
  if (bumps.size || overrides.size) {
    patches.push({ kind: "npm-deps", bumps: Object.fromEntries(bumps), overrides: Object.fromEntries(overrides) });
  }
  for (const file of tsconfigs) patches.push({ kind: "tsconfig-strict", file });
  for (const file of envFiles) patches.push({ kind: "gitignore-env", file });
  if (addCi) patches.push({ kind: "add-ci" });
  for (const cr of codeReplaces) patches.push({ kind: "code-replace", ...cr });

  // Merge-confidence: classify each dependency bump by semver delta so the PR
  // carries a risk signal (the user's CI, triggered by the PR, does the real
  // validation — running their code on our servers would be unsafe).
  const confidence = [];
  for (const [name, to] of [...bumps, ...overrides]) {
    const from = froms.get(name);
    const level = classifyBump(from, to);
    confidence.push({ name, from, to, level, direct: bumps.has(name) });
  }

  return { patches, manual, confidence };
}

// "patch" | "minor" | "major" | "unknown" — major bumps may include breaking changes.
export function classifyBump(from, to) {
  const pa = String(from || "").match(/(\d+)\.(\d+)\.(\d+)/);
  const pb = String(to || "").match(/(\d+)\.(\d+)\.(\d+)/);
  if (!pa || !pb) return "unknown";
  if (pa[1] !== pb[1]) return "major";
  if (pa[2] !== pb[2]) return "minor";
  return "patch";
}

function pickHigher(a, b) {
  if (!a) return b;
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0) ? a : b;
  return a;
}

function manualReason(f) {
  if (f.category === "secret") return "secrets must be rotated by a human; auto-editing could break the app or leak history";
  if (f.id?.startsWith("hygiene:key-file")) return "key removal + rotation must be done manually";
  if (f.id?.startsWith("hygiene:npmrc-token")) return "token removal must be done manually";
  if (f.id?.startsWith("hygiene:no-lockfile")) return "generating a lockfile requires installing dependencies";
  return "no automated remediation available";
}

// ---------------------------------------------------------------------------
// Application: mutate an on-disk tree per the plan
// ---------------------------------------------------------------------------
async function exists(p) { try { await access(p); return true; } catch { return false; } }

export async function applyPlan(dir, plan) {
  const changed = new Set();
  const removed = new Set();
  const summary = [];

  for (const patch of plan.patches) {
    if (patch.kind === "npm-deps") {
      const pkgPath = join(dir, "package.json");
      if (!(await exists(pkgPath))) { summary.push("skipped npm bumps: no package.json"); continue; }
      const raw = await readFile(pkgPath, "utf8");
      let json;
      try { json = JSON.parse(raw); } catch { summary.push("skipped npm bumps: unparsable package.json"); continue; }
      let touched = false;
      for (const [name, version] of Object.entries(patch.bumps)) {
        for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
          if (json[field] && json[field][name]) { json[field][name] = `^${version}`; touched = true; summary.push(`bump ${name} -> ^${version}`); }
        }
      }
      const overrides = patch.overrides || {};
      if (Object.keys(overrides).length) {
        json.overrides = json.overrides || {};
        for (const [name, version] of Object.entries(overrides)) {
          json.overrides[name] = `^${version}`; touched = true; summary.push(`override ${name} -> ^${version}`);
        }
      }
      if (touched) {
        const indent = raw.match(/\n(\s+)"/)?.[1]?.length || 2;
        await writeFile(pkgPath, JSON.stringify(json, null, indent) + "\n");
        changed.add("package.json");
      }
    } else if (patch.kind === "tsconfig-strict") {
      const p = join(dir, patch.file);
      if (!(await exists(p))) continue;
      const raw = await readFile(p, "utf8");
      let json;
      try { json = JSON.parse(raw.replace(/\/\/.*$/gm, "").replace(/,(\s*[}\]])/g, "$1")); } catch { summary.push(`skipped ${patch.file}: unparsable`); continue; }
      json.compilerOptions = json.compilerOptions || {};
      json.compilerOptions.strict = true;
      await writeFile(p, JSON.stringify(json, null, 2) + "\n");
      changed.add(patch.file);
      summary.push(`enable strict in ${patch.file}`);
    } else if (patch.kind === "gitignore-env") {
      const giPath = join(dir, ".gitignore");
      let gi = (await exists(giPath)) ? await readFile(giPath, "utf8") : "";
      const entry = patch.file;
      const lines = gi.split("\n").map((l) => l.trim());
      if (!lines.includes(entry) && !lines.includes(`/${entry}`)) {
        gi = gi.replace(/\s*$/, "") + `\n${entry}\n`;
        await writeFile(giPath, gi.replace(/^\n/, ""));
        changed.add(".gitignore");
      }
      const envPath = join(dir, patch.file);
      if (await exists(envPath)) { await unlink(envPath); removed.add(patch.file); summary.push(`untrack ${patch.file}`); }
    } else if (patch.kind === "add-ci") {
      const wfPath = join(dir, ".github", "workflows", "codecanic-ci.yml");
      if (!(await exists(wfPath))) {
        await mkdir(dirname(wfPath), { recursive: true });
        await writeFile(wfPath, CI_WORKFLOW);
        changed.add(".github/workflows/codecanic-ci.yml");
        summary.push("add CI workflow");
      }
    } else if (patch.kind === "code-replace") {
      // Apply a safe, line-local SAST fix (e.g. md5→sha256, yaml.load→safe_load).
      const p = join(dir, patch.file);
      if (!(await exists(p))) continue;
      const raw = await readFile(p, "utf8");
      const lines = raw.split("\n");
      const idx = patch.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let re;
      try { re = new RegExp(patch.search); } catch { continue; }
      if (!re.test(lines[idx])) continue; // line drifted — skip rather than corrupt
      lines[idx] = lines[idx].replace(re, patch.replace);
      await writeFile(p, lines.join("\n"));
      changed.add(patch.file);
      summary.push(`fix ${patch.file}:${patch.line} (${patch.title})`);
    } else if (patch.kind === "code-rewrite") {
      // AI-generated edit (BYOK): a literal, possibly multi-line snippet swap.
      // Literal (not regex) so model output with metacharacters is safe, and we
      // only apply when the exact original snippet is still present.
      const rel = String(patch.file || "");
      const p = join(dir, rel);
      // Containment guard: never let an edit escape the cloned tree.
      if (relative(dir, p).startsWith("..") || isAbsolute(rel)) { summary.push(`skipped ai fix: invalid path ${rel}`); continue; }
      if (!(await exists(p))) { summary.push(`skipped ai fix ${rel}: file missing`); continue; }
      const raw = await readFile(p, "utf8");
      const at = raw.indexOf(patch.find);
      if (at === -1) { summary.push(`skipped ai fix ${rel}: source drifted`); continue; }
      // Replace only the first occurrence to keep the edit minimal.
      const next = raw.slice(0, at) + patch.replace + raw.slice(at + patch.find.length);
      if (next === raw) continue;
      await writeFile(p, next);
      changed.add(rel);
      summary.push(`AI fix ${rel} (${patch.title})`);
    }
  }

  return { changed: [...changed], removed: [...removed], summary };
}

// ---------------------------------------------------------------------------
// Git + GitHub helpers
// ---------------------------------------------------------------------------
function git(args, { cwd, timeout = GIT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn("git", args, { cwd, env: { ...process.env, GIT_TERMINAL_PROMPT: "0" }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("git operation timed out")); }, timeout);
    child.on("error", (e) => { clearTimeout(timer); reject(e); });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) return resolve(out.trim());
      reject(new Error(`git ${args[0]} failed: ${(err || out).replace(/https:\/\/[^@\s]+@/g, "https://***@").trim().split("\n").pop()}`));
    });
  });
}

function cloneAuthed(cloneUrl, dest) {
  return new Promise((resolve, reject) => {
    // The clone URL embeds the GitHub token, so harden against a 3xx redirect to
    // an attacker host leaking it: disable redirect following + interactive
    // credential prompts, matching the read-only scan clone in _scanner.js.
    const child = spawn(
      "git",
      [
        "-c", "credential.helper=",
        "-c", "core.askpass=true",
        "-c", "http.followRedirects=false",
        "clone", "--depth", "1", "--single-branch", "--no-tags", cloneUrl, dest
      ],
      { env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GCM_INTERACTIVE: "never" }, stdio: ["ignore", "ignore", "pipe"] }
    );
    let err = "";
    child.stderr.on("data", (d) => { err += d; if (err.length > 4000) err = err.slice(-4000); });
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("Repository clone timed out.")); }, CLONE_TIMEOUT_MS);
    const sizeWatch = setInterval(async () => {
      if (await dirSizeExceeds(dest, MAX_CLONE_BYTES)) {
        clearInterval(sizeWatch);
        child.kill("SIGKILL");
        reject(new Error("Repository exceeds the maximum clone size."));
      }
    }, CLONE_SIZE_POLL_MS);
    child.on("error", (e) => { clearTimeout(timer); clearInterval(sizeWatch); reject(new Error(`git not available: ${e.message}`)); });
    child.on("close", (code) => {
      clearTimeout(timer);
      clearInterval(sizeWatch);
      if (code === 0) return resolve();
      const safe = err.replace(/https:\/\/[^@\s]+@/g, "https://***@");
      if (/Authentication failed|could not read Username|terminal prompts disabled|not found|HTTP Basic/i.test(safe)) {
        reject(new Error("Could not access repository — connect the provider with write access, or check the URL."));
      } else reject(new Error(`Clone failed: ${safe.split("\n").pop() || code}`));
    });
  });
}

async function createGithubPr({ owner, repo, head, base, title, body, token }) {
  const res = await fetchWithTimeout(`https://api.github.com/repos/${owner}/${repo}/pulls`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "Codecanic",
      "X-GitHub-Api-Version": "2022-11-28"
    },
    body: JSON.stringify({ title, head, base, body, maintainer_can_modify: true })
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 201) return { url: data.html_url, number: data.number };
  if (res.status === 422 && /A pull request already exists/i.test(JSON.stringify(data))) {
    throw new Error("A pull request for this branch already exists.");
  }
  throw new Error(`GitHub PR creation failed (${res.status}): ${data.message || "unknown error"}`);
}

const CONFIDENCE_ICON = { patch: "🟢", minor: "🟡", major: "🔴", unknown: "⚪" };

function buildPrBody(applied, manual, confidence, reportId, aiNotes = []) {
  const lines = ["## Codecanic automated repairs", "", "This PR was generated by Codecanic from an approved scan report.", ""];
  if (applied.summary.length) {
    lines.push("### Applied fixes");
    for (const s of applied.summary) lines.push(`- ${s}`);
    if (applied.changed.length) lines.push("", `Changed: ${applied.changed.join(", ")}`);
    if (applied.removed.length) lines.push(`Removed: ${applied.removed.join(", ")}`);
    if (applied.summary.some((s) => /bump|override/.test(s))) {
      lines.push("", "> ⚠️ Dependency versions were updated in `package.json`. Run `npm install` to refresh the lockfile before merging.");
    }
    if (applied.summary.some((s) => s.startsWith("AI fix"))) {
      lines.push("", "> 🤖 Some edits were generated by an AI model using **your own API key**. Review them as you would any AI-suggested change; your CI is the final gate.");
    }
  }
  if (confidence?.length) {
    lines.push("", "### Merge confidence");
    for (const c of confidence) {
      lines.push(`- ${CONFIDENCE_ICON[c.level] || "⚪"} \`${c.name}\` ${c.from || "?"} → ${c.to} — **${c.level}** update${c.level === "major" ? " (may include breaking changes — review carefully)" : ""}`);
    }
    lines.push("", "> This PR triggers your CI; rely on those checks as the final gate. Major upgrades warrant the closest review.");
  }
  if (Array.isArray(aiNotes) && aiNotes.length) {
    lines.push("", "### AI repair notes");
    for (const n of aiNotes) lines.push(`- ${n}`);
  }
  if (manual.length) {
    lines.push("", "### Manual action required (not auto-fixed)");
    for (const m of manual) lines.push(`- **${m.title}** (${m.target}) — ${m.reason}`);
  }
  lines.push("", `_Report: ${reportId || "n/a"} · generated by Codecanic_`);
  return lines.join("\n");
}

// A coarse 0–100 confidence score for the PR overall: patch=high, major=low.
export function confidenceScore(confidence = []) {
  if (!confidence.length) return 100;
  const weight = { patch: 100, minor: 80, major: 40, unknown: 60 };
  return Math.round(confidence.reduce((s, c) => s + (weight[c.level] ?? 60), 0) / confidence.length);
}

// ---------------------------------------------------------------------------
// Orchestration (production path)
// ---------------------------------------------------------------------------
// Deterministic branch name from the repair inputs (report + the exact set of
// findings). A retried job reuses the SAME branch, so the existing-branch/PR
// 422 guard short-circuits instead of opening a duplicate PR.
export function repairBranchName(reportId, findings = []) {
  const ids = (findings || []).map((f) => f?.id).filter(Boolean).sort();
  const hash = createHash("sha256").update(`${reportId || ""}|${ids.join(",")}`).digest("hex").slice(0, 12);
  return `codecanic/repair-${hash}`;
}

export async function runRepair({ sourceUrl, token, findings, reportId = null, aiPatches = [], aiHandledIds = [], aiNotes = [] }) {
  const meta = validateGitUrl(sourceUrl);
  if (!meta.host.endsWith("github.com")) {
    const e = new Error("Automated pull requests are supported for GitHub repositories in v1.");
    e.code = "unsupported";
    throw e;
  }
  if (!token) {
    const e = new Error("Connect GitHub with write access for this organization to open repair pull requests.");
    e.code = "access";
    throw e;
  }

  const plan = planRepairs(findings);
  // Fold in AI-generated edits computed at request time on the user's own key,
  // and stop listing those findings as "manual" since they now have a fix.
  if (Array.isArray(aiPatches) && aiPatches.length) {
    plan.patches.push(...aiPatches);
  }
  if (Array.isArray(aiHandledIds) && aiHandledIds.length) {
    const handled = new Set(aiHandledIds);
    plan.manual = plan.manual.filter((m) => !handled.has(m.id));
  }
  if (Array.isArray(aiNotes) && aiNotes.length) {
    plan.aiNotes = aiNotes;
  }
  if (!plan.patches.length) {
    return { opened: false, reason: "No automatically-fixable findings were selected.", applied: { changed: [], removed: [], summary: [] }, manual: plan.manual };
  }

  const base = process.env.CODECANIC_SCAN_TMP || tmpdir();
  const workDir = await mkdtemp(join(base, "codecanic-repair-"));
  const cloneUrl = `https://x-access-token:${token}@${meta.cleanUrl.replace(/^https:\/\//, "")}`;
  try {
    await cloneAuthed(cloneUrl, workDir);
    const baseBranch = await git(["rev-parse", "--abbrev-ref", "HEAD"], { cwd: workDir });
    // Deterministic branch (R1): a retry of the SAME (report, findings) reuses
    // this branch. If it already exists on the remote, a PR was already opened
    // for it — short-circuit rather than push a duplicate.
    const branch = repairBranchName(reportId, findings);
    let remoteHas = false;
    try {
      const ls = await git(["ls-remote", "--heads", "origin", branch], { cwd: workDir });
      remoteHas = Boolean(ls && ls.trim());
    } catch { /* ls-remote best-effort; fall through to the normal push/PR guard */ }
    if (remoteHas) {
      return { opened: false, reason: "A repair branch for these findings already exists; a pull request was already opened.", branch, baseBranch, applied: { changed: [], removed: [], summary: [] }, manual: plan.manual };
    }
    await git(["checkout", "-b", branch], { cwd: workDir });

    const applied = await applyPlan(workDir, plan);
    if (!applied.changed.length && !applied.removed.length) {
      return { opened: false, reason: "Selected fixes produced no file changes (already applied?).", applied, manual: plan.manual };
    }

    await git(["config", "user.email", "bot@codecanic.app"], { cwd: workDir });
    await git(["config", "user.name", "Codecanic Bot"], { cwd: workDir });
    await git(["add", "-A"], { cwd: workDir });
    await git(["commit", "-m", "Codecanic: automated security & hygiene repairs"], { cwd: workDir });
    await git(["push", "-u", "origin", branch], { cwd: workDir, timeout: CLONE_TIMEOUT_MS });

    const title = `Codecanic: ${applied.summary.length} automated repair${applied.summary.length === 1 ? "" : "s"}`;
    const body = buildPrBody(applied, plan.manual, plan.confidence, reportId, plan.aiNotes);
    const pr = await createGithubPr({ owner: meta.owner, repo: meta.repo, head: branch, base: baseBranch, title, body, token });

    return {
      opened: true, pullRequestUrl: pr.url, pullRequestNumber: pr.number, branch, baseBranch,
      applied, manual: plan.manual, confidence: plan.confidence, confidenceScore: confidenceScore(plan.confidence)
    };
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}
