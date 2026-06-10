// Codecanic real scan engine (v1).
//
// Replaces the previous hardcoded findings with genuine analysis of an actual
// repository tree. Three real analyzers run over a cloned (or on-disk) repo:
//   1. Dependency SCA  — parses manifests/lockfiles and queries OSV.dev for
//      known vulnerabilities (npm + PyPI).
//   2. Secret scanning — gitleaks-style regex + entropy over text files.
//   3. Repo hygiene    — deterministic file/content checks (committed secrets,
//      missing CI, tsconfig strict, missing lockfile, etc.).
//
// `scanDirectory(dir)` analyzes an on-disk tree (used directly by tests).
// `scanRepository({ sourceUrl, token })` validates + shallow-clones first.
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, extname, basename } from "node:path";
import { randomUUID } from "node:crypto";

// ---------------------------------------------------------------------------
// Limits (bound resource use / DoS surface)
// ---------------------------------------------------------------------------
const MAX_FILE_BYTES = 1_500_000; // skip files larger than this for content scans
const MAX_FILES = 8000; // cap tree walk
const MAX_FINDINGS = 500;
const CLONE_TIMEOUT_MS = 60_000;
// Hard ceiling on what an untrusted clone may write to worker disk. The 60s
// timeout only bounds *time* — a fast link can push gigabytes (one huge tip
// blob, or thousands of large blobs) and fill the worker disk before the
// per-file walk caps (which only bound reads, not the clone's writes) apply.
// A watchdog polls the clone dir and SIGKILLs git if it exceeds this.
const MAX_CLONE_BYTES = 2_000_000_000; // 2 GB
const CLONE_SIZE_POLL_MS = 3_000;

// Cheap bounded directory-size check: sums file sizes, skips symlinks, and
// early-exits as soon as the cap is exceeded so it stays fast on normal repos.
export async function dirSizeExceeds(dir, capBytes) {
  let total = 0;
  async function walk(d) {
    let entries;
    try { entries = await readdir(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (total > capBytes) return;
      const p = join(d, e.name);
      try {
        if (e.isSymbolicLink()) continue;
        if (e.isDirectory()) await walk(p);
        else { total += (await stat(p)).size; }
      } catch { /* file may vanish mid-clone — ignore */ }
    }
  }
  await walk(dir);
  return total > capBytes;
}
const OSV_TIMEOUT_MS = 15_000;
const MAX_OSV_PACKAGES = 600;

const SKIP_DIRS = new Set([
  ".git", "node_modules", "vendor", "dist", "build", ".next", ".turbo",
  "coverage", ".cache", "out", "target", ".venv", "venv", "__pycache__",
  ".gradle", "Pods", ".terraform", "bower_components"
]);

const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip",
  ".gz", ".tar", ".tgz", ".bz2", ".7z", ".rar", ".jar", ".war", ".class",
  ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".mov", ".avi",
  ".wav", ".bin", ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".node",
  ".wasm", ".pyc", ".lock", ".min.js", ".map"
]);

// ---------------------------------------------------------------------------
// URL validation + clone (SSRF-safe)
// ---------------------------------------------------------------------------
const DEFAULT_ALLOWED_HOSTS = new Set([
  "github.com", "www.github.com", "gitlab.com", "bitbucket.org"
]);

function allowedHosts() {
  const extra = (process.env.CODECANIC_SCAN_ALLOWED_HOSTS || "")
    .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  return new Set([...DEFAULT_ALLOWED_HOSTS, ...extra]);
}

export function validateGitUrl(sourceUrl) {
  let url;
  try {
    url = new URL(String(sourceUrl || "").trim());
  } catch {
    throw new Error("Provide a valid repository URL (https://host/owner/repo).");
  }
  if (url.protocol !== "https:") {
    throw new Error("Repository URL must use https.");
  }
  if (url.username || url.password) {
    throw new Error("Do not put credentials in the repository URL; connect the provider instead.");
  }
  const host = url.hostname.toLowerCase();
  if (!allowedHosts().has(host)) {
    throw new Error(`Unsupported host "${host}". Supported: ${[...allowedHosts()].join(", ")}.`);
  }
  // Normalize to a clean clone URL: strip trailing slash, ensure .git is fine either way.
  const path = url.pathname.replace(/\/+$/, "");
  const segments = path.split("/").filter(Boolean);
  if (segments.length < 2) {
    throw new Error("Repository URL must include an owner and repository name.");
  }
  const owner = segments[0];
  const repo = segments[1].replace(/\.git$/, "");
  // Harden: owner/repo flow into the GitHub API URL for PR creation
  // (api.github.com/repos/${owner}/${repo}/pulls). Reject anything that
  // isn't a plain provider slug so percent-encoded path-traversal
  // (`..%2f..`) or CRLF (`repo%0d%0aHost:`) can't ride into that URL.
  const SLUG = /^[A-Za-z0-9._-]+$/;
  if (!SLUG.test(owner) || !SLUG.test(repo)) {
    throw new Error("Repository owner and name may only contain letters, numbers, dots, underscores, and hyphens.");
  }
  return { host, owner, repo, cleanUrl: `https://${host}${path}` };
}

function authedCloneUrl({ host, cleanUrl }, token) {
  if (!token) return cleanUrl;
  const without = cleanUrl.replace(/^https:\/\//, "");
  // Provider-specific credential injection for private repos.
  if (host.endsWith("github.com")) return `https://x-access-token:${token}@${without}`;
  if (host.endsWith("gitlab.com")) return `https://oauth2:${token}@${without}`;
  if (host.endsWith("bitbucket.org")) return `https://x-token-auth:${token}@${without}`;
  return `https://${token}@${without}`;
}

function cloneRepo(cloneUrl, dest) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "git",
      [
        "-c", "credential.helper=",
        "-c", "core.askpass=true",
        "-c", "http.followRedirects=false",
        "clone", "--depth", "1", "--single-branch", "--no-tags",
        "--config", "advice.detachedHead=false",
        cloneUrl, dest
      ],
      { env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GCM_INTERACTIVE: "never" }, stdio: ["ignore", "ignore", "pipe"] }
    );
    let stderr = "";
    child.stderr.on("data", (d) => { stderr += d.toString(); if (stderr.length > 4000) stderr = stderr.slice(-4000); });
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("Repository clone timed out.")); }, CLONE_TIMEOUT_MS);
    // Disk-exhaustion watchdog: kill the clone if it writes more than the cap.
    const sizeWatch = setInterval(async () => {
      if (await dirSizeExceeds(dest, MAX_CLONE_BYTES)) {
        clearInterval(sizeWatch);
        child.kill("SIGKILL");
        reject(new Error("Repository exceeds the maximum clone size."));
      }
    }, CLONE_SIZE_POLL_MS);
    child.on("error", (err) => { clearTimeout(timer); clearInterval(sizeWatch); reject(new Error(`git not available: ${err.message}`)); });
    child.on("close", (code) => {
      clearTimeout(timer);
      clearInterval(sizeWatch);
      if (code === 0) return resolve();
      // Redact any token that may appear in echoed URLs.
      const safe = stderr.replace(/https:\/\/[^@\s]+@/g, "https://***@").trim();
      if (/Authentication failed|could not read Username|terminal prompts disabled|repository .* not found|HTTP Basic/i.test(safe)) {
        reject(new Error("Could not access repository — it may be private. Connect the provider for this organization, or check the URL."));
      } else {
        reject(new Error(`Clone failed: ${safe.split("\n").pop() || `git exited ${code}`}`));
      }
    });
  });
}

async function headCommit(dir) {
  return new Promise((resolve) => {
    const child = spawn("git", ["-C", dir, "rev-parse", "HEAD"], { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.on("close", () => resolve(out.trim() || null));
    child.on("error", () => resolve(null));
  });
}

// ---------------------------------------------------------------------------
// Tree walk
// ---------------------------------------------------------------------------
async function walk(root) {
  const files = [];
  async function recur(dir) {
    if (files.length >= MAX_FILES) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const full = join(dir, entry.name);
      // Skip symlinks: a symlinked directory cycle would waste the clone budget
      // re-walking, and a symlink out of the workdir could pull in unintended
      // files for content scanning.
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        await recur(full);
      } else if (entry.isFile()) {
        files.push(full);
      }
    }
  }
  await recur(root);
  return files;
}

function isBinaryName(path) {
  const lower = path.toLowerCase();
  for (const ext of BINARY_EXT) if (lower.endsWith(ext)) return true;
  return false;
}

async function readText(path) {
  try {
    const info = await stat(path);
    if (info.size > MAX_FILE_BYTES) return null;
    const buf = await readFile(path);
    if (buf.includes(0)) return null; // binary sniff: NUL byte
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Analyzer 1: dependency SCA via OSV.dev
// ---------------------------------------------------------------------------
function cleanVersion(spec) {
  if (typeof spec !== "string") return null;
  const m = spec.match(/\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?/);
  return m ? m[0] : null;
}

function parsePackageLock(json) {
  const out = [];
  if (json && json.packages && typeof json.packages === "object") {
    for (const [key, meta] of Object.entries(json.packages)) {
      if (!key || !meta || !meta.version) continue;
      const name = key.startsWith("node_modules/") ? key.split("node_modules/").pop() : meta.name;
      if (!name) continue;
      out.push({ ecosystem: "npm", name, version: meta.version });
    }
  }
  if (!out.length && json && json.dependencies && typeof json.dependencies === "object") {
    const recur = (deps) => {
      for (const [name, meta] of Object.entries(deps)) {
        if (meta && meta.version) out.push({ ecosystem: "npm", name, version: meta.version });
        if (meta && meta.dependencies) recur(meta.dependencies);
      }
    };
    recur(json.dependencies);
  }
  return out;
}

function parsePackageJson(json) {
  const out = [];
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const deps = json[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps)) {
      const version = cleanVersion(spec);
      if (version) out.push({ ecosystem: "npm", name, version });
    }
  }
  return out;
}

function parseYarnLock(text) {
  const out = [];
  const blocks = text.split(/\n(?=\S)/);
  for (const block of blocks) {
    const header = block.split("\n")[0] || "";
    const vline = block.match(/\n\s+version:?\s+"?([^"\n]+)"?/);
    if (!vline) continue;
    const nameMatch = header.match(/^"?(@?[^@"]+)@/);
    if (!nameMatch) continue;
    out.push({ ecosystem: "npm", name: nameMatch[1], version: vline[1].trim() });
  }
  return out;
}

function parseRequirementsTxt(text) {
  const out = [];
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)\s*==\s*([0-9][^\s;]*)/);
    if (m) out.push({ ecosystem: "PyPI", name: m[1], version: m[2] });
  }
  return out;
}

function dedupePackages(pkgs) {
  const seen = new Map();
  for (const p of pkgs) {
    if (!p.name || !p.version) continue;
    const key = `${p.ecosystem}:${p.name}:${p.version}`;
    if (!seen.has(key)) seen.set(key, p);
  }
  return [...seen.values()];
}

async function collectPackages(root, files) {
  const pkgs = [];
  let parsedLock = false;
  for (const file of files) {
    const name = basename(file).toLowerCase();
    if (name === "package-lock.json") {
      const text = await readText(file);
      if (text) { try { pkgs.push(...parsePackageLock(JSON.parse(text))); parsedLock = true; } catch {} }
    }
  }
  for (const file of files) {
    const name = basename(file).toLowerCase();
    if (name === "yarn.lock") {
      const text = await readText(file);
      if (text) { pkgs.push(...parseYarnLock(text)); parsedLock = true; }
    }
  }
  // Only fall back to package.json ranges when no lockfile gave us concrete versions.
  if (!parsedLock) {
    for (const file of files) {
      if (basename(file).toLowerCase() === "package.json") {
        const text = await readText(file);
        if (text) { try { pkgs.push(...parsePackageJson(JSON.parse(text))); } catch {} }
      }
    }
  }
  for (const file of files) {
    if (basename(file).toLowerCase() === "requirements.txt") {
      const text = await readText(file);
      if (text) pkgs.push(...parseRequirementsTxt(text));
    }
  }
  return dedupePackages(pkgs);
}

async function osvFetch(path, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OSV_TIMEOUT_MS);
  try {
    const res = await fetch(`https://api.osv.dev${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`OSV ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

// Map a numeric CVSS base score (0–10) to a severity bucket/label.
export function scoreToSeverity(score) {
  if (score >= 9) return { label: "critical", critical: true };
  if (score >= 7) return { label: "high", critical: true };
  if (score >= 4) return { label: "moderate", critical: false };
  if (score > 0) return { label: "low", critical: false };
  return { label: "low", critical: false };
}

function severityFromVuln(vuln) {
  // 1) OSV severity[] entries — usually a CVSS *vector* (CVSS_V3/CVSS_V31), but
  //    can also be a bare numeric score. Take the highest score we can derive.
  const sev = Array.isArray(vuln?.severity) ? vuln.severity : [];
  let best = null;
  for (const s of sev) {
    const score = parseCvssScore(s?.score);
    if (score != null && (best == null || score > best)) best = score;
  }

  // 2) database_specific fallbacks (cvss numeric, or a qualitative label).
  if (best == null) {
    const dsScore = parseCvssScore(vuln?.database_specific?.cvss?.score ?? vuln?.database_specific?.cvss);
    if (dsScore != null) best = dsScore;
  }
  if (best != null) return scoreToSeverity(best);

  const ds = vuln?.database_specific?.severity ?? vuln?.database_specific?.cvss?.severity;
  if (typeof ds === "string") {
    const u = ds.toUpperCase();
    if (u === "CRITICAL" || u === "HIGH") return { label: u.toLowerCase(), critical: true };
    if (u === "MODERATE" || u === "MEDIUM") return { label: "moderate", critical: false };
    if (u === "LOW") return { label: "low", critical: false };
  }
  return { label: "moderate", critical: false };
}

// Accept a CVSS *vector* string (compute the 3.x base score) OR a bare numeric
// score. Returns a number 0–10, or null if it can't be parsed.
export function parseCvssScore(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string") return null;
  const v = value.trim();
  if (/^\d+(\.\d+)?$/.test(v)) return Number(v);
  if (/^CVSS:3\.[01]\//i.test(v)) return cvss3BaseScore(v);
  return null;
}

// CVSS v3.0/v3.1 base-score calculator from the vector string. Implements the
// official base metric equations (FIRST.org CVSS v3.1 spec §7.1). Returns a
// number 0–10 (1-decimal, round-up) or null if required metrics are missing.
export function cvss3BaseScore(vector) {
  const m = {};
  for (const part of String(vector).split("/")) {
    const [k, val] = part.split(":");
    if (k && val) m[k.toUpperCase()] = val.toUpperCase();
  }
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const PR_S = { N: 0.85, L: 0.62, H: 0.27 }; // scope unchanged
  const PR_C = { N: 0.85, L: 0.68, H: 0.5 };  // scope changed
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const scopeChanged = m.S === "C";
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const PR = (scopeChanged ? PR_C : PR_S)[m.PR];
  const imp = { N: 0, L: 0.22, H: 0.56 };
  const C = imp[m.C], I = imp[m.I], A = imp[m.A];
  if ([AV, AC, PR, UI, C, I, A].some((x) => x == null)) return null;

  const iscBase = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = scopeChanged
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;
  const exploitability = 8.22 * AV * AC * PR * UI;
  if (impact <= 0) return 0;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUp1(raw);
}

// CVSS "Roundup": smallest 1-decimal number >= the input (spec §Appendix A).
function roundUp1(x) {
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

// Minimal semver compare on major.minor.patch (ignores pre-release ordering).
export function semverCmp(a, b) {
  const pa = String(a).replace(/^[^\d]*/, "").split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b).replace(/^[^\d]*/, "").split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

// From an OSV vuln, find the lowest "fixed" version for the given package that
// is greater than the currently-installed version.
export function extractFixedVersion(vuln, pkg) {
  const affected = Array.isArray(vuln?.affected) ? vuln.affected : [];
  const fixes = [];
  for (const a of affected) {
    if (a?.package?.name !== pkg.name) continue;
    for (const range of a.ranges || []) {
      for (const ev of range.events || []) {
        if (ev.fixed) fixes.push(ev.fixed);
      }
    }
  }
  const higher = fixes.filter((f) => semverCmp(f, pkg.version) > 0).sort(semverCmp);
  return higher[0] || fixes.sort(semverCmp).pop() || null;
}

async function readDirectDeps(files) {
  const direct = new Set();
  for (const file of files) {
    if (basename(file).toLowerCase() !== "package.json") continue;
    const text = await readText(file);
    if (!text) continue;
    try {
      const json = JSON.parse(text);
      for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
        for (const name of Object.keys(json[field] || {})) direct.add(name);
      }
    } catch {}
  }
  return direct;
}

async function analyzeDependencies(root, files) {
  const packages = await collectPackages(root, files);
  if (!packages.length) return { findings: [], scanned: { packages: 0, ecosystems: [] }, osv: "skipped" };

  const queried = packages.slice(0, MAX_OSV_PACKAGES);
  let batch;
  try {
    batch = await osvFetch("/v1/querybatch", {
      queries: queried.map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version }))
    });
  } catch (err) {
    return { findings: [], scanned: { packages: packages.length, ecosystems: [...new Set(packages.map((p) => p.ecosystem))] }, osv: `unavailable: ${err.message}` };
  }

  const results = Array.isArray(batch?.results) ? batch.results : [];
  const vulnIds = new Map(); // id -> { pkg }
  results.forEach((r, i) => {
    const vulns = r?.vulns || [];
    for (const v of vulns) if (v?.id && !vulnIds.has(v.id)) vulnIds.set(v.id, queried[i]);
  });

  const directNames = await readDirectDeps(files);

  // Fetch details for vulnerable packages (bounded).
  const findings = [];
  const ids = [...vulnIds.keys()].slice(0, 120);
  const details = await Promise.all(ids.map(async (id) => {
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), OSV_TIMEOUT_MS);
      const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: controller.signal });
      clearTimeout(t);
      if (!res.ok) return { id };
      return await res.json();
    } catch {
      return { id };
    }
  }));

  for (const vuln of details) {
    const pkg = vulnIds.get(vuln.id);
    if (!pkg) continue;
    const sev = severityFromVuln(vuln);
    const aliases = Array.isArray(vuln.aliases) ? vuln.aliases : [];
    const cve = aliases.find((a) => /^CVE-/.test(a)) || vuln.id;
    const summary = (vuln.summary || vuln.details || "Known vulnerability").split("\n")[0].slice(0, 200);
    const fixedVersion = extractFixedVersion(vuln, pkg);
    const direct = directNames.has(pkg.name);
    findings.push({
      id: `dep:${pkg.name}@${pkg.version}:${vuln.id}`,
      title: `Vulnerable dependency: ${pkg.name}@${pkg.version} (${cve})`,
      type: "security",
      category: "dependency",
      severity: sev.critical ? "critical" : "warning",
      severityLabel: sev.label,
      confidence: 95,
      target: `${pkg.ecosystem} · ${pkg.name}@${pkg.version}`,
      detail: summary,
      reference: `https://osv.dev/vulnerability/${vuln.id}`,
      fix: fixedVersion
        ? `Upgrade ${pkg.name} to ${fixedVersion} or later, regenerate the lockfile, and rerun tests.`
        : "Upgrade to a patched version, regenerate the lockfile, and rerun tests.",
      patchPreview: fixedVersion
        ? `Bump ${pkg.name} to ^${fixedVersion}.`
        : `Bump ${pkg.name} above the vulnerable range.`,
      // Structured data the repair engine consumes:
      remediation: fixedVersion ? { kind: direct ? "npm-bump-direct" : "npm-override", ecosystem: pkg.ecosystem, packageName: pkg.name, currentVersion: pkg.version, fixedVersion } : null
    });
  }

  return {
    findings,
    scanned: {
      packages: packages.length,
      ecosystems: [...new Set(packages.map((p) => p.ecosystem))],
      vulnerablePackages: new Set(findings.map((f) => f.target)).size
    },
    osv: "ok"
  };
}

// ---------------------------------------------------------------------------
// Analyzer 2: secret scanning
// ---------------------------------------------------------------------------
const SECRET_RULES = [
  { id: "aws-access-key", title: "AWS Access Key ID", critical: true, re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: "aws-secret-key", title: "AWS Secret Access Key", critical: true, re: /aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})/i },
  { id: "github-pat", title: "GitHub Personal Access Token", critical: true, re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/ },
  { id: "github-fine-grained", title: "GitHub fine-grained token", critical: true, re: /\bgithub_pat_[0-9a-zA-Z_]{82}\b/ },
  { id: "gitlab-pat", title: "GitLab Personal Access Token", critical: true, re: /\bglpat-[0-9A-Za-z_-]{20}\b/ },
  { id: "slack-token", title: "Slack token", critical: true, re: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/ },
  { id: "google-api-key", title: "Google API key", critical: true, re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "stripe-secret", title: "Stripe live secret key", critical: true, re: /\bsk_live_[0-9a-zA-Z]{24,}\b/ },
  { id: "private-key", title: "Private key material", critical: true, re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { id: "jwt", title: "Hardcoded JWT", critical: false, re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { id: "generic-secret", title: "Hardcoded secret/credential", critical: false, re: /(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[=:]\s*['"]([^'"\s]{12,})['"]/i, entropy: 3.2 }
];

function shannonEntropy(str) {
  const map = {};
  for (const ch of str) map[ch] = (map[ch] || 0) + 1;
  let e = 0;
  const len = str.length;
  for (const c of Object.values(map)) {
    const p = c / len;
    e -= p * Math.log2(p);
  }
  return e;
}

function redact(value) {
  if (value.length <= 8) return "****";
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

const SECRET_SCAN_EXT = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".env", ".yml", ".yaml",
  ".py", ".rb", ".go", ".java", ".kt", ".php", ".sh", ".bash", ".zsh", ".cfg",
  ".conf", ".ini", ".toml", ".properties", ".xml", ".txt", ".md", ".html", ".pem", ".key", ""
]);

async function analyzeSecrets(root, files) {
  const findings = [];
  let scannedFiles = 0;
  for (const file of files) {
    if (findings.length >= MAX_FINDINGS) break;
    if (isBinaryName(file)) continue;
    const ext = extname(file).toLowerCase();
    const base = basename(file).toLowerCase();
    const isEnv = base === ".env" || base.startsWith(".env");
    if (!SECRET_SCAN_EXT.has(ext) && !isEnv) continue;
    if (base.endsWith(".example") || base.endsWith(".sample") || base.endsWith(".template")) continue;
    const text = await readText(file);
    if (text == null) continue;
    scannedFiles++;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 2000) continue;
      for (const rule of SECRET_RULES) {
        const m = line.match(rule.re);
        if (!m) continue;
        const captured = m[1] || m[0];
        if (rule.entropy && shannonEntropy(captured) < rule.entropy) continue;
        findings.push({
          id: `secret:${rule.id}:${relative(root, file)}:${i + 1}`,
          title: `Exposed secret: ${rule.title}`,
          type: "security",
          category: "secret",
          severity: rule.critical ? "critical" : "warning",
          severityLabel: rule.critical ? "critical" : "moderate",
          confidence: rule.entropy ? 80 : 92,
          target: `${relative(root, file)}:${i + 1}`,
          detail: `Matched ${rule.title} (${redact(captured)}). Committed secrets must be treated as compromised.`,
          fix: "Rotate the credential immediately, remove it from history, and load it from a secret manager / env var.",
          patchPreview: "Replace the literal with a process.env reference and purge it from git history."
        });
        break; // one finding per line is enough
      }
    }
  }
  return { findings, scanned: { files: scannedFiles } };
}

// ---------------------------------------------------------------------------
// Analyzer 3: repo hygiene
// ---------------------------------------------------------------------------
async function analyzeHygiene(root, files) {
  const findings = [];
  const rels = files.map((f) => relative(root, f));
  const relSet = new Set(rels.map((r) => r.replace(/\\/g, "/")));
  const has = (re) => rels.some((r) => re.test(r.replace(/\\/g, "/")));

  // Committed secret files.
  for (const f of files) {
    const rel = relative(root, f).replace(/\\/g, "/");
    const base = basename(f).toLowerCase();
    if (base === ".env" || /^\.env\.(?!example|sample|template)/.test(base)) {
      findings.push(hyg("hygiene:committed-env", "Environment file committed to source control", "critical", rel,
        "A .env file is tracked in git. It typically holds live credentials.",
        "Remove it from the repo, add it to .gitignore, and rotate any exposed values.",
        { kind: "gitignore-env", file: rel }));
    } else if (/\.(pem|key|p12|pfx|keystore|jks)$/.test(base) || base === "id_rsa" || base === "id_dsa") {
      findings.push(hyg("hygiene:key-file", "Private key / keystore committed", "critical", rel,
        "A private key or keystore file is tracked in git.",
        "Remove it from the repo and history, and rotate the key."));
    } else if (base === ".npmrc") {
      const text = await readText(f);
      if (text && /_authToken\s*=/.test(text)) {
        findings.push(hyg("hygiene:npmrc-token", "npm auth token committed in .npmrc", "critical", rel,
          ".npmrc contains a registry _authToken.",
          "Remove the token and use NPM_TOKEN from the environment instead."));
      }
    }
  }

  // tsconfig strict off.
  for (const f of files) {
    if (/tsconfig.*\.json$/.test(basename(f))) {
      const text = await readText(f);
      if (!text) continue;
      let cfg;
      try { cfg = JSON.parse(text.replace(/\/\/.*$/gm, "").replace(/,(\s*[}\]])/g, "$1")); } catch { continue; }
      const co = cfg.compilerOptions || {};
      if (co.strict === false || (co.strict === undefined && co.noImplicitAny === false)) {
        findings.push(hyg("hygiene:ts-strict", "TypeScript strict mode disabled", "warning", relative(root, f).replace(/\\/g, "/"),
          "strict type-checking is off, which lets type-unsafe code through.",
          "Enable \"strict\": true and fix the surfaced type errors.",
          { kind: "tsconfig-strict", file: relative(root, f).replace(/\\/g, "/") }));
      }
    }
  }

  // package.json present but no lockfile.
  if (has(/(^|\/)package\.json$/) && !has(/(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json)$/)) {
    findings.push(hyg("hygiene:no-lockfile", "No dependency lockfile committed", "warning", "package.json",
      "Without a lockfile, installs are non-reproducible and harder to audit for supply-chain risk.",
      "Commit the generated lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml)."));
  }

  // No CI pipeline.
  const hasCI = has(/(^|\/)\.github\/workflows\//) || relSet.has(".gitlab-ci.yml") ||
    relSet.has("azure-pipelines.yml") || has(/(^|\/)\.circleci\//) || relSet.has(".travis.yml");
  if ((has(/(^|\/)package\.json$/) || has(/(^|\/)requirements\.txt$/)) && !hasCI) {
    findings.push(hyg("hygiene:no-ci", "No CI pipeline detected", "warning", "(repository root)",
      "No CI workflow was found, so changes can merge without automated build/test/scan.",
      "Add a CI workflow that runs build, tests, and security scans on every PR.",
      { kind: "add-ci" }));
  }

  return { findings };
}

function hyg(id, title, severity, target, detail, fix, remediation = null) {
  return {
    id, title, type: severity === "critical" ? "security" : "quality",
    category: "hygiene",
    severity, severityLabel: severity === "critical" ? "critical" : "moderate",
    confidence: 88, target, detail, fix,
    patchPreview: fix,
    remediation
  };
}

// ---------------------------------------------------------------------------
// Analyzer 4: lightweight SAST (Semgrep-style real-vuln patterns)
// ---------------------------------------------------------------------------
// Each rule matches a genuine vulnerability class. `autofix` (when present)
// makes a safe, line-local replacement the repair engine can open as a PR.
const SAST_RULES = [
  // JavaScript / TypeScript
  { id: "js-eval", langs: ["js"], re: /\beval\s*\(/, sev: "critical", title: "Use of eval() (code injection)", fix: "Avoid eval(); parse data explicitly or use a safe alternative." },
  { id: "js-new-function", langs: ["js"], re: /\bnew\s+Function\s*\(/, sev: "critical", title: "Dynamic new Function() (code injection)", fix: "Avoid constructing functions from strings." },
  { id: "js-child-exec", langs: ["js"], re: /\bexec(?:Sync)?\s*\(\s*[`'"][^`'")]*\$\{|\bexec(?:Sync)?\s*\([^)]*\+/, sev: "critical", title: "Command built from interpolation in exec() (command injection)", fix: "Use execFile/spawn with an args array; never interpolate user input into a shell command." },
  { id: "js-sql-concat", langs: ["js"], re: /\.(query|execute)\s*\(\s*[`'"][^`'"]*\$\{|\.(query|execute)\s*\([^)]*\+\s*\w/, sev: "critical", title: "SQL built by string concatenation (SQL injection)", fix: "Use parameterized queries / prepared statements." },
  { id: "js-weak-hash", langs: ["js"], re: /createHash\s*\(\s*['"](md5|sha1)['"]/, sev: "warning", title: "Weak hash algorithm (MD5/SHA-1)", fix: "Use SHA-256 or stronger.", autofix: { search: /(createHash\s*\(\s*['"])(md5|sha1)(['"])/, replace: "$1sha256$3" } },
  { id: "js-dangerous-html", langs: ["js"], re: /dangerouslySetInnerHTML/, sev: "warning", title: "dangerouslySetInnerHTML (XSS risk)", fix: "Sanitize HTML (e.g. DOMPurify) before injecting." },
  // Python
  { id: "py-eval-exec", langs: ["py"], re: /\b(eval|exec)\s*\(/, sev: "critical", title: "Use of eval()/exec() (code injection)", fix: "Avoid eval/exec on untrusted input." },
  { id: "py-yaml-load", langs: ["py"], re: /yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/, sev: "critical", title: "yaml.load() without SafeLoader (arbitrary code execution)", fix: "Use yaml.safe_load().", autofix: { search: /yaml\.load\s*\(/, replace: "yaml.safe_load(" } },
  { id: "py-pickle", langs: ["py"], re: /pickle\.loads?\s*\(/, sev: "critical", title: "pickle deserialization (RCE risk)", fix: "Avoid pickle on untrusted data; use JSON." },
  { id: "py-subprocess-shell", langs: ["py"], re: /subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True/, sev: "critical", title: "subprocess with shell=True (command injection)", fix: "Pass an args list and shell=False." },
  { id: "py-os-system", langs: ["py"], re: /\bos\.system\s*\(/, sev: "warning", title: "os.system() (command injection risk)", fix: "Use subprocess with an args list." },
  { id: "py-weak-hash", langs: ["py"], re: /hashlib\.(md5|sha1)\s*\(/, sev: "warning", title: "Weak hash algorithm (MD5/SHA-1)", fix: "Use hashlib.sha256.", autofix: { search: /(hashlib\.)(md5|sha1)(\s*\()/, replace: "$1sha256$3" } },
  { id: "py-requests-noverify", langs: ["py"], re: /verify\s*=\s*False/, sev: "warning", title: "TLS certificate verification disabled (verify=False)", fix: "Remove verify=False; verify certificates.", autofix: { search: /verify\s*=\s*False/, replace: "verify=True" } }
];

const SAST_LANG = { ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js", ".cjs": "js", ".py": "py" };

async function analyzeStaticCode(root, files) {
  const findings = [];
  let scanned = 0;
  for (const file of files) {
    if (findings.length >= MAX_FINDINGS) break;
    const lang = SAST_LANG[extname(file).toLowerCase()];
    if (!lang) continue;
    const base = basename(file).toLowerCase();
    // Skip test/spec/fixture files — high false-positive, low value.
    if (/\.(test|spec)\.|fixture|__tests__|\.min\./.test(base)) continue;
    const text = await readText(file);
    if (text == null) continue;
    scanned++;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 2000) continue;
      const trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue; // skip comments
      for (const rule of SAST_RULES) {
        if (!rule.langs.includes(lang)) continue;
        if (!rule.re.test(line)) continue;
        const rel = `${relative(root, file)}:${i + 1}`;
        findings.push({
          id: `sast:${rule.id}:${rel}`,
          title: rule.title,
          type: "security",
          category: "sast",
          severity: rule.sev,
          severityLabel: rule.sev === "critical" ? "high" : "moderate",
          confidence: rule.autofix ? 85 : 75,
          target: rel,
          detail: `${rule.title}. Static pattern match — review in context.`,
          fix: rule.fix,
          patchPreview: rule.fix,
          remediation: rule.autofix ? { kind: "code-replace", file: relative(root, file).replace(/\\/g, "/"), line: i + 1, search: rule.autofix.search.source, replace: rule.autofix.replace } : null
        });
        break; // one finding per line
      }
    }
  }
  return { findings, scanned: { files: scanned } };
}

// ---------------------------------------------------------------------------
// Analyzer 5: supply-chain / malware signals (Socket-style, from manifests)
// ---------------------------------------------------------------------------
const POPULAR_NPM = [
  "lodash", "react", "react-dom", "express", "axios", "chalk", "commander", "debug",
  "moment", "request", "vue", "webpack", "babel", "typescript", "jest", "eslint",
  "next", "dotenv", "uuid", "classnames", "prop-types", "redux", "rxjs", "tslib",
  "node-fetch", "yargs", "bluebird", "underscore", "async", "colors", "minimist"
];

// Damerau-Levenshtein (optimal string alignment) — counts an adjacent
// transposition as distance 1, since typosquats are commonly char swaps
// (e.g. "lodahs" vs "lodash") as well as substitutions/insertions/deletions.
function editDistance(a, b) {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 1) return 2; // we only care about distance <= 1
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); // transposition
      }
    }
  }
  return d[m][n];
}

async function analyzeSupplyChain(root, files) {
  const findings = [];
  for (const file of files) {
    if (basename(file).toLowerCase() !== "package.json") continue;
    const text = await readText(file);
    if (!text) continue;
    let json;
    try { json = JSON.parse(text); } catch { continue; }
    const rel = relative(root, file).replace(/\\/g, "/");
    const deps = { ...(json.dependencies || {}), ...(json.devDependencies || {}) };
    for (const [name, spec] of Object.entries(deps)) {
      // Typosquatting: name is 1 edit away from a popular package (but not equal).
      for (const popular of POPULAR_NPM) {
        if (name !== popular && Math.abs(name.length - popular.length) <= 1 && editDistance(name, popular) === 1) {
          findings.push(sc(`supplychain:typosquat:${name}`, `Possible typosquat: "${name}" resembles "${popular}"`, "critical", `${rel} · ${name}`,
            `The dependency "${name}" is one character from the popular package "${popular}" — a common malware/typosquat vector.`,
            `Verify "${name}" is intended; if you meant "${popular}", correct it.`));
          break;
        }
      }
      // Non-registry (mutable) sources: git/http/file specifiers.
      if (typeof spec === "string" && /^(git\+|git:|https?:|http:|file:|github:)/.test(spec)) {
        findings.push(sc(`supplychain:nonregistry:${name}`, `Non-registry dependency source: "${name}"`, "warning", `${rel} · ${name}`,
          `"${name}" resolves from a mutable source (${spec.slice(0, 48)}) rather than a pinned registry version — a supply-chain risk.`,
          "Pin to a published registry version with an integrity hash."));
      }
    }
  }
  return { findings };
}

function sc(id, title, severity, target, detail, fix) {
  return {
    id, title, type: "security", category: "supply-chain",
    severity, severityLabel: severity === "critical" ? "high" : "moderate",
    confidence: severity === "critical" ? 80 : 85, target, detail, fix, patchPreview: fix, remediation: null
  };
}

// ---------------------------------------------------------------------------
// Summary + orchestration
// ---------------------------------------------------------------------------
export function summarizeFindings(findings) {
  return {
    total: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    warnings: findings.filter((f) => f.severity === "warning").length,
    autofixable: findings.filter((f) => f.confidence >= 70).length,
    byCategory: findings.reduce((acc, f) => { acc[f.category] = (acc[f.category] || 0) + 1; return acc; }, {})
  };
}

const SEVERITY_RANK = { critical: 0, warning: 1 };

export async function scanDirectory(dir, { scanDepth = "full" } = {}) {
  const started = Date.now();
  const files = await walk(dir);
  const [deps, secrets, hygiene, sast, supply] = await Promise.all([
    analyzeDependencies(dir, files),
    analyzeSecrets(dir, files),
    analyzeHygiene(dir, files),
    analyzeStaticCode(dir, files),
    analyzeSupplyChain(dir, files)
  ]);

  let findings = [...deps.findings, ...secrets.findings, ...hygiene.findings, ...sast.findings, ...supply.findings];

  if (scanDepth && scanDepth !== "full") {
    findings = findings.filter((f) => f.type === scanDepth || f.severity === scanDepth || f.category === scanDepth);
  }

  findings.sort((a, b) =>
    (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
    (b.confidence - a.confidence)
  );
  findings = findings.slice(0, MAX_FINDINGS);
  // Stable fingerprint (line-number stripped) so suppressions survive line drift.
  for (const f of findings) f.fingerprint = f.id.replace(/:\d+$/, "");

  return {
    findings,
    summary: summarizeFindings(findings),
    scanned: {
      filesWalked: files.length,
      dependencies: deps.scanned,
      secretsScannedFiles: secrets.scanned.files,
      sastScannedFiles: sast.scanned.files,
      osv: deps.osv,
      durationMs: Date.now() - started
    }
  };
}

export async function scanRepository({ sourceUrl, token = null, scanDepth = "full" } = {}) {
  const meta = validateGitUrl(sourceUrl);
  const base = process.env.CODECANIC_SCAN_TMP || tmpdir();
  const workDir = await mkdtemp(join(base, "codecanic-scan-"));
  try {
    await cloneRepo(authedCloneUrl(meta, token), workDir);
    const commit = await headCommit(workDir);
    const result = await scanDirectory(workDir, { scanDepth });
    return {
      ...result,
      repository: { host: meta.host, owner: meta.owner, repo: meta.repo, url: meta.cleanUrl, commit }
    };
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}
