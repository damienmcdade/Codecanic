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
  return { host, owner: segments[0], repo: segments[1].replace(/\.git$/, ""), cleanUrl: `https://${host}${path}` };
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
    child.on("error", (err) => { clearTimeout(timer); reject(new Error(`git not available: ${err.message}`)); });
    child.on("close", (code) => {
      clearTimeout(timer);
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

function severityFromVuln(vuln) {
  const ds = vuln?.database_specific?.severity;
  if (typeof ds === "string") {
    const u = ds.toUpperCase();
    if (u === "CRITICAL" || u === "HIGH") return { label: u.toLowerCase(), critical: true };
    if (u === "MODERATE" || u === "MEDIUM" || u === "LOW") return { label: u.toLowerCase(), critical: false };
  }
  // CVSS vector → score bucket.
  const sev = Array.isArray(vuln?.severity) ? vuln.severity : [];
  for (const s of sev) {
    const score = parseCvssScore(s?.score);
    if (score != null) {
      if (score >= 7) return { label: score >= 9 ? "critical" : "high", critical: true };
      return { label: score >= 4 ? "moderate" : "low", critical: false };
    }
  }
  return { label: "moderate", critical: false };
}

function parseCvssScore(vector) {
  if (typeof vector !== "string") return null;
  if (/^\d+(\.\d+)?$/.test(vector)) return Number(vector);
  return null; // full CVSS vector parsing is out of scope for v1
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
      fix: "Upgrade to a patched version, regenerate the lockfile, and rerun tests.",
      patchPreview: `Bump ${pkg.name} above the vulnerable range and refresh the lockfile.`
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
        "Remove it from the repo, add it to .gitignore, and rotate any exposed values."));
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
          "Enable \"strict\": true and fix the surfaced type errors."));
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
      "Add a CI workflow that runs build, tests, and security scans on every PR."));
  }

  return { findings };
}

function hyg(id, title, severity, target, detail, fix) {
  return {
    id, title, type: severity === "critical" ? "security" : "quality",
    category: "hygiene",
    severity, severityLabel: severity === "critical" ? "critical" : "moderate",
    confidence: 88, target, detail, fix,
    patchPreview: fix
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
  const [deps, secrets, hygiene] = await Promise.all([
    analyzeDependencies(dir, files),
    analyzeSecrets(dir, files),
    analyzeHygiene(dir, files)
  ]);

  let findings = [...deps.findings, ...secrets.findings, ...hygiene.findings];

  if (scanDepth && scanDepth !== "full") {
    findings = findings.filter((f) => f.type === scanDepth || f.severity === scanDepth || f.category === scanDepth);
  }

  findings.sort((a, b) =>
    (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
    (b.confidence - a.confidence)
  );
  findings = findings.slice(0, MAX_FINDINGS);

  return {
    findings,
    summary: summarizeFindings(findings),
    scanned: {
      filesWalked: files.length,
      dependencies: deps.scanned,
      secretsScannedFiles: secrets.scanned.files,
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
