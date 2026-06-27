// AI-powered code repair (BYOK).
//
// For findings that have no deterministic remediation — SAST issues like
// eval(), command/SQL injection, unsafe deserialization — we ask the user's own
// Claude model to propose a concrete code edit. This runs SYNCHRONOUSLY inside
// the /api/repair request so the user's API key (see _byok.js) is used and
// discarded within that one request and is never persisted. The resulting
// edits (plain diffs, no secrets) are what flow into the async PR job.
//
// We deliberately DO NOT auto-edit secret findings: committed credentials must
// be rotated by a human, and rewriting them could leak history or break boot.
import { anthropicComplete } from "./_byok.js";
import { logger } from "./_log.js";

// Bound synchronous cost/latency: at most this many AI fixes per repair run.
const MAX_AI_FINDINGS = Number(process.env.CODECANIC_AI_REPAIR_MAX || 5);
// Cap file size sent to the model (chars). Larger files are windowed.
const MAX_FILE_CHARS = 14000;
const WINDOW_LINES = 80; // context lines on each side of the flagged line when windowing

/** Parse a "path/to/file.ext:123" target into { file, line }. */
function parseTarget(target) {
  const s = String(target || "");
  const m = s.match(/^(.*):(\d+)$/);
  if (!m) return null;
  const file = m[1].trim();
  const line = Number(m[2]);
  if (!file || !Number.isFinite(line) || line < 1) return null;
  // Require something that looks like a real source path (has an extension).
  if (!/\.[A-Za-z0-9]+$/.test(file)) return null;
  return { file, line };
}

/**
 * Findings an AI can safely attempt: unresolved SAST code issues with a
 * file:line target. Excludes secrets (human rotation), dependency/hygiene
 * items (handled deterministically), and anything already auto-fixable.
 */
export function pickAiEligible(findings = []) {
  const out = [];
  for (const f of findings) {
    if (!f || f.remediation) continue; // already has a deterministic fix
    if (f.category !== "sast") continue; // only code-pattern issues
    const loc = parseTarget(f.target);
    if (!loc) continue;
    out.push({ finding: f, ...loc });
  }
  return out;
}

/** Fetch one file's raw text from GitHub using the org's repo token. */
async function fetchFile({ owner, repo, path, token }, timeoutMs = 15000) {
  const safePath = path.split("/").map(encodeURIComponent).join("/");
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${safePath}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github.raw",
        "User-Agent": "Codecanic",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const text = await res.text();
    return typeof text === "string" ? text : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Window a large file around the flagged line so the prompt stays bounded. */
function windowContent(content, line) {
  if (content.length <= MAX_FILE_CHARS) return { text: content, windowed: false };
  const lines = content.split("\n");
  const start = Math.max(0, line - 1 - WINDOW_LINES);
  const end = Math.min(lines.length, line - 1 + WINDOW_LINES);
  return { text: lines.slice(start, end).join("\n"), windowed: true, startLine: start + 1 };
}

function extractJson(text) {
  if (!text) return null;
  // Tolerate ```json fences and surrounding prose.
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const raw = fenced ? fenced[1] : text;
  const first = raw.indexOf("{");
  const last = raw.lastIndexOf("}");
  if (first === -1 || last === -1 || last <= first) return null;
  try {
    return JSON.parse(raw.slice(first, last + 1));
  } catch {
    return null;
  }
}

const SYSTEM = `You are a senior application-security engineer fixing a single flagged issue in a source file.
Return ONLY minified JSON. Two shapes are allowed:
- A fix: {"find":"<exact snippet copied verbatim from the file>","replace":"<corrected code>","explanation":"<one sentence>"}
- A skip: {"skip":true,"reason":"<short reason>"}
Rules:
- "find" MUST be an exact, contiguous substring of the file shown, long enough to occur exactly once. Copy it character-for-character (preserve indentation and quotes). It may span multiple lines.
- "replace" must be a safe, minimal, drop-in correction that keeps the surrounding code working. Do not reformat unrelated code.
- Never invent APIs. If you cannot produce a safe, confident, self-contained edit, skip.
- Do not touch secrets/credentials. If the issue is a hardcoded secret, skip.`;

/**
 * Generate AI patch operations for the eligible findings.
 * @returns {Promise<{patches: Array, handledIds: string[], notes: string[], capped: number}>}
 *   patches: { kind:"code-rewrite", file, find, replace, title, findingId, explanation }
 */
export async function generateAiPatches({ meta, token, findings, anthropicKey, model }) {
  const eligible = pickAiEligible(findings);
  const notes = [];
  if (!eligible.length) return { patches: [], handledIds: [], notes, capped: 0 };

  const capped = Math.max(0, eligible.length - MAX_AI_FINDINGS);
  const work = eligible.slice(0, MAX_AI_FINDINGS);

  const patches = [];
  const handledIds = [];

  // Sequential: bounds concurrent spend on the user's key and keeps the
  // synchronous request within platform timeouts.
  for (const { finding, file, line } of work) {
    let content;
    try {
      content = await fetchFile({ owner: meta.owner, repo: meta.repo, path: file, token });
    } catch {
      content = null;
    }
    if (!content) {
      notes.push(`Skipped AI fix for ${file}:${line} — couldn't read the file from GitHub.`);
      continue;
    }

    const win = windowContent(content, line);
    const prompt = [
      `File: ${file}`,
      `Flagged line: ${line}`,
      `Issue: ${finding.title}`,
      `Recommended fix: ${finding.fix || "Remediate the flagged security issue."}`,
      win.windowed ? `(Showing lines ${win.startLine}+ of a large file.)` : "",
      "",
      "----- BEGIN FILE -----",
      win.text,
      "----- END FILE -----",
    ].filter(Boolean).join("\n");

    let raw;
    try {
      raw = await anthropicComplete(anthropicKey, { model, system: SYSTEM, prompt, maxTokens: 1500 });
    } catch (err) {
      // A key/auth/rate error is terminal for this run — re-throw so the
      // request surfaces a clear, client-safe message and pops the key panel.
      if (err?.code === "anthropic_key_required" || err?.code === "anthropic_key_invalid" || err?.code === "anthropic_rate_limited") {
        throw err;
      }
      logger.warn?.("ai_repair.call_failed", { file, code: err?.code });
      notes.push(`Skipped AI fix for ${file}:${line} — the AI call failed.`);
      continue;
    }

    const parsed = extractJson(raw);
    if (!parsed || parsed.skip || typeof parsed.find !== "string" || typeof parsed.replace !== "string") {
      notes.push(`Left ${file}:${line} for manual review — no confident AI fix${parsed?.reason ? ` (${parsed.reason})` : ""}.`);
      continue;
    }
    // Validate the edit anchors to the real file content before trusting it.
    if (!parsed.find.length || parsed.find === parsed.replace || !content.includes(parsed.find)) {
      notes.push(`Left ${file}:${line} for manual review — the proposed edit didn't match the file.`);
      continue;
    }

    patches.push({
      kind: "code-rewrite",
      file,
      find: parsed.find,
      replace: parsed.replace,
      title: finding.title,
      findingId: finding.id,
      explanation: typeof parsed.explanation === "string" ? parsed.explanation.slice(0, 240) : "",
    });
    handledIds.push(finding.id);
  }

  if (capped > 0) {
    notes.push(`${capped} more AI-eligible finding(s) were not auto-fixed this run (limit ${MAX_AI_FINDINGS}). Re-run the repair to address more.`);
  }
  return { patches, handledIds, notes, capped };
}
