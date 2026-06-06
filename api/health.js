import { readFileSync } from "node:fs";
import { join } from "node:path";
import { json } from "./_lib.js";
import { q, backendKind } from "./_db.js";

// Build stamp written by scripts/build.mjs at deploy time. Read once at startup.
let buildInfo = { commit: null, builtAt: null };
try {
  buildInfo = JSON.parse(readFileSync(join(process.cwd(), "public", "version.json"), "utf8"));
} catch {
  /* not built (dev) — fall back to env/local below */
}
const stampedCommit = buildInfo.commit && buildInfo.commit !== "unknown" ? buildInfo.commit : null;

// Probe the data layer with a short-timeout SELECT 1 so a dead DB surfaces as an
// unhealthy check (drives Railway's restart policy + uptime monitors) instead of
// a falsely-green "ok".
async function probeDb() {
  const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error("db probe timeout")), 3000));
  try {
    await Promise.race([q("SELECT 1"), timeout]);
    return { ok: true, kind: await backendKind().catch(() => null) };
  } catch (err) {
    return { ok: false, error: String(err?.message || err) };
  }
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }

  const db = await probeDb();
  json(res, db.ok ? 200 : 503, {
    name: "Codecanic",
    status: db.ok ? "ok" : "degraded",
    db: db.ok ? { status: "up", kind: db.kind } : { status: "down", error: db.error },
    version: process.env.npm_package_version || "0.1.0",
    platform:
      process.env.RAILWAY_SERVICE_NAME ||
      process.env.VERCEL_PROJECT_NAME ||
      process.env.CODECANIC_PLATFORM ||
      "local",
    deployment:
      process.env.RAILWAY_DEPLOYMENT_ID ||
      process.env.VERCEL_DEPLOYMENT_ID ||
      process.env.CODECANIC_DEPLOYMENT_ID ||
      "local",
    commit:
      process.env.RAILWAY_GIT_COMMIT_SHA ||
      process.env.VERCEL_GIT_COMMIT_SHA ||
      stampedCommit ||
      process.env.CODECANIC_COMMIT_SHA ||
      "local",
    builtAt: buildInfo.builtAt || null,
    checkedAt: new Date().toISOString()
  });
}
