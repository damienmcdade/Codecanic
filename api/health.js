import { readFileSync } from "node:fs";
import { join } from "node:path";
import { json } from "./_lib.js";

// Build stamp written by scripts/build.mjs at deploy time. Read once at startup.
let buildInfo = { commit: null, builtAt: null };
try {
  buildInfo = JSON.parse(readFileSync(join(process.cwd(), "public", "version.json"), "utf8"));
} catch {
  /* not built (dev) — fall back to env/local below */
}
const stampedCommit = buildInfo.commit && buildInfo.commit !== "unknown" ? buildInfo.commit : null;

export default function handler(req, res) {
  if (req.method !== "GET") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }

  json(res, 200, {
    name: "Codecanic",
    status: "ok",
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
