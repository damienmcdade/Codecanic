import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { randomBytes } from "node:crypto";
import auth from "./api/auth.js";
import connectors from "./api/connectors.js";
import health from "./api/health.js";
import oauth from "./api/oauth.js";
import orgs from "./api/orgs.js";
import repair from "./api/repair.js";
import scan from "./api/scan.js";
import jobs from "./api/jobs.js";
import suppressions from "./api/suppressions.js";
import billing from "./api/billing.js";
import { logger, newRequestId } from "./api/_log.js";
import { initObservability, captureException, flushObservability } from "./api/_observability.js";
import { startWorker, stopWorker } from "./api/_worker.js";

const port = Number(process.env.PORT || 3000);
const publicDir = join(process.cwd(), "public");

const exactRoutes = new Map([
  ["/api/connectors", connectors],
  ["/api/health", health],
  ["/api/jobs", jobs],
  ["/api/orgs", orgs],
  ["/api/repair", repair],
  ["/api/scan", scan],
  ["/api/suppressions", suppressions],
  ["/api/billing", billing]
]);

const prefixRoutes = [
  { prefix: "/api/auth/", handler: auth },
  { prefix: "/api/oauth/", handler: oauth },
  { prefix: "/api/jobs/", handler: jobs },
  { prefix: "/api/billing/", handler: billing }
];

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".webmanifest": "application/manifest+json; charset=utf-8"
};

function send(res, status, body, type = "text/plain; charset=utf-8") {
  res.writeHead(status, {
    "Content-Type": type,
    "X-Content-Type-Options": "nosniff"
  });
  res.end(body);
}

async function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const rawPath = url.pathname === "/" ? "/index.html" : url.pathname;
  const safePath = normalize(rawPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(publicDir, safePath);

  if (!filePath.startsWith(publicDir)) {
    send(res, 403, "Forbidden");
    return;
  }

  try {
    const fileStat = await stat(filePath);
    if (!fileStat.isFile()) throw new Error("Not a file");
    res.writeHead(200, {
      "Content-Type": contentTypes[extname(filePath)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff"
    });
    createReadStream(filePath).pipe(res);
  } catch {
    const indexPath = join(publicDir, "index.html");
    res.writeHead(200, {
      "Content-Type": contentTypes[".html"],
      "X-Content-Type-Options": "nosniff"
    });
    createReadStream(indexPath).pipe(res);
  }
}

const baseSecurityHeaders = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
  "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
  "Cross-Origin-Resource-Policy": "same-origin"
};

const AD_SCRIPT_HOSTS =
  "https://pagead2.googlesyndication.com https://tpc.googlesyndication.com https://googleads.g.doubleclick.net https://ep1.adtrafficquality.google https://ep2.adtrafficquality.google https://www.googletagservices.com";
const AD_FRAME_HOSTS =
  "https://googleads.g.doubleclick.net https://tpc.googlesyndication.com https://www.google.com https://ep1.adtrafficquality.google https://ep2.adtrafficquality.google";
const AD_IMG_HOSTS =
  "https://pagead2.googlesyndication.com https://tpc.googlesyndication.com https://googleads.g.doubleclick.net https://www.google.com https://*.gstatic.com https://*.googleusercontent.com";
const AD_CONNECT_HOSTS =
  "https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net https://ep1.adtrafficquality.google https://ep2.adtrafficquality.google https://csi.gstatic.com";

function buildCsp(nonce) {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' ${AD_SCRIPT_HOSTS}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: ${AD_IMG_HOSTS}`,
    `connect-src 'self' ${AD_CONNECT_HOSTS}`,
    "font-src 'self'",
    `frame-src ${AD_FRAME_HOSTS}`,
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'"
  ].join("; ");
}

function applySecurityHeaders(req, res) {
  const nonce = randomBytes(16).toString("base64url");
  req.cspNonce = nonce;
  res.setHeader("Content-Security-Policy", buildCsp(nonce));
  for (const [k, v] of Object.entries(baseSecurityHeaders)) res.setHeader(k, v);
}

const stateChangingMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function originAllowed(req) {
  const origin = req.headers.origin || req.headers.referer;
  if (!origin) return false;
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  const host = req.headers.host || "";
  const expectedHost = host.split(":")[0];
  const originHost = parsed.hostname;
  if (originHost === expectedHost) return true;
  const allowList = (process.env.CODECANIC_ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (allowList.includes(parsed.origin)) return true;
  if (originHost === "codecanic.app") return true;
  if (originHost.endsWith(".vercel.app") && originHost.includes("codecanic")) return true;
  return false;
}

const server = createServer(async (req, res) => {
  const startedAt = Date.now();
  const reqId = newRequestId();
  req.id = reqId;
  res.setHeader("X-Request-Id", reqId);
  applySecurityHeaders(req, res);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  // Log every request on completion. Only the pathname is logged — never the
  // query string (it can carry verification/reset tokens) or the body.
  res.on("finish", () => {
    logger.info("request", {
      reqId, method: req.method, path: url.pathname,
      status: res.statusCode, durationMs: Date.now() - startedAt
    });
  });

  async function runHandler(handler) {
    try {
      await handler(req, res);
    } catch (err) {
      logger.error("handler_error", { reqId, path: url.pathname, err });
      captureException(err, { reqId, path: url.pathname, method: req.method });
      if (!res.headersSent) send(res, 500, JSON.stringify({ error: "Internal error." }), "application/json; charset=utf-8");
    }
  }

  if (
    stateChangingMethods.has(req.method) &&
    url.pathname.startsWith("/api/") &&
    !url.pathname.startsWith("/api/oauth/callback") &&
    !url.pathname.startsWith("/api/billing/webhook") &&
    !originAllowed(req)
  ) {
    send(res, 403, JSON.stringify({ error: "Cross-origin request rejected." }), "application/json; charset=utf-8");
    return;
  }

  const handler = exactRoutes.get(url.pathname);
  if (handler) return void (await runHandler(handler));

  const prefixed = prefixRoutes.find(({ prefix }) => url.pathname.startsWith(prefix));
  if (prefixed) return void (await runHandler(prefixed.handler));

  if (req.method !== "GET" && req.method !== "HEAD") {
    send(res, 405, "Method not allowed");
    return;
  }

  await serveStatic(req, res);
});

initObservability();

server.listen(port, "0.0.0.0", () => {
  logger.info("server.listening", { port });
  // Disable the in-process worker with CODECANIC_DISABLE_WORKER=1 (e.g. when
  // running a separate dedicated worker process).
  if (process.env.CODECANIC_DISABLE_WORKER !== "1") startWorker();
});

// Last-resort handlers so a stray rejection/exception is reported, not silent.
process.on("unhandledRejection", (reason) => {
  logger.error("unhandledRejection", { err: reason });
  captureException(reason instanceof Error ? reason : new Error(String(reason)), { kind: "unhandledRejection" });
});
process.on("uncaughtException", async (err) => {
  logger.error("uncaughtException", { err });
  await captureException(err, { kind: "uncaughtException" });
  await flushObservability();
  process.exit(1);
});

// Graceful shutdown: stop accepting connections, drain in-flight requests, then
// close the database pool. Railway/Vercel send SIGTERM on every deploy/restart.
let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info("shutdown.start", { signal });
  stopWorker();
  const force = setTimeout(() => { logger.error("shutdown.forced"); process.exit(1); }, 10_000);
  force.unref();
  server.close(async () => {
    try {
      const { closeDb } = await import("./api/_db.js");
      await closeDb();
    } catch {}
    await flushObservability();
    clearTimeout(force);
    process.exit(0);
  });
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
