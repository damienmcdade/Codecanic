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

const port = Number(process.env.PORT || 3000);
const publicDir = join(process.cwd(), "public");

const exactRoutes = new Map([
  ["/api/connectors", connectors],
  ["/api/health", health],
  ["/api/orgs", orgs],
  ["/api/repair", repair],
  ["/api/scan", scan]
]);

const prefixRoutes = [
  { prefix: "/api/auth/", handler: auth },
  { prefix: "/api/oauth/", handler: oauth }
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
  "Cross-Origin-Opener-Policy": "same-origin",
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
  applySecurityHeaders(req, res);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (
    stateChangingMethods.has(req.method) &&
    url.pathname.startsWith("/api/") &&
    !url.pathname.startsWith("/api/oauth/callback") &&
    !originAllowed(req)
  ) {
    send(res, 403, JSON.stringify({ error: "Cross-origin request rejected." }), "application/json; charset=utf-8");
    return;
  }

  const handler = exactRoutes.get(url.pathname);

  if (handler) {
    try {
      await handler(req, res);
    } catch (err) {
      console.error("[handler error]", err);
      if (!res.headersSent) send(res, 500, JSON.stringify({ error: "Internal error." }), "application/json; charset=utf-8");
    }
    return;
  }

  const prefixed = prefixRoutes.find(({ prefix }) => url.pathname.startsWith(prefix));
  if (prefixed) {
    try {
      await prefixed.handler(req, res);
    } catch (err) {
      console.error("[handler error]", err);
      if (!res.headersSent) send(res, 500, JSON.stringify({ error: "Internal error." }), "application/json; charset=utf-8");
    }
    return;
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    send(res, 405, "Method not allowed");
    return;
  }

  await serveStatic(req, res);
});

server.listen(port, "0.0.0.0", () => {
  console.log(`Codecanic server listening on port ${port}`);
});
