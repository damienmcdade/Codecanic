import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import auth from "./api/auth.js";
import checkout from "./api/checkout.js";
import connectors from "./api/connectors.js";
import health from "./api/health.js";
import oauth from "./api/oauth.js";
import orgs from "./api/orgs.js";
import repair from "./api/repair.js";
import scan from "./api/scan.js";

const port = Number(process.env.PORT || 3000);
const publicDir = join(process.cwd(), "public");

const exactRoutes = new Map([
  ["/api/checkout", checkout],
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

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const handler = exactRoutes.get(url.pathname);

  if (handler) {
    await handler(req, res);
    return;
  }

  const prefixed = prefixRoutes.find(({ prefix }) => url.pathname.startsWith(prefix));
  if (prefixed) {
    await prefixed.handler(req, res);
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
