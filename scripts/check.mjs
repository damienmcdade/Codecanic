import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const requiredFiles = [
  "index.html",
  "styles.css",
  "app.js",
  "manifest.webmanifest",
  "sw.js",
  "assets/cyber-garage.svg",
  "vercel.json",
  "railway.json",
  "README.md",
  "server.js",
  "api/_lib.js",
  "api/_auth.js",
  "api/_data.js",
  "api/auth.js",
  "api/orgs.js",
  "api/oauth.js",
  "api/scan.js",
  "api/repair.js",
  "api/checkout.js",
  "api/connectors.js",
  "api/health.js",
  ".env.example"
];

for (const file of requiredFiles) {
  await access(file);
}

const html = await readFile("index.html", "utf8");
for (const marker of ["Codecanic", "Connectors", "Findings report", "Tiered repair speed"]) {
  if (!html.includes(marker)) {
    throw new Error(`Missing expected UI marker: ${marker}`);
  }
}

const tempDir = await mkdtemp(join(tmpdir(), "codecanic-check-"));
process.env.CODECANIC_DATA_DIR = tempDir;
process.env.CODECANIC_SESSION_SECRET = "check-secret-do-not-use-in-prod";

const { resetCache } = await import("../api/_data.js");
resetCache();

const { default: authHandler } = await import("../api/auth.js");
const { default: scanHandler } = await import("../api/scan.js");
const { default: repairHandler } = await import("../api/repair.js");

function mockResponse() {
  return {
    statusCode: 200,
    headers: {},
    body: "",
    setHeader(key, value) {
      this.headers[key] = value;
    },
    end(value) {
      this.body = value;
    },
    writeHead(status, headers) {
      this.statusCode = status;
      Object.assign(this.headers, headers);
    }
  };
}

function mockRequest(method, body, { path = "/api/test", cookie = "" } = {}) {
  const listeners = {};
  return {
    method,
    headers: { host: "codecanic.local", cookie },
    url: path,
    on(event, callback) {
      listeners[event] = callback;
      if (event === "end") {
        queueMicrotask(() => {
          if (body) listeners.data?.(Buffer.from(JSON.stringify(body)));
          listeners.end?.();
        });
      }
      return this;
    }
  };
}

async function invoke(handler, method, body, options = {}) {
  const req = mockRequest(method, body, options);
  const res = mockResponse();
  await handler(req, res);
  return { res, data: res.body ? JSON.parse(res.body) : null };
}

const signupRes = await invoke(authHandler, "POST", {
  email: "checker@codecanic.local",
  password: "check-password-123",
  organization: "Codecanic Check"
}, { path: "/api/auth/signup" });

if (!signupRes.data?.user) {
  throw new Error("Signup did not return a user.");
}

const setCookie = signupRes.res.headers["Set-Cookie"];
const cookieHeader = setCookie ? setCookie.split(";")[0] : "";
if (!cookieHeader.startsWith("codecanic_session=")) {
  throw new Error("Signup did not set a session cookie.");
}

const orgSlug = signupRes.data.activeOrganization.slug;

async function authedInvoke(handler, method, body, path = "/api/test") {
  const separator = path.includes("?") ? "&" : "?";
  return invoke(handler, method, body, {
    path: `${path}${separator}organization=${encodeURIComponent(orgSlug)}`,
    cookie: cookieHeader
  });
}

resetCache();
const scan = await authedInvoke(scanHandler, "POST", {
  sourceUrl: "https://github.com/damienmcdade/Codecanic",
  scanDepth: "full",
  tier: "Max"
}, "/api/scan");

if (!scan.data?.findings?.length || scan.data.summary.critical < 1) {
  throw new Error("Scan API did not return a usable report.");
}

const repair = await authedInvoke(repairHandler, "POST", {
  findingIds: [scan.data.findings[0].id],
  tier: "Max",
  reportId: scan.data.id
}, "/api/repair");

if (!repair.data?.branchName || repair.data.status !== "queued") {
  throw new Error("Repair API did not queue a repair job.");
}

await rm(tempDir, { recursive: true, force: true });
console.log("Codecanic project check passed.");
