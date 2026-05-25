import { access, readFile } from "node:fs/promises";

const requiredFiles = [
  "index.html",
  "styles.css",
  "app.js",
  "manifest.webmanifest",
  "sw.js",
  "vercel.json",
  "railway.json",
  "README.md",
  "api/_lib.js",
  "api/scan.js",
  "api/repair.js",
  "api/checkout.js",
  "api/connectors.js",
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
    }
  };
}

function mockRequest(method, body) {
  const listeners = {};
  return {
    method,
    headers: { host: "codecanic.local" },
    url: "/api/test",
    on(event, callback) {
      listeners[event] = callback;
      return this;
    },
    emitBody() {
      if (body) listeners.data?.(Buffer.from(JSON.stringify(body)));
      listeners.end?.();
    }
  };
}

async function invoke(handler, body) {
  const req = mockRequest("POST", body);
  const res = mockResponse();
  const promise = handler(req, res);
  req.emitBody();
  await promise;
  return JSON.parse(res.body);
}

const scan = await invoke(scanHandler, {
  sourceUrl: "https://github.com/damienmcdade/Codecanic",
  scanDepth: "full",
  tier: "Max"
});
if (!scan.findings?.length || scan.summary.critical < 1) {
  throw new Error("Scan API did not return a usable report.");
}

const repair = await invoke(repairHandler, {
  findingIds: [scan.findings[0].id],
  tier: "Max",
  reportId: scan.id
});
if (!repair.branchName || repair.status !== "queued") {
  throw new Error("Repair API did not queue a repair job.");
}

console.log("Codecanic project check passed.");
