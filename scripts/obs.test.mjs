// Proves the observability layer: structured-log formatting, secret redaction
// (so tokens/passwords never reach logs), request-id shape, and that error
// capture is a safe no-op without SENTRY_DSN.
delete process.env.SENTRY_DSN; // ensure the no-op path
import { formatLog, redact, newRequestId } from "../api/_log.js";
import { observabilityEnabled, captureException } from "../api/_observability.js";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}

console.log("Structured log formatting");
{
  const line = formatLog("info", "request", { method: "POST", path: "/api/scan", status: 200 });
  const parsed = JSON.parse(line);
  ok("emits valid single-line JSON", typeof line === "string" && !line.includes("\n"));
  ok("includes level + msg + fields", parsed.level === "info" && parsed.msg === "request" && parsed.path === "/api/scan");
}

console.log("\nSecret redaction (no tokens/passwords in logs)");
{
  const r = redact({
    email: "a@b.com",
    password: "Sup3rSecret!",
    accessToken: "ghp_xxx",
    nested: { authorization: "Bearer abc", cookie: "session=zzz", safe: "ok" },
    list: [{ refresh_token: "rt_123" }]
  });
  ok("top-level password redacted", r.password === "[redacted]");
  ok("accessToken redacted", r.accessToken === "[redacted]");
  ok("nested authorization redacted", r.nested.authorization === "[redacted]");
  ok("nested cookie redacted", r.nested.cookie === "[redacted]");
  ok("non-secret fields preserved", r.email === "a@b.com" && r.nested.safe === "ok");
  ok("secrets inside arrays redacted", r.list[0].refresh_token === "[redacted]");
}

console.log("\nError serialization");
{
  const r = redact({ err: new Error("boom") });
  ok("Error serialized to name/message/stack", r.err.name === "Error" && r.err.message === "boom" && typeof r.err.stack === "string");
  const line = formatLog("error", "handler_error", { err: new Error("x") });
  ok("error log line is valid JSON", !!JSON.parse(line));
}

console.log("\nRequest id");
{
  const id = newRequestId();
  ok("request id is 16 hex chars", /^[0-9a-f]{16}$/.test(id), id);
  ok("request ids are unique", newRequestId() !== newRequestId());
}

console.log("\nSentry capture is a safe no-op without DSN");
{
  ok("observability disabled without SENTRY_DSN", observabilityEnabled() === false);
  let threw = false;
  try { await captureException(new Error("should not throw"), { reqId: "x" }); } catch { threw = true; }
  ok("captureException no-ops without throwing", threw === false);
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
