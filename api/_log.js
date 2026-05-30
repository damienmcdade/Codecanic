// Structured JSON logging for Codecanic. Dependency-free. One JSON object per
// line, with secret-ish fields redacted so tokens/passwords never reach logs.
import { randomBytes } from "node:crypto";

const REDACT_KEYS = /(pass(word)?|secret|token|authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token)/i;

export function redact(value, depth = 0) {
  if (depth > 4 || value == null) return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (typeof value === "object") {
    if (value instanceof Error) return { name: value.name, message: value.message, stack: value.stack };
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = REDACT_KEYS.test(k) ? "[redacted]" : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

export function formatLog(level, msg, fields = {}) {
  return JSON.stringify({ level, msg, ...redact(fields) });
}

function emit(level, msg, fields) {
  const line = formatLog(level, msg, fields);
  if (level === "error" || level === "warn") process.stderr.write(line + "\n");
  else process.stdout.write(line + "\n");
}

export const logger = {
  info: (msg, fields) => emit("info", msg, fields),
  warn: (msg, fields) => emit("warn", msg, fields),
  error: (msg, fields) => emit("error", msg, fields)
};

export function newRequestId() {
  return randomBytes(8).toString("hex");
}
