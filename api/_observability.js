// Error tracking via Sentry — pluggable and no-op without configuration.
// When SENTRY_DSN is set, @sentry/node is lazily initialized and exceptions are
// reported. Without it (dev/test), captureException is a safe no-op; the
// structured logger has already recorded the error either way.
import { logger } from "./_log.js";

let sentry = null;
let initStarted = false;

export function observabilityEnabled() {
  return Boolean(process.env.SENTRY_DSN);
}

export async function initObservability() {
  if (initStarted || !observabilityEnabled()) return;
  initStarted = true;
  try {
    const Sentry = await import("@sentry/node");
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV || process.env.RAILWAY_ENVIRONMENT || "production",
      release: process.env.RAILWAY_GIT_COMMIT_SHA || process.env.VERCEL_GIT_COMMIT_SHA,
      tracesSampleRate: Number(process.env.SENTRY_TRACES_SAMPLE_RATE || 0)
    });
    sentry = Sentry;
    logger.info("observability.init", { provider: "sentry" });
  } catch (err) {
    logger.warn("observability.init_failed", { err });
  }
}

export async function captureException(err, context = {}) {
  if (!observabilityEnabled()) return;
  try {
    if (!sentry) await initObservability();
    sentry?.captureException(err, { extra: context });
  } catch (e) {
    logger.warn("observability.capture_failed", { err: e });
  }
}

export async function flushObservability(timeoutMs = 2000) {
  try { await sentry?.flush?.(timeoutMs); } catch {}
}
