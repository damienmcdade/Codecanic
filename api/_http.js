// Shared outbound-fetch helper with a hard timeout.
//
// The single in-process worker (and request handlers) make outbound calls to
// GitHub, Stripe, OSV, Resend, and provider APIs. Without a timeout a hung
// upstream connection stalls the worker (or a request) indefinitely. This wraps
// fetch with an AbortController + timer that is always cleared in finally.
const DEFAULT_TIMEOUT_MS = Number(process.env.CODECANIC_FETCH_TIMEOUT_MS || 15_000);

export async function fetchWithTimeout(url, options = {}, ms = DEFAULT_TIMEOUT_MS) {
  // Honour a caller-supplied signal by aborting our controller if it fires.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  const external = options.signal;
  if (external) {
    if (external.aborted) controller.abort();
    else external.addEventListener("abort", () => controller.abort(), { once: true });
  }
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
