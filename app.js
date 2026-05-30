const connectors = [
  { name: "GitHub", detail: "Repos, pull requests, dependency graph", status: "Disconnected", icon: "GH", type: "oauth" },
  { name: "Vercel", detail: "Deployments, env vars, runtime logs", status: "Disconnected", icon: "▲", type: "oauth" },
  { name: "Railway", detail: "Services, workers, databases, logs", status: "Disconnected", icon: "RW", type: "manual" },
  { name: "Xcode", detail: "iOS projects, signing, build settings", status: "Disconnected", icon: "XC", type: "manual" },
  { name: "GitLab", detail: "Repositories, CI pipelines, issues", status: "Disconnected", icon: "GL", type: "oauth" },
  { name: "Bitbucket", detail: "Repositories, workspaces, pull requests", status: "Disconnected", icon: "BB", type: "oauth" }
];

function connectorMeta(name) {
  return connectors.find((c) => c.name === name) || null;
}

const scanSteps = [
  ["Discover", "Map repositories, services, build systems, and package managers."],
  ["Analyze", "Run lint, type, dependency, secret, infra, and deployment checks."],
  ["Prioritize", "Score findings by severity, blast radius, and autofix confidence."],
  ["Repair", "Prepare patches for user-approved segments and rerun validation."]
];

const fallbackFindings = [
  {
    id: "demo-secret-env",
    title: "Potential secret exposed in deployment environment",
    type: "security",
    severity: "critical",
    confidence: 91,
    target: "Vercel / Production",
    fix: "Rotate key, move value to managed secret storage, and update deployment references.",
    patchPreview: "Replace plaintext environment value with provider-managed secret reference."
  }
];

const defaultState = {
  connectors: {},
  activeReport: null,
  repairJobs: [],
  audit: ["Workspace created"],
  activeOrgSlug: null
};

const state = loadState();
let activeFilter = "all";
const session = { user: null, organizations: [] };

const connectorList = document.querySelector("#connector-list");
const scanTimeline = document.querySelector("#scan-timeline");
const findingsRoot = document.querySelector("#findings");
const scanState = document.querySelector("#scan-state");
const toast = document.querySelector("#toast");
const jobList = document.querySelector("#job-list");
const auditList = document.querySelector("#audit-list");
const queueCount = document.querySelector("#queue-count");
const navTargets = [...document.querySelectorAll(".nav-links a, .bay-strip a")];

function loadState() {
  try {
    return { ...defaultState, ...JSON.parse(localStorage.getItem("codecanic-state")) };
  } catch {
    return { ...defaultState };
  }
}

function saveState() {
  localStorage.setItem("codecanic-state", JSON.stringify(state));
}

function audit(message) {
  state.audit = [`${new Date().toLocaleString()}: ${message}`, ...state.audit].slice(0, 20);
  saveState();
  renderAudit();
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  window.setTimeout(() => toast.classList.remove("visible"), 2800);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fireControl(control) {
  control.classList.remove("is-firing");
  void control.offsetWidth;
  control.classList.add("is-firing");
  window.setTimeout(() => control.classList.remove("is-firing"), 480);
}

function activeOrg() {
  return session.organizations.find((org) => org.slug === state.activeOrgSlug) || session.organizations[0] || null;
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const org = activeOrg();
  if (org) headers["X-Codecanic-Org"] = org.slug;
  const response = await fetch(path, {
    credentials: "same-origin",
    headers,
    ...options
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const err = new Error(data.error || "Request failed.");
    err.status = response.status;
    throw err;
  }
  return data;
}

function currentFindings() {
  return state.activeReport?.findings || fallbackFindings;
}

function renderConnectors() {
  connectorList.innerHTML = connectors
    .map((connector) => {
      const live = state.connectors[connector.name] || {};
      const isConnected = live.status === "connected";
      const isReady = live.status === "ready" || live.status === "authorization_ready";
      const needsConfig = live.status === "configuration_required";
      const buttonLabel = isConnected
        ? "Manage"
        : needsConfig
        ? "Needs setup"
        : isReady
        ? "Connect"
        : "Connect";
      const statusLine = isConnected
        ? `Connected${live.connectedAt ? ` · ${new Date(live.connectedAt).toLocaleDateString()}` : ""}`
        : needsConfig
        ? "Admin setup required"
        : "Not connected";
      const statusClass = isConnected ? "is-connected" : needsConfig ? "is-warn" : "is-idle";
      return `
        <div class="connector ${statusClass}">
          <div class="connector-info">
            <span class="connector-icon" aria-hidden="true">${escapeHtml(connector.icon)}</span>
            <span>
              <strong>${escapeHtml(connector.name)}</strong>
              <span>${escapeHtml(connector.detail)}</span>
              <span class="connector-status">${escapeHtml(statusLine)}</span>
            </span>
          </div>
          <button class="secondary ${isConnected ? "connected" : ""}" type="button" data-connect="${escapeHtml(connector.name)}">
            ${escapeHtml(buttonLabel)}
          </button>
        </div>
      `;
    })
    .join("");
}

function renderTimeline(activeIndex = state.activeReport ? scanSteps.length : -1) {
  document.body.classList.toggle("scan-active", activeIndex >= 0 && activeIndex < scanSteps.length);
  scanTimeline.innerHTML = scanSteps
    .map((step, index) => {
      const complete = activeIndex > index;
      const active = activeIndex === index;
      const marker = complete ? "✓" : active ? "…" : index + 1;
      return `
        <div class="timeline-step">
          <div class="timeline-info">
            <span class="step-icon" aria-hidden="true">${marker}</span>
            <span>
              <strong>${step[0]}</strong>
              <span>${step[1]}</span>
            </span>
          </div>
          <span class="pill">${complete ? "Done" : active ? "Running" : "Queued"}</span>
        </div>
      `;
    })
    .join("");
}

function renderFindings() {
  const visible = currentFindings().filter(
    (finding) =>
      activeFilter === "all" || finding.severity === activeFilter || finding.type === activeFilter
  );

  findingsRoot.innerHTML = visible
    .map((finding) => {
      const id = escapeHtml(finding.id);
      const title = escapeHtml(finding.title);
      return `
        <article class="finding" data-finding="${id}">
          <label class="checkbox-row" aria-label="Select ${title}">
            <input type="checkbox" data-repair="${id}" />
          </label>
          <div>
            <h3>${title}</h3>
            <p>${escapeHtml(finding.fix)}</p>
            <div class="finding-meta">
              <span class="severity">${escapeHtml(finding.severity)}</span>
              <span>${escapeHtml(finding.type)}</span>
              <span>${escapeHtml(finding.confidence ?? 70)}% confidence</span>
              <span>${escapeHtml(finding.target)}</span>
            </div>
            <code>${escapeHtml(finding.patchPreview || "Patch preview will appear after scan.")}</code>
          </div>
          <button class="secondary" type="button" data-single="${id}">Approve</button>
        </article>
      `;
    })
    .join("");
}

function renderJobs() {
  queueCount.textContent = `${state.repairJobs.length} queued`;
  jobList.innerHTML = state.repairJobs.length
    ? state.repairJobs
        .map(
          (job) => `
            <article class="job">
              <strong>${escapeHtml(job.branchName)}</strong>
              <span>${escapeHtml(job.findingIds.length)} repairs · ${escapeHtml(job.status)} · ${escapeHtml(job.workerCount)} workers</span>
            </article>
          `
        )
        .join("")
    : `<p class="empty-state">Approved repairs will appear here.</p>`;
}

function renderAudit() {
  auditList.innerHTML = state.audit.map((item) => `<p>${escapeHtml(item)}</p>`).join("");
}

function renderSummary() {
  const summary = state.activeReport?.summary || { critical: 1, warnings: 0, autofixable: 1 };
  document.querySelector("#critical-count").textContent = summary.critical;
  document.querySelector("#warning-count").textContent = summary.warnings;
  document.querySelector("#autofix-count").textContent = summary.autofixable;
  scanState.textContent = state.activeReport ? "Report ready" : "Ready";
}

function renderAccount() {
  const card = document.querySelector("#account-card");
  if (!card) return;
  const signedOut = card.querySelector(".account-signed-out");
  const signedIn = card.querySelector(".account-signed-in");
  if (session.user) {
    signedOut.hidden = true;
    signedIn.hidden = false;
    card.querySelector("#account-name").textContent = session.user.name || session.user.email;
    card.querySelector("#account-email").textContent = session.user.email;
    const select = card.querySelector("#org-switcher");
    const current = activeOrg();
    select.innerHTML = session.organizations
      .map((org) => `<option value="${escapeHtml(org.slug)}">${escapeHtml(org.name)}</option>`)
      .join("");
    if (current) select.value = current.slug;
  } else {
    signedOut.hidden = false;
    signedIn.hidden = true;
  }
  const banner = document.querySelector("#verify-banner");
  if (banner) banner.hidden = !(session.user && session.user.emailVerified === false);
}

function renderAll() {
  renderAccount();
  renderConnectors();
  renderTimeline();
  renderFindings();
  renderJobs();
  renderAudit();
  renderSummary();
}

async function refreshSession() {
  try {
    const data = await api("/api/auth/me");
    session.user = data.user || null;
    session.organizations = data.organizations || [];
    if (session.user) {
      const current = activeOrg();
      state.activeOrgSlug = current ? current.slug : null;
      saveState();
    } else {
      state.activeOrgSlug = null;
    }
  } catch {
    session.user = null;
    session.organizations = [];
  }
  renderAccount();
  await loadAllConnectorStatuses();
}

function openAuthModal(mode = "signin") {
  const modal = document.querySelector("#auth-modal");
  modal.hidden = false;
  modal.setAttribute("aria-hidden", "false");
  setAuthMode(mode);
}

function closeAuthModal() {
  const modal = document.querySelector("#auth-modal");
  modal.hidden = true;
  modal.setAttribute("aria-hidden", "true");
  document.querySelector("#auth-error").hidden = true;
  document.querySelector("#auth-form").reset();
}

function setAuthMode(mode) {
  const isSignup = mode === "signup";
  document.querySelector("#auth-modal-title").textContent = isSignup ? "Create account" : "Sign in";
  document.querySelector("#auth-submit").textContent = isSignup ? "Create account" : "Sign in";
  document.querySelectorAll("[data-auth-tab]").forEach((tab) => {
    tab.classList.toggle("selected", tab.dataset.authTab === mode);
  });
  document.querySelectorAll("[data-auth-only]").forEach((field) => {
    field.hidden = field.dataset.authOnly !== mode;
  });
  document.querySelector("#auth-form").dataset.mode = mode;
}

async function submitAuth(form) {
  const mode = form.dataset.mode || "signin";
  const fd = new FormData(form);
  const payload = Object.fromEntries(fd);
  if (mode === "signup") {
    payload.acceptTerms = form.querySelector("#acceptTerms")?.checked === true;
    payload.ageConfirmed = form.querySelector("#ageConfirm")?.checked === true;
    payload.marketingOptIn = form.querySelector("#marketingOptIn")?.checked === true;
    payload.age = payload.ageConfirmed ? 16 : 0;
  }
  const errorEl = document.querySelector("#auth-error");
  errorEl.hidden = true;
  try {
    const endpoint = mode === "signup" ? "/api/auth/signup" : "/api/auth/login";
    const data = await api(endpoint, { method: "POST", body: JSON.stringify(payload) });
    session.user = data.user;
    session.organizations = data.organizations || [];
    if (data.activeOrganization) state.activeOrgSlug = data.activeOrganization.slug;
    saveState();
    closeAuthModal();
    audit(`Signed in as ${session.user.email}`);
    renderAll();
    showToast(`Welcome, ${session.user.name || session.user.email}.`);
    loadAllConnectorStatuses();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.hidden = false;
  }
}

async function signOut() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch {
    /* ignore */
  }
  session.user = null;
  session.organizations = [];
  state.activeOrgSlug = null;
  state.connectors = {};
  saveState();
  audit("Signed out");
  renderAll();
  showToast("Signed out.");
}

async function resendVerification() {
  try {
    await api("/api/auth/resend-verification", { method: "POST" });
    showToast("Verification email sent. Check your inbox.");
  } catch (error) {
    showToast(error.message || "Could not send verification email.");
  }
}

async function requestPasswordReset() {
  const email = document.querySelector("#auth-form")?.querySelector('input[name="email"]')?.value?.trim();
  if (!email) {
    const errorEl = document.querySelector("#auth-error");
    errorEl.textContent = "Enter your email above, then click “Forgot password?”.";
    errorEl.hidden = false;
    return;
  }
  try {
    await api("/api/auth/request-password-reset", { method: "POST", body: JSON.stringify({ email }) });
  } catch {
    /* generic by design */
  }
  showToast("If an account exists for that email, a reset link is on its way.");
}

function openResetModal(token) {
  const modal = document.querySelector("#reset-modal");
  if (!modal) return;
  modal.dataset.token = token || "";
  modal.hidden = false;
  modal.setAttribute("aria-hidden", "false");
}

function closeResetModal() {
  const modal = document.querySelector("#reset-modal");
  if (!modal) return;
  modal.hidden = true;
  modal.setAttribute("aria-hidden", "true");
  document.querySelector("#reset-error").hidden = true;
  document.querySelector("#reset-form").reset();
  // Drop the token from the URL so it isn't re-triggered or left in history.
  if (location.pathname === "/reset-password") history.replaceState(null, "", "/");
}

async function submitResetPassword(form) {
  const fd = new FormData(form);
  const password = String(fd.get("password") || "");
  const confirm = String(fd.get("confirm") || "");
  const errorEl = document.querySelector("#reset-error");
  errorEl.hidden = true;
  if (password !== confirm) {
    errorEl.textContent = "Passwords do not match.";
    errorEl.hidden = false;
    return;
  }
  const token = document.querySelector("#reset-modal")?.dataset.token || "";
  try {
    await api("/api/auth/reset-password", { method: "POST", body: JSON.stringify({ token, password }) });
    closeResetModal();
    showToast("Password updated. Please sign in.");
    openAuthModal("signin");
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.hidden = false;
  }
}

const legalText = {
  privacy: `
    <h3>Privacy Policy</h3>
    <p class="muted">Last updated: 2026-05-26. Version 2.</p>
    <p>This policy describes what data Codecanic collects, why, where it goes, and how long we keep it. We are the data controller for the personal data described below. For any request — access, deletion, correction, complaint — email <a href="mailto:privacy@codecanic.app">privacy@codecanic.app</a>. We respond within 30 days as required by GDPR Article 12(3).</p>

    <h4>1. What we collect and why</h4>
    <table class="legal-table"><tbody>
      <tr><th>Data</th><th>Purpose</th><th>Lawful basis (GDPR Art. 6)</th><th>Retention</th></tr>
      <tr><td>Email, name, password hash (scrypt + salt)</td><td>Account creation, authentication, security</td><td>Contract (Art. 6(1)(b))</td><td>Until you delete your account (immediate, permanent)</td></tr>
      <tr><td>Organizations and roles</td><td>Workspace ownership and access control</td><td>Contract</td><td>Until you delete account or leave the organization</td></tr>
      <tr><td>OAuth access tokens (GitHub, Vercel, GitLab, Bitbucket) and manual tokens (Railway, Xcode)</td><td>Run scans and propose repairs on your authorization</td><td>Contract</td><td>Until you disconnect the provider, leave the org, or delete account; deletion is immediate and cascades</td></tr>
      <tr><td>Scan reports and repair queue entries</td><td>Show you findings, let you approve fixes</td><td>Contract</td><td>Until you delete account or remove report</td></tr>
      <tr><td>Signed session cookie <code>codecanic_session</code> (HttpOnly, Secure, SameSite=Strict)</td><td>Identify your authenticated browser</td><td>Contract — strictly necessary</td><td>14 days from issue, refreshed on activity</td></tr>
      <tr><td>Acceptance timestamps for Terms + Privacy Policy</td><td>Demonstrate informed consent</td><td>Legal obligation (Art. 6(1)(c))</td><td>Life of the account + 6 years</td></tr>
      <tr><td>Marketing opt-in flag</td><td>Honour your email preference (we do not currently send any marketing emails)</td><td>Consent (Art. 6(1)(a))</td><td>Until you delete account or opt out</td></tr>
      <tr><td>HTTP request logs (IP, path, status, timestamp, user agent)</td><td>Abuse detection, debugging, security audit</td><td>Legitimate interest (Art. 6(1)(f))</td><td>30 days then rotated</td></tr>
      <tr><td>Failed-login counters (IP + email)</td><td>Rate-limit credential stuffing</td><td>Legitimate interest</td><td>15 minutes after last failure</td></tr>
    </tbody></table>

    <h4>2. Cookies and similar technologies</h4>
    <table class="legal-table"><tbody>
      <tr><th>Cookie</th><th>Set by</th><th>Purpose</th><th>Lifetime</th></tr>
      <tr><td><code>codecanic_session</code></td><td>Codecanic (1st party)</td><td>Authentication — strictly necessary, set only after sign-in</td><td>14 days</td></tr>
      <tr><td><code>codecanic-cookie-consent</code> (localStorage)</td><td>Codecanic</td><td>Remember your consent choice on the cookie banner</td><td>Until you clear browser storage</td></tr>
      <tr><td><code>codecanic-state</code> (localStorage)</td><td>Codecanic</td><td>Cache your dashboard layout, connector status, audit trail</td><td>Until you sign out, delete the account, or clear browser storage</td></tr>
      <tr><td>Google AdSense cookies (<code>__gads</code>, <code>__gpi</code>, <code>IDE</code>, others)</td><td>Google (3rd party)</td><td>Ad delivery, frequency capping, fraud detection, optionally personalisation. <strong>Only set after you accept on the cookie banner.</strong></td><td>Up to 13 months (Google policy)</td></tr>
    </tbody></table>
    <p>If you select <strong>Essential only</strong> on the cookie banner the AdSense script is not loaded at all — no Google cookies are set, no requests are made to Google ad servers, and the sponsor slots remain blank.</p>

    <h4>3. Advertising</h4>
    <p>Codecanic is free for everyone and supported by ads served by Google AdSense (publisher <code>ca-pub-8731629548430880</code>). When you accept ad cookies, Google may receive your approximate location, device, IP-derived signals, and AdSense cookie identifiers to deliver and measure personalised or non-personalised ads. Manage your Google ad preferences at <a href="https://adssettings.google.com" target="_blank" rel="noopener noreferrer">adssettings.google.com</a>. Google's privacy policy: <a href="https://policies.google.com/privacy" target="_blank" rel="noopener noreferrer">policies.google.com/privacy</a>.</p>
    <p>EEA / UK / Swiss users: when consent is required, Google's IAB TCF v2.2 prompt may also appear before personalised ads are served. You can withdraw consent at any time by clicking <strong>Manage cookies</strong> in your account card.</p>

    <h4>4. Subprocessors (third parties that process data on our behalf)</h4>
    <table class="legal-table"><tbody>
      <tr><th>Subprocessor</th><th>Role</th><th>Region</th></tr>
      <tr><td>Vercel Inc.</td><td>Static frontend hosting (codecanic.app) and edge proxy for <code>/api/*</code></td><td>USA</td></tr>
      <tr><td>Railway Corp.</td><td>API hosting and persistent data store</td><td>USA (US West region)</td></tr>
      <tr><td>Google LLC (AdSense)</td><td>Sponsor ad delivery — only after you opt in</td><td>USA</td></tr>
      <tr><td>GitHub, GitLab, Bitbucket, Vercel, Railway, Apple Developer (when you connect them)</td><td>OAuth identity and the read scopes you grant for each scan</td><td>USA / EEA depending on provider</td></tr>
    </tbody></table>

    <h4>5. International data transfers</h4>
    <p>Codecanic is hosted in the United States. If you access the service from the EEA, UK, or Switzerland, your personal data is transferred to the US. We rely on the European Commission Standard Contractual Clauses (Module 2, Controller-to-Processor) with each subprocessor named above, and on each subprocessor's published Data Processing Addendum. Copies are available on request to <a href="mailto:privacy@codecanic.app">privacy@codecanic.app</a>.</p>

    <h4>6. Your rights</h4>
    <ul>
      <li><strong>Access and portability (Art. 15 + 20):</strong> click <em>Download my data</em> in your account card. Format: JSON. Tokens are redacted to <code>***redacted***</code> for safety; if you need the original tokens, fetch them yourself from the provider before exporting.</li>
      <li><strong>Erasure (Art. 17):</strong> click <em>Delete account</em>. Your user record, sessions, sole-owned organizations, and every connector credential are removed immediately and permanently. There are no soft-delete backups; nothing is retained after the action completes.</li>
      <li><strong>Rectification (Art. 16):</strong> email <a href="mailto:privacy@codecanic.app">privacy@codecanic.app</a> with corrections.</li>
      <li><strong>Restriction / objection (Art. 18 + 21):</strong> email us. For processing based on legitimate interest you can object at any time.</li>
      <li><strong>Consent withdrawal:</strong> click <em>Manage cookies</em> in your account card to switch ad consent off, or unsubscribe from any future marketing email we send.</li>
      <li><strong>Lodge a complaint:</strong> you can complain to your local supervisory authority. In the EU, find yours at <a href="https://edpb.europa.eu/about-edpb/about-edpb/members_en" target="_blank" rel="noopener noreferrer">edpb.europa.eu</a>. In the UK, the ICO (<a href="https://ico.org.uk" target="_blank" rel="noopener noreferrer">ico.org.uk</a>).</li>
    </ul>

    <h4>7. California (CCPA / CPRA) notice</h4>
    <p>If you are a California resident:</p>
    <ul>
      <li><strong>Categories collected</strong>: identifiers (email, IP), commercial info (organization), internet activity (request logs), inferences (none).</li>
      <li><strong>"Sale" of personal information</strong>: we do not sell personal information.</li>
      <li><strong>"Sharing" for cross-context behavioural advertising</strong>: when you accept ad cookies, we share advertising identifiers with Google AdSense. You can opt out at any time by selecting <em>Essential only</em> on the cookie banner or by clicking <em>Manage cookies</em>. We treat that signal as your <strong>Do Not Sell or Share My Personal Information</strong> request.</li>
      <li><strong>Sensitive PII</strong>: we do not collect sensitive personal information as defined by CCPA.</li>
      <li><strong>Right to limit use</strong>: not applicable because we do not use sensitive PII.</li>
      <li><strong>Authorised agent</strong>: you may designate one in writing.</li>
    </ul>

    <h4>8. Security</h4>
    <ul>
      <li>TLS 1.2+ enforced via HSTS preload on every connection.</li>
      <li>Passwords: scrypt (CPU-hard) with per-user 16-byte random salt. Plaintext passwords never stored.</li>
      <li>Provider access tokens: AES-256-GCM encrypted at rest with a key derived from a 64-character server secret via scrypt KDF.</li>
      <li>Sessions: HMAC-SHA256 signed cookie, <code>HttpOnly</code>, <code>Secure</code>, <code>SameSite=Strict</code>, max 5 concurrent per user.</li>
      <li>Anti-CSRF: every state-changing request requires a same-origin Origin header.</li>
      <li>Anti-brute-force: 15-minute lockout after 5 failed login attempts per IP+email.</li>
      <li>Password policy: minimum 15 characters with uppercase, lowercase, digit, and symbol (DISA STIG aligned).</li>
      <li>Strict Content-Security-Policy with per-request script nonce. X-Frame-Options DENY. No iframes embed Codecanic.</li>
    </ul>
    <p><strong>Breach notification</strong>: if we discover a personal data breach we will notify the relevant supervisory authority within 72 hours (GDPR Art. 33). If the breach is likely to result in high risk to your rights or freedoms we will notify affected users without undue delay (Art. 34).</p>

    <h4>9. Children</h4>
    <p>Codecanic is not directed to children under 16. We require explicit age confirmation at signup. If we learn that an account belongs to a child under 16 we will delete it and remove all associated data. To report such an account, email <a href="mailto:privacy@codecanic.app">privacy@codecanic.app</a>.</p>

    <h4>10. Automated decision-making</h4>
    <p>Scan findings and proposed repairs are produced by deterministic rules and pattern matchers. We do not currently use machine-learning models that profile you or make automated decisions producing legal effects. If that changes we will update this policy and notify you.</p>

    <h4>11. Accessibility</h4>
    <p>Codecanic aims to meet WCAG 2.1 AA where practical. The dashboard supports keyboard navigation, screen-reader-compatible ARIA labels on interactive controls, sufficient colour contrast, and respects <code>prefers-reduced-motion</code> for animations. We have not yet completed a formal accessibility audit. Report accessibility barriers to <a href="mailto:accessibility@codecanic.app">accessibility@codecanic.app</a>; we will acknowledge within 5 business days.</p>

    <h4>12. Changes</h4>
    <p>If we make material changes to this policy we will display a banner on first sign-in after the change and update the "Last updated" date above. Continued use after the effective date constitutes acceptance.</p>

    <h4>13. Contact</h4>
    <p>Privacy / data requests: <a href="mailto:privacy@codecanic.app">privacy@codecanic.app</a>.<br>Accessibility: <a href="mailto:accessibility@codecanic.app">accessibility@codecanic.app</a>.<br>Security disclosure: <a href="mailto:security@codecanic.app">security@codecanic.app</a>.<br>Trust + safety: <a href="mailto:abuse@codecanic.app">abuse@codecanic.app</a>.</p>
  `,
  terms: `
    <h3>Terms of Service</h3>
    <p class="muted">Last updated: 2026-05-26. Version 2.</p>
    <p>By creating an account or using Codecanic ("the Service") you agree to these terms. If you do not agree, do not use the Service.</p>

    <h4>1. The Service</h4>
    <p>Codecanic scans repositories and infrastructure you authorize, generates prioritized reports, and proposes repairs for your review. The Service is free of charge and supported by sponsor advertising. You retain ownership of your code, your provider accounts, and any data you submit.</p>

    <h4>2. Eligibility</h4>
    <p>You must be at least 16 years old and able to enter a binding contract. You may use the Service on behalf of a company; if so, you represent that you have authority to bind that company.</p>

    <h4>3. Your account</h4>
    <p>You are responsible for keeping your password secure and for everything that happens under your account. Notify us at <a href="mailto:security@codecanic.app">security@codecanic.app</a> immediately if you suspect unauthorized access.</p>

    <h4>4. Acceptable Use Policy (AUP)</h4>
    <p>You agree NOT to:</p>
    <ul>
      <li>Connect any provider account you are not authorized to access.</li>
      <li>Use the Service to scan, modify, or generate repairs for systems or repositories you do not own or do not have explicit written permission to test.</li>
      <li>Reverse engineer, disassemble, decompile, or attempt to extract source code from the Service except as permitted by applicable law.</li>
      <li>Overload, flood, spam, denial-of-service, or otherwise interfere with the Service or other users.</li>
      <li>Use the Service to develop, train, or evaluate a competing product without our written permission.</li>
      <li>Upload, scan, or generate repairs for malicious code, malware, stalkerware, illegal content (CSAM, copyrighted material you do not own, sanctioned-party content), or content that infringes third-party rights.</li>
      <li>Bypass the consent or paywall mechanisms or attempt to access another user's data.</li>
      <li>Use the Service in violation of any applicable export control, sanctions, or trade law (including OFAC and EU sanctions).</li>
    </ul>
    <p>Violations may result in immediate suspension and, where appropriate, referral to law enforcement.</p>

    <h4>5. Repairs and pull requests</h4>
    <p>Codecanic proposes repairs but does NOT merge them automatically. You approve the segments you want, and Codecanic prepares a draft pull request on your behalf using your authorized provider tokens. You are responsible for reviewing the proposed code before merging into production. Codecanic makes no representation that proposed repairs are correct, complete, or fit for any particular purpose.</p>

    <h4>6. Your content</h4>
    <p>You grant Codecanic a worldwide, non-exclusive, royalty-free, terminable licence to access, copy, scan, and process the repository content and metadata you connect, solely to provide the Service to you. You may revoke this licence at any time by disconnecting the relevant connector or deleting your account, after which we cease the corresponding processing within 30 days (in practice, immediately for connector disconnect / account delete).</p>

    <h4>7. Intellectual property and DMCA</h4>
    <p>Codecanic and the Service are owned by us and protected by IP laws. The trademarks, logos, and service marks displayed on Codecanic are our property or the property of their respective owners and may not be used without permission.</p>
    <p><strong>DMCA — Digital Millennium Copyright Act (US 17 U.S.C. § 512)</strong>: if you believe content on Codecanic infringes your copyright, send a notice to our designated agent at <a href="mailto:dmca@codecanic.app">dmca@codecanic.app</a> including:</p>
    <ol>
      <li>Your physical or electronic signature.</li>
      <li>Identification of the copyrighted work claimed to have been infringed.</li>
      <li>Identification of the allegedly infringing material and where it is located on the Service.</li>
      <li>Your contact information (address, phone, email).</li>
      <li>A statement that you have a good-faith belief that the use is not authorized.</li>
      <li>A statement, under penalty of perjury, that the notice is accurate and you are authorized to act on behalf of the owner.</li>
    </ol>
    <p>Counter-notices may be sent to the same address. We may terminate repeat infringers per our DMCA policy.</p>

    <h4>8. Cost and ads</h4>
    <p>The Service is free of charge. We do not collect payment information. The Service is supported by ads delivered via Google AdSense; see the Privacy Policy for details and your consent controls.</p>

    <h4>9. Suspension and termination</h4>
    <p>You may delete your account at any time via the dashboard. We may suspend or terminate your access (with or without notice) if you violate these terms, applicable law, or our AUP. On termination, sections 7, 9, 10, 11, 12, 13, and 14 survive.</p>

    <h4>10. Disclaimers</h4>
    <p>THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS, IMPLIED, OR STATUTORY, INCLUDING WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, OR NON-INFRINGEMENT. WE DO NOT WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED, SECURE, OR FREE OF ERRORS, OR THAT SCAN FINDINGS OR PROPOSED REPAIRS ARE CORRECT OR COMPLETE.</p>

    <h4>11. Limitation of liability</h4>
    <p>TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT WILL CODECANIC'S TOTAL AGGREGATE LIABILITY FOR ANY CLAIM ARISING FROM OR RELATING TO THE SERVICE EXCEED ONE HUNDRED US DOLLARS (USD 100). WE ARE NOT LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES, INCLUDING LOSS OF PROFITS, DATA, GOODWILL, OR BUSINESS INTERRUPTION, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. Some jurisdictions do not allow these limitations; in those jurisdictions our liability is limited to the smallest amount permitted by law.</p>

    <h4>12. Indemnification</h4>
    <p>You agree to indemnify and hold Codecanic harmless from any claim, demand, loss, or expense (including reasonable legal fees) arising from your violation of these terms, your AUP violations, or your infringement of any third-party right (including IP rights) through your use of the Service.</p>

    <h4>13. Governing law and dispute resolution</h4>
    <p>These terms are governed by the laws of the jurisdiction in which Codecanic is principally operated, without regard to its conflict-of-law rules. Before bringing any claim, you agree to first contact us at <a href="mailto:legal@codecanic.app">legal@codecanic.app</a> and attempt good-faith resolution for at least 30 days. If unresolved, any dispute will be brought in the small-claims court of competent jurisdiction or, at either party's election, before a neutral arbitrator under the rules of a recognised arbitration body. Class actions are waived to the extent permitted by law. Nothing in this section prevents you from exercising any non-waivable consumer rights under your local law.</p>

    <h4>14. Severability + entire agreement</h4>
    <p>If any provision of these terms is held unenforceable, the remaining provisions remain in force. These terms (together with the Privacy Policy) constitute the entire agreement between you and Codecanic regarding the Service and supersede any prior agreements.</p>

    <h4>15. Force majeure</h4>
    <p>We are not liable for failure or delay caused by events beyond reasonable control — natural disasters, war, terrorism, civil disturbance, pandemic, government action, infrastructure outage at a subprocessor, or denial-of-service attack.</p>

    <h4>16. Changes</h4>
    <p>If we make material changes to these terms we will display a banner on first sign-in after the change and update the "Last updated" date. Continued use after the effective date constitutes acceptance. If you do not accept the changes, stop using the Service and delete your account.</p>
  `
};

function openLegalModal(tab = "privacy") {
  const modal = document.querySelector("#legal-modal");
  modal.hidden = false;
  modal.setAttribute("aria-hidden", "false");
  setLegalTab(tab);
}

function closeLegalModal() {
  const modal = document.querySelector("#legal-modal");
  modal.hidden = true;
  modal.setAttribute("aria-hidden", "true");
}

function setLegalTab(tab) {
  document.querySelectorAll("[data-legal-tab]").forEach((btn) => {
    btn.classList.toggle("selected", btn.dataset.legalTab === tab);
  });
  document.querySelector("#legal-modal-title").textContent =
    tab === "terms" ? "Terms of Service" : "Privacy Policy";
  document.querySelector("#legal-body").innerHTML = legalText[tab] || "";
}

async function downloadMyData() {
  try {
    const data = await api("/api/auth/export");
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `codecanic-data-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    audit("Personal data exported");
    showToast("Your data has been downloaded.");
  } catch (error) {
    showToast(error.message);
  }
}

const COOKIE_CONSENT_KEY = "codecanic-cookie-consent";
const ADSENSE_LOADER_URL = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-8731629548430880";

function getConsent() {
  try {
    return localStorage.getItem(COOKIE_CONSENT_KEY) || "pending";
  } catch {
    return "pending";
  }
}

function setConsent(value) {
  try {
    localStorage.setItem(COOKIE_CONSENT_KEY, value);
  } catch {}
}

function loadAdSenseScript() {
  if (document.querySelector('script[data-codecanic-ads="1"]')) return;
  const s = document.createElement("script");
  s.src = ADSENSE_LOADER_URL;
  s.async = true;
  s.crossOrigin = "anonymous";
  s.dataset.codecanicAds = "1";
  s.onload = () => loadAdSlots();
  document.head.appendChild(s);
}

function loadAdSlots() {
  if (getConsent() !== "accepted") return;
  const slots = document.querySelectorAll("ins.adsbygoogle");
  for (const slot of slots) {
    if (slot.dataset.loaded === "1") continue;
    const id = slot.getAttribute("data-ad-slot") || "";
    if (!id || id.startsWith("REPLACE_WITH")) continue;
    try {
      (window.adsbygoogle = window.adsbygoogle || []).push({});
      slot.dataset.loaded = "1";
    } catch (err) {
      console.warn("AdSense push failed", err);
    }
  }
}

function applyConsent(consent) {
  setConsent(consent);
  document.body.classList.toggle("consent-accepted", consent === "accepted");
  document.body.classList.toggle("consent-essential", consent === "essential");
  hideCookieBanner();
  if (consent === "accepted") {
    loadAdSenseScript();
  }
}

function maybeShowCookieBanner() {
  const consent = getConsent();
  document.body.classList.toggle("consent-accepted", consent === "accepted");
  document.body.classList.toggle("consent-essential", consent === "essential");
  if (consent === "accepted") {
    loadAdSenseScript();
    return;
  }
  if (consent === "pending") {
    const banner = document.querySelector("#cookie-banner");
    if (banner) banner.hidden = false;
  }
}

function hideCookieBanner() {
  const banner = document.querySelector("#cookie-banner");
  if (banner) banner.hidden = true;
}

function showCookieBanner() {
  const banner = document.querySelector("#cookie-banner");
  if (banner) banner.hidden = false;
}

function openDeleteAccountModal() {
  const modal = document.querySelector("#delete-modal");
  modal.hidden = false;
  modal.setAttribute("aria-hidden", "false");
  document.querySelector("#delete-confirm-input").value = "";
  document.querySelector("#delete-password-input").value = "";
  document.querySelector("#delete-submit").disabled = true;
  document.querySelector("#delete-error").hidden = true;
}

function closeDeleteAccountModal() {
  const modal = document.querySelector("#delete-modal");
  modal.hidden = true;
  modal.setAttribute("aria-hidden", "true");
}

function updateDeleteSubmitState() {
  const confirm = document.querySelector("#delete-confirm-input").value.trim().toUpperCase();
  const password = document.querySelector("#delete-password-input").value;
  document.querySelector("#delete-submit").disabled = !(confirm === "DELETE" && password.length >= 1);
}

async function submitDeleteAccount() {
  const confirm = document.querySelector("#delete-confirm-input").value.trim().toUpperCase();
  const password = document.querySelector("#delete-password-input").value;
  const errorEl = document.querySelector("#delete-error");
  errorEl.hidden = true;
  if (confirm !== "DELETE") {
    errorEl.textContent = 'Type "DELETE" exactly to confirm.';
    errorEl.hidden = false;
    return;
  }
  if (!password) {
    errorEl.textContent = "Re-enter your password to confirm.";
    errorEl.hidden = false;
    return;
  }
  const submit = document.querySelector("#delete-submit");
  submit.disabled = true;
  submit.textContent = "Deleting…";
  try {
    await api("/api/auth/account", {
      method: "POST",
      body: JSON.stringify({ password, confirm })
    });
    try {
      localStorage.removeItem("codecanic-state");
    } catch {}
    session.user = null;
    session.organizations = [];
    state.activeOrgSlug = null;
    state.connectors = {};
    state.activeReport = null;
    state.repairJobs = [];
    state.audit = [];
    closeDeleteAccountModal();
    renderAll();
    showToast("Account deleted. We're sorry to see you go.");
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.hidden = false;
    submit.disabled = false;
    submit.textContent = "Delete account forever";
  }
}

async function createOrganization() {
  const name = window.prompt("Name for the new organization");
  if (!name) return;
  try {
    const data = await api("/api/orgs", { method: "POST", body: JSON.stringify({ name }) });
    session.organizations = [...session.organizations, data.organization];
    state.activeOrgSlug = data.organization.slug;
    saveState();
    audit(`Created organization ${data.organization.name}`);
    renderAll();
    showToast(`Organization ${data.organization.name} created.`);
  } catch (error) {
    showToast(error.message);
  }
}

const wizard = {
  provider: null,
  pollTimer: null,
  popup: null,
  popupTimer: null,
  detail: null
};

const wizardEl = () => document.querySelector("#connect-modal");

function renderProviderSwitcher() {
  const el = document.querySelector("#connect-switcher");
  if (!el) return;
  el.innerHTML = connectors
    .map((c) => {
      const live = state.connectors[c.name] || {};
      const connected = live.status === "connected";
      const isCurrent = c.name === wizard.provider;
      const cls = [
        "switcher-chip",
        isCurrent ? "current" : "",
        connected ? "connected" : "",
        c.type === "manual" ? "manual" : "oauth"
      ]
        .filter(Boolean)
        .join(" ");
      return `<button class="${cls}" type="button" data-switch-provider="${escapeHtml(c.name)}">
        <span class="switcher-icon" aria-hidden="true">${escapeHtml(c.icon)}</span>
        <span>${escapeHtml(c.name)}</span>
      </button>`;
    })
    .join("");
}

function setWizardStep(step) {
  document.querySelectorAll("#connect-stepper li").forEach((li) => {
    const order = ["preflight", "authorize", "verify"];
    const idx = order.indexOf(li.dataset.step);
    const cur = order.indexOf(step);
    li.classList.toggle("active", idx === cur);
    li.classList.toggle("complete", idx < cur);
  });
}

function showWizardError(message) {
  const el = document.querySelector("#connect-error");
  if (!message) {
    el.hidden = true;
    el.textContent = "";
    return;
  }
  el.hidden = false;
  el.textContent = message;
}

function openConnectionWizard(name) {
  const meta = connectorMeta(name);
  if (!meta) return;
  wizard.provider = name;
  wizard.detail = null;
  showWizardError("");
  document.querySelector("#connect-icon").textContent = meta.icon;
  document.querySelector("#connect-modal-title").textContent = `Connect ${name}`;
  document.querySelector("#connect-subtitle").textContent =
    meta.type === "manual" ? "Paste-token setup, 3 steps" : "Guided OAuth setup, 3 steps";
  document.querySelector("#connect-summary").textContent = "";
  document.querySelector("#connect-oauth-name").textContent = name;
  document.querySelector("#connect-manual-title").textContent = `Paste your ${name} token`;
  ["connect-admin", "connect-manual", "connect-oauth", "connect-confirm", "connect-guide"].forEach((id) => {
    document.querySelector(`#${id}`).hidden = true;
  });
  document.querySelector("#connect-verify-result").hidden = true;
  document.querySelector("#connect-oauth-progress").hidden = true;
  wizardGuide.open = false;
  document.querySelector("#connect-guide-toggle").setAttribute("aria-expanded", "false");
  const modal = wizardEl();
  modal.hidden = false;
  modal.setAttribute("aria-hidden", "false");
  setWizardStep("preflight");
  renderProviderSwitcher();
  loadWizardDetail();
}

function closeConnectionWizard() {
  const modal = wizardEl();
  modal.hidden = true;
  modal.setAttribute("aria-hidden", "true");
  stopOAuthPolling();
  wizard.provider = null;
}

function renderPreflight(detail) {
  const meta = connectorMeta(wizard.provider);
  const org = activeOrg();
  const items = [
    {
      ok: Boolean(session.user),
      label: session.user ? `Signed in as ${session.user.email}` : "Sign in to Codecanic",
      action: session.user
        ? null
        : { label: "Sign in", run: () => { closeConnectionWizard(); openAuthModal("signin"); } }
    },
    {
      ok: Boolean(org),
      label: org ? `Workspace: ${org.name}` : "Choose a workspace",
      action: org ? null : { label: "Create workspace", run: () => createOrganization() }
    },
    {
      ok: detail.configured,
      label: detail.configured
        ? `${wizard.provider} is configured on Codecanic`
        : `${wizard.provider} needs admin setup`,
      action: null
    }
  ];

  if (meta.type === "oauth") {
    items.push({
      ok: true,
      label: "Browser allows pop-ups for this site",
      hint: "If a window doesn't open in step 2, allow pop-ups for this site and retry."
    });
  }

  const list = document.querySelector("#connect-preflight");
  list.innerHTML = items
    .map((item, idx) => {
      const icon = item.ok ? "✓" : "!";
      const cls = item.ok ? "ok" : "todo";
      const hint = item.hint ? `<small>${escapeHtml(item.hint)}</small>` : "";
      const button = item.action
        ? `<button class="ghost" type="button" data-preflight="${idx}">${escapeHtml(item.action.label)}</button>`
        : "";
      return `<li class="${cls}"><span class="preflight-mark">${icon}</span><span>${escapeHtml(item.label)}${hint}</span>${button}</li>`;
    })
    .join("");
  list.querySelectorAll("[data-preflight]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.preflight);
      items[idx]?.action?.run?.();
    });
  });

  return items.every((item) => item.ok);
}

function renderAdminBlock(detail) {
  const admin = document.querySelector("#connect-admin");
  if (detail.status !== "configuration_required") {
    admin.hidden = true;
    return;
  }
  admin.hidden = false;
  document.querySelector("#connect-admin-intro").textContent =
    detail.message || `${wizard.provider} requires environment variables before users can connect.`;
  document.querySelector("#connect-admin-steps").innerHTML = (detail.adminInstructions || [])
    .map((step) => `<li>${escapeHtml(step)}</li>`)
    .join("");
  const lines = [];
  if (detail.requiredEnv) lines.push(`${detail.requiredEnv}=...`);
  if (detail.requiredSecretEnv) lines.push(`${detail.requiredSecretEnv}=...`);
  if (detail.redirectUri) lines.push(`# Redirect URL: ${detail.redirectUri}`);
  document.querySelector("#connect-admin-snippet").textContent = lines.join("\n");
}

function renderManualBlock(detail) {
  const block = document.querySelector("#connect-manual");
  if (detail.type !== "manual" || detail.status === "connected") {
    block.hidden = true;
    return;
  }
  block.hidden = false;
  const steps = detail.tokenInstructions || [];
  document.querySelector("#connect-manual-steps").innerHTML = steps
    .map((step) => `<li>${escapeHtml(step)}</li>`)
    .join("");
  const link = document.querySelector("#connect-manual-link");
  if (detail.tokenUrl) {
    link.href = detail.tokenUrl;
    link.hidden = false;
    link.textContent = `Open ${wizard.provider} token page →`;
  } else {
    link.hidden = true;
  }
  document.querySelector("#connect-manual-input").value = "";
  document.querySelector("#connect-manual-input").placeholder =
    wizard.provider === "Xcode" ? "10-character Team ID" : "Paste personal access token";
}

function detectGuideOs() {
  const ua = (navigator.userAgent || "").toLowerCase();
  if (ua.includes("mac")) return "mac";
  if (ua.includes("win")) return "windows";
  if (ua.includes("linux") || ua.includes("ubuntu") || ua.includes("debian")) return "linux";
  return "mac";
}

const wizardGuide = { os: detectGuideOs(), open: false };

function renderGuide(detail) {
  const guide = document.querySelector("#connect-guide");
  const setupWrap = document.querySelector("#connect-guide-setup-wrap");
  const setupTitle = document.querySelector("#connect-guide-setup-title");
  const stepsList = document.querySelector("#connect-guide-steps");
  const provLabel = document.querySelectorAll(".guide-provider");
  const cliWrap = document.querySelector("#connect-guide-cli-wrap");
  const cliName = document.querySelector(".guide-cli-name");
  const cliCmd = document.querySelector("#connect-guide-cli-cmd");
  const cliQuick = document.querySelector("#connect-guide-cli-quickstart");
  const cliLink = document.querySelector("#connect-guide-cli-link");

  provLabel.forEach((el) => (el.textContent = wizard.provider || ""));

  const isManual = detail.type === "manual";
  if (isManual) {
    setupTitle.innerHTML = `Where to find your <span class="guide-provider">${escapeHtml(wizard.provider || "")}</span> token`;
    const tokenSteps = detail.tokenInstructions || [];
    stepsList.innerHTML = tokenSteps.map((s) => `<li>${escapeHtml(s)}</li>`).join("");
    setupWrap.hidden = !tokenSteps.length;
  } else {
    setupTitle.innerHTML = `Admin: register an OAuth app on <span class="guide-provider">${escapeHtml(wizard.provider || "")}</span>`;
    const steps = detail.setupSteps || [];
    stepsList.innerHTML = steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("");
    setupWrap.hidden = !steps.length;
  }

  if (detail.cli) {
    cliWrap.hidden = false;
    cliName.textContent = detail.cli.name;
    cliQuick.textContent = detail.cli.quickstart || "";
    cliLink.href = detail.cli.homepage || "#";
    cliLink.hidden = !detail.cli.homepage;
    const os = wizardGuide.os;
    document.querySelectorAll("#connect-guide .connect-guide-tabs button").forEach((b) => {
      b.classList.toggle("selected", b.dataset.cliOs === os);
    });
    cliCmd.textContent = detail.cli.install?.[os] || "Not available for this OS.";
  } else {
    cliWrap.hidden = true;
  }

  const toggle = document.querySelector("#connect-guide-toggle");
  toggle.setAttribute("aria-expanded", wizardGuide.open ? "true" : "false");
  guide.hidden = !wizardGuide.open;
}

function renderOAuthBlock(detail) {
  const block = document.querySelector("#connect-oauth");
  if (detail.type !== "oauth" || detail.status === "connected" || detail.status === "configuration_required") {
    block.hidden = true;
    return;
  }
  block.hidden = false;
  document.querySelector("#connect-oauth-progress").hidden = true;
  const button = document.querySelector("#connect-oauth-start");
  button.disabled = !detail.authUrl;
  renderGuide(detail);
}

function renderConfirmBlock(detail) {
  const block = document.querySelector("#connect-confirm");
  const projects = document.querySelector("#connect-projects");
  if (detail.status !== "connected") {
    block.hidden = true;
    if (projects) projects.hidden = true;
    return;
  }
  block.hidden = false;
  document.querySelector("#connect-confirm-title").textContent = `${wizard.provider} connected`;
  const when = detail.connectedAt ? `Linked ${new Date(detail.connectedAt).toLocaleString()}` : "Token saved";
  document.querySelector("#connect-confirm-detail").textContent = when;
  document.querySelector("#connect-verify-result").hidden = true;
  loadProjects();
}

async function loadWizardDetail() {
  const name = wizard.provider;
  if (!name) return;
  showWizardError("");
  try {
    const detail = await api(`/api/connectors?name=${encodeURIComponent(name)}`);
    wizard.detail = detail;
    state.connectors[name] = {
      status: detail.status,
      type: detail.type,
      connectedAt: detail.connectedAt || null
    };
    saveState();
    renderConnectors();
    renderProviderSwitcher();
    const ready = renderPreflight(detail);
    renderAdminBlock(detail);
    renderManualBlock(detail);
    renderOAuthBlock(detail);
    renderConfirmBlock(detail);
    renderGuide(detail);
    const summaryEl = document.querySelector("#connect-summary");
    summaryEl.textContent = detail.accessSummary || "";
    if (detail.status === "connected") {
      setWizardStep("verify");
    } else if (ready && detail.configured) {
      setWizardStep("authorize");
    } else {
      setWizardStep("preflight");
    }
  } catch (error) {
    showWizardError(error.message || "Could not load connector status.");
  }
}

function stopOAuthPolling() {
  if (wizard.pollTimer) {
    window.clearInterval(wizard.pollTimer);
    wizard.pollTimer = null;
  }
  if (wizard.popupTimer) {
    window.clearInterval(wizard.popupTimer);
    wizard.popupTimer = null;
  }
  if (wizard.popup && !wizard.popup.closed) {
    try { wizard.popup.close(); } catch {}
  }
  wizard.popup = null;
  document.querySelector("#connect-oauth-progress").hidden = true;
}

function startOAuthFlow() {
  const detail = wizard.detail;
  if (!detail || !detail.authUrl) {
    showWizardError("Authorization URL is not ready yet.");
    return;
  }
  const popup = window.open(detail.authUrl, "codecanic-oauth", "width=600,height=720,noopener=no");
  if (!popup) {
    showWizardError("Browser blocked the authorization window. Allow pop-ups for this site and try again.");
    return;
  }
  wizard.popup = popup;
  document.querySelector("#connect-oauth-progress").hidden = false;
  audit(`${wizard.provider} authorization opened`);

  wizard.pollTimer = window.setInterval(async () => {
    try {
      const data = await api("/api/oauth/status");
      const conn = (data.connections || []).find((c) => c.provider === wizard.provider);
      if (conn) {
        stopOAuthPolling();
        await loadWizardDetail();
        showToast(`${wizard.provider} connected.`);
      }
    } catch {}
  }, 2000);

  wizard.popupTimer = window.setInterval(() => {
    if (wizard.popup && wizard.popup.closed) {
      window.clearInterval(wizard.popupTimer);
      wizard.popupTimer = null;
      window.setTimeout(async () => {
        await loadWizardDetail();
        if (wizard.detail?.status !== "connected") {
          showWizardError("Authorization window closed before completing. Try again to finish connecting.");
          stopOAuthPolling();
        }
      }, 1200);
    }
  }, 1000);
}

async function submitManualToken() {
  const token = document.querySelector("#connect-manual-input").value.trim();
  if (!token) {
    showWizardError("Paste a token to continue.");
    return;
  }
  showWizardError("");
  try {
    await api("/api/oauth/manual", {
      method: "POST",
      body: JSON.stringify({ provider: wizard.provider, token })
    });
    audit(`${wizard.provider} token saved`);
    showToast(`${wizard.provider} connected.`);
    await loadWizardDetail();
  } catch (error) {
    showWizardError(error.message);
  }
}

async function verifyConnection() {
  const result = document.querySelector("#connect-verify-result");
  result.hidden = false;
  result.className = "connect-verify-result pending";
  result.textContent = "Pinging provider…";
  try {
    const data = await api(
      `/api/connectors?action=verify&name=${encodeURIComponent(wizard.provider)}`
    );
    if (data.verified) {
      result.className = "connect-verify-result ok";
      result.textContent = `Verified · ${data.account || "live token"}${data.scope ? ` · scope: ${data.scope}` : ""}`;
      audit(`${wizard.provider} verified (${data.account || "ok"})`);
    } else {
      result.className = "connect-verify-result fail";
      result.textContent = `Token rejected: ${data.message || "unknown error"}`;
    }
  } catch (error) {
    result.className = "connect-verify-result fail";
    result.textContent = error.message || "Verification failed.";
  }
}

async function disconnectProvider() {
  if (!wizard.provider) return;
  if (!window.confirm(`Disconnect ${wizard.provider} from this workspace?`)) return;
  try {
    await api("/api/oauth/disconnect", {
      method: "POST",
      body: JSON.stringify({ provider: wizard.provider })
    });
    audit(`${wizard.provider} disconnected`);
    showToast(`${wizard.provider} disconnected.`);
    await loadWizardDetail();
  } catch (error) {
    showWizardError(error.message);
  }
}

async function loadProjects() {
  const box = document.querySelector("#connect-projects");
  const picker = document.querySelector("#project-picker");
  if (!wizard.provider) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  picker.innerHTML = `<div class="project-picker-empty"><span class="spinner" aria-hidden="true"></span> Loading projects from ${escapeHtml(wizard.provider)}…</div>`;
  try {
    const data = await api(`/api/connectors?action=projects&name=${encodeURIComponent(wizard.provider)}`);
    if (data.error) {
      picker.innerHTML = `<div class="project-picker-empty">${escapeHtml(data.error)}</div>`;
      return;
    }
    const projects = data.projects || [];
    if (!projects.length) {
      const note = data.message || "No projects returned. The account may not have any repositories yet.";
      picker.innerHTML = `<div class="project-picker-empty">${escapeHtml(note)}</div>`;
      return;
    }
    picker.innerHTML = projects
      .map((project) => {
        const url = project.url || "";
        return `
          <div class="project">
            <div>
              <strong>${escapeHtml(project.name || project.id)}</strong>
              <span>${escapeHtml(project.description || url)}</span>
            </div>
            <button class="secondary" type="button" data-pick-project="${escapeHtml(url)}">Scan this</button>
          </div>
        `;
      })
      .join("");
  } catch (error) {
    picker.innerHTML = `<div class="project-picker-empty">${escapeHtml(error.message || "Could not load projects.")}</div>`;
  }
}

function chooseProject(url) {
  if (!url) return;
  const input = document.querySelector("#source-url");
  input.value = url;
  audit(`Project selected for scan: ${url}`);
  showToast("Project loaded into the scan form.");
  closeConnectionWizard();
  document.querySelector("#scan")?.scrollIntoView({ behavior: "smooth", block: "start" });
  input.focus({ preventScroll: true });
}

async function loadAllConnectorStatuses() {
  if (!session.user) return;
  try {
    const data = await api("/api/connectors?action=list");
    for (const entry of data.connectors || []) {
      state.connectors[entry.name] = {
        status: entry.status,
        type: entry.type,
        connectedAt: entry.connectedAt || null,
        scope: entry.scope || null
      };
    }
    saveState();
    renderConnectors();
  } catch {
    /* unauthenticated or transient — keep cached state */
  }
}

window.addEventListener("message", (event) => {
  if (event.origin !== window.location.origin) return;
  const data = event.data;
  if (!data || data.type !== "codecanic:connector") return;
  if (!wizard.provider || data.provider !== wizard.provider) return;
  stopOAuthPolling();
  if (data.success) {
    loadWizardDetail().then(() => showToast(`${wizard.provider} connected.`));
  } else {
    showWizardError(data.message || "Authorization did not complete.");
  }
});

async function runScan() {
  const sourceUrl = document.querySelector("#source-url").value.trim();
  const scanDepth = document.querySelector("#scan-depth").value;
  scanState.textContent = "Running";
  showToast("Full infrastructure scan started.");

  let index = 0;
  renderTimeline(index);
  const timer = window.setInterval(() => {
    index += 1;
    renderTimeline(Math.min(index, scanSteps.length - 1));
  }, 420);

  try {
    const report = await api("/api/scan", {
      method: "POST",
      body: JSON.stringify({ sourceUrl, scanDepth, connectors: state.connectors })
    });
    window.clearInterval(timer);
    document.body.classList.remove("scan-active");
    state.activeReport = report;
    audit(`Scan completed for ${report.sourceUrl}`);
    saveState();
    renderAll();
    showToast("Report ready. Review and approve repairs.");
  } catch (error) {
    window.clearInterval(timer);
    document.body.classList.remove("scan-active");
    scanState.textContent = "Scan failed";
    audit(`Scan failed: ${error.message}`);
    showToast(error.message || "Scan failed. Connect a provider and retry.");
  }
}

async function approveRepairs(findingIds) {
  if (!findingIds.length) {
    showToast("Select repairs before approving.");
    return;
  }

  try {
    const job = await api("/api/repair", {
      method: "POST",
      body: JSON.stringify({ findingIds, reportId: state.activeReport?.id })
    });
    state.repairJobs = [job, ...state.repairJobs];
    audit(`${findingIds.length} repairs approved`);
    saveState();
    renderJobs();
    showToast("Repair job queued for patch generation.");
  } catch (error) {
    showToast(error.message);
  }
}

function exportReport() {
  const report = state.activeReport;
  if (!report) {
    showToast("Run a scan before exporting.");
    return;
  }

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `codecanic-report-${report.id}.json`;
  link.click();
  URL.revokeObjectURL(url);
  audit("Report exported");
}

document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const control = target.closest("button, a");
  if (control instanceof HTMLElement) fireControl(control);

  const jumpTarget = target.dataset.jump;
  if (jumpTarget) {
    document.querySelector(jumpTarget)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  if (target.dataset.authOpen) openAuthModal(target.dataset.authOpen);
  if (target.dataset.authTab) setAuthMode(target.dataset.authTab);
  if (target.id === "auth-close") closeAuthModal();
  if (target.id === "sign-out-button") signOut();
  if (target.id === "new-org-button") createOrganization();
  if (target.id === "delete-account-button") openDeleteAccountModal();
  if (target.id === "delete-close" || target.id === "delete-cancel") closeDeleteAccountModal();
  if (target.id === "delete-submit") submitDeleteAccount();
  if (target.dataset.openLegal) openLegalModal(target.dataset.openLegal);
  if (target.dataset.legalTab) setLegalTab(target.dataset.legalTab);
  if (target.id === "legal-close") closeLegalModal();
  if (target.id === "download-data") downloadMyData();
  if (target.id === "cookie-accept") applyConsent("accepted");
  if (target.id === "cookie-reject") applyConsent("essential");
  if (target.id === "manage-cookies") showCookieBanner();

  if (target.id === "run-scan") runScan();
  if (target.id === "export-report") exportReport();
  if (target.dataset.connect) {
    if (!session.user) {
      openAuthModal("signin");
      showToast("Sign in to connect a provider.");
    } else {
      openConnectionWizard(target.dataset.connect);
    }
  }
  if (target.id === "refresh-connectors") loadAllConnectorStatuses();
  if (target.id === "connect-guide-toggle") {
    wizardGuide.open = !wizardGuide.open;
    if (wizard.detail) renderGuide(wizard.detail);
  }
  if (target.dataset.cliOs) {
    wizardGuide.os = target.dataset.cliOs;
    if (wizard.detail) renderGuide(wizard.detail);
  }
  if (target.id === "connect-close") closeConnectionWizard();
  if (target.id === "connect-oauth-start") startOAuthFlow();
  if (target.id === "connect-oauth-cancel") stopOAuthPolling();
  if (target.id === "connect-manual-submit") submitManualToken();
  if (target.id === "connect-verify") verifyConnection();
  if (target.id === "connect-disconnect") disconnectProvider();
  if (target.dataset.pickProject) chooseProject(target.dataset.pickProject);
  const switchEl = target.closest("[data-switch-provider]");
  if (switchEl) {
    const switchTo = switchEl.dataset.switchProvider;
    if (switchTo && switchTo !== wizard.provider) openConnectionWizard(switchTo);
  }
  if (target.dataset.single) approveRepairs([target.dataset.single]);

  if (target.id === "approve-selected") {
    const ids = [...document.querySelectorAll("[data-repair]:checked")].map((item) => item.dataset.repair);
    approveRepairs(ids);
  }

  if (target.id === "clear-audit") {
    state.audit = [];
    saveState();
    renderAudit();
  }

  if (target.dataset.filter) {
    activeFilter = target.dataset.filter;
    document.querySelectorAll(".segmented button").forEach((button) => {
      button.classList.toggle("selected", button === target);
    });
    renderFindings();
  }
});

function syncActiveNavigation() {
  const sections = ["overview", "connectors", "scan", "repairs"]
    .map((id) => document.getElementById(id))
    .filter(Boolean);
  const active = [...sections].reverse().find((section) => section.getBoundingClientRect().top <= 160);
  if (!active) return;
  navTargets.forEach((link) => {
    link.classList.toggle("active", link.getAttribute("href") === `#${active.id}`);
  });
}

window.addEventListener("scroll", syncActiveNavigation, { passive: true });

document.querySelector("#scan-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!session.user) {
    openAuthModal("signin");
    showToast("Sign in to start a scan.");
    return;
  }
  if (session.user.emailVerified === false) {
    document.querySelector("#verify-banner").hidden = false;
    showToast("Verify your email address before scanning.");
    return;
  }
  runScan();
});

document.querySelector("#auth-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitAuth(event.currentTarget);
});

document.querySelector("#resend-verify")?.addEventListener("click", resendVerification);
document.querySelector("#forgot-password")?.addEventListener("click", requestPasswordReset);
document.querySelector("#reset-close")?.addEventListener("click", closeResetModal);
document.querySelector("#reset-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  submitResetPassword(event.currentTarget);
});

document.querySelector("#delete-confirm-input").addEventListener("input", updateDeleteSubmitState);
document.querySelector("#delete-password-input").addEventListener("input", updateDeleteSubmitState);

document.querySelector("#org-switcher").addEventListener("change", (event) => {
  state.activeOrgSlug = event.target.value;
  state.connectors = {};
  saveState();
  audit(`Active org switched to ${state.activeOrgSlug}`);
  renderConnectors();
  loadAllConnectorStatuses();
});

document.querySelector("#select-all").addEventListener("change", (event) => {
  document.querySelectorAll("[data-repair]").forEach((checkbox) => {
    checkbox.checked = event.target.checked;
  });
});

if ("serviceWorker" in navigator && location.protocol !== "file:") {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  });
}

renderAll();
syncActiveNavigation();
refreshSession();
maybeShowCookieBanner();
loadAdSlots();

// Password-reset deep link: /reset-password?token=... (served as the SPA shell).
if (location.pathname === "/reset-password") {
  const token = new URLSearchParams(location.search).get("token");
  if (token) openResetModal(token);
}
