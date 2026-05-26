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

const legalText = {
  privacy: `
    <h3>Privacy Policy</h3>
    <p class="muted">Last updated: 2026-05-26.</p>
    <p>Codecanic stores the personal data you give us so we can scan code, run repairs, and bill you. We are the data controller. Email <a href="mailto:privacy@codecanic.app">privacy@codecanic.app</a> for any data subject request.</p>
    <h4>What we collect</h4>
    <ul>
      <li>Email, name, password hash (scrypt with random salt), and account creation timestamp.</li>
      <li>Organizations you create or join, and your role in each.</li>
      <li>Access tokens you connect (GitHub, Vercel, GitLab, Bitbucket, Railway, Xcode). These are stored only for the linked workspace and used to fulfil scans and repairs you request.</li>
      <li>Scan reports and repair audit entries generated from your repositories.</li>
      <li>Signed session cookie (<code>codecanic_session</code>) that identifies your browser session. Sent on requests to Codecanic only.</li>
      <li>Server logs (IP address, request path, timestamps) retained for up to 30 days for security and abuse prevention.</li>
    </ul>
    <h4>Advertising</h4>
    <p>Codecanic is free for everyone. To keep the lights on we display ads served by Google AdSense (publisher ID <code>ca-pub-8731629548430880</code>). Google may set cookies, read approximate location and device information, and use this data to serve and measure personalised or non-personalised ads. Manage your ad choices at <a href="https://adssettings.google.com" target="_blank" rel="noopener">adssettings.google.com</a>. EEA / UK / Swiss users see a Google-provided consent prompt before any non-essential cookie is set.</p>
    <h4>What we do NOT do</h4>
    <ul>
      <li>We do not sell your data.</li>
      <li>We do not pass your connected provider tokens, repository content, or scan results to Google or any other ad partner.</li>
      <li>We do not access provider data outside what is necessary to fulfil a scan or repair you requested.</li>
    </ul>
    <h4>Your rights (GDPR / CCPA / equivalent)</h4>
    <ul>
      <li><strong>Access / portability:</strong> click "Download my data" in your account card.</li>
      <li><strong>Deletion:</strong> click "Delete account" to permanently erase your record and sole-owned organizations.</li>
      <li><strong>Rectification:</strong> email <a href="mailto:privacy@codecanic.app">privacy@codecanic.app</a> for name/email corrections.</li>
      <li><strong>Opt out of marketing:</strong> opt-in only — uncheck the marketing box at signup or email us.</li>
    </ul>
    <h4>Security</h4>
    <p>Sessions are signed with HMAC-SHA256. Cookies use <code>HttpOnly</code>, <code>Secure</code> (in production), and <code>SameSite=Strict</code>. Provider tokens are stored encrypted at rest. Failed login attempts trigger a 15-minute lockout after 5 attempts. TLS is enforced on all connections.</p>
    <h4>Children</h4>
    <p>Codecanic is not directed to children under 16. We require an age confirmation at signup and will delete any account we discover belongs to a child under 16.</p>
  `,
  terms: `
    <h3>Terms of Service</h3>
    <p class="muted">Last updated: 2026-05-26.</p>
    <p>By creating an account you agree to these terms. If you do not agree, do not use Codecanic.</p>
    <h4>Service</h4>
    <p>Codecanic scans repositories and infrastructure you connect to it and proposes repairs for your review. You retain ownership of your code, your provider accounts, and any data you submit.</p>
    <h4>Acceptable use</h4>
    <ul>
      <li>Connect only providers you are authorised to access.</li>
      <li>Do not use Codecanic to scan or modify systems you do not own or have written permission to test.</li>
      <li>Do not attempt to reverse engineer, abuse, or overload the service.</li>
      <li>Do not upload illegal content or use Codecanic to violate any applicable law.</li>
    </ul>
    <h4>Repairs and pull requests</h4>
    <p>Codecanic proposes repairs but never merges them. You approve the segments you want before any change is queued. You are responsible for reviewing the code Codecanic suggests before merging it into production.</p>
    <h4>Cost</h4>
    <p>Codecanic is free for everyone. The service is supported by ads shown via Google AdSense. There are no paid plans, no card on file, and no subscription to cancel.</p>
    <h4>Termination</h4>
    <p>You can delete your account at any time. We may suspend accounts that violate these terms or applicable law.</p>
    <h4>Warranty + liability</h4>
    <p>Codecanic is provided free of charge and "as is" without warranties. To the extent permitted by law, Codecanic's total liability for any claim is limited to USD 100. Codecanic is not liable for indirect or consequential damages.</p>
    <h4>Governing law</h4>
    <p>These terms are governed by the laws applicable to where Codecanic is incorporated. Disputes will be resolved in the courts of that jurisdiction.</p>
    <h4>Changes</h4>
    <p>If we materially change these terms we will notify you by email and via this dashboard.</p>
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

function loadAdSlots() {
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

function maybeShowCookieBanner() {
  try {
    if (localStorage.getItem("codecanic-cookie-ack") === "1") return;
  } catch {
    return;
  }
  const banner = document.querySelector("#cookie-banner");
  if (banner) banner.hidden = false;
}

function ackCookieBanner() {
  try {
    localStorage.setItem("codecanic-cookie-ack", "1");
  } catch {}
  document.querySelector("#cookie-banner").hidden = true;
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
  if (target.id === "cookie-acknowledge") ackCookieBanner();

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
  runScan();
});

document.querySelector("#auth-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitAuth(event.currentTarget);
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
