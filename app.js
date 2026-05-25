const connectors = [
  { name: "GitHub", detail: "Repos, pull requests, dependency graph", status: "Disconnected", icon: "GH" },
  { name: "Vercel", detail: "Deployments, env vars, runtime logs", status: "Disconnected", icon: "▲" },
  { name: "Railway", detail: "Services, workers, databases, logs", status: "Disconnected", icon: "RW" },
  { name: "Xcode", detail: "iOS projects, signing, build settings", status: "Disconnected", icon: "XC" },
  { name: "GitLab", detail: "Repositories, CI pipelines, issues", status: "Disconnected", icon: "GL" },
  { name: "Bitbucket", detail: "Repositories, workspaces, pull requests", status: "Disconnected", icon: "BB" }
];

const scanSteps = [
  ["Discover", "Map repositories, services, build systems, and package managers."],
  ["Analyze", "Run lint, type, dependency, secret, infra, and deployment checks."],
  ["Prioritize", "Score findings by severity, blast radius, and autofix confidence."],
  ["Repair", "Prepare patches for user-approved segments and rerun validation."]
];

const plans = [
  { name: "Free", price: "$0", speed: "Slowest queue", workers: "1 worker", cta: "Start free" },
  { name: "Basic", price: "$19", speed: "Medium queue", workers: "3 workers", cta: "Choose Basic" },
  { name: "Pro", price: "$59", speed: "Faster queue", workers: "8 workers", cta: "Choose Pro", featured: true },
  { name: "Max", price: "$149", speed: "Fastest available", workers: "Priority worker pool", cta: "Choose Max" }
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
  tier: "Pro",
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
const pricingGrid = document.querySelector("#pricing-grid");
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

function planByName(name) {
  return plans.find((plan) => plan.name === name) || plans[0];
}

function currentFindings() {
  return state.activeReport?.findings || fallbackFindings;
}

function renderConnectors() {
  connectorList.innerHTML = connectors
    .map((connector) => {
      const live = state.connectors[connector.name];
      const status = live?.status || connector.status;
      const className = status === "Connected" ? "connected" : "";
      return `
        <div class="connector">
          <div class="connector-info">
            <span class="connector-icon" aria-hidden="true">${connector.icon}</span>
            <span>
              <strong>${connector.name}</strong>
              <span>${connector.detail}</span>
            </span>
          </div>
          <button class="secondary ${className}" type="button" data-connect="${connector.name}">
            ${status}
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
    .map(
      (finding) => `
        <article class="finding" data-finding="${finding.id}">
          <label class="checkbox-row" aria-label="Select ${finding.title}">
            <input type="checkbox" data-repair="${finding.id}" />
          </label>
          <div>
            <h3>${finding.title}</h3>
            <p>${finding.fix}</p>
            <div class="finding-meta">
              <span class="severity">${finding.severity}</span>
              <span>${finding.type}</span>
              <span>${finding.confidence || 70}% confidence</span>
              <span>${finding.target}</span>
            </div>
            <code>${finding.patchPreview || "Patch preview will appear after scan."}</code>
          </div>
          <button class="secondary" type="button" data-single="${finding.id}">Approve</button>
        </article>
      `
    )
    .join("");
}

function renderPricing() {
  pricingGrid.innerHTML = plans
    .map(
      (plan) => `
        <article class="price-card ${plan.featured ? "featured" : ""}">
          <h3>${plan.name}</h3>
          <div class="price">${plan.price}<small>/mo</small></div>
          <p>${plan.speed}</p>
          <p>${plan.workers}</p>
          <button class="${state.tier === plan.name ? "primary" : "secondary"}" type="button" data-plan="${plan.name}">
            ${state.tier === plan.name ? "Active" : plan.cta}
          </button>
        </article>
      `
    )
    .join("");
}

function renderJobs() {
  queueCount.textContent = `${state.repairJobs.length} queued`;
  jobList.innerHTML = state.repairJobs.length
    ? state.repairJobs
        .map(
          (job) => `
            <article class="job">
              <strong>${job.branchName}</strong>
              <span>${job.findingIds.length} repairs · ${job.status} · ${job.workerCount} workers</span>
            </article>
          `
        )
        .join("")
    : `<p class="empty-state">Approved repairs will appear here.</p>`;
}

function renderAudit() {
  auditList.innerHTML = state.audit.map((item) => `<p>${item}</p>`).join("");
}

function renderSummary() {
  const summary = state.activeReport?.summary || { critical: 1, warnings: 0, autofixable: 1 };
  document.querySelector("#critical-count").textContent = summary.critical;
  document.querySelector("#warning-count").textContent = summary.warnings;
  document.querySelector("#autofix-count").textContent = summary.autofixable;
  scanState.textContent = state.activeReport ? "Report ready" : "Ready";
  const plan = planByName(state.tier);
  document.querySelector("#current-tier").textContent = plan.name;
  document.querySelector("#tier-speed").textContent = `${plan.speed}, ${plan.workers}`;
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
      .map((org) => `<option value="${org.slug}">${org.name}</option>`)
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
  renderPricing();
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
  saveState();
  audit("Signed out");
  renderAll();
  showToast("Signed out.");
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

async function connectSource(name) {
  try {
    const result = await api(`/api/connectors?name=${encodeURIComponent(name)}`);
    if (result.authUrl) {
      state.connectors[name] = { status: "Authorization ready", authUrl: result.authUrl };
      window.open(result.authUrl, "_blank", "noopener,noreferrer");
      audit(`${name} authorization opened`);
      showToast(`${name} authorization opened.`);
    } else {
      state.connectors[name] = { status: "Needs config", requiredEnv: result.requiredEnv };
      audit(`${name} needs ${result.requiredEnv}`);
      showToast(result.message);
    }
  } catch (error) {
    state.connectors[name] = { status: "Demo connected" };
    audit(`${name} connected in demo mode`);
    showToast(`${name} connected in demo mode.`);
  }
  saveState();
  renderConnectors();
}

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
      body: JSON.stringify({ sourceUrl, scanDepth, tier: state.tier, connectors: state.connectors })
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
    const findings = fallbackFindings;
    state.activeReport = {
      id: crypto.randomUUID(),
      sourceUrl: sourceUrl || "Demo workspace",
      scanDepth,
      tier: state.tier,
      status: "report_ready",
      createdAt: new Date().toISOString(),
      summary: { critical: 1, warnings: 0, autofixable: 1 },
      findings
    };
    audit("Demo scan completed");
    saveState();
    renderAll();
    showToast("Demo report ready. Deploy API endpoints for live scans.");
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
      body: JSON.stringify({ findingIds, tier: state.tier, reportId: state.activeReport?.id })
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

async function choosePlan(planName) {
  if (planName === "Free") {
    state.tier = planName;
    audit("Free plan activated");
    saveState();
    renderAll();
    showToast("Free plan activated.");
    return;
  }

  try {
    const checkout = await api("/api/checkout", {
      method: "POST",
      body: JSON.stringify({ plan: planName })
    });
    if (checkout.url) {
      window.location.href = checkout.url;
      return;
    }
    state.tier = planName;
    audit(`${planName} selected; Stripe configuration needed`);
    saveState();
    renderAll();
    showToast(checkout.message || `${planName} selected.`);
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

  if (target.id === "run-scan") runScan();
  if (target.id === "export-report") exportReport();
  if (target.dataset.connect) connectSource(target.dataset.connect);
  if (target.dataset.single) approveRepairs([target.dataset.single]);
  if (target.dataset.plan) choosePlan(target.dataset.plan);

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
  const sections = ["overview", "connectors", "scan", "repairs", "billing"]
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

document.querySelector("#org-switcher").addEventListener("change", (event) => {
  state.activeOrgSlug = event.target.value;
  saveState();
  audit(`Active org switched to ${state.activeOrgSlug}`);
});

document.querySelector("#select-all").addEventListener("change", (event) => {
  document.querySelectorAll("[data-repair]").forEach((checkbox) => {
    checkbox.checked = event.target.checked;
  });
});

const checkoutParams = new URLSearchParams(window.location.search);
if (checkoutParams.get("checkout") === "success" && checkoutParams.get("plan")) {
  state.tier = checkoutParams.get("plan");
  audit(`${state.tier} checkout completed`);
  saveState();
  history.replaceState(null, "", window.location.pathname);
}

if ("serviceWorker" in navigator && location.protocol !== "file:") {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  });
}

renderAll();
syncActiveNavigation();
refreshSession();
