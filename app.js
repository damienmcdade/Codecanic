const connectors = [
  { name: "GitHub", detail: "Repos, pull requests, dependency graph", status: "Connected", icon: "GH" },
  { name: "Vercel", detail: "Deployments, env vars, runtime logs", status: "Ready", icon: "▲" },
  { name: "Railway", detail: "Services, workers, databases, logs", status: "Needs auth", icon: "RW" },
  { name: "Xcode", detail: "iOS projects, signing, build settings", status: "Ready", icon: "XC" },
  { name: "GitLab", detail: "Repositories, CI pipelines, issues", status: "Available", icon: "GL" },
  { name: "Bitbucket", detail: "Repositories, workspaces, pull requests", status: "Available", icon: "BB" }
];

const scanSteps = [
  ["Discover", "Map repositories, services, build systems, and package managers."],
  ["Analyze", "Run lint, type, dependency, secret, infra, and deployment checks."],
  ["Prioritize", "Score findings by severity, blast radius, and autofix confidence."],
  ["Repair", "Prepare patches for user-approved segments and rerun validation."]
];

const findings = [
  {
    id: "secret-env",
    title: "Potential secret exposed in deployment environment",
    type: "security",
    severity: "critical",
    target: "Vercel / Production",
    fix: "Rotate key, move value to managed secret, update deployment config."
  },
  {
    id: "dep-update",
    title: "Outdated dependency with known vulnerability",
    type: "security",
    severity: "critical",
    target: "github.com/company/api",
    fix: "Upgrade package, regenerate lockfile, run unit and integration checks."
  },
  {
    id: "ts-strict",
    title: "TypeScript strict mode disabled in shared package",
    type: "quality",
    severity: "warning",
    target: "packages/core/tsconfig.json",
    fix: "Enable strict checks and patch unsafe call sites."
  },
  {
    id: "slow-build",
    title: "Build cache is not configured for deployment workers",
    type: "performance",
    severity: "warning",
    target: "Railway / worker-service",
    fix: "Add cache-aware install and build steps for repeat deployments."
  },
  {
    id: "ios-signing",
    title: "iOS build settings missing release signing guardrails",
    type: "quality",
    severity: "warning",
    target: "Xcode / Codecanic.xcodeproj",
    fix: "Add release configuration checks and signing validation."
  }
];

const plans = [
  { name: "Free", price: "$0", speed: "Slowest queue", workers: "1 worker", cta: "Start free" },
  { name: "Basic", price: "$19", speed: "Medium queue", workers: "3 workers", cta: "Choose Basic" },
  { name: "Pro", price: "$59", speed: "Faster queue", workers: "8 workers", cta: "Choose Pro", featured: true },
  { name: "Max", price: "$149", speed: "Fastest available", workers: "Priority worker pool", cta: "Choose Max" }
];

const connectorList = document.querySelector("#connector-list");
const scanTimeline = document.querySelector("#scan-timeline");
const findingsRoot = document.querySelector("#findings");
const pricingGrid = document.querySelector("#pricing-grid");
const scanState = document.querySelector("#scan-state");
const toast = document.querySelector("#toast");
let activeFilter = "all";

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  window.setTimeout(() => toast.classList.remove("visible"), 2600);
}

function renderConnectors() {
  connectorList.innerHTML = connectors
    .map(
      (connector) => `
        <div class="connector">
          <div class="connector-info">
            <span class="connector-icon" aria-hidden="true">${connector.icon}</span>
            <span>
              <strong>${connector.name}</strong>
              <span>${connector.detail}</span>
            </span>
          </div>
          <button class="secondary" type="button" data-connect="${connector.name}">
            ${connector.status}
          </button>
        </div>
      `
    )
    .join("");
}

function renderTimeline(activeIndex = -1) {
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
  const visible = findings.filter(
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
              <span>${finding.target}</span>
            </div>
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
          <button class="${plan.featured ? "primary" : "secondary"}" type="button" data-plan="${plan.name}">
            ${plan.cta}
          </button>
        </article>
      `
    )
    .join("");
}

function runScan() {
  scanState.textContent = "Running";
  showToast("Full infrastructure scan started.");
  let index = 0;
  renderTimeline(index);
  const timer = window.setInterval(() => {
    index += 1;
    if (index >= scanSteps.length) {
      window.clearInterval(timer);
      renderTimeline(scanSteps.length);
      scanState.textContent = "Report ready";
      showToast("Report ready. Review and approve repairs.");
      return;
    }
    renderTimeline(index);
  }, 700);
}

document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const jumpTarget = target.dataset.jump;
  if (jumpTarget) {
    document.querySelector(jumpTarget)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  if (target.id === "run-scan") runScan();

  if (target.id === "export-report") {
    showToast("Report export prepared for PDF and CSV delivery.");
  }

  if (target.dataset.connect) {
    showToast(`${target.dataset.connect} connector authorization queued.`);
  }

  if (target.dataset.single) {
    showToast("Selected repair approved. Patch generation queued.");
  }

  if (target.id === "approve-selected") {
    const count = document.querySelectorAll("[data-repair]:checked").length;
    showToast(count ? `${count} repairs approved.` : "Select repairs before approving.");
  }

  if (target.dataset.filter) {
    activeFilter = target.dataset.filter;
    document.querySelectorAll(".segmented button").forEach((button) => {
      button.classList.toggle("selected", button === target);
    });
    renderFindings();
  }

  if (target.dataset.plan) {
    document.querySelector("#current-tier").textContent = target.dataset.plan;
    const plan = plans.find((item) => item.name === target.dataset.plan);
    document.querySelector("#tier-speed").textContent = `${plan.speed}, ${plan.workers}`;
    showToast(`${target.dataset.plan} checkout session ready.`);
  }
});

document.querySelector("#select-all").addEventListener("change", (event) => {
  document.querySelectorAll("[data-repair]").forEach((checkbox) => {
    checkbox.checked = event.target.checked;
  });
});

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  });
}

renderConnectors();
renderTimeline();
renderFindings();
renderPricing();
