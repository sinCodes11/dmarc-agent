function byId(id) { return document.getElementById(id); }
function qs(name) { return new URLSearchParams(window.location.search).get(name); }

function showError(targetId, message) {
  const el = byId(targetId);
  if (!el) return;
  el.textContent = message;
  el.classList.remove("hidden");
}

function clearError(targetId) {
  const el = byId(targetId);
  if (!el) return;
  el.textContent = "";
  el.classList.add("hidden");
}

function norm(value, fallback = "Unknown") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

async function requestJSON(url, options = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.message || data?.error || "Request failed");
  return data;
}

// JsonReporter uses "findings" not "issues"
function asIssues(result) {
  const findings = result?.findings || [];
  if (!Array.isArray(findings)) return [];
  return findings.map((item, idx) => ({
    title: norm(item.title || `Issue ${idx + 1}`),
    severity: norm(item.severity, "INFO").toUpperCase(),
    description: norm(item.description, "No details provided."),
    remediation: norm(item.remediation, ""),
  }));
}

// JsonReporter returns recommended_records as {spf, dmarc, dkim} object
// Filter out non-record values like "requires_provider_action" or "present"
function asRecords(result) {
  const records = result?.recommended_records;
  if (!records || typeof records !== "object" || Array.isArray(records)) return [];

  const dnsNames = { spf: "@", dmarc: "_dmarc" };
  const skipValues = ["present", "no_action_required", "requires_provider_action"];

  return Object.entries(records)
    .filter(([, value]) => {
      if (!value || typeof value !== "string") return false;
      if (skipValues.some(skip => value.toLowerCase().includes(skip))) return false;
      return value.trimStart().toLowerCase().startsWith("v=");
    })
    .map(([key, value]) => ({
      type: "TXT",
      name: dnsNames[key] || key,
      value,
      label: key.toUpperCase(),
    }));
}

function severityClasses(sev) {
  const s = (sev || "INFO").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "text-red-300 border-red-500/40 bg-red-900/40";
  if (s === "MEDIUM") return "text-amber-300 border-amber-500/40 bg-amber-900/30";
  if (s === "LOW") return "text-green-300 border-green-500/40 bg-green-900/30";
  return "text-slate-300 border-slate-500/40 bg-slate-800/40";
}

// Renders a status card using JsonReporter's security_status structure
function renderStatusCard(target, key, value) {
  let checkedLabel, statusText, presenceText;

  if (key === "spf") {
    checkedLabel = "CHECKED";
    presenceText = value?.present ? "Present" : "Missing";
    const qualifierMap = {
      "-": "-all (hardfail ✓)",
      "~": "~all (softfail)",
      "+": "+all (CRITICAL - pass all)",
      "?": "?all (neutral)"
    };
    statusText = value?.present
      ? norm(qualifierMap[value?.all_qualifier] || value?.all_qualifier, "unknown")
      : "Not configured";
  } else if (key === "dkim") {
    checkedLabel = value?.checked ? "CHECKED" : "NOT CHECKED";
    presenceText = !value?.checked
      ? "n/a"
      : value?.present ? "Present" : "Missing";
    statusText = !value?.checked
      ? "Selector check not run"
      : value?.present ? `Selector: ${value.selector}` : "Not found";
  } else if (key === "dmarc") {
    checkedLabel = "CHECKED";
    presenceText = value?.present ? "Present" : "Missing";
    statusText = value?.present
      ? `p=${norm(value?.policy, "unknown")}`
      : "Not configured";
  } else {
    checkedLabel = "CHECKED";
    presenceText = value?.present ? "Present" : "Missing";
    statusText = "unknown";
  }

  target.insertAdjacentHTML(
    "beforeend",
    `<div class="panel rounded-xl p-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-lg font-semibold text-white">${key.toUpperCase()}</h3>
        <span class="text-xs uppercase tracking-widest text-slate-300">${checkedLabel}</span>
      </div>
      <p class="text-sm text-slate-200">Status: <span class="font-semibold">${statusText}</span></p>
      <p class="text-sm text-slate-200 mt-1">Presence: <span class="font-semibold">${presenceText}</span></p>
    </div>`
  );
}

function initIndexPage() {
  const form = byId("scan-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError("scan-error");

    const domain = norm(byId("domain-input")?.value, "").trim().toLowerCase();
    if (!domain) { showError("scan-error", "Please enter a domain."); return; }

    byId("scan-button")?.setAttribute("disabled", "true");
    byId("scan-button")?.classList.add("opacity-70");
    byId("loading-row")?.classList.remove("hidden");

    try {
      const data = await requestJSON("/api/scan", {
        method: "POST",
        body: JSON.stringify({ domain }),
      });
      window.location.href = `/results.html?scan_id=${encodeURIComponent(data.scan_id)}`;
    } catch (err) {
      showError("scan-error", err.message || "Could not run scan.");
      byId("scan-button")?.removeAttribute("disabled");
      byId("scan-button")?.classList.remove("opacity-70");
      byId("loading-row")?.classList.add("hidden");
    }
  });
}

function initResultsPage() {
  const marker = byId("results-root");
  if (!marker) return;

  const scanId = qs("scan_id");
  if (!scanId) { showError("results-error", "Missing scan_id in URL."); return; }
  byId("scan-id") && (byId("scan-id").textContent = scanId);

  requestJSON(`/api/scan/${encodeURIComponent(scanId)}`)
    .then((data) => {
      // result is the JsonReporter dict stored directly
      const result = data.result || {};

      byId("domain-name") && (byId("domain-name").textContent = norm(result.domain));

      // Risk badge
      const risk = norm(result.risk_level, "UNKNOWN").toUpperCase();
      const badge = byId("risk-badge");
      if (badge) {
        badge.textContent = `${risk} RISK`;
        badge.className = badge.className.replace(/\brisk-\S+/g, "");
        badge.classList.add(`risk-${risk}`);
      }

      // Status cards — JsonReporter uses security_status not status
      const statusWrap = byId("status-grid");
      const securityStatus = result.security_status || {};
      ["spf", "dkim", "dmarc"].forEach((key) => {
        if (securityStatus[key] !== undefined) {
          renderStatusCard(statusWrap, key, securityStatus[key]);
        }
      });

      // Issues — JsonReporter uses findings not issues
      const issueWrap = byId("issues-list");
      const issues = asIssues(result);
      if (!issues.length) {
        issueWrap.innerHTML = '<li class="text-slate-300">No issues detected.</li>';
      } else {
        issueWrap.innerHTML = issues.map((issue, idx) =>
          `<li class="panel rounded-xl p-4 border ${severityClasses(issue.severity)}">
            <p class="text-sm uppercase tracking-wider mb-1">${idx + 1}. ${issue.severity}</p>
            <p class="font-semibold text-white">${issue.title}</p>
            <p class="text-slate-200 text-sm mt-1">${issue.description}</p>
            ${issue.remediation ? `<p class="text-slate-300 text-xs mt-2 italic">${issue.remediation}</p>` : ""}
          </li>`
        ).join("");
      }

      // Recommended records
      const recordWrap = byId("records-wrap");
      const records = asRecords(result);
      if (!records.length) {
        recordWrap.innerHTML = '<p class="text-slate-300">No record changes needed.</p>';
      } else {
        recordWrap.innerHTML = records.map((rec, idx) =>
          `<div class="panel rounded-xl p-4">
            <div class="flex items-center justify-between gap-3 mb-2">
              <p class="text-sm uppercase tracking-wider text-slate-300">${rec.label} - Type: ${rec.type} - Name: <code>${rec.name}</code></p>
              <button class="copy-btn text-xs bg-blue-500 hover:bg-blue-400 text-white px-3 py-1 rounded-md" data-copy="record-${idx}">Copy</button>
            </div>
            <code id="record-${idx}" class="block whitespace-pre-wrap break-all text-sm text-slate-100">${rec.value}</code>
          </div>`
        ).join("");

        document.querySelectorAll(".copy-btn").forEach((btn) => {
          btn.addEventListener("click", async () => {
            const target = byId(btn.getAttribute("data-copy"));
            if (!target) return;
            await navigator.clipboard.writeText(target.innerText);
            btn.textContent = "Copied";
            setTimeout(() => { btn.textContent = "Copy"; }, 1200);
          });
        });
      }

      byId("results-loading")?.classList.add("hidden");
      byId("results-content")?.classList.remove("hidden");

      // Report email form
      const reportForm = byId("report-form");
      reportForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        clearError("report-error");
        byId("report-success")?.classList.add("hidden");

        const email = norm(byId("report-email")?.value, "").trim();
        const company = norm(byId("report-company")?.value, "").trim();
        if (!email || !company) {
          showError("report-error", "Please enter both email and company name.");
          return;
        }

        try {
          const resp = await requestJSON(`/api/scan/${encodeURIComponent(scanId)}/report`, {
            method: "POST",
            body: JSON.stringify({ email, company }),
          });
          const successEl = byId("report-success");
          successEl.textContent = resp.message || "Report sent! Check your inbox.";
          successEl.classList.remove("hidden");
        } catch (err) {
          showError("report-error", err.message || "Could not send report.");
        }
      });
    })
    .catch((err) => {
      byId("results-loading")?.classList.add("hidden");
      showError("results-error", err.message || "Could not load scan results.");
    });
}

document.addEventListener("DOMContentLoaded", () => {
  initIndexPage();
  initResultsPage();
});
