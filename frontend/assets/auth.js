function getToken() { return localStorage.getItem("sentrydmarc_token"); }
function setToken(t) { localStorage.setItem("sentrydmarc_token", t); }
function clearToken() { localStorage.removeItem("sentrydmarc_token"); }
function authHeaders() {
  return { "Content-Type": "application/json", "Authorization": "Bearer " + (getToken() || "") };
}
function requireAuth() {
  if (!getToken()) {
    window.location.href = "/login";
    return false;
  }
  return true;
}
function logout() {
  clearToken();
  localStorage.removeItem("sentrydmarc_email");
  window.location.href = "/login";
}

function riskBadgeClass(riskLevel) {
  const level = String(riskLevel || "UNKNOWN").toUpperCase();
  if (["LOW", "MEDIUM", "HIGH"].includes(level)) return `risk-${level}`;
  return "risk-UNKNOWN";
}

function fmtDate(iso) {
  if (!iso) return "Never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Never";
  return d.toLocaleString();
}

function asIssues(result) {
  const findings = result?.findings || [];
  if (!Array.isArray(findings)) return [];
  return findings.map((item, idx) => ({
    title: item?.title || `Issue ${idx + 1}`,
    severity: String(item?.severity || "INFO").toUpperCase(),
    description: item?.description || "No details provided.",
    remediation: item?.remediation || "",
  }));
}

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

function renderStatusCard(target, key, value) {
  let checkedLabel;
  let statusText;
  let presenceText;

  if (key === "spf") {
    checkedLabel = "CHECKED";
    presenceText = value?.present ? "Present" : "Missing";
    const qualifierMap = { "-": "-all (hardfail ✓)", "~": "~all (softfail)", "+": "+all (CRITICAL)", "?": "?all (neutral)" };
    statusText = value?.present ? (qualifierMap[value?.all_qualifier] || value?.all_qualifier || "unknown") : "Not configured";
  } else if (key === "dkim") {
    checkedLabel = value?.checked ? "CHECKED" : "NOT CHECKED";
    presenceText = !value?.checked ? "n/a" : (value?.present ? "Present" : "Missing");
    statusText = !value?.checked ? "Selector check not run" : (value?.present ? `Selector: ${value.selector}` : "Not found");
  } else {
    checkedLabel = "CHECKED";
    presenceText = value?.present ? "Present" : "Missing";
    statusText = value?.present ? `p=${value?.policy || "unknown"}` : "Not configured";
  }

  target.insertAdjacentHTML(
    "beforeend",
    `<div class="panel rounded-lg p-5">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-base font-semibold" style="font-family:var(--font-mono)">${key.toUpperCase()}</h3>
        <span class="text-xs uppercase tracking-widest" style="color:var(--text-muted);font-family:var(--font-mono)">${checkedLabel}</span>
      </div>
      <p class="text-sm" style="font-family:var(--font-sans);color:var(--text-secondary)">Status: <span class="font-semibold" style="color:var(--text-primary)">${statusText}</span></p>
      <p class="text-sm mt-1" style="font-family:var(--font-sans);color:var(--text-secondary)">Presence: <span class="font-semibold" style="color:var(--text-primary)">${presenceText}</span></p>
    </div>`
  );
}
