const PLAN_DOMAIN_LIMITS = { starter: 1, growth: 5, business: 15 };

function planLabel(plan) {
  const p = String(plan || "starter").toLowerCase();
  return p.charAt(0).toUpperCase() + p.slice(1);
}

async function loadDashboard() {
  if (!requireAuth()) return;

  try {
    const [user, domains] = await Promise.all([
      requestJSON("/api/user", { headers: authHeaders() }),
      requestJSON("/api/user/domains", { headers: authHeaders() }),
    ]);

    byId("plan-badge").textContent = `${planLabel(user.plan)} Plan`;
    const limit = PLAN_DOMAIN_LIMITS[String(user.plan || "starter").toLowerCase()] || 1;
    byId("domain-limit").textContent = `${domains.length} of ${limit} domains`;

    const wrap = byId("domains-wrap");
    if (!domains.length) {
      byId("empty-state").classList.remove("hidden");
      wrap.innerHTML = "";
    } else {
      byId("empty-state").classList.add("hidden");
      wrap.innerHTML = domains.map((domain) => {
        const risk = String(domain.current_risk_level || "UNKNOWN").toUpperCase();
        return `<button data-domain-id="${domain.id}" class="panel rounded-xl p-5 text-left hover:border-blue-400/60 transition-colors">
          <div class="flex items-center justify-between gap-3">
            <h3 class="text-lg font-semibold">${domain.domain}</h3>
            <span class="px-3 py-1 rounded-lg text-xs font-semibold ${riskBadgeClass(risk)}">${risk}</span>
          </div>
          <p class="text-slate-300 text-sm mt-3">Last scanned: ${fmtDate(domain.last_scanned_at)}</p>
        </button>`;
      }).join("");

      wrap.querySelectorAll("button[data-domain-id]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const id = btn.getAttribute("data-domain-id");
          window.location.href = `/domain?id=${encodeURIComponent(id)}`;
        });
      });
    }
  } catch (err) {
    showError("dashboard-error", err.message || "Failed to load dashboard");
  }
}

function initAddDomain() {
  const form = byId("add-domain-form");
  if (!form) return;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError("add-domain-error");

    const domain = String(byId("domain-input")?.value || "").trim().toLowerCase();
    if (!domain) {
      showError("add-domain-error", "Enter a domain");
      return;
    }

    const btn = byId("add-domain-btn");
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Adding...";

    try {
      await requestJSON("/api/user/domains", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ domain }),
      });
      byId("domain-input").value = "";
      await loadDashboard();
    } catch (err) {
      showError("add-domain-error", err.message || "Unable to add domain");
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  byId("logout-btn")?.addEventListener("click", logout);
  initAddDomain();
  await loadDashboard();
});
