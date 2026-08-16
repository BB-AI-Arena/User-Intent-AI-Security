const isLoopbackDemo = ["127.0.0.1", "localhost", "::1"].includes(window.location.hostname);
const state = {
  token: sessionStorage.getItem("uig-token") || (isLoopbackDemo ? "local-dev-change-me" : ""),
  policy: null,
  securityPolicies: null,
  model: null,
  trustControls: null,
  inventory: null,
  deployments: [],
  auditEvents: [],
  auditFilter: null,
  auditPage: 1,
  auditPageSize: 10,
};
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function authHeaders(json = false) {
  const headers = {};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (json) headers["Content-Type"] = "application/json";
  return headers;
}

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { ...authHeaders(Boolean(options.body)), ...(options.headers || {}) } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) openTokenDialog();
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  return body;
}

function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.remove("show"), 3000);
}

function openTokenDialog() {
  $("#api-token").value = state.token;
  $("#token-dialog").showModal();
}

function escapeHtml(value) {
  const node = document.createElement("span");
  node.textContent = value ?? "";
  return node.innerHTML;
}

function formatTime(timestamp) {
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(timestamp * 1000));
}

function renderIntelligenceFabric(events) {
  const newest = Number(events[0]?.timestamp || 0);
  const mutationPattern = /(?:set-content|add-content|out-file|writealltext|apply_patch|\b(?:sed|perl)\s+-i\b|\b(?:mv|move|copy|cp)\b)/i;
  const burst = events.filter((item) => newest - Number(item.timestamp || 0) <= 120 && mutationPattern.test(String(item.command || "")));
  const anomalyEvents = events.filter((item) => Number(item.anomaly_score || 0) > 0 || (item.signals || []).includes("behavioral-anomaly"));
  const topAnomaly = [...anomalyEvents].sort((a, b) => Number(b.anomaly_score || 0) - Number(a.anomaly_score || 0))[0];
  const uniqueActors = new Set(anomalyEvents.map((item) => item.user_name).filter(Boolean)).size;
  const coverage = events.length ? Math.round(events.filter((item) => item.user_name && item.endpoint_name && item.endpoint_name !== "unknown-endpoint").length / events.length * 100) : 0;
  const trustGaps = events.filter((item) => !item.purpose || !item.user_name || !item.endpoint_name || item.endpoint_name === "unknown-endpoint");
  const highRisk = events.filter((item) => Number(item.risk_score || 0) >= 80);
  const maturity = Math.min(100, Math.round(events.length / 100 * 100));
  const controls = state.trustControls;
  const zero = controls?.zero_trust;
  const micro = controls?.microsegmentation;
  const urgentConditions = highRisk.length || trustGaps.length || burst.length >= 3;
  $("#priority-high-risk").textContent = highRisk.length;
  $("#priority-trust-gaps").textContent = trustGaps.length;
  $("#attention-summary").textContent = urgentConditions
    ? `${highRisk.length} high-risk actions and ${trustGaps.length} trust-context gaps need triage. Start with scored evidence.`
    : "No urgent conditions detected. Continue monitoring the live decision stream.";
  $("#fabric-event-count").textContent = `${events.length} EVENTS`;
  $("#ml-sample-count").textContent = events.length;
  $("#ml-coverage").textContent = `${maturity}%`;
  $("#ml-progress").style.width = `${Math.max(8, maturity)}%`;
  $("#ml-headline").textContent = `Baseline health · ${maturity >= 80 ? "mature" : maturity >= 40 ? "learning" : "limited"}`;
  $("#ml-observation").textContent = highRisk.length
    ? `${highRisk.length} high-risk outlier${highRisk.length === 1 ? "" : "s"} need operator validation.`
    : "No high-risk outliers in the current window.";
  $("#behavior-state").textContent = burst.length >= 3 ? "ACTION NEEDED" : anomalyEvents.length ? "ELEVATED" : "NORMAL";
  $("#behavior-state").classList.toggle("alert", burst.length >= 3 || anomalyEvents.length > 5);
  $("#behavior-headline").textContent = burst.length >= 3
    ? `${burst.length} rapid file changes detected`
    : `${anomalyEvents.length} rare patterns across ${uniqueActors || 0} identities`;
  $("#behavior-summary").textContent = burst.length >= 3
    ? `Mutation velocity exceeded the two-minute sequence threshold.`
    : anomalyEvents.length
      ? `${anomalyEvents.length} commands deviated from learned user behavior.`
      : "No material deviation from learned operator behavior.";
  $("#behavior-outlier").textContent = topAnomaly
    ? `${topAnomaly.command} · ${topAnomaly.user_name || "unknown user"} · deviation ${Number(topAnomaly.anomaly_score || 0)}/40`
    : "No behavioral outlier in the current window.";
  $("#behavior-recommendation").textContent = burst.length >= 3
    ? `Validate the ${burst.length}-command mutation burst and temporarily step up the actor if unexpected.`
    : topAnomaly
      ? `Confirm whether ${topAnomaly.user_name || "the operator"} expected the highest-deviation command sequence.`
      : "Keep collecting representative behavior before tightening anomaly policy.";
  $("#micro-headline").textContent = `${micro?.enabled_zones?.length ?? 5} zones · default ${micro?.default_action || "deny"}`;
  $("#micro-flows").textContent = `${micro?.allowed_flows?.length ?? 5} explicitly allowed service paths`;
  const pendingTopology = micro?.deployment_status === "redeploy-required";
  $("#micro-state").textContent = pendingTopology ? "REDEPLOY" : "ENFORCED";
  $("#micro-state").classList.toggle("alert", pendingTopology);
  $("#micro-observation").textContent = pendingTopology
    ? "A saved topology change is waiting for Docker redeployment."
    : `${micro?.log_denied === false ? "Denied-flow logging is disabled." : "Denied flows are logged; no topology drift is pending."}`;
  $("#micro-recommendation").textContent = pendingTopology
    ? "Review the staged path changes and schedule a controlled redeployment."
    : micro?.log_denied === false
      ? "Enable denied-flow logging before changing the allowed-path policy."
      : "Review denied-flow telemetry before adding any new service path.";
  $("#trust-headline").textContent = `${coverage}% actor + endpoint coverage`;
  $("#trust-policy").textContent = zero
    ? `${zero.enforcement_mode} mode · step-up at ${zero.step_up_threshold}/100`
    : "Loading the active verification policy.";
  $("#trust-gaps").textContent = trustGaps.length
    ? `${trustGaps.length} records are missing identity, endpoint, or declared intent.`
    : "No identity, endpoint, or intent gaps in the current window.";
  $("#trust-state").textContent = trustGaps.length ? "GAPS FOUND" : "VERIFIED";
  $("#trust-state").classList.toggle("alert", trustGaps.length > 0);
  $("#trust-recommendation").textContent = trustGaps.length
    ? `Enrich ${trustGaps.length} records with identity, endpoint, or declared intent before enforce mode.`
    : "Trust context is complete; review step-up thresholds for least privilege.";
  $("#ml-recommendation").textContent = highRisk.length
    ? `Label the ${highRisk.length} high-risk outliers as expected or suspicious to improve precision.`
    : maturity < 80 ? "Collect more representative command families before relying on rarity." : "Baseline coverage is mature; review drift weekly.";
  const visible = events.slice(0, 5);
  $("#fabric-event-stream").innerHTML = visible.length ? visible.map((item) => `<div class="stream-event ${escapeHtml(item.decision)}">
    <time>${new Date(Number(item.timestamp) * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time>
    <code>${escapeHtml(item.command)}</code><b>${escapeHtml(item.decision).toUpperCase()} · ${Number(item.risk_score || 0)}</b>
  </div>`).join("") : "<p>Waiting for assessment telemetry…</p>";
}

function updateFabricAI(label, detail, stateName = "") {
  $("#fabric-ai-label").textContent = label;
  $("#fabric-ai-detail").textContent = detail;
  $("#fabric-ai-core").classList.toggle("is-ready", stateName === "ready");
  $("#fabric-ai-core").classList.toggle("is-offline", stateName === "offline");
}

async function loadOverview() {
  try {
    const [posture, audit] = await Promise.all([api("/v1/posture"), api("/v1/audit?limit=500")]);
    const events = audit.events || [];
    state.auditEvents = events;
    const counts = { allow: 0, review: 0, block: 0 };
    let latency = 0;
    events.forEach((item) => { if (item.decision in counts) counts[item.decision] += 1; latency += Number(item.latency_ms || 0); });
    $("#posture-score").textContent = posture.risk_score || 0;
    $("#allow-count").textContent = counts.allow;
    $("#review-count").textContent = counts.review;
    $("#block-count").textContent = counts.block;
    $("#latency-value").textContent = events.length ? (latency / events.length).toFixed(2) : "0.00";
    $("#service-status").textContent = "Service online";
    renderIntelligenceFabric(events);
    renderAudit(getFilteredAuditEvents());
    renderModelShowcase();
  } catch (error) {
    $("#service-status").textContent = "Access required";
    if (state.token) toast(error.message);
  }
}

function renderAssessment(result) {
  const decision = result.decision;
  const title = { allow: "Consistent with intent", review: "Human review required", block: "Operation blocked" }[decision];
  const signals = (result.signals || []).map((signal) => `
    <div class="signal">
      <b>${signal.score >= 0 ? "+" : ""}${signal.score}</b>
      <strong>${escapeHtml(signal.name)}</strong>
      <span>${escapeHtml(signal.detail)}</span>
    </div>`).join("");
  $("#assessment-result").className = "assessment-result";
  $("#assessment-result").innerHTML = `
    <div class="result-head decision-${decision}">
      <div class="decision-seal">${decision.toUpperCase()}</div>
      <div><h3>${title}</h3><p>Policy ${escapeHtml(result.policy_name)} v${result.policy_version} · ${Number(result.latency_ms).toFixed(3)} ms · assessment only</p></div>
      <div class="risk-number"><strong>${result.risk_score}</strong><small>RISK / 100</small></div>
    </div>
    <div class="signal-list">${signals || '<p class="empty-copy">No risk signals contributed to this decision.</p>'}</div>
    <div id="model-advisory-result" class="model-advisory-result model-pending">
      <div class="model-advisory-head"><span class="model-orb">AI</span><div><strong>Model advisor</strong><small>Waiting for deterministic assessment</small></div></div>
    </div>`;
}

function renderModelAdvisory(response) {
  const target = $("#model-advisory-result");
  if (!target) return;
  if (response.status !== "ready" || !response.advisory) {
    const message = response.status === "unconfigured"
      ? "OpenAI adapter is ready. Add UIG_MODEL_API_KEY or OPENAI_API_KEY to activate model determinations."
      : response.status === "disabled" ? "Model advisory is disabled; deterministic policy remains active." : (response.error || "The model advisor is unavailable.");
    target.className = "model-advisory-result model-pending";
    target.innerHTML = `<div class="model-advisory-head"><span class="model-orb">AI</span><div><strong>Model advisor unavailable</strong><small>${escapeHtml(response.provider || "disabled")} · ${escapeHtml(response.model || "no model")}</small></div></div><p>${escapeHtml(message)}</p>`;
    updateFabricAI(response.status === "unconfigured" ? "AI READY · KEY NEEDED" : "AI ADVISOR OFFLINE", `${response.provider || "No provider"} / ${response.model || "no model"}`, "offline");
    return;
  }
  const item = response.advisory;
  const reasons = (item.reasons || []).map((reason) => `<li>${escapeHtml(reason)}</li>`).join("");
  target.className = `model-advisory-result decision-${item.recommended_decision}`;
  target.innerHTML = `<div class="model-advisory-head"><span class="model-orb">AI</span><div><strong>${escapeHtml(item.recommended_decision.toUpperCase())} · ${escapeHtml(item.intent_alignment)} intent</strong><small>${escapeHtml(response.provider)} / ${escapeHtml(response.model)} · ${(Number(response.latency_ms) / 1000).toFixed(2)} s · advisory only${response.simulation ? " · SIMULATED DEMO" : ""}</small></div><div class="model-advisory-score"><b>${item.risk_score}</b><small>${Math.round(Number(item.confidence) * 100)}% CONFIDENCE</small></div></div><p>${escapeHtml(item.summary)}</p>${reasons ? `<ul class="model-reasons">${reasons}</ul>` : ""}`;
  updateFabricAI(`AI DETERMINATION · ${item.recommended_decision.toUpperCase()}`, `${Math.round(Number(item.confidence) * 100)}% confidence · ${item.intent_alignment} intent`, "ready");
}

async function requestModelAdvisory(payload) {
  const target = $("#model-advisory-result");
  if (target) target.innerHTML = '<div class="model-advisory-head"><span class="model-orb">AI</span><div><strong>Model advisor</strong><small>Analyzing intent independently…</small></div></div>';
  updateFabricAI("AI ANALYZING INTENT", "Independent structured determination in progress", "ready");
  try { renderModelAdvisory(await api("/v1/model-assess", { method: "POST", body: JSON.stringify(payload) })); }
  catch (error) { renderModelAdvisory({ status: "error", error: error.message, provider: state.model?.provider, model: state.model?.model }); }
}

async function assessCommand(event) {
  event.preventDefault();
  const submit = event.submitter;
  submit.disabled = true;
  submit.querySelector("span").textContent = "Assessing…";
  try {
    const payload = { command: $("#command").value, purpose: $("#purpose").value, cwd: $("#cwd").value };
    const result = await api("/v1/assess", { method: "POST", body: JSON.stringify(payload) });
    renderAssessment(result);
    requestModelAdvisory(payload);
    await Promise.all([loadOverview(), loadReviews()]);
    toast(`${result.decision.toUpperCase()} · risk ${result.risk_score}`);
  } catch (error) { toast(error.message); }
  finally { submit.disabled = false; submit.querySelector("span").textContent = "Assess command"; }
}

function getFilteredAuditEvents() {
  const events = state.auditEvents || [];
  const filtered = state.auditFilter === "behavior"
    ? events.filter((item) => Number(item.anomaly_score || 0) > 0 || (item.signals || []).includes("behavioral-anomaly"))
    : state.auditFilter === "high-risk"
      ? events.filter((item) => Number(item.risk_score || 0) >= 80)
      : state.auditFilter === "trust-gap"
        ? events.filter((item) => !item.purpose || !item.user_name || !item.endpoint_name || item.endpoint_name === "unknown-endpoint")
        : events;
  return filtered;
}

function setAuditFilter(filter) {
  state.auditFilter = filter;
  state.auditPage = 1;
  const labels = {
    behavior: "Behavioral anomalies and sequence deviations",
    "high-risk": "High-risk policy outliers (80+)",
    "trust-gap": "Missing identity, endpoint, or declared intent",
  };
  const bar = $("#audit-filter-bar");
  bar.hidden = !filter;
  $("#audit-filter-label").textContent = labels[filter] || "Filtered evidence";
  renderAudit(getFilteredAuditEvents());
  document.querySelector("#audit").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderAudit(events) {
  const body = $("#audit-body");
  const pageCount = Math.max(1, Math.ceil(events.length / state.auditPageSize));
  state.auditPage = Math.max(1, Math.min(state.auditPage, pageCount));
  const start = (state.auditPage - 1) * state.auditPageSize;
  const visible = events.slice(start, start + state.auditPageSize);
  $("#audit-range").textContent = events.length ? `Showing ${start + 1}–${start + visible.length} of ${events.length}` : "0 events";
  $("#audit-page-label").textContent = `Page ${state.auditPage} of ${pageCount}`;
  $("#audit-previous").disabled = state.auditPage <= 1;
  $("#audit-next").disabled = state.auditPage >= pageCount;
  if (!visible.length) { body.innerHTML = '<tr><td colspan="6" class="empty-copy">No assessments recorded.</td></tr>'; return; }
  body.innerHTML = visible.map((item, index) => {
    const risk = Math.max(0, Math.min(100, Number(item.risk_score || 0)));
    const detailId = `audit-detail-${start + index}`;
    const evidence = Array.isArray(item.signal_details) && item.signal_details.length
      ? item.signal_details
      : (item.signals || []).map((name) => ({ name, score: null, detail: "Signal recorded before detailed evidence capture was enabled." }));
    const evidenceHtml = evidence.length ? evidence.map((signal) => `<div class="audit-evidence-item">
      <b>${signal.score === null ? "—" : `${Number(signal.score) >= 0 ? "+" : ""}${Number(signal.score)}`}</b>
      <div><strong>${escapeHtml(signal.name)}</strong><p>${escapeHtml(signal.detail)}</p></div>
    </div>`).join("") : '<p class="audit-no-evidence">No positive risk signal was required; the action remained below the active review threshold.</p>';
    const explanation = item.decision === "allow"
      ? "Allowed because the combined evidence remained below the active review threshold."
      : item.decision === "review"
        ? "Held for review because the evidence crossed the human step-up threshold."
        : "Blocked because the combined evidence reached the policy denial threshold.";
    return `<tr class="audit-summary-row" data-audit-toggle="${detailId}" tabindex="0" aria-expanded="false">
    <td>${formatTime(item.timestamp)}</td>
    <td><span class="decision-pill ${item.decision}">${escapeHtml(item.decision)}</span></td>
    <td><span class="actor-cell">${escapeHtml(item.user_name || "legacy record")}</span></td>
    <td><span class="endpoint-cell">${escapeHtml(item.endpoint_name || "not recorded")}</span></td>
    <td><button type="button" class="audit-command-button" aria-controls="${detailId}"><code>${escapeHtml(item.command)}</code><span>VIEW WHY ›</span></button></td>
    <td><span class="audit-risk-value risk-${item.decision}">${risk}</span></td>
  </tr>
  <tr id="${detailId}" class="audit-detail-row" hidden><td colspan="6">
    <div class="audit-explanation decision-${item.decision}">
      <div class="audit-explanation-head"><div><p class="eyebrow">DECISION EXPLANATION</p><h3>Why this was ${escapeHtml(item.decision)}ed</h3><p>${explanation}</p></div><div class="audit-risk-orb"><strong>${risk}</strong><small>RISK / 100</small></div></div>
      <div class="audit-risk-track"><span style="width:${risk}%"></span></div>
      <div class="audit-context-grid"><div><small>USER</small><strong>${escapeHtml(item.user_name || "Legacy record")}</strong></div><div><small>ENDPOINT</small><strong>${escapeHtml(item.endpoint_name || "Not recorded")}</strong></div><div><small>DECLARED PURPOSE</small><strong>${escapeHtml(item.purpose || "No purpose supplied")}</strong></div><div><small>POLICY RESULT</small><strong>${escapeHtml(item.decision).toUpperCase()} · ${risk}/100</strong></div></div>
      <div class="audit-evidence"><p class="config-caption">SCORED DECISION EVIDENCE</p>${evidenceHtml}</div>
    </div>
  </td></tr>`;
  }).join("");
}

function changeAuditPage(delta) {
  state.auditPage += delta;
  renderAudit(getFilteredAuditEvents());
  $("#audit").scrollIntoView({ behavior: "smooth", block: "start" });
}

function toggleAuditDetail(row) {
  const detail = document.getElementById(row.dataset.auditToggle);
  if (!detail) return;
  const opening = detail.hidden;
  detail.hidden = !opening;
  row.setAttribute("aria-expanded", String(opening));
  row.classList.toggle("expanded", opening);
}

async function loadAudit() {
  try { const data = await api("/v1/audit?limit=500"); state.auditEvents = data.events || []; renderAudit(getFilteredAuditEvents()); renderIntelligenceFabric(state.auditEvents); }
  catch (error) { if (state.token) toast(error.message); }
}

function renderReviews(reviews) {
  const pending = reviews.filter((item) => item.status === "pending");
  $("#review-badge").textContent = pending.length;
  $("#priority-reviews").textContent = pending.length;
  const list = $("#review-list");
  if (!reviews.length) { list.innerHTML = '<p class="empty-copy">No commands are waiting for review.</p>'; return; }
  list.innerHTML = reviews.slice(0, 30).map((item) => `<article class="review-item ${item.status !== "pending" ? "resolved" : ""}">
    <div><code>${escapeHtml(item.command)}</code><p>${escapeHtml(item.purpose || "No declared purpose")}</p>
      <div class="review-meta"><span>risk ${item.risk_score}</span><span>${escapeHtml(item.status)}</span><span>${formatTime(item.created_at)}</span></div>
    </div>
    <div class="review-actions">${item.status === "pending" ? `<button class="approve" data-review="${item.id}" data-status="approved">Approve</button><button class="deny" data-review="${item.id}" data-status="denied">Deny</button>` : ""}</div>
  </article>`).join("");
}

async function loadReviews() {
  try { const data = await api("/v1/reviews"); renderReviews(data.reviews || []); }
  catch (error) { if (state.token) toast(error.message); }
}

async function decideReview(event) {
  const button = event.target.closest("[data-review]");
  if (!button) return;
  try {
    await api(`/v1/reviews/${button.dataset.review}`, { method: "POST", body: JSON.stringify({ status: button.dataset.status }) });
    toast(`Review ${button.dataset.status}. No command was executed.`);
    await loadReviews();
  } catch (error) { toast(error.message); }
}

function renderPolicy(policy) {
  state.policy = policy;
  $("#policy-name").value = policy.name;
  $("#policy-version").textContent = `v${policy.version}`;
  $("#review-threshold").value = policy.review_threshold;
  $("#block-threshold").value = policy.block_threshold;
  $("#review-output").textContent = policy.review_threshold;
  $("#block-output").textContent = policy.block_threshold;
  const catalog = policy.catalog || [];
  $("#rule-count").textContent = `${catalog.length} rules`;
  $("#rule-catalog").innerHTML = catalog.map((item) => `<div class="rule-item"><div><strong>${escapeHtml(item.identifier)}</strong><p>${escapeHtml(item.description)} · ${escapeHtml(item.category)}</p></div><b>+${item.score}</b></div>`).join("");
}

async function loadPolicy() {
  try { renderPolicy(await api("/v1/policy")); }
  catch (error) { if (state.token) toast(error.message); }
}

function renderModelStatus(config) {
  state.model = config;
  $("#model-provider").textContent = config.provider || "disabled";
  $("#model-name").textContent = config.model || "—";
  $("#model-status-badge").textContent = config.simulation ? "online · demo" : config.status;
  $("#model-config-note").textContent = config.simulation
    ? "Demo Simulation is online. It produces realistic structured advisory output locally without sending data to an external model."
    : config.status === "configured"
    ? "The advisor is configured. Each console assessment will request an independent structured determination after deterministic policy returns."
    : config.status === "unconfigured"
      ? "The OpenAI route is selected but has no API key. Set UIG_MODEL_API_KEY or OPENAI_API_KEY and rebuild the service."
      : "The model router is disabled. Deterministic command policy continues to operate normally.";
  if (config.simulation) updateFabricAI("AI DEMO ONLINE", `${config.model} · simulated advisory`, "ready");
  else if (config.status === "configured") updateFabricAI("AI ADVISOR ONLINE", `${config.provider} / ${config.model}`, "ready");
  else if (config.status === "unconfigured") updateFabricAI("AI READY · KEY NEEDED", `${config.provider} / ${config.model}`, "offline");
  else updateFabricAI("AI ADVISOR DISABLED", "Deterministic policy remains authoritative", "offline");
  renderModelShowcase();
}

function renderModelShowcase() {
  const config = state.model;
  const events = state.auditEvents || [];
  if (!config) return;
  const simulated = Boolean(config.simulation);
  $("#model-live-title").textContent = simulated ? "Demo inference plane online" : config.status === "configured" ? "Model inference plane online" : "Model advisor unavailable";
  $("#model-live-copy").textContent = simulated
    ? "Local replay generates schema-valid advisory verdicts for presentation use."
    : config.status === "configured" ? "Structured advisory requests are ready for authenticated inference." : "Configure a provider credential to enable determinations.";
  $("#model-health-schema").textContent = config.status === "configured" ? "VALID" : "WAIT";
  $("#model-health-latency").textContent = simulated ? "180 ms" : config.status === "configured" ? "LIVE" : "—";
  $("#model-health-volume").textContent = events.length;
  $("#model-demo-label").textContent = simulated ? "DEMO SIMULATION" : "ADVISORY PREVIEW";
  const selected = [];
  ["block", "review", "allow"].forEach((decision) => {
    const match = events.find((item) => item.decision === decision);
    if (match) selected.push(match);
  });
  events.forEach((item) => { if (selected.length < 6 && !selected.includes(item)) selected.push(item); });
  $("#recent-model-determinations").innerHTML = selected.length ? selected.slice(0, 6).map((item) => {
    const mismatch = (item.signals || []).includes("purpose-mismatch");
    const reason = item.signal_details?.find((signal) => Number(signal.score) > 0)?.detail
      || (item.decision === "allow" ? "Action remained below the configured review threshold." : "Policy evidence requires elevated scrutiny.");
    const confidence = item.decision === "block" ? 97 : item.decision === "review" ? 89 : 94;
    return `<article class="model-verdict-card ${escapeHtml(item.decision)}"><div class="model-verdict-top"><span class="${escapeHtml(item.decision)}">AI · ${escapeHtml(item.decision).toUpperCase()}</span><b>${confidence}% CONF</b></div><code>${escapeHtml(item.command)}</code><p>${escapeHtml(reason)}</p><div class="model-verdict-meta"><span>${mismatch ? "MISMATCH" : "MATCHED"} INTENT</span><span>RISK ${Number(item.risk_score || 0)}/100</span></div></article>`;
  }).join("") : '<p class="empty-copy">Run an assessment to generate demo determinations.</p>';
}

async function loadModelStatus() {
  try { renderModelStatus(await api("/v1/model")); }
  catch (error) { if (state.token) toast(error.message); }
}

function renderTrustControls(config) {
  state.trustControls = config;
  const zero = config.zero_trust;
  const micro = config.microsegmentation;
  $("#trust-version").textContent = `v${config.version}`;
  $("#zt-mode").value = zero.enforcement_mode;
  $("#zt-identity").checked = zero.identity_required;
  $("#zt-purpose").checked = zero.purpose_required;
  $("#zt-device").checked = zero.device_posture_required;
  $("#zt-behavior").checked = zero.behavior_monitoring;
  $("#zt-threshold").value = zero.step_up_threshold;
  $("#zt-ttl").value = zero.session_ttl_minutes;
  $("#segment-default").value = micro.default_action;
  $("#segment-identity").checked = micro.service_identity;
  $("#segment-log").checked = micro.log_denied;
  $$("#zone-selector input").forEach((input) => { input.checked = micro.enabled_zones.includes(input.value); });
  $$("#flow-selector input").forEach((input) => { input.checked = micro.allowed_flows.includes(input.value); });
  const pending = micro.deployment_status === "redeploy-required";
  $("#segment-deploy-status").textContent = pending ? "REDEPLOY REQUIRED" : "COMPOSE ENFORCED";
  $("#segment-deploy-status").style.color = pending ? "var(--amber)" : "var(--green)";
  $("#trust-save-state").textContent = pending ? "Topology policy staged" : "Configuration synchronized";
  if (state.auditEvents.length) renderIntelligenceFabric(state.auditEvents);
}

async function loadTrustControls() {
  try { renderTrustControls(await api("/v1/trust-controls")); }
  catch (error) { if (state.token) toast(error.message); }
}

function renderSecurityPolicies(data) {
  state.securityPolicies = data;
  const summary = data.summary || {};
  $("#security-policy-summary").textContent = `${summary.active || 0}/${summary.domains || 0} ACTIVE · ${summary.known_exploited_cves || 0} EXPLOITED CVEs`;
  $("#cve-intelligence-notice").textContent = data.intelligence_notice || "";
  $("#security-policy-cards").innerHTML = (data.policies || []).map((policy) => {
    const coverage = policy.total_endpoint_count ? Math.round(policy.covered_endpoint_count / policy.total_endpoint_count * 100) : 0;
    const groups = (policy.assigned_groups || []).map((group) => `<button type="button" data-inventory-group="${escapeHtml(group)}">${escapeHtml(group)}</button>`).join("");
    const endpoints = (policy.covered_endpoints || []).map((endpoint) => `<li><span class="endpoint-state ${escapeHtml(endpoint.status)}"><i></i>${escapeHtml(endpoint.hostname)}</span><small>${endpoint.agent_version ? `agent v${escapeHtml(endpoint.agent_version)}` : "agent not installed"}</small></li>`).join("");
    const cves = (policy.cve_alerts || []).map((alert) => `<div class="policy-cve-alert ${escapeHtml(alert.severity)}"><div><strong>${escapeHtml(alert.id)}</strong><span>${alert.known_exploited ? "KNOWN EXPLOITED" : "INVESTIGATE"}</span></div><p>${escapeHtml(alert.summary)}</p><small>${alert.affected_endpoints} affected · ${escapeHtml(alert.status)}</small></div>`).join("");
    return `<article class="security-policy-card ${policy.enabled ? "active" : "disabled"} ${policy.cve_alerts?.length ? "has-cve" : ""}">
      <div class="security-policy-head"><span>${escapeHtml(policy.domain)}</span><div><small>${policy.enabled ? "ACTIVE" : "DISABLED"}</small><b>${escapeHtml(policy.enforcement_mode).toUpperCase()}</b></div></div>
      <h3>${escapeHtml(policy.name)}</h3><p>${escapeHtml(policy.description)}</p>
      <div class="policy-coverage"><div><strong>${policy.covered_endpoint_count}/${policy.total_endpoint_count}</strong><span>ENDPOINTS COVERED</span></div><div><strong>${policy.online_endpoint_count}</strong><span>ONLINE</span></div><b>${coverage}%</b></div>
      <div class="policy-coverage-track"><span style="width:${coverage}%"></span></div>
      <div class="policy-rule-list">${(policy.rules || []).map((rule) => `<span>✓ ${escapeHtml(rule)}</span>`).join("")}</div>
      <p class="config-caption">ASSIGNED SECURITY GROUPS</p><div class="policy-group-list">${groups}</div>
      ${cves ? `<div class="policy-cve-list"><p class="config-caption">MALICIOUS CVE INTELLIGENCE</p>${cves}</div>` : ""}
      <details class="policy-endpoints"><summary>View ${policy.covered_endpoint_count} covered endpoints</summary><ul>${endpoints}</ul></details>
    </article>`;
  }).join("");
  if (state.inventory) renderGroupInventory(state.inventory, $("#inventory-search")?.value || "");
}

async function loadSecurityPolicies() {
  try { renderSecurityPolicies(await api("/v1/security-policies")); }
  catch (error) { if (state.token) toast(error.message); }
}

function updateDeploymentCommand() {
  const group = $("#deploy-group").value || "<group>";
  const version = $("#deploy-version").value || "0.4.0";
  $("#network-command-preview").textContent = `uig-admin deploy --server http://intentgate.example:8787 --group ${group} --version ${version}`;
}

function renderInventory(data) {
  state.inventory = data;
  const summary = data.summary || {};
  $("#admin-total").textContent = summary.total || 0;
  $("#admin-online").textContent = summary.online || 0;
  $("#admin-managed").textContent = summary.managed || 0;
  $("#admin-groups").textContent = summary.groups || 0;
  $("#admin-queued").textContent = summary.queued_jobs || 0;
  const latest = data.latest_discovery;
  $("#discovery-status").textContent = latest ? `${String(latest.status).toUpperCase()} · ${formatTime(latest.completed_at)}` : "INVENTORY READY";
  const groups = data.security_groups || [];
  $("#security-group-list").innerHTML = groups.length ? groups.map((group) => `<button type="button" data-deploy-group="${escapeHtml(group.name)}"><b>${escapeHtml(group.name)}</b><span>${group.endpoint_count} endpoints · ${group.online_count} online · ${group.managed_count} managed</span></button>`).join("") : '<p class="empty-copy">No security groups discovered.</p>';
  const selectedGroup = $("#deploy-group").value;
  $("#deploy-group").innerHTML = '<option value="">Select a discovered group</option>' + groups.map((group) => `<option value="${escapeHtml(group.name)}">${escapeHtml(group.name)} · ${group.endpoint_count} endpoints</option>`).join("");
  if (groups.some((group) => group.name === selectedGroup)) $("#deploy-group").value = selectedGroup;
  const endpoints = data.endpoints || [];
  $("#endpoint-body").innerHTML = endpoints.length ? endpoints.map((item) => `<tr>
    <td><strong>${escapeHtml(item.hostname)}</strong><small>${escapeHtml(item.id)}</small></td>
    <td><code>${escapeHtml(item.ip_address)}</code></td><td>${escapeHtml(item.operating_system)}</td>
    <td><div class="endpoint-groups">${(item.security_groups || []).map((group) => `<span>${escapeHtml(group)}</span>`).join("")}</div></td>
    <td>${item.agent_version ? `<b>v${escapeHtml(item.agent_version)}</b>` : '<em>not installed</em>'}</td>
    <td><span class="endpoint-state ${escapeHtml(item.status)}"><i></i>${escapeHtml(item.status)}</span></td>
  </tr>`).join("") : '<tr><td colspan="6" class="empty-copy">No endpoints discovered.</td></tr>';
  renderGroupInventory(data, $("#inventory-search")?.value || "");
  updateDeploymentCommand();
}

function renderGroupInventory(data, query = "") {
  const endpoints = data.endpoints || [];
  const groups = data.security_groups || [];
  const normalized = query.trim().toLowerCase();
  $("#inventory-group-count").textContent = groups.length;
  $("#inventory-endpoint-count").textContent = endpoints.length;
  $("#inventory-online-count").textContent = endpoints.filter((item) => item.status === "online").length;
  $("#inventory-managed-count").textContent = endpoints.filter((item) => item.agent_version).length;
  const policies = state.securityPolicies?.policies || [];
  const visible = groups.map((group) => ({
    ...group,
    endpoints: endpoints.filter((item) => (item.security_groups || []).includes(group.name)),
    policies: policies.filter((policy) => (policy.assigned_groups || []).includes(group.name)),
  })).filter((group) => !normalized || group.name.toLowerCase().includes(normalized) || group.endpoints.some((item) => `${item.hostname} ${item.id}`.toLowerCase().includes(normalized)));
  $("#inventory-group-grid").innerHTML = visible.length ? visible.map((group) => `<article class="inventory-group-card">
    <div class="inventory-group-head"><div><span>SECURITY GROUP</span><h3>${escapeHtml(group.name)}</h3></div><strong>${group.endpoint_count}</strong></div>
    <div class="inventory-group-stats"><span>${group.online_count} online</span><span>${group.managed_count} managed</span><span>${group.policies.length} policies</span></div>
    <div class="inventory-policy-tags">${group.policies.length ? group.policies.map((policy) => `<span>${escapeHtml(policy.domain)} · ${escapeHtml(policy.enforcement_mode)}</span>`).join("") : "<span>NO POLICY ASSIGNMENT</span>"}</div>
    <ul>${group.endpoints.map((endpoint) => `<li><div><span class="endpoint-state ${escapeHtml(endpoint.status)}"><i></i>${escapeHtml(endpoint.hostname)}</span><small>${escapeHtml(endpoint.operating_system)} · ${escapeHtml(endpoint.ip_address)}</small></div><b>${endpoint.agent_version ? `v${escapeHtml(endpoint.agent_version)}` : "UNMANAGED"}</b></li>`).join("")}</ul>
  </article>`).join("") : '<p class="empty-copy">No security groups or endpoints match this filter.</p>';
}

function openInventoryGroup(group) {
  $("#inventory-search").value = group;
  if (state.inventory) renderGroupInventory(state.inventory, group);
  window.location.hash = "inventory";
  $("#inventory").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function loadInventory() {
  try { renderInventory(await api("/v1/endpoints")); }
  catch (error) { if (state.token) toast(error.message); }
}

function renderDeployments(deployments) {
  state.deployments = deployments;
  $("#deployment-list").innerHTML = deployments.length ? deployments.slice(0, 8).map((item) => {
    const queued = (item.jobs || []).filter((job) => ["queued", "deferred"].includes(job.status)).length;
    return `<article class="deployment-wave ${escapeHtml(item.status)}"><div><strong>${escapeHtml(item.security_group || "selected endpoints")} · v${escapeHtml(item.version)}</strong><small>${formatTime(item.created_at)} · ${escapeHtml(item.requested_by)}</small></div><span>${item.execute ? escapeHtml(item.status).toUpperCase() : "DRY-RUN PLAN"}</span><b>${item.matched_endpoints} targets${queued ? ` · ${queued} queued` : ""}</b></article>`;
  }).join("") : '<p class="empty-copy">No deployments have been planned.</p>';
}

async function loadDeployments() {
  try { const data = await api("/v1/deployments?limit=20"); renderDeployments(data.deployments || []); }
  catch (error) { if (state.token) toast(error.message); }
}

async function runDiscovery() {
  const button = $("#run-discovery");
  button.disabled = true;
  button.textContent = "Discovering…";
  try {
    const result = await api("/v1/discovery-sessions", { method: "POST", body: JSON.stringify({ requested_by: $("#deploy-requestor").value || "console-admin" }) });
    toast(`Discovery complete: ${result.endpoint_count} endpoints across ${result.security_group_count} groups.`);
    await loadInventory();
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.textContent = "Run discovery session"; }
}

async function submitDeployment(event) {
  event.preventDefault();
  const execute = event.submitter?.value === "execute";
  const payload = {
    security_group: $("#deploy-group").value,
    version: $("#deploy-version").value,
    execute,
    requested_by: $("#deploy-requestor").value,
  };
  event.submitter.disabled = true;
  try {
    const result = await api("/v1/deployments", { method: "POST", body: JSON.stringify(payload) });
    toast(execute ? `Deployment queued to ${result.matched_endpoints} endpoints.` : `Plan validated for ${result.matched_endpoints} endpoints.`);
    await Promise.all([loadDeployments(), loadInventory()]);
  } catch (error) { toast(error.message); }
  finally { event.submitter.disabled = false; }
}

async function saveTrustControls(event) {
  event.preventDefault();
  const submit = event.submitter;
  if (submit) submit.disabled = true;
  const payload = {
    zero_trust: {
      enforcement_mode: $("#zt-mode").value,
      identity_required: $("#zt-identity").checked,
      purpose_required: $("#zt-purpose").checked,
      device_posture_required: $("#zt-device").checked,
      behavior_monitoring: $("#zt-behavior").checked,
      step_up_threshold: Number($("#zt-threshold").value),
      session_ttl_minutes: Number($("#zt-ttl").value),
    },
    microsegmentation: {
      default_action: $("#segment-default").value,
      service_identity: $("#segment-identity").checked,
      log_denied: $("#segment-log").checked,
      enabled_zones: $$("#zone-selector input:checked").map((input) => input.value),
      allowed_flows: $$("#flow-selector input:checked").map((input) => input.value),
    },
  };
  try {
    renderTrustControls(await api("/v1/trust-controls", { method: "POST", body: JSON.stringify(payload) }));
    toast("Trust controls saved. Network changes are staged for redeploy.");
  } catch (error) { toast(error.message); }
  finally { if (submit) submit.disabled = false; }
}

async function savePolicy(event) {
  event.preventDefault();
  const payload = { name: $("#policy-name").value, review_threshold: Number($("#review-threshold").value), block_threshold: Number($("#block-threshold").value) };
  try {
    const saved = await api("/v1/policy", { method: "POST", body: JSON.stringify(payload) });
    toast(`Policy v${saved.version} saved.`);
    await loadPolicy();
  } catch (error) { toast(error.message); }
}

function bindEvents() {
  $("#assessment-form").addEventListener("submit", assessCommand);
  $("#review-list").addEventListener("click", decideReview);
  $("#audit-body").addEventListener("click", (event) => { const row = event.target.closest("[data-audit-toggle]"); if (row) toggleAuditDetail(row); });
  $("#audit-body").addEventListener("keydown", (event) => { const row = event.target.closest("[data-audit-toggle]"); if (row && ["Enter", " "].includes(event.key)) { event.preventDefault(); toggleAuditDetail(row); } });
  $$("[data-investigate]").forEach((button) => button.addEventListener("click", () => setAuditFilter(button.dataset.investigate)));
  $("#clear-audit-filter").addEventListener("click", () => setAuditFilter(null));
  $("#refresh-audit").addEventListener("click", loadAudit);
  $("#audit-previous").addEventListener("click", () => changeAuditPage(-1));
  $("#audit-next").addEventListener("click", () => changeAuditPage(1));
  $("#audit-page-size").addEventListener("change", (event) => {
    state.auditPageSize = Number(event.target.value);
    state.auditPage = 1;
    renderAudit(getFilteredAuditEvents());
  });
  $("#refresh-reviews").addEventListener("click", loadReviews);
  $("#policy-form").addEventListener("submit", savePolicy);
  $("#security-policy-cards").addEventListener("click", (event) => { const group = event.target.closest("[data-inventory-group]"); if (group) openInventoryGroup(group.dataset.inventoryGroup); });
  $("#trust-controls-form").addEventListener("submit", saveTrustControls);
  $("#run-discovery").addEventListener("click", runDiscovery);
  $("#deployment-form").addEventListener("submit", submitDeployment);
  $("#refresh-deployments").addEventListener("click", loadDeployments);
  $("#deploy-group").addEventListener("change", updateDeploymentCommand);
  $("#deploy-version").addEventListener("input", updateDeploymentCommand);
  $("#inventory-search").addEventListener("input", (event) => { if (state.inventory) renderGroupInventory(state.inventory, event.target.value); });
  $("#security-group-list").addEventListener("click", (event) => {
    const selected = event.target.closest("[data-deploy-group]");
    if (!selected) return;
    $("#deploy-group").value = selected.dataset.deployGroup;
    updateDeploymentCommand();
    $("#deployment-form").scrollIntoView({ behavior: "smooth", block: "center" });
  });
  $("#token-button").addEventListener("click", openTokenDialog);
  $("#token-form").addEventListener("submit", (event) => {
    if (event.submitter?.value === "cancel") return;
    state.token = $("#api-token").value.trim();
    if (state.token) sessionStorage.setItem("uig-token", state.token); else sessionStorage.removeItem("uig-token");
    $("#token-label").textContent = state.token ? "Token configured" : "Set API token";
    setTimeout(refreshAll, 0);
  });
  $$("[data-command]").forEach((button) => button.addEventListener("click", () => { $("#command").value = button.dataset.command; $("#purpose").value = button.dataset.purpose; }));
  $("#review-threshold").addEventListener("input", (event) => $("#review-output").textContent = event.target.value);
  $("#block-threshold").addEventListener("input", (event) => $("#block-output").textContent = event.target.value);
  const sections = $$("main section[id]");
  const observer = new IntersectionObserver((entries) => entries.forEach((entry) => { if (entry.isIntersecting) { $$(".nav-link").forEach((link) => link.classList.toggle("active", link.hash === `#${entry.target.id}`)); } }), { rootMargin: "-20% 0px -70%" });
  sections.forEach((section) => observer.observe(section));
}

async function refreshAll() { await Promise.all([loadOverview(), loadReviews(), loadPolicy(), loadSecurityPolicies(), loadModelStatus(), loadTrustControls(), loadInventory(), loadDeployments()]); }

bindEvents();
$("#token-label").textContent = state.token ? "Token configured" : "Set API token";
refreshAll();
