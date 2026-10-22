"use strict";
// All dynamic text is inserted with textContent (never innerHTML) so file names or API text cannot inject markup.
const $ = (id) => document.getElementById(id);
const state = { maxMb: 50, threshold: 0.4, busy: false, mappingStatus: "inferred", features: [] };

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
const pct = (p) => (p >= 0.9995 ? "99.9%+" : p < 0.0005 ? "<0.1%" : (p * 100).toFixed(1) + "%");
const fmtBytes = (n) => (n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB");
const fmtNum = (v) => (Number.isInteger(v) ? v.toLocaleString("en-US") : Number(v).toPrecision(6));

function showError(msg) { const a = $("alert"); a.textContent = msg; a.classList.remove("hidden"); }
function clearError() { $("alert").classList.add("hidden"); $("alert").textContent = ""; }

function setBusy(on, text) {
  state.busy = on;
  $("busy").classList.toggle("hidden", !on);
  if (text) $("busyText").textContent = text;
  $("drop").setAttribute("aria-disabled", on ? "true" : "false");
  document.querySelectorAll(".samples .btn").forEach((b) => (b.disabled = on));
}

async function api(path, opts) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 90000);
  try {
    const res = await fetch(path, { ...opts, signal: ctl.signal });
    let body = null;
    try { body = await res.json(); } catch (_) { /* non-JSON error page */ }
    if (!res.ok) {
      const m = body && body.error && body.error.message;
      throw new Error(m || `The server returned an error (HTTP ${res.status}).`);
    }
    return body;
  } catch (e) {
    if (e.name === "AbortError") throw new Error("The scan timed out. Try again, or use a smaller file.");
    if (e instanceof TypeError) throw new Error("Cannot reach the backend. Check that the server is running, then retry.");
    throw e;
  } finally { clearTimeout(t); }
}

async function init() {
  try {
    const [health, info] = await Promise.all([api("/api/health"), api("/api/models")]);
    state.maxMb = info.max_upload_mb; state.threshold = info.threshold_benign;
    state.mappingStatus = info.feature_mapping_status; state.features = info.features_used;
    $("maxMb").textContent = state.maxMb;
    const n = health.models_loaded.length, total = info.models.length;
    const s = $("status");
    s.textContent = `${n} of ${total} models ready`;
    s.className = "status " + (n === total ? "ok" : "bad");
    if (n < total) showError("Some models failed to load: " + Object.keys(health.models_failed).join(", ") + ". Results will use the remaining models.");
    renderMapping(info);
    renderSamples(info.samples);
    renderMetrics(info.models);
  } catch (e) {
    const s = $("status"); s.textContent = "Backend unavailable"; s.className = "status bad";
    showError(e.message);
  }
}

function renderMapping(info) {
  if (info.feature_mapping_status === "verified") return;
  const b = $("mappingBanner");
  b.textContent = "";
  b.append(el("strong", null, "Feature mapping is inferred, not verified. "),
    document.createTextNode("The models take 7 selected inputs, but the training script never saved which columns were selected. They were inferred from the trained trees (" +
      info.features_used.join(", ") + "). Treat scores as provisional until you run scripts/recover_feature_selection.py with your training CSV."));
  b.classList.remove("hidden");
}

function renderSamples(samples) {
  const box = $("samples"); box.textContent = "";
  if (!samples.length) { box.append(el("p", "hint", "No bundled samples found in test_files/.")); return; }
  samples.forEach((s) => {
    const b = el("button", "btn"); b.type = "button";
    b.append(el("span", null, s.label), el("small", null, s.file));
    b.addEventListener("click", () => scan(`/api/scan-sample/${encodeURIComponent(s.file)}`, { method: "POST" }, s.file));
    box.append(b);
  });
}

function renderMetrics(models) {
  const tb = $("metricsTable").querySelector("tbody"); tb.textContent = "";
  models.forEach((m) => {
    const tr = el("tr"); tr.append(el("td", null, m.name));
    const t = m.training_metrics;
    ["Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"].forEach((k) => tr.append(el("td", "num", t ? (t[k] * 100).toFixed(2) + "%" : "n/a")));
    tb.append(tr);
  });
}

async function scan(path, opts, label) {
  if (state.busy) return;
  clearError(); setBusy(true, `Analysing ${label}…`);
  try {
    const data = await api(path, opts);
    renderResult(data);
  } catch (e) { showError(e.message); }
  finally { setBusy(false); }
}

function renderResult(d) {
  $("placeholder").classList.add("hidden"); $("result").classList.remove("hidden");
  const mal = d.verdict === "Malicious";
  const v = $("verdict"); v.className = "verdict " + (mal ? "mal" : "ben");
  $("vWord").textContent = d.verdict;
  const agree = mal ? d.votes.malicious : d.votes.benign;
  $("vSub").textContent = `${agree} of ${d.votes.total} models vote ${d.verdict}. Average malicious probability: ${pct(d.mean_p_malicious)}.`;
  $("fName").textContent = d.file.name; $("fSize").textContent = fmtBytes(d.file.size_bytes);
  $("fHash").textContent = d.file.sha256; $("fTime").textContent = d.analysis_ms + " ms";

  const votes = $("votes"); votes.textContent = "";
  d.models.forEach((m) => {
    const row = el("div", "vote");
    const name = el("div", "name", m.model);
    if (m.model === "Stacking") name.append(el("small", null, "meta-ensemble"));
    row.append(name);
    if (!m.available) { row.append(el("div", "hint", "Not loaded: " + m.error), el("div", "out")); votes.append(row); return; }
    const track = el("div", "track");
    const fill = el("div", "fill" + (m.label === "Malicious" ? " mal" : ""));
    fill.style.width = (m.p_malicious * 100).toFixed(2) + "%";
    const line = el("div", "line"); line.style.left = ((1 - state.threshold) * 100) + "%";
    track.append(fill, line);
    track.setAttribute("role", "img");
    track.setAttribute("aria-label", `${m.model}: ${pct(m.p_malicious)} probability malicious`);
    const conf = m.label === "Malicious" ? m.p_malicious : m.p_benign;
    const out = el("div", "out");
    out.append(el("b", m.label === "Malicious" ? "mal" : "ben", m.label), el("span", null, `${pct(conf)} confidence`));
    row.append(track, out); votes.append(row);
  });
  $("rule").textContent = d.decision_rule;

  const used = new Set(Object.keys(d.model_features_used));
  const tb = $("featTable").querySelector("tbody"); tb.textContent = "";
  Object.entries(d.model_features_used).forEach(([k, val]) => {
    const tr = el("tr"); tr.append(el("td", null, k), el("td", "num", fmtNum(val)), el("td", "hex", Number.isInteger(val) ? "0x" + val.toString(16).toUpperCase() : ""));
    tb.append(tr);
  });
  const ab = $("allTable").querySelector("tbody"); ab.textContent = "";
  Object.entries(d.extracted_features).forEach(([k, val]) => {
    const tr = el("tr", used.has(k) ? "" : "unused"); tr.append(el("td", null, k + (used.has(k) ? " (model input)" : "")), el("td", "num", fmtNum(val)));
    ab.append(tr);
  });

  const li = el("li"); li.append(el("span", "nm", d.file.name), el("span", "tag " + (mal ? "mal" : "ben"), d.verdict));
  const list = $("recent"); const first = list.firstElementChild;
  if (first && first.classList.contains("empty")) first.remove();
  list.prepend(li); while (list.children.length > 8) list.lastElementChild.remove();
  $("result").scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

function handleFile(file) {
  if (!file) return;
  if (file.size === 0) return showError("That file is empty.");
  if (file.size > state.maxMb * 1048576) return showError(`That file is ${fmtBytes(file.size)}. The limit is ${state.maxMb} MB.`);
  const fd = new FormData(); fd.append("file", file);
  scan("/api/scan", { method: "POST", body: fd }, file.name);
}

const drop = $("drop"), input = $("fileInput");
drop.addEventListener("click", () => input.click());
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
input.addEventListener("change", () => { handleFile(input.files[0]); input.value = ""; });
["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => handleFile(e.dataTransfer.files[0]));
// stop the browser from navigating to a file dropped outside the drop zone
["dragover", "drop"].forEach((t) => window.addEventListener(t, (e) => e.preventDefault()));

init();
