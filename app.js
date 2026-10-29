import { scanDomain, normalizeRoot, inScope } from "./scanner.js";
const $ = (id) => document.getElementById(id);
const state = { tab: "overview", data: null, history: [], busy: false };
const MAX_STORED_SCANS = 10;
const icon = (name, cls = "ui-icon") => `<svg class="${cls}" aria-hidden="true"><use href="icons/ui/sprite.svg#${name}"></use></svg>`;
let partialRenderPending = false;

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
const toast = (message) => { const el = $("toast"); el.textContent = message; el.classList.add("show"); setTimeout(() => el.classList.remove("show"), 2800); };
function setStatus(main, detail) {
  $("statStatus").textContent = main;
  const status = document.querySelector(".header-state");
  if (status) status.dataset.state = main.toLowerCase().replace(/[^a-z]+/g, "-");
  $("statusDetail").textContent = detail;
}
function showPartialScan(data) {
  state.data = data;
  updateStats();
  setStatus("Inspecting", `${data.liveHosts.length} hosts responding · ${data.endpoints.length} routes · ${data.indicators.length} findings`);
  if (!partialRenderPending) {
    partialRenderPending = true;
    requestAnimationFrame(() => { partialRenderPending = false; render(); });
  }
}
async function startScan() {
  if (state.busy) return;
  let root; try { root = normalizeRoot($("domain").value); } catch (e) { toast(e.message); return; }
  state.busy = true; $("start").disabled = true; $("start").innerHTML = `<span>Discovering…</span>${icon("loader-circle", "ui-icon spin")}`;
  setStatus("Discovering", "Discovering in-scope hosts and routes");
  try {
    state.data = await scanDomain(root, {}, progress => {
      if (progress.phase === "partial" && progress.data?.root === root) {
        showPartialScan(progress.data);
      } else if (progress.phase === "hosts") {
        $("statSubs").textContent = progress.hostsFound;
        if (progress.endpoints !== undefined) $("statEndpoints").textContent = progress.endpoints;
        setStatus("Inspecting", `${progress.liveHosts || 0} responsive · ${progress.hostsFound} hosts discovered`);
      } else if (progress.phase === "sources") {
        setStatus("Inspecting", `${progress.sourceFilesScanned} source files · ${progress.sourceMapsScanned} maps`);
      }
    });
    $("statSubs").textContent = state.data.subdomains.length;
    await chrome.storage.local.set({ latestScan: state.data });
    const { scans = [] } = await chrome.storage.local.get({ scans: [] });
    state.history = [state.data, ...scans.filter(s => s.root !== root || s.started !== state.data.started)].slice(0, MAX_STORED_SCANS);
    await chrome.storage.local.set({ scans: state.history });
    updateStats(); render();
    setStatus("Complete", `${new Date(state.data.completed).toLocaleString()} · ${state.data.liveHosts.length} hosts · ${state.data.sourceFilesScanned} source files · ${state.data.sourceMapsScanned} maps${state.data.hostScanLimited || state.data.sourceScanLimited ? " · scan cap reached" : ""}${state.data.sourceInventoryLimited ? " · inventory shortened" : ""}`);
    toast(`Found ${state.data.subdomains.length} hosts and ${state.data.endpoints.length} endpoint references.`);
  } catch (e) { setStatus("Error", e.message); toast(`Scan stopped: ${e.message}`); }
  finally {
    state.busy = false; $("start").disabled = false; $("start").innerHTML = `<span>Scan again</span>${icon("arrow-right")}`;
  }
}
function updateStats() {
  const d = state.data; if (!d) return;
  $("statSubs").textContent = d.subdomains.length; $("statEndpoints").textContent = d.endpoints.length; $("statIndicators").textContent = d.indicators.length;
  $("countOverview").textContent = d.subdomains.length + d.endpoints.length + d.indicators.length;
  $("countSubdomains").textContent = d.subdomains.length; $("countEndpoints").textContent = d.endpoints.length; $("countFindings").textContent = d.indicators.length; $("countSources").textContent = d.sourceFilesScanned || 0;
}
function row(title, meta, badge = "", openUrl = "", copyText = "") {
  const action = openUrl ? `<button class="open-result" type="button" data-open-url="${escapeHtml(openUrl)}" title="Open in new tab" aria-label="Open ${escapeHtml(title)} in new tab">${icon("external-link")}</button>` : "";
  const copy = copyText ? `<button class="copy-result" type="button" data-copy-text="${escapeHtml(copyText)}" title="Copy finding" aria-label="Copy ${escapeHtml(title)}">${icon("copy")}</button>` : "";
  return `<div class="result-row"><div class="result-main"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(meta)}</small></div><div class="result-actions">${badge ? `<span class="badge">${escapeHtml(badge)}</span>` : ""}${copy}${action}</div></div>`;
}
function iconForSection(title) {
  const value = title.toLowerCase();
  if (/subdomain|host/.test(value)) return "globe";
  if (/endpoint|route|swagger|openapi|api/.test(value)) return "route";
  if (/email/.test(value)) return "mail";
  if (/phone/.test(value)) return "phone";
  if (/jwt|secret|key|token/.test(value)) return "key-round";
  if (/ip|port|network/.test(value)) return "network";
  if (/sensitive|finding|data|id-like|private/.test(value)) return "shield-alert";
  if (/path/.test(value)) return "file-search";
  return "file-search";
}
function section(title, count, body) { return `<section class="result-section"><div class="result-heading"><h3>${icon(iconForSection(title))}${escapeHtml(title)}</h3><span>${count}</span></div>${body || `<div class="empty">No matches yet.</div>`}</section>`; }
function findingsByType(items, maxTypes = Infinity, maxRows = Infinity) {
  const groups = new Map();
  for (const item of items) { if (!groups.has(item.type)) groups.set(item.type, []); groups.get(item.type).push(item); }
  return [...groups.entries()].slice(0, maxTypes).map(([type, matches]) => section(type, matches.length, matches.slice(0, maxRows).map(item => row(item.value, `Source: ${item.source}${item.country ? ` · ${item.country}` : ""}`, "REVIEW", "", item.value)).join(""))).join("");
}
async function copyToClipboard(value) {
  try { await navigator.clipboard.writeText(value); }
  catch {
    const input = document.createElement("textarea"); input.value = value; input.style.position = "fixed"; input.style.opacity = "0";
    document.body.appendChild(input); input.select();
    const copied = document.execCommand("copy"); input.remove();
    if (!copied) throw new Error("Clipboard access is unavailable.");
  }
  toast("Finding copied.");
}
function render() {
  const d = state.data; if (!d) { $("panel").innerHTML = `<div class="welcome"><div class="welcome-glyph">${icon("search")}</div><h2>No scan results yet</h2><p>Enter a domain above to start.</p></div>`; return; }
  const q = $("filter").value.trim().toLowerCase();
  const match = value => !q || value.toLowerCase().includes(q);
  const subs = d.subdomains.filter(x => match(x));
  const eps = d.endpoints.filter(x => match(`${x.url} ${x.source} ${x.kind}`));
  const inds = d.indicators.filter(x => match(`${x.type} ${x.value} ${x.source}`));
  const warning = d.sourceErrors.length ? `<div class="notice">Some passive sources could not be read: ${escapeHtml(d.sourceErrors.join(" · "))}</div>` : "";
  if (state.tab === "subdomains") $("panel").innerHTML = `${warning}${section("Discovered hosts", subs.length, subs.map(x => row(x, d.liveHosts.includes(x) ? "Responded to GET" : "Certificate transparency", d.liveHosts.includes(x) ? "RESPONDS" : "CT LOG", `https://${x}/`)).join(""))}`;
  else if (state.tab === "endpoints") $("panel").innerHTML = `${warning}${section("Endpoint references", eps.length, eps.map(x => row(x.url, `Source: ${x.source}`, x.kind, x.url)).join(""))}${section("Swagger / OpenAPI signals", d.swagger.length, d.swagger.filter(match).map(x => row(x, "Documentation reference", "SPEC")).join(""))}`;
  else if (state.tab === "findings") $("panel").innerHTML = `${warning}<div class="findings-groups">${findingsByType(inds)}</div>`;
  else if (state.tab === "sources") {
    const files = (d.sourceFiles || []).filter(file => match(`${file.url} ${file.kind} ${file.source}`));
    const inventoryNote = d.sourceInventoryLimited ? `<div class="notice">The full scan inspected ${d.sourceFilesScanned} source files; this inventory is shortened to fit browser storage.</div>` : "";
    $("panel").innerHTML = `${warning}${inventoryNote}${section("Source files and maps", files.length, files.map(file => {
      let openUrl = "";
      try { const target = new URL(file.url); if (/^https?:$/.test(target.protocol) && inScope(target.hostname, d.root)) openUrl = target.href; } catch {}
      return row(file.url, `${file.kind} · ${file.bytes} bytes · ${file.source}`, file.kind === "Source map" ? "MAP" : "SOURCE", openUrl);
    }).join(""))}`;
  }
  else $("panel").innerHTML = `${warning}<div class="overview-grid">${section("Subdomains", subs.length, subs.slice(0, 8).map(x => row(x, d.liveHosts.includes(x) ? "Responsive" : "Certificate transparency", d.liveHosts.includes(x) ? "LIVE" : "CT", `https://${x}/`)).join(""))}${section("Endpoint references", eps.length, eps.slice(0, 8).map(x => row(x.url, x.source, x.kind, x.url)).join(""))}<section class="grouped-findings"><div class="result-heading"><h3>Sensitive data by type</h3><span>${inds.length}</span></div>${findingsByType(inds, 4, 3) || `<div class="empty">No matches yet.</div>`}</section>${section("Swagger / OpenAPI", d.swagger.length, d.swagger.slice(0, 6).map(x => row(x, "Specification signal", "SPEC")).join(""))}</div><div class="run-meta">${d.inProgress ? "Scan in progress" : `Last scan: ${escapeHtml(new Date(d.completed).toLocaleString())}`} · Scope: <b>${escapeHtml(d.root)}</b> · ${d.failedHosts.length} hosts did not respond · ${d.sourceFilesScanned || 0} source files · ${d.sourceMapsScanned || 0} source maps${d.sourceScanLimited || d.hostScanLimited ? " · scan cap reached" : ""}${d.sourceInventoryLimited ? " · source inventory shortened" : ""}</div>`;
}
function exportData(format) {
  if (!state.data) { toast("Run a scan before exporting."); return; }
  const d = state.data;
  let content, mime, ext;
  if (format === "json") { content = JSON.stringify(d, null, 2); mime = "application/json"; ext = "json"; }
  else if (format === "csv") {
    const rows = [["category","value","source","details"]];
    for (const host of d.subdomains) rows.push(["subdomain",host,"certificate transparency",d.liveHosts.includes(host)?"responds":"not verified"]);
    for (const ep of d.endpoints) rows.push(["endpoint",ep.url,ep.source,ep.kind]);
    for (const i of d.indicators) rows.push([`indicator:${i.type}`,i.value,i.source,i.context]);
    for (const file of (d.sourceFiles || [])) rows.push([`source:${file.kind}`,file.url,file.source,`${file.bytes} bytes`]);
    content = rows.map(r => r.map(v => { const s = String(v ?? "").replace(/[\r\n]+/g," "); return `"${(/^[=+@\-]/.test(s) ? "'" : "") + s.replace(/"/g,'""')}"`; }).join(",")).join("\r\n"); mime = "text/csv;charset=utf-8"; ext = "csv";
  } else { content = [`Domein Research Report`, `Scope: ${d.root}`, `Started: ${d.started}`, `Completed: ${d.completed}`, `Source files scanned: ${d.sourceFilesScanned || 0}`, `Source maps parsed: ${d.sourceMapsScanned || 0}`, `Source scan limit reached: ${d.sourceScanLimited || d.hostScanLimited ? "yes" : "no"}`, `Source inventory shortened: ${d.sourceInventoryLimited ? "yes" : "no"}`, ``, `SUBDOMAINS (${d.subdomains.length})`, ...d.subdomains, ``, `ENDPOINT REFERENCES (${d.endpoints.length})`, ...d.endpoints.map(e => `${e.url} [${e.kind}] — ${e.source}`), ``, `SOURCE FILES (${d.sourceFiles?.length || 0})`, ...(d.sourceFiles || []).map(f => `${f.kind}: ${f.url} — ${f.bytes} bytes — ${f.source}`), ``, `SENSITIVE DATA CANDIDATES (${d.indicators.length})`, ...d.indicators.map(i => `${i.type}: ${i.value} — ${i.source}`), ``, `SWAGGER / OPENAPI SIGNALS`, ...d.swagger].join("\n"); mime = "text/plain;charset=utf-8"; ext = "txt"; }
  const blob = new Blob([content], { type: mime }), url = URL.createObjectURL(blob), a = document.createElement("a"); a.href = url; a.download = `domein-${d.root}-${new Date().toISOString().slice(0,10)}.${ext}`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1500); toast(`${ext.toUpperCase()} report exported.`);
}
async function useActiveTab() {
  try {
    const sourceTab = Number(new URLSearchParams(location.search).get("sourceTab"));
    const tab = sourceTab ? await chrome.tabs.get(sourceTab) : (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0];
    if (!tab?.url || !/^https?:/.test(tab.url)) throw new Error("No web page available. Enter the domain manually.");
    $("domain").value = new URL(tab.url).hostname;
  } catch (e) { toast(e.message); }
}
async function syncActiveSite(tabId) {
  try {
    const tab = tabId ? await chrome.tabs.get(tabId) : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
    if (!tab?.url || !/^https?:/.test(tab.url)) return;
    const host = new URL(tab.url).hostname.toLowerCase();
    $("domain").value = host.replace(/^www\./, "");
    const saved = await chrome.storage.local.get({ scans: [], latestScan: null });
    state.history = saved.scans;
    const candidates = [...saved.scans, ...(saved.latestScan ? [saved.latestScan] : [])]
      .filter(scan => scan?.root && inScope(host, scan.root.toLowerCase()))
      .sort((a, b) => Date.parse(b.completed || b.started) - Date.parse(a.completed || a.started));
    state.data = candidates[0] || null;
    if (state.data) { updateStats(); setStatus("Scanned", new Date(state.data.completed).toLocaleString()); }
    else {
      $("statSubs").textContent = "—"; $("statEndpoints").textContent = "—"; $("statIndicators").textContent = "—";
      $("countOverview").textContent = "0"; $("countSubdomains").textContent = "0"; $("countEndpoints").textContent = "0"; $("countFindings").textContent = "0"; $("countSources").textContent = "0";
      setStatus("Ready", "No saved scan for this site yet");
    }
    render();
  } catch {}
}
async function init() {
  const saved = await chrome.storage.local.get({ latestScan: null, scans: [] }); state.data = saved.latestScan; state.history = saved.scans;
  let activeHost = "";
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:/.test(tab.url)) activeHost = new URL(tab.url).hostname.toLowerCase();
  } catch {}
  if (activeHost) {
    $("domain").value = activeHost.replace(/^www\./, "");
    const candidates = [...saved.scans, ...(saved.latestScan ? [saved.latestScan] : [])]
      .filter(scan => scan?.root && inScope(activeHost, scan.root.toLowerCase()))
      .sort((a, b) => Date.parse(b.completed || b.started) - Date.parse(a.completed || a.started));
    state.data = candidates[0] || null;
  } else if (state.data) $("domain").value = state.data.root;
  if (state.data) { updateStats(); setStatus("Scanned", new Date(state.data.completed).toLocaleString()); }
  else if (activeHost) setStatus("Ready", "No saved scan for this site yet");
  render();
  $("start").addEventListener("click", startScan); $("activeTab").addEventListener("click", useActiveTab);
  chrome.tabs.onActivated.addListener(({ tabId }) => { void syncActiveSite(tabId); });
  chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
    if (!tab.active) return;
    if (change.status === "complete" || change.url) void syncActiveSite(tabId);
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && (changes.latestScan || changes.scans) && !state.busy) void syncActiveSite();
  });
  chrome.runtime.onMessage.addListener(message => {
    if (message?.type !== "domein-scan-progress" || !message.data?.root) return;
    try { if (normalizeRoot($("domain").value) === message.data.root) showPartialScan(message.data); } catch {}
  });
  $("panel").addEventListener("click", e => {
    const copyButton = e.target.closest("[data-copy-text]");
    if (copyButton) { void copyToClipboard(copyButton.dataset.copyText).catch(error => toast(error.message)); return; }
    const button = e.target.closest("[data-open-url]"); if (!button) return;
    try {
      const target = new URL(button.dataset.openUrl);
      if (!state.data || !/^https?:$/.test(target.protocol) || !inScope(target.hostname, state.data.root)) throw new Error("This link is outside the current scan scope.");
      chrome.tabs.create({ url: target.href, active: true });
    } catch (error) { toast(error.message || "Could not open this result."); }
  });
  $("tabs").addEventListener("click", e => { const button = e.target.closest("[data-tab]"); if (!button) return; state.tab = button.dataset.tab; document.querySelectorAll(".tab").forEach(t => { const selected = t === button; t.classList.toggle("selected", selected); t.setAttribute("aria-pressed", String(selected)); }); render(); });
  $("filter").addEventListener("input", render); $("export").addEventListener("click", () => exportData($("format").value)); $("exportTop").addEventListener("click", () => exportData("json"));
  $("domain").addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
}
init().catch(e => toast(e.message));
