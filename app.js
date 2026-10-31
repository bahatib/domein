import { scanDomain, normalizeRoot, inScope } from "./scanner.js";
import { getArchivedResponseCount, listArchivedResponses, getArchivedResponse, getAllArchivedResponses, importArchivedResponses } from "./response-store.js";
const $ = (id) => document.getElementById(id);
const state = { tab: "overview", data: null, history: [], busy: false, autoScanning: false, archiveRows: [], archiveOpenId: null, archiveCount: 0 };
const MAX_STORED_SCANS = 10;
const icon = (name, cls = "ui-icon") => `<svg class="${cls}" aria-hidden="true"><use href="icons/ui/sprite.svg#${name}"></use></svg>`;
let partialRenderPending = false;

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
let toastTimer = null;
const toast = (message) => {
  const el = $("toast");
  if (!el) return;
  if (toastTimer) clearTimeout(toastTimer);
  el.textContent = message;
  el.classList.add("show");
  toastTimer = setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => {
      if (!el.classList.contains("show")) el.textContent = "";
    }, 300);
  }, 3500);
};
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
  render();
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
function hasDisplayableScanResults(data) {
  if (!data) return false;
  const seeded = new Set([data.root, `www.${data.root}`]);
  return (data.subdomains || []).some(host => !seeded.has(host))
    || (data.liveHosts || []).length > 0
    || (data.endpoints || []).length > 0
    || (data.indicators || []).length > 0
    || (data.swagger || []).length > 0
    || (data.sourceFilesScanned || 0) > 0;
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
async function copyToClipboard(value, customToast = "Finding copied.") {
  try { await navigator.clipboard.writeText(value); }
  catch {
    const input = document.createElement("textarea"); input.value = value; input.style.position = "fixed"; input.style.opacity = "0";
    document.body.appendChild(input); input.select();
    const copied = document.execCommand("copy"); input.remove();
    if (!copied) throw new Error("Clipboard access is unavailable.");
  }
  if (customToast) toast(customToast);
}

async function copyCurrentTab() {
  if (!state.data) { toast("Run a scan before copying results."); return; }
  const d = state.data;
  const tab = state.tab;
  const q = ($("filter")?.value || "").trim().toLowerCase();
  const match = value => !q || String(value).toLowerCase().includes(q);

  if (tab === "subdomains") {
    const hosts = (d.subdomains || []).filter(x => match(x));
    if (!hosts.length) { toast(q ? "No matching hosts displayed to copy." : "No hosts to copy."); return; }
    await copyToClipboard(hosts.join("\n"), `Copied ${hosts.length} hosts to clipboard.`);
  } else if (tab === "endpoints") {
    const endpoints = (d.endpoints || []).filter(x => match(`${x.url} ${x.source} ${x.kind}`));
    if (!endpoints.length) { toast(q ? "No matching routes displayed to copy." : "No routes to copy."); return; }
    await copyToClipboard(endpoints.map(e => e.url).join("\n"), `Copied ${endpoints.length} routes to clipboard.`);
  } else if (tab === "findings") {
    const indicators = (d.indicators || []).filter(x => match(`${x.type} ${x.value} ${x.source}`));
    if (!indicators.length) { toast(q ? "No matching findings displayed to copy." : "No findings to copy."); return; }
    await copyToClipboard(indicators.map(i => `${i.type}: ${i.value} — ${i.source}`).join("\n"), `Copied ${indicators.length} findings to clipboard.`);
  } else if (tab === "sources") {
    const sources = (d.sourceFiles || []).filter(f => match(`${f.url} ${f.kind} ${f.source}`));
    if (!sources.length) { toast(q ? "No matching source files displayed to copy." : "No source files to copy."); return; }
    await copyToClipboard(sources.map(f => `${f.kind}: ${f.url} (${f.bytes} B)`).join("\n"), `Copied ${sources.length} sources to clipboard.`);
  } else if (tab === "archive") {
    toast("Use 'Export archive' in the toolbar to download responses.");
  } else {
    const subs = (d.subdomains || []).filter(x => match(x));
    const eps = (d.endpoints || []).filter(x => match(`${x.url} ${x.source} ${x.kind}`));
    const inds = (d.indicators || []).filter(x => match(`${x.type} ${x.value} ${x.source}`));
    const text = [
      `Domein Research: ${d.root}`,
      `Completed: ${new Date(d.completed || d.started).toLocaleString()}`,
      `Hosts (${subs.length}):`,
      ...subs.slice(0, 50),
      ...(subs.length > 50 ? [`...and ${subs.length - 50} more`] : []),
      ``,
      `Routes (${eps.length}):`,
      ...eps.slice(0, 50).map(e => `${e.url} [${e.kind}]`),
      ...(eps.length > 50 ? [`...and ${eps.length - 50} more`] : []),
      ``,
      `Findings (${inds.length}):`,
      ...inds.slice(0, 50).map(i => `${i.type}: ${i.value}`),
      ...(inds.length > 50 ? [`...and ${inds.length - 50} more`] : [])
    ].join("\n");
    await copyToClipboard(text, "Copied scan overview to clipboard.");
  }
}
function render() {
  if (state.tab === "archive") { void renderArchive(); return; }
  const d = state.data, hasResults = hasDisplayableScanResults(d);
  if (!d || ((state.busy || state.autoScanning) && !hasResults)) {
    const loading = state.busy || state.autoScanning;
    $("panel").innerHTML = `<div class="welcome ${loading ? "loading-state" : ""}"><div class="welcome-glyph ${loading ? "loading-spinner" : ""}">${icon(loading ? "loader-circle" : "search", loading ? "ui-icon spin" : "ui-icon")}</div><h2>${loading ? "Scanning this site…" : "No scan results yet"}</h2><p>${loading ? "Discovering hosts and processing responses. Results will appear as they’re found." : "Enter a domain above to start."}</p></div>`;
    return;
  }
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
async function renderArchive() {
  const panel = $("panel"), query = $("filter").value.trim();
  panel.innerHTML = `<div class="empty">Loading archived responses…</div>`;
  try {
    const [total, rows] = await Promise.all([getArchivedResponseCount(), listArchivedResponses(query, 100)]);
    if (state.tab !== "archive" || query !== $("filter").value.trim()) return;
    state.archiveCount = total; $("countArchive").textContent = total;
    const list = rows.map(record => {
      const expanded = state.archiveOpenId === record.id;
      return `<button class="archive-record" type="button" data-archive-id="${record.id}" aria-expanded="${expanded}"><span class="archive-record-main"><strong>${escapeHtml(record.url)}</strong><small>${escapeHtml(record.root)} · ${escapeHtml(new Date(record.timestamp).toLocaleString())} · ${formatBytes(record.bodyBytes || 0)}</small></span><span class="badge">${escapeHtml(record.status)}</span></button>${expanded && state.archiveDetail ? archiveDetailMarkup(state.archiveDetail) : ""}`;
    }).join("");
    const emptyMessage = state.busy || state.autoScanning
      ? `<div class="archive-loading"><svg class="ui-icon spin"><use href="icons/ui/sprite.svg#loader-circle"></use></svg><strong>Processing responses…</strong><span>New records will appear here as the scan runs.</span></div>`
      : `<div class="empty">${total ? "No archived responses match this filter." : "No responses archived yet. Run a scan to start building the local archive."}</div>`;
    const scanStatus = state.busy || state.autoScanning ? `<span class="archive-progress"><svg class="ui-icon spin"><use href="icons/ui/sprite.svg#loader-circle"></use></svg> Processing</span>` : "";
    panel.innerHTML = `<div class="archive-toolbar"><span>${total} responses stored · newest 100 shown ${scanStatus}</span><span><button class="archive-export" type="button" data-archive-action="sync-aws" style="color:var(--brand-accent,#159f70);font-weight:600;">Sync to AWS</button> <button class="archive-export" type="button" data-archive-action="import">Import JSON</button> <button class="archive-export" type="button" data-archive-action="export">Export archive</button></span></div><input id="archive-file" type="file" accept="application/json,.json" hidden><div>${list || emptyMessage}</div>`;
  } catch (error) { panel.innerHTML = `<div class="notice">Could not read the response archive: ${escapeHtml(error.message)}</div>`; }
}
function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}
function archiveDetailMarkup(record) {
  const textual = /text|json|javascript|xml|yaml|graphql|x-www-form-urlencoded/i.test(record.contentType || "");
  // The detail is populated separately after retrieval to avoid HTML-injecting a saved response.
  const preview = state.archiveBodyPreview;
  return `<div class="archive-detail" data-archive-detail="${record.id}"><div class="archive-meta"><b>Requested</b><span>${escapeHtml(record.requestedUrl)}</span><b>Final URL</b><span>${escapeHtml(record.url)}</span><b>Content type</b><span>${escapeHtml(record.contentType || "unknown")}</span><b>Size</b><span>${formatBytes(record.bodyBytes || 0)}</span></div><pre>${textual ? (preview == null ? "Loading response body…" : escapeHtml(preview)) : "Binary response body. Use Export archive to preserve and move the full body."}</pre><button class="archive-export" type="button" data-archive-action="download-record" data-record-id="${record.id}">Export this response</button></div>`;
}
async function showArchiveRecord(id) {
  state.archiveOpenId = id; state.archiveDetail = id == null ? null : await getArchivedResponse(id); state.archiveBodyPreview = null; await renderArchive();
  if (!state.archiveDetail) return;
  const target = document.querySelector(`[data-archive-detail="${id}"] pre`);
  if (!target) return;
  if (/text|json|javascript|xml|yaml|graphql|x-www-form-urlencoded/i.test(state.archiveDetail.contentType || "")) {
    const bodyText = await state.archiveDetail.body.text();
    state.archiveBodyPreview = bodyText.length > 500_000 ? `${bodyText.slice(0, 500_000)}\n\n[Preview truncated. Export the archive to retrieve the complete response.]` : bodyText;
    target.textContent = state.archiveBodyPreview;
  }
}
function saveJsonFile(value, filename) {
  const blob = new Blob([JSON.stringify(value)], { type: "application/json" });
  const url = URL.createObjectURL(blob), anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 3000);
}
async function exportResponseArchive(recordId = null) {
  try {
    const records = recordId == null ? await getAllArchivedResponses() : [await getArchivedResponse(recordId)].filter(Boolean);
    if (!records.length) { toast("There are no archived responses to export."); return; }
    const output = [];
    for (const record of records) {
      const { body, ...metadata } = record;
      const bytes = new Uint8Array(await body.arrayBuffer());
      let binary = "";
      const chunkSize = 0x8000;
      for (let i = 0; i < bytes.length; i += chunkSize) binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
      output.push({ ...metadata, bodyType: body.type, bodyBase64: btoa(binary) });
    }
    saveJsonFile({ format: "domein-response-archive", version: 1, exportedAt: new Date().toISOString(), records: output }, `domein-response-archive-${new Date().toISOString().slice(0, 10)}.json`);
    toast(`Exported ${output.length} archived response${output.length === 1 ? "" : "s"}.`);
  } catch (error) { toast(`Archive export failed: ${error.message}`); }
}
async function importResponseArchive(file) {
  try {
    const bundle = JSON.parse(await file.text());
    if (bundle?.format !== "domein-response-archive" || bundle.version !== 1) throw new Error("This file is not a supported Domein response archive.");
    await importArchivedResponses(bundle.records);
    toast(`Imported ${bundle.records.length} response records.`); await renderArchive();
  } catch (error) { toast(`Archive import failed: ${error.message}`); }
}
function exportData(format) {
  if (!state.data) { toast("Run a scan before exporting."); return; }
  const d = state.data;
  const tab = state.tab;
  const q = ($("filter")?.value || "").trim().toLowerCase();
  const match = value => !q || String(value).toLowerCase().includes(q);
  let content, mime, ext, filename;

  if (tab === "subdomains") {
    filename = `domein-${d.root}-hosts`;
    const hosts = (d.subdomains || []).filter(x => match(x));
    if (format === "json") {
      content = JSON.stringify({ root: d.root, tab: "hosts", count: hosts.length, hosts: hosts.map(h => ({ host: h, responsive: d.liveHosts.includes(h) })) }, null, 2);
      mime = "application/json"; ext = "json";
    } else if (format === "csv") {
      const rows = [["host", "status", "source"]];
      for (const h of hosts) rows.push([h, d.liveHosts.includes(h) ? "responsive" : "not verified", "certificate transparency"]);
      content = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\r\n");
      mime = "text/csv;charset=utf-8"; ext = "csv";
    } else {
      content = hosts.join("\n");
      mime = "text/plain;charset=utf-8"; ext = "txt";
    }
  } else if (tab === "endpoints") {
    filename = `domein-${d.root}-routes`;
    const endpoints = (d.endpoints || []).filter(x => match(`${x.url} ${x.source} ${x.kind}`));
    if (format === "json") {
      content = JSON.stringify({ root: d.root, tab: "routes", count: endpoints.length, routes: endpoints }, null, 2);
      mime = "application/json"; ext = "json";
    } else if (format === "csv") {
      const rows = [["url", "kind", "source"]];
      for (const ep of endpoints) rows.push([ep.url, ep.kind, ep.source]);
      content = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\r\n");
      mime = "text/csv;charset=utf-8"; ext = "csv";
    } else {
      content = endpoints.map(e => `${e.url} [${e.kind}] — ${e.source}`).join("\n");
      mime = "text/plain;charset=utf-8"; ext = "txt";
    }
  } else if (tab === "findings") {
    filename = `domein-${d.root}-findings`;
    const indicators = (d.indicators || []).filter(x => match(`${x.type} ${x.value} ${x.source}`));
    if (format === "json") {
      content = JSON.stringify({ root: d.root, tab: "findings", count: indicators.length, findings: indicators }, null, 2);
      mime = "application/json"; ext = "json";
    } else if (format === "csv") {
      const rows = [["type", "value", "source", "context"]];
      for (const i of indicators) rows.push([i.type, i.value, i.source, i.context || ""]);
      content = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\r\n");
      mime = "text/csv;charset=utf-8"; ext = "csv";
    } else {
      content = indicators.map(i => `${i.type}: ${i.value} — ${i.source}`).join("\n");
      mime = "text/plain;charset=utf-8"; ext = "txt";
    }
  } else if (tab === "sources") {
    filename = `domein-${d.root}-sources`;
    const sources = (d.sourceFiles || []).filter(f => match(`${f.url} ${f.kind} ${f.source}`));
    if (format === "json") {
      content = JSON.stringify({ root: d.root, tab: "sources", count: sources.length, sources }, null, 2);
      mime = "application/json"; ext = "json";
    } else if (format === "csv") {
      const rows = [["kind", "url", "bytes", "source"]];
      for (const f of sources) rows.push([f.kind, f.url, f.bytes, f.source]);
      content = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\r\n");
      mime = "text/csv;charset=utf-8"; ext = "csv";
    } else {
      content = sources.map(f => `${f.kind}: ${f.url} — ${f.bytes} bytes — ${f.source}`).join("\n");
      mime = "text/plain;charset=utf-8"; ext = "txt";
    }
  } else if (tab === "archive") {
    exportResponseArchive();
    return;
  } else {
    // Overview: full export
    filename = `domein-${d.root}-full`;
    if (format === "json") { content = JSON.stringify(d, null, 2); mime = "application/json"; ext = "json"; }
    else if (format === "csv") {
      const rows = [["category","value","source","details"]];
      for (const host of d.subdomains) rows.push(["subdomain",host,"certificate transparency",d.liveHosts.includes(host)?"responds":"not verified"]);
      for (const ep of d.endpoints) rows.push(["endpoint",ep.url,ep.source,ep.kind]);
      for (const i of d.indicators) rows.push([`indicator:${i.type}`,i.value,i.source,i.context]);
      for (const file of (d.sourceFiles || [])) rows.push([`source:${file.kind}`,file.url,file.source,`${file.bytes} bytes`]);
      content = rows.map(r => r.map(v => `"${String(v ?? "").replace(/[\r\n]+/g," ").replace(/"/g,'""')}"`).join(",")).join("\r\n"); mime = "text/csv;charset=utf-8"; ext = "csv";
    } else {
      content = [`Domein Research Report`, `Scope: ${d.root}`, `Started: ${d.started}`, `Completed: ${d.completed}`, `Source files scanned: ${d.sourceFilesScanned || 0}`, `Source maps parsed: ${d.sourceMapsScanned || 0}`, ``, `SUBDOMAINS (${d.subdomains.length})`, ...d.subdomains, ``, `ENDPOINT REFERENCES (${d.endpoints.length})`, ...d.endpoints.map(e => `${e.url} [${e.kind}] — ${e.source}`), ``, `SOURCE FILES (${d.sourceFiles?.length || 0})`, ...(d.sourceFiles || []).map(f => `${f.kind}: ${f.url} — ${f.bytes} bytes — ${f.source}`), ``, `SENSITIVE DATA CANDIDATES (${d.indicators.length})`, ...d.indicators.map(i => `${i.type}: ${i.value} — ${i.source}`), ``, `SWAGGER / OPENAPI SIGNALS`, ...d.swagger].join("\n");
      mime = "text/plain;charset=utf-8"; ext = "txt";
    }
  }

  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${filename}-${new Date().toISOString().slice(0,10)}.${ext}`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
  toast(`Exported ${tab === "overview" ? "full report" : tab} as ${ext.toUpperCase()}.`);
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
    state.autoScanning = false;
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
    chrome.runtime.sendMessage({ type: "domein-get-active-scans" }).then(({ roots = [] } = {}) => {
      try {
        if (normalizeRoot($("domain").value) !== normalizeRoot(tab.url)) return;
        state.autoScanning = roots.includes(normalizeRoot(tab.url));
        if (!state.data || state.tab === "archive") render();
      } catch {}
    }).catch(() => {});
  } catch {}
}
async function init() {
  const saved = await chrome.storage.local.get({ latestScan: null, scans: [] }); state.data = saved.latestScan; state.history = saved.scans;
  try { state.archiveCount = await getArchivedResponseCount(); $("countArchive").textContent = state.archiveCount; } catch {}
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
    if (message?.type === "domein-scan-status" && message.root) {
      try {
        if (normalizeRoot($("domain").value) !== message.root) return;
        state.autoScanning = Boolean(message.inProgress);
        if (state.autoScanning) setStatus("Inspecting", message.detail || "Processing scan results");
        else if (!state.busy && message.phase === "complete") setStatus("Complete", message.detail || "Scan complete");
        if (!state.data || state.tab === "archive") render();
      } catch {}
      return;
    }
    if (message?.type === "domein-archive-updated") {
      void getArchivedResponseCount().then(count => {
        state.archiveCount = count; $("countArchive").textContent = count;
        if (state.tab === "archive") render();
      }).catch(() => {});
      return;
    }
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
  $("tabs").addEventListener("click", e => { const button = e.target.closest("[data-tab]"); if (!button) return; state.tab = button.dataset.tab; state.archiveOpenId = null; state.archiveDetail = null; document.querySelectorAll(".tab").forEach(t => { const selected = t === button; t.classList.toggle("selected", selected); t.setAttribute("aria-pressed", String(selected)); }); render(); });
  $("filter").addEventListener("input", render);
  $("exportTop")?.addEventListener("click", () => exportData("json"));
  $("copyTab")?.addEventListener("click", () => { void copyCurrentTab().catch(err => toast(err.message)); });

  const exportToggle = $("exportToggle");
  const exportMenu = $("exportMenu");
  exportToggle?.addEventListener("click", (e) => {
    e.stopPropagation();
    const isHidden = exportMenu.hasAttribute("hidden");
    if (isHidden) {
      exportMenu.removeAttribute("hidden");
      exportToggle.setAttribute("aria-expanded", "true");
    } else {
      exportMenu.setAttribute("hidden", "");
      exportToggle.setAttribute("aria-expanded", "false");
    }
  });

  exportMenu?.addEventListener("click", (e) => {
    const item = e.target.closest("[data-export-format]");
    if (!item) return;
    const format = item.dataset.exportFormat;
    exportMenu.setAttribute("hidden", "");
    exportToggle?.setAttribute("aria-expanded", "false");
    exportData(format);
  });

  document.addEventListener("click", (e) => {
    if (!e.target.closest("#exportDropdown")) {
      exportMenu?.setAttribute("hidden", "");
      exportToggle?.setAttribute("aria-expanded", "false");
    }
  });
  $("panel").addEventListener("click", e => {
    const recordButton = e.target.closest("[data-archive-id]");
    if (recordButton) { const id = Number(recordButton.dataset.archiveId); void showArchiveRecord(state.archiveOpenId === id ? null : id); return; }
    const action = e.target.closest("[data-archive-action]")?.dataset.archiveAction;
    if (action === "export") void exportResponseArchive();
    else if (action === "download-record") void exportResponseArchive(e.target.closest("[data-record-id]").dataset.recordId);
    else if (action === "import") $("archive-file")?.click();
    else if (action === "sync-aws") {
      toast("Syncing archive to AWS database...");
      chrome.runtime.sendMessage({ type: "domein-sync-archive-now" });
    }
  });
  $("panel").addEventListener("change", e => { if (e.target.id === "archive-file" && e.target.files?.[0]) void importResponseArchive(e.target.files[0]); });
  chrome.runtime.sendMessage({ type: "domein-get-active-scans" }).then(({ roots = [] } = {}) => {
    try { state.autoScanning = roots.includes(normalizeRoot($("domain").value)); if (state.autoScanning && !state.data) render(); } catch {}
  }).catch(() => {});
  $("domain").addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
}
init().catch(e => toast(e.message));
