const $ = (id) => document.getElementById(id);
const state = { tab: "overview", data: null, history: [], busy: false };
const MAX_TEXT = 1_000_000, MAX_MAP_TEXT = 2_000_000, MAX_HOST_TEXT = 12_000_000;
const MAX_HOSTS = 120, CONCURRENCY = 5, MAX_SOURCE_FILES = 40, MAX_SOURCE_MAPS = 5, MAX_IMPORT_DEPTH = 3;
const MAX_RECORDED_SOURCE_FILES = 1500, MAX_STORED_SCANS = 10;
const icon = (name, cls = "ui-icon") => `<svg class="${cls}" aria-hidden="true"><use href="icons/ui/sprite.svg#${name}"></use></svg>`;

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
const toast = (message) => { const el = $("toast"); el.textContent = message; el.classList.add("show"); setTimeout(() => el.classList.remove("show"), 2800); };
function normalizeRoot(raw) {
  let value = raw.trim();
  if (!value) throw new Error("Enter a domain to scan.");
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
  const u = new URL(value);
  if (!/^https?:$/.test(u.protocol) || !u.hostname.includes(".") || u.hostname === "localhost" || /^[\d.]+$/.test(u.hostname)) throw new Error("Enter a public root domain such as example.com.");
  return u.hostname.toLowerCase().replace(/^www\./, "");
}
function inScope(host, root) { host = host.toLowerCase().replace(/\.$/, ""); return host === root || host.endsWith(`.${root}`); }
function normalizeHost(value, root) {
  let host = String(value || "").trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!host || host.includes("*") || !inScope(host, root)) return null;
  return host;
}
async function timeoutFetch(url, ms = 5000) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), ms);
  try { return await fetch(url, { signal: controller.signal, redirect: "follow", credentials: "omit", cache: "no-store" }); }
  finally { clearTimeout(timer); }
}
function setStatus(main, detail) {
  $("statStatus").textContent = main;
  const status = document.querySelector(".header-state");
  if (status) status.dataset.state = main.toLowerCase().replace(/[^a-z]+/g, "-");
  $("statusDetail").textContent = detail;
}
function logLine(label, message) { $("statusDetail").textContent = `${label}: ${message}`; }
function recordSourceFile(result, key, file) {
  if (result.sourceFiles.has(key)) { result.sourceFiles.set(key, file); return; }
  if (result.sourceFiles.size >= MAX_RECORDED_SOURCE_FILES) { result.sourceInventoryLimited = true; return; }
  result.sourceFiles.set(key, file);
}

async function getCertificateHosts(root) {
  const hosts = new Set([root, `www.${root}`]);
  const errors = [];
  try {
    const response = await timeoutFetch(`https://crt.sh/?q=${encodeURIComponent(`%.${root}`)}&output=json`, 12000);
    if (!response.ok) throw new Error(`crt.sh returned ${response.status}`);
    const rows = await response.json();
    for (const row of rows) for (const item of String(row.name_value || "").split(/[\r\n,]+/)) {
      const host = normalizeHost(item, root); if (host) hosts.add(host);
    }
  } catch (e) { errors.push(`crt.sh: ${e.message}`); }
  try {
    const response = await timeoutFetch(`https://api.ctlogs.dev/v1/hosts/${encodeURIComponent(root)}`, 12000);
    if (!response.ok) throw new Error(`ctlogs.dev returned ${response.status}`);
    const data = await response.json();
    const candidates = Array.isArray(data) ? data : (data.hosts || data.subdomains || data.data || []);
    for (const row of candidates) {
      const host = normalizeHost(typeof row === "string" ? row : (row.host || row.hostname || row.name || row.subdomain), root);
      if (host) hosts.add(host);
    }
  } catch (e) { errors.push(`ctlogs.dev: ${e.message}`); }
  return { hosts: [...hosts].slice(0, MAX_HOSTS), errors };
}
function extractIndicators(text, source, root, bag, hosts) {
  const rules = [
    ["Email", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
    ["Phone", /(?<![\w])(?:\+?\d[\d ().-]{7,}\d)(?!\w)/g],
    ["IPv4", /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g],
    ["JWT", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
    ["ID-like number", /\b(?:\d{16}|\d{13}|\d{11})\b/g],
    ["Secret candidate", /\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|gh[pousr]_[A-Za-z0-9_]{30,}|(?:api[_-]?key|secret|token)\s*[:=]\s*["'][^"'\s]{8,}["'])\b/gi],
    ["Private key marker", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g]
  ];
  for (const [type, re] of rules) for (const m of text.matchAll(re)) {
    const value = m[0].slice(0, 240), key = `${type}\0${value}`;
    if (!bag.has(key)) bag.set(key, { type, value, source, context: text.slice(Math.max(0, m.index - 36), Math.min(text.length, m.index + m[0].length + 36)).replace(/\s+/g, " ") });
  }
  const domainRe = /(?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?/gi;
  for (const m of text.matchAll(domainRe)) {
    try { const host = normalizeHost(new URL(m[0].includes("://") ? m[0] : `https://${m[0]}`).hostname, root); if (host) hosts.add(host); } catch {}
  }
}
const endpointRe = /(?:["'`])((?:https?:\/\/[^"'`\s<>]+|\/{1,2}[A-Za-z0-9_.$~!%&'()*+,;=:@/?#-]{1,250}))(?:["'`])/g;
function extractEndpoints(text, source, root, endpoints, swagger, indicators) {
  for (const m of text.matchAll(endpointRe)) {
    let raw = m[1].replace(/\\\//g, "/").replace(/[),;]+$/, "");
    let url;
    try { url = new URL(raw, source); } catch { continue; }
    if (!inScope(url.hostname, root)) continue;
    if (url.port) { const key = `Port\0${url.port}`; if (!indicators.has(key)) indicators.set(key, { type: "Port", value: url.port, source, context: raw }); }
    const path = `${url.pathname}${url.search}`;
    if (path.length < 2 || path.length > 260 || /\.(?:png|jpe?g|gif|svg|woff2?|ttf|ico)(?:$|\?)/i.test(path)) continue;
    const key = `${url.origin}${path}`;
    if (!endpoints.has(key)) endpoints.set(key, { url: key, host: url.hostname, path, source, kind: /swagger|openapi|api-docs/i.test(path) ? "API documentation" : /\bapi\b|\/v\d+\//i.test(path) ? "API route" : /\.[a-z0-9]{1,8}(?:$|\?)/i.test(path) ? "Static path" : "Path" });
    if (/swagger|openapi|api-docs/i.test(path)) swagger.add(key);
  }
  for (const m of text.matchAll(/(?:swagger-ui|swagger\.json|openapi\.json|openapi\.ya?ml|v\d+\/api-docs)/gi)) swagger.add(`${source} · ${m[0]}`);
}
function extractAssetUrls(html, source, root) {
  const out = new Set();
  const re = /(?:src|href)\s*=\s*["']([^"']+)["']/gi;
  for (const m of html.matchAll(re)) {
    const url = scopedFileUrl(m[1], source, root, /\.(?:m?js|cjs|jsx|ts|tsx|vue)$/i);
    if (url) out.add(url);
  }
  return [...out].slice(0, 24);
}
function extractInlineScripts(html, source) {
  const scripts = [], pattern = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  for (const match of html.matchAll(pattern)) {
    if (/\bsrc\s*=/.test(match[1]) || !match[2].trim()) continue;
    if (/\btype\s*=\s*["'](?:application\/json|application\/ld\+json)["']/i.test(match[1])) continue;
    scripts.push({ url: `${source}#inline-script-${scripts.length + 1}`, text: match[2].slice(0, MAX_TEXT), depth: 0, parent: source, kind: "Inline JavaScript" });
    if (scripts.length >= 30) break;
  }
  return scripts;
}
function scopedFileUrl(reference, base, root, extension) {
  try {
    const value = String(reference).trim().replace(/\\\//g, "/").replace(/\\u002f/gi, "/");
    if (!value || value.length > 2048 || value.includes("${")) return null;
    const url = new URL(value, base);
    if (!/^https?:$/.test(url.protocol) || !inScope(url.hostname, root) || !extension.test(url.pathname)) return null;
    url.hash = "";
    return url.href;
  } catch { return null; }
}
function extractSourceReferences(text, source, root) {
  const references = new Set();
  const specifiers = new Set();
  const importPatterns = [
    /\b(?:import|export)\s*(?:[^'"`;]*?\sfrom\s*)?\(?\s*["']([^"']{1,500})["']\s*\)?/g,
    /\brequire\s*\(\s*["']([^"']{1,500})["']\s*\)/g
  ];
  for (const pattern of importPatterns) for (const match of text.matchAll(pattern)) specifiers.add(match[1]);
  // Also catch script/chunk references in runtime configuration and generated bundles.
  const explicitFiles = /["'`]((?:https?:\/\/|\/\/|\/|\.\.\/|\.\/)?[^"'`\s<>]{1,500}?\.(?:m?js|cjs|jsx|ts|tsx|vue)(?:[?#][^"'`\s<>]*)?)["'`]/gi;
  for (const match of text.matchAll(explicitFiles)) specifiers.add(match[1]);
  for (const reference of specifiers) {
    const value = reference.trim();
    if (!value || value.startsWith("#") || value.startsWith("data:") || value.startsWith("blob:")) continue;
    const hasCodeExtension = /\.(?:m?js|cjs|jsx|ts|tsx|vue)(?:[?#]|$)/i.test(value);
    if (!hasCodeExtension && !/^(?:https?:)?\/\/|^\/|^\.\.?\//i.test(value)) continue;
    const suffixAt = value.search(/[?#]/), pathPart = suffixAt < 0 ? value : value.slice(0, suffixAt), query = suffixAt < 0 ? "" : value.slice(suffixAt);
    const candidates = hasCodeExtension ? [value] : [".js", ".mjs", ".cjs"].map(suffix => `${pathPart}${suffix}${query}`).concat(`${pathPart.replace(/\/$/, "")}/index.js${query}`);
    for (const candidate of candidates) {
      const url = scopedFileUrl(candidate, source, root, /\.(?:m?js|cjs|jsx|ts|tsx|vue)$/i);
      if (url) references.add(url);
    }
  }
  return [...references];
}
function extractSourceMapReferences(text, source) {
  const maps = new Set();
  const patterns = [
    /\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/g,
    /\/\*[#@]\s*sourceMappingURL\s*=\s*([^*\s]+)\s*\*\//g
  ];
  for (const pattern of patterns) for (const match of text.matchAll(pattern)) {
    const reference = match[1].replace(/[;,)]+$/, "");
    try { maps.add(new URL(reference, source).href); } catch {}
  }
  return [...maps];
}
function sourceMapSibling(source) {
  try { const url = new URL(source); if (url.hash.startsWith("#inline-script-")) return null; url.hash = ""; url.pathname += ".map"; return url.href; } catch { return null; }
}
async function readLimited(response, maxBytes) {
  if (!response.body?.getReader) return (await response.text()).slice(0, maxBytes);
  const reader = response.body.getReader(), decoder = new TextDecoder();
  let output = "", bytes = 0;
  while (bytes < maxBytes) {
    const { value, done } = await reader.read();
    if (done) break;
    const remaining = maxBytes - bytes, chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value;
    bytes += chunk.byteLength; output += decoder.decode(chunk, { stream: true });
    if (chunk.byteLength < value.byteLength) { await reader.cancel().catch(() => {}); break; }
  }
  if (bytes >= maxBytes) await reader.cancel().catch(() => {});
  output += decoder.decode();
  return output;
}
function decodeInlineMap(reference) {
  try {
    if (reference.length > 3_000_000 || !reference.startsWith("data:application/json")) return null;
    const comma = reference.indexOf(","); if (comma < 0) return null;
    const metadata = reference.slice(0, comma), payload = reference.slice(comma + 1);
    if (/;base64/i.test(metadata)) {
      const binary = atob(payload), bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
      return bytes.byteLength <= MAX_MAP_TEXT ? new TextDecoder().decode(bytes) : null;
    }
    const decoded = decodeURIComponent(payload);
    return new TextEncoder().encode(decoded).byteLength <= MAX_MAP_TEXT ? decoded : null;
  } catch { return null; }
}
function sourceMapSourceUrl(map, sourceName, mapUrl, root) {
  try {
    let base = mapUrl;
    if (map.sourceRoot) base = new URL(map.sourceRoot, mapUrl).href;
    const resolved = new URL(sourceName, base);
    if (!/^https?:$/.test(resolved.protocol) || !inScope(resolved.hostname, root)) return null;
    if (!/\.(?:m?js|cjs|jsx|ts|tsx|vue)$/i.test(resolved.pathname)) return null;
    return resolved.href;
  } catch { return null; }
}
function analyzeSourceText(text, source, root, result, depth, enqueueSource, enqueueMap, allowSiblingMap = true) {
  extractEndpoints(text, source, root, result.endpoints, result.swagger, result.indicators);
  extractIndicators(text, source, root, result.indicators, result.allHosts);
  for (const reference of extractSourceReferences(text, source, root)) enqueueSource(reference, depth + 1, source);
  for (const reference of extractSourceMapReferences(text, source)) enqueueMap(reference, depth);
  if (allowSiblingMap) {
    const siblingMap = sourceMapSibling(source);
    if (siblingMap) enqueueMap(siblingMap, depth);
  }
}
async function crawlSourceFiles(initialFiles, root, result) {
  const sourceQueue = [], mapQueue = [];
  const queuedSources = new Set(), queuedMaps = new Set();
  let totalText = 0, sourceAttempts = 0, mapAttempts = 0;
  const enqueueSource = (url, depth, parent = "") => {
    if (depth > MAX_IMPORT_DEPTH) { result.sourceScanLimited = true; return; }
    if (queuedSources.has(url)) return;
    if (sourceQueue.length + sourceAttempts >= MAX_SOURCE_FILES) { result.sourceScanLimited = true; return; }
    const safe = scopedFileUrl(url, parent || url, root, /\.(?:m?js|cjs|jsx|ts|tsx|vue)$/i);
    if (!safe) return;
    queuedSources.add(safe); sourceQueue.push({ url: safe, depth, parent });
  };
  const enqueueMap = (reference, depth) => {
    if (depth > MAX_IMPORT_DEPTH || mapQueue.length + mapAttempts >= MAX_SOURCE_MAPS) { result.sourceScanLimited = true; return; }
    if (reference.startsWith("data:application/json")) {
      const inlineText = decodeInlineMap(reference);
      if (!inlineText) return;
      const key = `inline:${inlineText.length}:${inlineText.slice(0, 80)}`;
      if (queuedMaps.has(key)) return;
      queuedMaps.add(key); mapQueue.push({ url: key, text: inlineText, depth }); return;
    }
    let url;
    try { url = new URL(reference); } catch { return; }
    if (!/^https?:$/.test(url.protocol) || !inScope(url.hostname, root) || !/\.map$/i.test(url.pathname)) return;
    if (queuedMaps.has(url.href)) return;
    queuedMaps.add(url.href); mapQueue.push({ url: url.href, depth });
  };
  for (const file of initialFiles) {
    if (file.text !== undefined) {
      queuedSources.add(file.url);
      sourceQueue.push({ ...file, parent: "HTML document" });
    } else enqueueSource(file.url, 0, file.parent || "HTML document");
  }
  const analyzeMap = (mapText, mapUrl, depth) => {
    let map;
    try { map = JSON.parse(mapText); } catch { return; }
    if (!Array.isArray(map.sources)) return;
    result.sourceMapsScanned++;
    recordSourceFile(result, mapUrl, { url: mapUrl, kind: "Source map", source: mapUrl.startsWith("inline:") ? "Inline source map" : mapUrl, bytes: mapText.length });
    for (let i = 0; i < map.sources.length; i++) {
      const name = String(map.sources[i] || "");
      const sourceUrl = sourceMapSourceUrl(map, name, mapUrl, root) || mapUrl;
      const embedded = map.sourcesContent?.[i];
      if (typeof embedded === "string" && embedded) {
        const sourceText = embedded.slice(0, MAX_TEXT), sourceBytes = new TextEncoder().encode(sourceText).byteLength;
        if (totalText + sourceBytes > MAX_HOST_TEXT) { result.sourceScanLimited = true; continue; }
        recordSourceFile(result, `${mapUrl}#${i}`, { url: name || sourceUrl, kind: "Embedded source", source: mapUrl, bytes: embedded.length });
        result.sourceFilesScanned++;
        analyzeSourceText(sourceText, sourceUrl, root, result, depth, enqueueSource, enqueueMap, false);
        totalText += sourceBytes;
      } else if (sourceUrl !== mapUrl) enqueueSource(sourceUrl, depth + 1, mapUrl);
    }
  };
  while ((sourceQueue.length && sourceAttempts < MAX_SOURCE_FILES) || (mapQueue.length && mapAttempts < MAX_SOURCE_MAPS)) {
    if (sourceQueue.length && sourceAttempts < MAX_SOURCE_FILES) {
      const batch = sourceQueue.splice(0, Math.min(3, MAX_SOURCE_FILES - sourceAttempts)); sourceAttempts += batch.length;
      await pool(batch, 3, async file => {
        try {
          let text = file.text, finalUrl = file.url, byteSize = text?.length || 0;
          if (text === undefined) {
            const response = await timeoutFetch(file.url, 7000);
            if (!response.ok || !inScope(new URL(response.url).hostname, root)) return;
            const type = response.headers.get("content-type") || "";
            if (!/(javascript|ecmascript|text\/plain|text\/html|text\/x-)/i.test(type) && !/\.(?:m?js|cjs|jsx|ts|tsx|vue)$/i.test(new URL(response.url).pathname)) return;
            finalUrl = response.url; text = await readLimited(response, MAX_TEXT); byteSize = new TextEncoder().encode(text).byteLength;
          }
          if (totalText + byteSize > MAX_HOST_TEXT) { result.sourceScanLimited = true; return; }
          totalText += byteSize; result.sourceFilesScanned++;
          recordSourceFile(result, finalUrl, { url: finalUrl, kind: file.kind || "JavaScript/source", source: file.parent || "HTML document", bytes: byteSize });
          analyzeSourceText(text, finalUrl, root, result, file.depth, enqueueSource, enqueueMap);
          logLine("Inspecting sources", `${result.sourceFilesScanned} files · ${result.sourceMapsScanned} maps`);
        } catch {}
      });
    } else {
      const batch = mapQueue.splice(0, Math.min(2, MAX_SOURCE_MAPS - mapAttempts)); mapAttempts += batch.length;
      await pool(batch, 2, async file => {
        try {
          if (file.text !== undefined) {
            const bytes = new TextEncoder().encode(file.text).byteLength;
            if (totalText + bytes > MAX_HOST_TEXT) { result.sourceScanLimited = true; return; }
            totalText += bytes; analyzeMap(file.text, file.url, file.depth); return;
          }
          const response = await timeoutFetch(file.url, 7000);
          if (!response.ok || !inScope(new URL(response.url).hostname, root)) return;
          const text = await readLimited(response, MAX_MAP_TEXT);
          const bytes = new TextEncoder().encode(text).byteLength;
          if (totalText + bytes > MAX_HOST_TEXT) { result.sourceScanLimited = true; return; }
          totalText += bytes; analyzeMap(text, response.url, file.depth);
          logLine("Inspecting sources", `${result.sourceFilesScanned} files · ${result.sourceMapsScanned} maps`);
        } catch {}
      });
    }
  }
  if (sourceQueue.length || mapQueue.length) result.sourceScanLimited = true;
}
async function pool(items, limit, worker) {
  let index = 0; await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (index < items.length) { const item = items[index++]; await worker(item); } }));
}
async function scanHost(host, root, result) {
  const base = `https://${host}/`;
  let response, source = base;
  try { response = await timeoutFetch(base); }
  catch (e) {
    try { source = `http://${host}/`; response = await timeoutFetch(source); }
    catch { result.failedHosts.push(host); return; }
  }
  if (!response.ok || !inScope(new URL(response.url).hostname, root)) return;
  let contentType = response.headers.get("content-type") || "";
  if (!/(text\/|javascript|json|xml)/i.test(contentType)) return;
  let text = await readLimited(response, MAX_TEXT); source = response.url;
  result.liveHosts.add(host);
  extractEndpoints(text, source, root, result.endpoints, result.swagger, result.indicators);
  extractIndicators(text, source, root, result.indicators, result.allHosts);
  const isHtml = /html/i.test(contentType);
  const isScript = /javascript|ecmascript/i.test(contentType) || /\.(?:m?js|cjs|jsx|ts|tsx|vue)$/i.test(new URL(source).pathname);
  const initialFiles = isHtml ? [...extractAssetUrls(text, source, root).map(url => ({ url, depth: 0, parent: source })), ...extractInlineScripts(text, source)] : [];
  if (isScript) initialFiles.unshift({ url: source, text, depth: 0, parent: "Host root response" });
  if (initialFiles.length) await crawlSourceFiles(initialFiles, root, result);
}
async function startScan() {
  if (state.busy) return;
  let root; try { root = normalizeRoot($("domain").value); } catch (e) { toast(e.message); return; }
  const scopeOrigins = [`https://${root}/*`, `https://*.${root}/*`, `http://${root}/*`, `http://*.${root}/*`];
  try {
    const permitted = await chrome.permissions.request({ origins: scopeOrigins });
    if (!permitted) { toast("Domain access was not granted; no target requests were sent."); return; }
  } catch (e) { toast(`Could not request domain access: ${e.message}`); return; }
  state.busy = true; $("start").disabled = true; $("start").innerHTML = `<span>Discovering…</span>${icon("loader-circle", "ui-icon spin")}`;
  setStatus("Discovering", "Querying public certificate transparency sources");
  const started = new Date().toISOString();
  try {
    const discovery = await getCertificateHosts(root);
    const result = { root, started, hosts: new Set(discovery.hosts), liveHosts: new Set(), allHosts: new Set(discovery.hosts), endpoints: new Map(), indicators: new Map(), swagger: new Set(), sourceFiles: new Map(), sourceFilesScanned: 0, sourceMapsScanned: 0, sourceScanLimited: false, sourceInventoryLimited: false, hostScanLimited: false, failedHosts: [], sourceErrors: discovery.errors };
    $("statSubs").textContent = result.hosts.size;
    setStatus("Inspecting", `Checking ${result.hosts.size} in-scope hosts (bounded GET)`);
    const pendingHosts = [...result.hosts], queuedHosts = new Set(pendingHosts);
    while (pendingHosts.length) {
      const batch = pendingHosts.splice(0, CONCURRENCY);
      await pool(batch, CONCURRENCY, async host => { await scanHost(host, root, result); logLine("Inspecting", `${result.liveHosts.size} responsive hosts · ${result.endpoints.size} routes · ${result.sourceFilesScanned} sources`); });
      for (const host of result.allHosts) {
        if (queuedHosts.has(host)) continue;
        if (queuedHosts.size >= MAX_HOSTS) { result.hostScanLimited = true; continue; }
        queuedHosts.add(host); result.hosts.add(host); pendingHosts.push(host);
      }
    }
    state.data = { root, started, completed: new Date().toISOString(), subdomains: [...result.hosts].sort(), liveHosts: [...result.liveHosts].sort(), endpoints: [...result.endpoints.values()].sort((a,b) => a.url.localeCompare(b.url)), indicators: [...result.indicators.values()].sort((a,b) => a.type.localeCompare(b.type)), swagger: [...result.swagger], sourceFiles: [...result.sourceFiles.values()].sort((a,b) => a.url.localeCompare(b.url)), sourceFilesScanned: result.sourceFilesScanned, sourceMapsScanned: result.sourceMapsScanned, sourceScanLimited: result.sourceScanLimited, sourceInventoryLimited: result.sourceInventoryLimited, hostScanLimited: result.hostScanLimited, failedHosts: result.failedHosts, sourceErrors: result.sourceErrors };
    await chrome.storage.local.set({ latestScan: state.data });
    const { scans = [] } = await chrome.storage.local.get({ scans: [] });
    state.history = [state.data, ...scans.filter(s => s.root !== root || s.started !== started)].slice(0, MAX_STORED_SCANS);
    await chrome.storage.local.set({ scans: state.history });
    updateStats(); render(); setStatus("Complete", `${state.data.liveHosts.length} hosts · ${state.data.sourceFilesScanned} source files · ${state.data.sourceMapsScanned} maps${state.data.hostScanLimited || state.data.sourceScanLimited ? " · scan cap reached" : ""}${state.data.sourceInventoryLimited ? " · inventory shortened" : ""}`);
    toast(`Found ${state.data.subdomains.length} hosts and ${state.data.endpoints.length} endpoint references.`);
  } catch (e) { setStatus("Error", e.message); toast(`Scan stopped: ${e.message}`); }
  finally { state.busy = false; $("start").disabled = false; $("start").innerHTML = `<span>Start scan</span>${icon("arrow-right")}`; }
}
function updateStats() {
  const d = state.data; if (!d) return;
  $("statSubs").textContent = d.subdomains.length; $("statEndpoints").textContent = d.endpoints.length; $("statIndicators").textContent = d.indicators.length;
  $("countOverview").textContent = d.subdomains.length + d.endpoints.length + d.indicators.length;
  $("countSubdomains").textContent = d.subdomains.length; $("countEndpoints").textContent = d.endpoints.length; $("countFindings").textContent = d.indicators.length; $("countSources").textContent = d.sourceFilesScanned || 0;
}
function row(title, meta, badge = "", openUrl = "") {
  const action = openUrl ? `<button class="open-result" type="button" data-open-url="${escapeHtml(openUrl)}" title="Open in new tab" aria-label="Open ${escapeHtml(title)} in new tab">${icon("external-link")}</button>` : "";
  return `<div class="result-row"><div class="result-main"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(meta)}</small></div><div class="result-actions">${badge ? `<span class="badge">${escapeHtml(badge)}</span>` : ""}${action}</div></div>`;
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
  return [...groups.entries()].slice(0, maxTypes).map(([type, matches]) => section(type, matches.length, matches.slice(0, maxRows).map(item => row(item.value, `Source: ${item.source}`, "REVIEW")).join(""))).join("");
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
  else $("panel").innerHTML = `${warning}<div class="overview-grid">${section("Subdomains", subs.length, subs.slice(0, 8).map(x => row(x, d.liveHosts.includes(x) ? "Responsive" : "Certificate transparency", d.liveHosts.includes(x) ? "LIVE" : "CT", `https://${x}/`)).join(""))}${section("Endpoint references", eps.length, eps.slice(0, 8).map(x => row(x.url, x.source, x.kind, x.url)).join(""))}<section class="grouped-findings"><div class="result-heading"><h3>Sensitive data by type</h3><span>${inds.length}</span></div>${findingsByType(inds, 4, 3) || `<div class="empty">No matches yet.</div>`}</section>${section("Swagger / OpenAPI", d.swagger.length, d.swagger.slice(0, 6).map(x => row(x, "Specification signal", "SPEC")).join(""))}</div><div class="run-meta">Last scan: ${escapeHtml(new Date(d.completed).toLocaleString())} · Scope: <b>${escapeHtml(d.root)}</b> · ${d.failedHosts.length} hosts did not respond · ${d.sourceFilesScanned || 0} source files · ${d.sourceMapsScanned || 0} source maps${d.sourceScanLimited || d.hostScanLimited ? " · scan cap reached" : ""}${d.sourceInventoryLimited ? " · source inventory shortened" : ""}</div>`;
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
  chrome.tabs.onUpdated.addListener((tabId, change, tab) => { if (tab.active && (change.status === "complete" || change.url)) void syncActiveSite(tabId); });
  $("panel").addEventListener("click", e => {
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
