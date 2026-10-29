const MAX_TEXT = 1_000_000, MAX_MAP_TEXT = 2_000_000, MAX_HOST_TEXT = 12_000_000;
const MAX_HOSTS = 120, CONCURRENCY = 10, SOURCE_CONCURRENCY = 6, MAX_SOURCE_FILES = 40, MAX_SOURCE_MAPS = 5, MAX_IMPORT_DEPTH = 3;
const MAX_RECORDED_SOURCE_FILES = 1500;
const REQUEST_CONCURRENCY = 20;
// Rwanda RURA numbering plan: mobile NDCs 72/73/77/78/79; fixed NDCs 22/23/25/28.
const PHONE_PATTERNS = [
  { country: "Rwanda", regex: /(?<!\d)(?:(?:\+?250|000250)[\s().-]*(?:7[23789]|2[2358])(?:[\s().-]*\d){7}|0[\s().-]*(?:7[23789]|2[2358])(?:[\s().-]*\d){7})(?!\d)/g }
];

export function normalizeRoot(raw) {
  let value = raw.trim();
  if (!value) throw new Error("Enter a domain to scan.");
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
  const u = new URL(value);
  if (!/^https?:$/.test(u.protocol) || !u.hostname.includes(".") || u.hostname === "localhost" || /^[\d.]+$/.test(u.hostname)) throw new Error("Enter a public root domain such as example.com.");
  return u.hostname.toLowerCase().replace(/^www\./, "");
}
export function inScope(host, root) { host = host.toLowerCase().replace(/\.$/, ""); return host === root || host.endsWith(`.${root}`); }
function normalizeHost(value, root) {
  let host = String(value || "").trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!host || host.includes("*") || !inScope(host, root)) return null;
  return host;
}
function createRequestLimiter(limit = REQUEST_CONCURRENCY) {
  let active = 0;
  const waiters = [];
  return async (url, ms = 5000) => {
  if (active >= limit) await new Promise(resolve => waiters.push(resolve));
  active++;
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), ms);
  try { return await fetch(url, { signal: controller.signal, redirect: "follow", credentials: "omit", cache: "no-store" }); }
  finally {
    clearTimeout(timer);
    active--;
    waiters.shift()?.();
  }
  };
}
function recordSourceFile(result, key, file) {
  if (result.sourceFiles.has(key)) { result.sourceFiles.set(key, file); return; }
  if (result.sourceFiles.size >= MAX_RECORDED_SOURCE_FILES) { result.sourceInventoryLimited = true; return; }
  result.sourceFiles.set(key, file);
}

async function getCertificateHosts(root, maxHosts = MAX_HOSTS, request) {
  const hosts = new Set([root, `www.${root}`]);
  const errors = [];
  const lookups = await Promise.allSettled([
    (async () => {
      const response = await request(`https://crt.sh/?q=${encodeURIComponent(`%.${root}`)}&output=json`, 12000);
      if (!response.ok) throw new Error(`crt.sh returned ${response.status}`);
      const rows = await response.json();
      for (const row of rows) for (const item of String(row.name_value || "").split(/[\r\n,]+/)) {
        const host = normalizeHost(item, root); if (host) hosts.add(host);
      }
    })(),
    (async () => {
      const response = await request(`https://api.ctlogs.dev/v1/hosts/${encodeURIComponent(root)}`, 12000);
      if (!response.ok) throw new Error(`ctlogs.dev returned ${response.status}`);
      const data = await response.json();
      const candidates = Array.isArray(data) ? data : (data.hosts || data.subdomains || data.data || []);
      for (const row of candidates) {
        const host = normalizeHost(typeof row === "string" ? row : (row.host || row.hostname || row.name || row.subdomain), root);
        if (host) hosts.add(host);
      }
    })()
  ]);
  for (let i = 0; i < lookups.length; i++) if (lookups[i].status === "rejected") errors.push(`${i ? "ctlogs.dev" : "crt.sh"}: ${lookups[i].reason?.message || "request failed"}`);
  return { hosts: [...hosts].slice(0, maxHosts), limited: hosts.size > maxHosts, errors };
}
function extractIndicators(text, source, root, bag, hosts) {
  const rules = [
    ["Email", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
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
  for (const { country, regex } of PHONE_PATTERNS) {
    regex.lastIndex = 0;
    for (const match of text.matchAll(regex)) {
      const value = match[0].trim(), digits = value.replace(/\D/g, "");
      const canonical = digits.startsWith("000250") ? digits.slice(3) : digits.startsWith("0") ? `250${digits.slice(1)}` : digits;
      const key = `Phone\0${canonical}`;
      if (!bag.has(key)) bag.set(key, { type: "Phone", country, value, source, context: text.slice(Math.max(0, match.index - 36), Math.min(text.length, match.index + value.length + 36)).replace(/\s+/g, " ") });
    }
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
async function crawlSourceFiles(initialFiles, root, result, onProgress, emitPartial, request) {
  const sourceQueue = [], mapQueue = [];
  const queuedSources = new Set(), queuedMaps = new Set();
  const limits = result.limits;
  let totalText = 0, sourceAttempts = 0, mapAttempts = 0;
  const enqueueSource = (url, depth, parent = "") => {
    if (depth > limits.maxImportDepth) { result.sourceScanLimited = true; return; }
    if (queuedSources.has(url)) return;
    if (sourceQueue.length + sourceAttempts >= limits.maxSourceFiles) { result.sourceScanLimited = true; return; }
    const safe = scopedFileUrl(url, parent || url, root, /\.(?:m?js|cjs|jsx|ts|tsx|vue)$/i);
    if (!safe) return;
    queuedSources.add(safe); sourceQueue.push({ url: safe, depth, parent });
  };
  const enqueueMap = (reference, depth) => {
    if (depth > limits.maxImportDepth || mapQueue.length + mapAttempts >= limits.maxSourceMaps) { result.sourceScanLimited = true; return; }
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
        if (totalText + sourceBytes > limits.maxHostText) { result.sourceScanLimited = true; continue; }
        recordSourceFile(result, `${mapUrl}#${i}`, { url: name || sourceUrl, kind: "Embedded source", source: mapUrl, bytes: embedded.length });
        result.sourceFilesScanned++;
        onProgress?.({ phase: "sources", sourceFilesScanned: result.sourceFilesScanned, sourceMapsScanned: result.sourceMapsScanned });
        analyzeSourceText(sourceText, sourceUrl, root, result, depth, enqueueSource, enqueueMap, false);
        totalText += sourceBytes;
        emitPartial?.();
      } else if (sourceUrl !== mapUrl) enqueueSource(sourceUrl, depth + 1, mapUrl);
    }
  };
  while ((sourceQueue.length && sourceAttempts < limits.maxSourceFiles) || (mapQueue.length && mapAttempts < limits.maxSourceMaps)) {
    if (sourceQueue.length && sourceAttempts < limits.maxSourceFiles) {
      const batch = sourceQueue.splice(0, Math.min(3, limits.maxSourceFiles - sourceAttempts)); sourceAttempts += batch.length;
      await pool(batch, SOURCE_CONCURRENCY, async file => {
        try {
          let text = file.text, finalUrl = file.url, byteSize = text?.length || 0;
          if (text === undefined) {
            const response = await request(file.url, 7000);
            if (!response.ok || !inScope(new URL(response.url).hostname, root)) return;
            const type = response.headers.get("content-type") || "";
            if (!/(javascript|ecmascript|text\/plain|text\/html|text\/x-)/i.test(type) && !/\.(?:m?js|cjs|jsx|ts|tsx|vue)$/i.test(new URL(response.url).pathname)) return;
            finalUrl = response.url; text = await readLimited(response, MAX_TEXT); byteSize = new TextEncoder().encode(text).byteLength;
          }
          if (totalText + byteSize > limits.maxHostText) { result.sourceScanLimited = true; return; }
          totalText += byteSize; result.sourceFilesScanned++;
          recordSourceFile(result, finalUrl, { url: finalUrl, kind: file.kind || "JavaScript/source", source: file.parent || "HTML document", bytes: byteSize });
          onProgress?.({ phase: "sources", sourceFilesScanned: result.sourceFilesScanned, sourceMapsScanned: result.sourceMapsScanned });
          analyzeSourceText(text, finalUrl, root, result, file.depth, enqueueSource, enqueueMap);
          emitPartial?.();
        } catch {}
      });
    } else {
      const batch = mapQueue.splice(0, Math.min(SOURCE_CONCURRENCY, limits.maxSourceMaps - mapAttempts)); mapAttempts += batch.length;
      await pool(batch, SOURCE_CONCURRENCY, async file => {
        try {
          if (file.text !== undefined) {
            const bytes = new TextEncoder().encode(file.text).byteLength;
            if (totalText + bytes > limits.maxHostText) { result.sourceScanLimited = true; return; }
            totalText += bytes; analyzeMap(file.text, file.url, file.depth); emitPartial?.(); return;
          }
          const response = await request(file.url, 7000);
          if (!response.ok || !inScope(new URL(response.url).hostname, root)) return;
          const text = await readLimited(response, MAX_MAP_TEXT);
          const bytes = new TextEncoder().encode(text).byteLength;
          if (totalText + bytes > limits.maxHostText) { result.sourceScanLimited = true; return; }
          totalText += bytes; analyzeMap(text, response.url, file.depth);
          emitPartial?.();
        } catch {}
      });
    }
  }
  if (sourceQueue.length || mapQueue.length) result.sourceScanLimited = true;
}
async function pool(items, limit, worker) {
  let index = 0; await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (index < items.length) { const item = items[index++]; await worker(item); } }));
}
function scanSnapshot(result, inProgress = true) {
  return { root: result.root, started: result.started, completed: inProgress ? null : new Date().toISOString(), inProgress, subdomains: [...result.hosts].sort(), liveHosts: [...result.liveHosts].sort(), endpoints: [...result.endpoints.values()].sort((a,b) => a.url.localeCompare(b.url)), indicators: [...result.indicators.values()].sort((a,b) => a.type.localeCompare(b.type)), swagger: [...result.swagger], sourceFiles: [...result.sourceFiles.values()].sort((a,b) => a.url.localeCompare(b.url)), sourceFilesScanned: result.sourceFilesScanned, sourceMapsScanned: result.sourceMapsScanned, sourceScanLimited: result.sourceScanLimited, sourceInventoryLimited: result.sourceInventoryLimited, hostScanLimited: result.hostScanLimited, failedHosts: [...result.failedHosts], sourceErrors: [...result.sourceErrors] };
}
async function scanHost(host, root, result, onProgress, emitPartial, request) {
  const base = `https://${host}/`;
  let response, source = base;
  try { response = await request(base); }
  catch (e) {
    try { source = `http://${host}/`; response = await request(source); }
    catch { result.failedHosts.push(host); return; }
  }
  if (!response.ok || !inScope(new URL(response.url).hostname, root)) return;
  let contentType = response.headers.get("content-type") || "";
  if (!/(text\/|javascript|json|xml)/i.test(contentType)) return;
  let text = await readLimited(response, MAX_TEXT); source = response.url;
  result.liveHosts.add(host);
  extractEndpoints(text, source, root, result.endpoints, result.swagger, result.indicators);
  extractIndicators(text, source, root, result.indicators, result.allHosts);
  emitPartial?.();
  const isHtml = /html/i.test(contentType);
  const isScript = /javascript|ecmascript/i.test(contentType) || /\.(?:m?js|cjs|jsx|ts|tsx|vue)$/i.test(new URL(source).pathname);
  const initialFiles = isHtml ? [...extractAssetUrls(text, source, root).map(url => ({ url, depth: 0, parent: source })), ...extractInlineScripts(text, source)] : [];
  if (isScript) initialFiles.unshift({ url: source, text, depth: 0, parent: "Host root response" });
  if (initialFiles.length) await crawlSourceFiles(initialFiles, root, result, onProgress, emitPartial, request);
}

export async function scanDomain(rawRoot, options = {}, onProgress) {
  const root = normalizeRoot(rawRoot);
  const limits = options.automatic ? { maxHosts: 20, maxSourceFiles: 12, maxSourceMaps: 2, maxImportDepth: 2, maxHostText: 6_000_000 } : { maxHosts: MAX_HOSTS, maxSourceFiles: MAX_SOURCE_FILES, maxSourceMaps: MAX_SOURCE_MAPS, maxImportDepth: MAX_IMPORT_DEPTH, maxHostText: MAX_HOST_TEXT };
  const started = new Date().toISOString();
  const request = createRequestLimiter();
  onProgress?.({ phase: "discovery", root });
  const discovery = await getCertificateHosts(root, limits.maxHosts, request);
  const seed = options.pageSnapshot?.root === root ? options.pageSnapshot : null;
  const result = { root, started, limits, hosts: new Set(discovery.hosts), liveHosts: new Set(), allHosts: new Set(discovery.hosts), endpoints: new Map(), indicators: new Map(), swagger: new Set(), sourceFiles: new Map(), sourceFilesScanned: 0, sourceMapsScanned: 0, sourceScanLimited: false, sourceInventoryLimited: false, hostScanLimited: discovery.limited, failedHosts: [], sourceErrors: discovery.errors };
  let lastPartialAt = 0;
  const emitPartial = (force = false) => {
    const now = Date.now();
    if (!force && now - lastPartialAt < 180) return;
    lastPartialAt = now;
    onProgress?.({ phase: "partial", data: scanSnapshot(result) });
  };
  emitPartial(true);
  onProgress?.({ phase: "hosts", hostsFound: result.hosts.size, liveHosts: 0, endpoints: 0 });
  const scanPageSeed = async () => {
  if (seed?.url && inScope(new URL(seed.url).hostname, root)) {
    const pageText = String(seed.html || "").slice(0, MAX_TEXT);
    if (pageText) {
      try {
        const source = new URL(seed.url).href;
        result.liveHosts.add(new URL(source).hostname);
        extractEndpoints(pageText, source, root, result.endpoints, result.swagger, result.indicators);
        extractIndicators(pageText, source, root, result.indicators, result.allHosts);
        const initialFiles = [...extractAssetUrls(pageText, source, root).map(url => ({ url, depth: 0, parent: source })), ...extractInlineScripts(pageText, source)];
        if (initialFiles.length) await crawlSourceFiles(initialFiles, root, result, progress => onProgress?.(progress), emitPartial, request);
        emitPartial(true);
      } catch {}
    }
  }
  };
  const pendingHosts = [...result.hosts], queuedHosts = new Set(pendingHosts);
  let cursor = 0;
  const worker = async () => {
    while (cursor < pendingHosts.length) {
      const host = pendingHosts[cursor++];
      await scanHost(host, root, result, onProgress, emitPartial, request);
      onProgress?.({ phase: "hosts", hostsFound: result.hosts.size, liveHosts: result.liveHosts.size, endpoints: result.endpoints.size, sourceFilesScanned: result.sourceFilesScanned, sourceMapsScanned: result.sourceMapsScanned });
      let discoveredHostAdded = false;
      for (const found of result.allHosts) {
        if (queuedHosts.has(found)) continue;
        if (queuedHosts.size >= limits.maxHosts) { result.hostScanLimited = true; continue; }
        queuedHosts.add(found); result.hosts.add(found); pendingHosts.push(found); discoveredHostAdded = true;
      }
      if (discoveredHostAdded) emitPartial();
    }
  };
  await Promise.all([scanPageSeed(), ...Array.from({ length: Math.min(CONCURRENCY, pendingHosts.length) }, worker)]);
  return scanSnapshot(result, false);
}
