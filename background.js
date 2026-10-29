import { scanDomain, normalizeRoot } from "./scanner.js";

const AUTO_SCAN_COOLDOWN = 30 * 60 * 1000;
const MAX_STORED_SCANS = 10;
const activeAutoScans = new Map();
const autoScanTabs = new Map();
const activeAutoScanData = new Map();
const autoScanQueue = [];
const MAX_PARALLEL_AUTO_SCANS = 2;
let runningAutoScans = 0;
const pageSnapshots = new Map();

async function capturePageSnapshot(tabId, root) {
  try {
    const [{ result } = {}] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => ({ url: location.href, html: document.documentElement?.outerHTML?.slice(0, 1_000_000) || "" })
    });
    if (result?.html && normalizeRoot(result.url) === root) pageSnapshots.set(root, result);
  } catch {}
  return pageSnapshots.get(root) || null;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get({ scans: [] }, ({ scans }) => {
    if (!Array.isArray(scans)) chrome.storage.local.set({ scans: [] });
  });
  chrome.action.setBadgeBackgroundColor({ color: "#159f70" });
  chrome.sidePanel?.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, ([tab]) => {
    if (tab?.id) { updateBadge(tab.id, tab.url); void autoScanTab(tab.url, tab.id); }
  });
});

// Fallback for Chrome versions that do not support openPanelOnActionClick.
chrome.action.onClicked.addListener((tab) => {
  if (tab?.windowId) chrome.sidePanel?.open({ windowId: tab.windowId }).catch(() => {});
});

function matchesRoot(host, root) { return host === root || host.endsWith(`.${root}`); }

async function autoScanTab(tabUrl, tabId) {
  let root;
  try { root = normalizeRoot(tabUrl); } catch { return; }
  if (activeAutoScans.has(root)) { if (tabId != null) autoScanTabs.get(root)?.add(tabId); return activeAutoScans.get(root); }
  try {
    const { scans = [], latestScan = null } = await chrome.storage.local.get({ scans: [], latestScan: null });
    const previous = [...scans, ...(latestScan ? [latestScan] : [])]
      .filter(scan => scan?.root === root)
      .sort((a, b) => Date.parse(b.completed || b.started) - Date.parse(a.completed || a.started))[0];
    const lastComplete = Date.parse(previous?.completed || previous?.started || "");
    if (Number.isFinite(lastComplete) && Date.now() - lastComplete < AUTO_SCAN_COOLDOWN) return;
  } catch { return; }

  if (activeAutoScans.has(root)) { if (tabId != null) autoScanTabs.get(root)?.add(tabId); return activeAutoScans.get(root); }
  let resolveTask;
  const task = new Promise(resolve => { resolveTask = resolve; });
  activeAutoScans.set(root, task);
  autoScanTabs.set(root, new Set(tabId == null ? [] : [tabId]));
  autoScanQueue.push({ root, resolveTask, tabId });
  drainAutoScanQueue();
  return task;
}

function drainAutoScanQueue() {
  while (runningAutoScans < MAX_PARALLEL_AUTO_SCANS && autoScanQueue.length) {
    const { root, resolveTask, tabId } = autoScanQueue.shift();
    const tabIds = autoScanTabs.get(root) || new Set();
    runningAutoScans++;
    void (async () => {
      try {
        void chrome.runtime.sendMessage({ type: "domein-scan-status", root, inProgress: true, phase: "discovering", detail: "Discovering hosts and collecting responses" }).catch(() => {});
        let pendingSnapshot = null, lastBroadcast = 0, broadcastTimer = null;
        const broadcast = () => {
          broadcastTimer = null;
          if (!pendingSnapshot) return;
          const data = pendingSnapshot; pendingSnapshot = null; lastBroadcast = Date.now();
          activeAutoScanData.set(root, data);
          for (const tabId of tabIds) void setBadgeFromScan(tabId, data).catch(() => {});
          void chrome.runtime.sendMessage({ type: "domein-scan-progress", data }).catch(() => {});
        };
        const pageSnapshot = tabId == null ? pageSnapshots.get(root) || null : await capturePageSnapshot(tabId, root);
        const data = await scanDomain(root, { automatic: true, pageSnapshot }, progress => {
          if (progress.phase !== "partial") {
            void chrome.runtime.sendMessage({ type: "domein-scan-status", root, inProgress: true, phase: progress.phase, detail: progress.phase === "sources" ? `Processing ${progress.sourceFilesScanned || 0} source files · ${progress.sourceMapsScanned || 0} maps` : `Inspecting ${progress.hostsFound || 0} discovered hosts` }).catch(() => {});
            return;
          }
          pendingSnapshot = progress.data;
          if (Date.now() - lastBroadcast >= 180) broadcast();
          else if (!broadcastTimer) broadcastTimer = setTimeout(broadcast, 180 - (Date.now() - lastBroadcast));
        });
        if (broadcastTimer) clearTimeout(broadcastTimer);
        if (pendingSnapshot) broadcast();
        const { scans = [] } = await chrome.storage.local.get({ scans: [] });
        const history = [data, ...scans.filter(scan => scan.root !== root || scan.started !== data.started)].slice(0, MAX_STORED_SCANS);
        await chrome.storage.local.set({ latestScan: data, scans: history });
        void chrome.runtime.sendMessage({ type: "domein-scan-status", root, inProgress: false, phase: "complete", detail: "Scan complete" }).catch(() => {});
      } catch (error) {
        console.warn("Domein automatic scan failed:", root, error?.message || error);
        void chrome.runtime.sendMessage({ type: "domein-scan-status", root, inProgress: false, phase: "error", detail: "Scan could not be completed" }).catch(() => {});
      } finally {
        activeAutoScanData.delete(root);
        activeAutoScans.delete(root);
        autoScanTabs.delete(root);
        for (const tabId of tabIds) void updateBadge(tabId);
        runningAutoScans--;
        resolveTask();
        drainAutoScanQueue();
      }
    })();
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "domein-get-active-scans") {
    sendResponse({ roots: [...activeAutoScans.keys()] });
    return false;
  }
  if (message?.type !== "domein-capture-page") return;
  const tabId = sender.tab?.id;
  if (tabId == null || !message.snapshot?.url) return;
  try {
    const root = normalizeRoot(message.snapshot.url);
    if (typeof message.snapshot.html === "string" && message.snapshot.html.length <= 1_000_000) {
      pageSnapshots.set(root, { url: message.snapshot.url, html: message.snapshot.html });
      sendResponse({ ok: true });
    }
  } catch {}
  return true;
});

async function updateBadge(tabId, tabUrl) {
  try {
    if (!tabUrl) tabUrl = (await chrome.tabs.get(tabId)).url;
    const host = new URL(tabUrl).hostname.toLowerCase();
    let scan;
    try { scan = activeAutoScanData.get(normalizeRoot(tabUrl)); } catch {}
    if (!scan) {
      const { scans = [], latestScan } = await chrome.storage.local.get({ scans: [], latestScan: null });
      const candidates = [...scans, ...(latestScan ? [latestScan] : [])]
        .filter(item => item?.root && matchesRoot(host, item.root.toLowerCase()))
        .sort((a, b) => Date.parse(b.completed || b.started) - Date.parse(a.completed || a.started));
      scan = candidates[0];
    }
    await setBadgeFromScan(tabId, scan);
  } catch {
    try { await chrome.action.setBadgeText({ tabId, text: "" }); } catch {}
  }
}
async function setBadgeFromScan(tabId, scan) {
  const total = scan ? (scan.subdomains?.length || 0) + (scan.endpoints?.length || 0) + (scan.indicators?.length || 0) : 0;
  await chrome.action.setBadgeText({ tabId, text: total ? (total > 99 ? "99+" : String(total)) : "" });
}

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId).then(tab => { void updateBadge(tabId, tab.url); void autoScanTab(tab.url, tabId); }).catch(() => {});
});
chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.status === "complete" || change.url) updateBadge(tabId, tab.url);
  if (change.status === "complete") void autoScanTab(tab.url, tabId);
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || (!changes.scans && !changes.latestScan)) return;
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, ([tab]) => { if (tab?.id) updateBadge(tab.id, tab.url); });
});
chrome.runtime.onStartup.addListener(() => {
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, ([tab]) => {
    if (tab?.id) { updateBadge(tab.id, tab.url); void autoScanTab(tab.url, tab.id); }
  });
});
