import { scanDomain, normalizeRoot } from "./scanner.js";
import { getArchivedResponsesBatch, deleteArchivedResponses, getArchivedResponseCount } from "./response-store.js";

const AUTO_SCAN_COOLDOWN = 30 * 60 * 1000;
const MAX_STORED_SCANS = 10;
const activeAutoScans = new Map();
const autoScanTabs = new Map();
const activeAutoScanData = new Map();
const autoScanQueue = [];
const MAX_PARALLEL_AUTO_SCANS = 2;
let runningAutoScans = 0;
const pageSnapshots = new Map();

// --- AWS API Sync Configuration & Deduplication ---
export const AWS_SYNC_CONFIG = {
  apiUrl: "https://hs9m562woa.execute-api.eu-north-1.amazonaws.com/sync",
  secretKey: "Tn2os8seE5umQo/zA8ZbXqNjr6mYpSY9X769BqbsBAE="
};

async function getSyncConfig() {
  const { syncConfig } = await chrome.storage.local.get({ syncConfig: AWS_SYNC_CONFIG });
  return { ...AWS_SYNC_CONFIG, ...syncConfig };
}

/**
 * Generates a SHA-256 fingerprint of the scan data to detect if findings have changed.
 */
async function computeScanHash(scan) {
  if (!scan || !scan.root) return "";
  const normalized = {
    root: scan.root,
    subdomains: (scan.subdomains || []).slice().sort(),
    endpoints: (scan.endpoints || []).map(e => (typeof e === "string" ? e : e.url || "")).sort(),
    indicators: (scan.indicators || []).map(i => `${i.type || ""}:${i.value || ""}`).sort(),
    swagger: (scan.swagger || []).slice().sort()
  };
  const str = JSON.stringify(normalized);
  const buffer = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Synchronizes a single scan to AWS API Gateway if not already synced or if new findings exist.
 */
export async function syncScanToApi(scan) {
  if (!scan || !scan.root || scan.inProgress) return false;

  try {
    const config = await getSyncConfig();
    if (!config.apiUrl) return false;

    const { syncedScans = {} } = await chrome.storage.local.get({ syncedScans: {} });
    const hash = await computeScanHash(scan);

    // DEDUPLICATION:
    // If this website (root) already has this exact hash in syncedScans, skip sending duplicate data!
    if (syncedScans[scan.root]?.hash === hash) {
      console.log(`[Domein Sync] No changes for ${scan.root} (hash matched). Skipping sync to avoid duplicates.`);
      return false;
    }

    const payload = {
      id: scan.root, // Deterministic ID ensures one clean record per domain in DynamoDB
      scanId: scan.root,
      root: scan.root,
      started: scan.started,
      completed: scan.completed || new Date().toISOString(),
      stats: {
        hosts: scan.subdomains?.length || 0,
        endpoints: scan.endpoints?.length || 0,
        findings: scan.indicators?.length || 0,
        sourceFiles: scan.sourceFilesScanned || 0,
        sourceMaps: scan.sourceMapsScanned || 0
      },
      subdomains: scan.subdomains || [],
      endpoints: scan.endpoints || [],
      indicators: scan.indicators || [],
      swagger: scan.swagger || [],
      liveHosts: scan.liveHosts || []
    };

    console.log(`[Domein Sync] Uploading scan for ${scan.root} to AWS...`);
    const response = await fetch(config.apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${config.secretKey}`
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      console.warn(`[Domein Sync] API responded with ${response.status}:`, errText);
      return false;
    }

    // Save hash and timestamp to record that this state was synced
    syncedScans[scan.root] = {
      hash,
      syncedAt: new Date().toISOString(),
      findingsCount: payload.stats.findings,
      hostsCount: payload.stats.hosts
    };
    await chrome.storage.local.set({ syncedScans });
    console.log(`[Domein Sync] Successfully synced ${scan.root} to AWS!`);
    return true;
  } catch (err) {
    console.error(`[Domein Sync] Error syncing ${scan.root}:`, err);
    return false;
  }
}

let isSyncingArchive = false;
let archiveDrainDebounceTimer = null;

/**
 * Debounced trigger to drain the local archive buffer into AWS DynamoDB.
 */
export function scheduleArchiveDrain(delayMs = 2500) {
  if (archiveDrainDebounceTimer) clearTimeout(archiveDrainDebounceTimer);
  archiveDrainDebounceTimer = setTimeout(() => {
    archiveDrainDebounceTimer = null;
    void syncArchivedResponsesToApi();
  }, delayMs);
}

/**
 * Iterates through all archived responses in IndexedDB, uploads them to the AWS API,
 * and deletes them locally upon successful upload so that the archive count reduces to 0.
 * Keeps payloads bounded below DynamoDB's 400KB limit.
 */
export async function syncArchivedResponsesToApi() {
  if (isSyncingArchive) return;
  isSyncingArchive = true;

  try {
    const config = await getSyncConfig();
    if (!config.apiUrl || !config.secretKey) {
      isSyncingArchive = false;
      return;
    }

    let remaining = await getArchivedResponseCount();
    if (remaining === 0) {
      isSyncingArchive = false;
      return;
    }

    console.log(`[Domein Archive Sync] Starting upload for ${remaining} archived responses...`);

    const BATCH_SIZE = 15;
    while (remaining > 0) {
      const batch = await getArchivedResponsesBatch(BATCH_SIZE);
      if (!batch.length) break;

      const successfulIds = [];

      await Promise.all(
        batch.map(async (record) => {
          try {
            const isText = /text|json|javascript|xml|yaml|html|graphql/i.test(record.contentType || "");
            let bodyText = "";
            let isTruncated = false;
            if (isText && record.body && record.bodyBytes > 0) {
              try {
                // Safeguard against DynamoDB 400KB limit: bound text to 150KB
                const fullText = await record.body.text();
                if (fullText.length > 150_000) {
                  bodyText = fullText.slice(0, 150_000);
                  isTruncated = true;
                } else {
                  bodyText = fullText;
                }
              } catch {}
            }

            const payload = {
              id: `resp_${record.root}_${record.id}`,
              scanId: `resp_${record.root}_${record.id}`,
              root: record.root,
              timestamp: record.timestamp,
              completed: record.timestamp,
              type: "archived-response",
              stats: { findings: 0, hosts: 0 },
              url: record.url,
              requestedUrl: record.requestedUrl,
              status: record.status,
              statusText: record.statusText,
              contentType: record.contentType,
              bodyBytes: record.bodyBytes,
              isTruncated,
              headers: record.headers,
              bodyText
            };

            const res = await fetch(config.apiUrl, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${config.secretKey}`
              },
              body: JSON.stringify(payload)
            });

            if (res.ok) {
              successfulIds.push(record.id);
            } else {
              console.warn(`[Domein Archive Sync] Record #${record.id} failed with HTTP ${res.status}`);
            }
          } catch (err) {
            console.error(`[Domein Archive Sync] Network error on record #${record.id}:`, err);
          }
        })
      );

      if (successfulIds.length > 0) {
        await deleteArchivedResponses(successfulIds);
        remaining -= successfulIds.length;
        console.log(`[Domein Archive Sync] Uploaded and cleared ${successfulIds.length} responses. Remaining: ${remaining}`);
      } else {
        console.warn("[Domein Archive Sync] Batch failed completely. Pausing archive sync.");
        break;
      }

      await new Promise(resolve => setTimeout(resolve, 80));
    }
  } catch (err) {
    console.error("[Domein Archive Sync] Error during archive sync:", err);
  } finally {
    isSyncingArchive = false;
  }
}

/**
 * Scans all existing scans in local storage and synchronizes any that haven't been synced,
 * and starts syncing the response archive.
 */
export async function syncAllStoredScans() {
  try {
    const { scans = [], latestScan = null } = await chrome.storage.local.get({ scans: [], latestScan: null });
    const all = [...(latestScan ? [latestScan] : []), ...scans];
    const uniqueByRoot = new Map();
    for (const s of all) {
      if (s?.root && !uniqueByRoot.has(s.root)) {
        uniqueByRoot.set(s.root, s);
      }
    }

    console.log(`[Domein Sync] Checking ${uniqueByRoot.size} existing scans for synchronization...`);
    for (const s of uniqueByRoot.values()) {
      await syncScanToApi(s);
    }

    // Automatically sync archived responses as well
    void syncArchivedResponsesToApi();
  } catch (err) {
    console.error("[Domein Sync] Error syncing stored scans:", err);
  }
}


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
  void syncAllStoredScans();
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

        // Automatically sync to AWS API on scan completion
        void syncScanToApi(data);
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
  if (message?.type === "domein-sync-all-now") {
    syncAllStoredScans().then(() => sendResponse({ ok: true })).catch(e => sendResponse({ ok: false, error: e?.message }));
    return true;
  }
  if (message?.type === "domein-sync-archive-now") {
    syncArchivedResponsesToApi().then(() => sendResponse({ ok: true })).catch(e => sendResponse({ ok: false, error: e?.message }));
    return true;
  }
  if (message?.type === "domein-archive-updated") {
    scheduleArchiveDrain(3000);
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
  if (area !== "local") return;
  if (changes.scans || changes.latestScan) {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, ([tab]) => { if (tab?.id) updateBadge(tab.id, tab.url); });
  }
  // Sync when a manual scan is saved from the sidepanel
  if (changes.latestScan?.newValue && !changes.latestScan.newValue.inProgress) {
    void syncScanToApi(changes.latestScan.newValue);
  }
});
chrome.runtime.onStartup.addListener(() => {
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, ([tab]) => {
    if (tab?.id) { updateBadge(tab.id, tab.url); void autoScanTab(tab.url, tab.id); }
  });
  void syncAllStoredScans();
});

// Run immediate check when service worker starts
void syncAllStoredScans();

// Periodic drain every 60 seconds to keep the local buffer near zero
setInterval(() => {
  scheduleArchiveDrain(500);
}, 60 * 1000);

