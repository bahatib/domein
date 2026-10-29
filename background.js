chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get({ scans: [] }, ({ scans }) => {
    if (!Array.isArray(scans)) chrome.storage.local.set({ scans: [] });
  });
  chrome.action.setBadgeBackgroundColor({ color: "#159f70" });
  chrome.sidePanel?.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, ([tab]) => { if (tab?.id) updateBadge(tab.id, tab.url); });
});

// Fallback for Chrome versions that do not support openPanelOnActionClick.
chrome.action.onClicked.addListener((tab) => {
  if (tab?.windowId) chrome.sidePanel?.open({ windowId: tab.windowId }).catch(() => {});
});

function matchesRoot(host, root) { return host === root || host.endsWith(`.${root}`); }

async function updateBadge(tabId, tabUrl) {
  try {
    if (!tabUrl) tabUrl = (await chrome.tabs.get(tabId)).url;
    const host = new URL(tabUrl).hostname.toLowerCase();
    const { scans = [], latestScan } = await chrome.storage.local.get({ scans: [], latestScan: null });
    const candidates = [...scans, ...(latestScan ? [latestScan] : [])]
      .filter(scan => scan?.root && matchesRoot(host, scan.root.toLowerCase()))
      .sort((a, b) => Date.parse(b.completed || b.started) - Date.parse(a.completed || a.started));
    const scan = candidates[0];
    const total = scan ? (scan.subdomains?.length || 0) + (scan.endpoints?.length || 0) + (scan.indicators?.length || 0) : 0;
    await chrome.action.setBadgeText({ tabId, text: total ? (total > 99 ? "99+" : String(total)) : "" });
  } catch {
    try { await chrome.action.setBadgeText({ tabId, text: "" }); } catch {}
  }
}

chrome.tabs.onActivated.addListener(({ tabId }) => updateBadge(tabId));
chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.status === "complete" || change.url) updateBadge(tabId, tab.url);
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || (!changes.scans && !changes.latestScan)) return;
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, ([tab]) => { if (tab?.id) updateBadge(tab.id, tab.url); });
});
chrome.runtime.onStartup.addListener(() => {
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, ([tab]) => { if (tab?.id) updateBadge(tab.id, tab.url); });
});
