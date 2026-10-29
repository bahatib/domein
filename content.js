(() => {
  const capture = () => {
    try {
      const html = document.documentElement?.outerHTML;
      if (!html) return;
      chrome.runtime.sendMessage({
        type: "domein-capture-page",
        snapshot: { url: location.href, html: html.slice(0, 1_000_000) }
      }).catch(() => {});
    } catch {}
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", capture, { once: true });
  } else capture();

  let previousUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== previousUrl) {
      previousUrl = location.href;
      setTimeout(capture, 150);
    }
  }).observe(document, { subtree: true, childList: true });
})();
