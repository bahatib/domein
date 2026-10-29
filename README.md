# Domein Research

A local Manifest V3 browser extension for authorized attack-surface research. It uses public Certificate Transparency sources (`crt.sh` and `ctlogs.dev`) for passive subdomain discovery, followed by bounded GET requests to each discovered host inside the entered root domain. It inspects returned HTML, inline scripts, linked JavaScript, recursively referenced source files, and available source maps for hostnames, URL paths, API routes, Swagger/OpenAPI references, and requested indicators (email, phone, IPv4, ports, ID-like numbers, JWTs, and common secret patterns).

## Load in Chrome

1. Open `chrome://extensions` and enable Developer mode.
2. Choose **Load unpacked** and select this folder.
3. Click the Domein icon in Chrome’s toolbar to open its persistent right-side panel. It fills in the current page’s domain and displays saved results.
4. The authorization indicator stays enabled, so scanning does not require checkbox confirmation. Domein uses the same broad host-access pattern as FindSomething (`<all_urls>`): Chrome asks for website access when you install or reload the updated extension, then scans do not trigger a separate per-domain prompt. To change the grant later, open `chrome://extensions` → Domein Research → **Details** → **Site access**.

The background service worker automatically scans HTTP(S) sites as their pages finish loading, even while the side panel is closed. It skips a domain with a scan from the last 30 minutes. To keep browsing scans bounded, automatic runs inspect up to 20 hosts, 12 source files and 2 source maps per host; **Scan again** runs the full manual limits (up to 120 hosts, 40 source files and 5 maps per host). When the panel is open, hosts, routes and findings appear as they are discovered; the badge updates when a scan completes.

The toolbar badge shows the saved count for the active site’s root domain after a scan (subdomains + endpoint references + indicator matches). It clears on sites with no matching saved scan and updates when you switch tabs. The side panel follows the active tab and displays its saved scan when available; tab addresses are used only to match sites to local scan results.

No local-folder analysis is included. Reports can be exported as JSON, CSV, or plain text. Data remains in extension local storage until browser data is cleared.

## Scope and limits

- Discovery is rooted in the exact registrable domain supplied by you. Results for unrelated domains are ignored.
- CT lookup is passive. Requests are GET-only and stay within the selected root domain. Each responding page is checked for routes and linked scripts; same-scope static hosts found in page or source content are queued too, up to 120 hosts total. Per host, Domein follows up to 40 same-scope script/source files (including relative and dynamic imports) and parses up to 5 source maps, with a maximum import depth of 3 and per-file/total byte limits. Source-map `sourcesContent` is searched locally; external mapped sources are fetched only when their URL remains in scope. There is no wordlist guessing, port scanning, authentication bypass, form submission, or arbitrary endpoint execution.
- Endpoint results are static references found in page and script text; this does not claim the routes are live.
- ID-like values and secret-shaped strings can be false positives. Treat findings as sensitive. Values are stored locally and are not sent to a server.
- Phone findings currently use Rwanda’s numbering ranges for mobile and fixed lines, with exact length and prefix checks to avoid matching arbitrary digit strings as phones.
- API availability and response shapes at public CT services can change. The UI reports source errors instead of treating them as empty results.
- Source maps can be absent, truncated by configured size limits, or omit embedded original code. The scan reports the source/map counts and indicates when a cap was reached.

This project is an independent implementation and does not copy FindSomething source code.

Interface icons use the locally bundled Lucide SVG sprite in `icons/ui/`; its ISC license is included alongside the assets. The extension badge and panel logo use the supplied `icons/logo.png` navy-and-green branding.
