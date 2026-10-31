# Domein Research

A local Manifest V3 browser extension for authorized attack-surface research. It uses public Certificate Transparency sources (`crt.sh` and `ctlogs.dev`) for passive subdomain discovery, followed by bounded GET requests to each discovered host inside the entered root domain. It inspects returned HTML, inline scripts, linked JavaScript, recursively referenced source files, and available source maps for hostnames, URL paths, API routes, Swagger/OpenAPI references, and requested indicators (email, phone, IPv4, ports, ID-like numbers, JWTs, and common secret patterns).

## Load in Chrome

1. Open `chrome://extensions` and enable Developer mode.
2. Choose **Load unpacked** and select this folder.
3. Click the Domein icon in Chrome’s toolbar to open its persistent right-side panel. It fills in the current page’s domain and displays saved results.
4. The authorization indicator stays enabled, so scanning does not require checkbox confirmation. Domein uses the same broad host-access pattern as FindSomething (`<all_urls>`): Chrome asks for website access when you install or reload the updated extension, then scans do not trigger a separate per-domain prompt. To change the grant later, open `chrome://extensions` → Domein Research → **Details** → **Site access**.

The background service worker automatically scans HTTP(S) sites as their pages finish loading, even while the side panel is closed. It skips a domain with a scan from the last 30 minutes. To keep browsing scans bounded, automatic runs inspect up to 20 hosts, 12 source files and 2 source maps per host; **Scan again** runs the full manual limits (up to 120 hosts, 40 source files and 5 maps per host). When the panel is open, hosts, routes and findings appear as they are discovered; the toolbar badge count increments during the scan.

The toolbar badge shows the saved count for the active site’s root domain after a scan (subdomains + endpoint references + indicator matches). It clears on sites with no matching saved scan and updates when you switch tabs. The side panel follows the active tab and displays its saved scan when available; tab addresses are used only to match sites to local scan results.

No local-folder analysis is included. Parsed scan reports remain in extension local storage, and every HTTP response fetched by Domein during discovery or source inspection is also archived automatically in an extension-local IndexedDB database (`domein-response-archive`, object store `responses`). Each record includes the request/final URL, status, headers, timestamp, scan root and ID, and the complete response body as a Blob. This happens in the background without a download prompt or native helper. Open the **Archive** tab to search and inspect recent responses, export a portable JSON archive, or import that archive into another Chrome profile. The archive stays in this Chrome profile and is removed if the extension's site data is cleared; it is not written as a standalone file. Reports can still be exported as JSON, CSV, or plain text.

## Core Features & How They Work

Domein performs multi-stage, passive and active attack-surface recon directly from the browser:

### 1. Passive Subdomain Discovery
- **How it works**: Queries public Certificate Transparency (CT) registries (`crt.sh` and `ctlogs.dev`) for all certificates registered under the target root domain.
- **Benefits**: Discovers subdomains without sending a single packet to the target's servers, identifying infrastructure that may not be linked on the main site.

### 2. Active Host Probing & Verification
- **How it works**: Sends non-destructive HTTP/HTTPS `GET` requests to each discovered hostname to verify if it is live and responding.
- **Verification**: Categorizes hosts as either actively responding (`LIVE`) or only recorded in certificate registries (`CT`).
- **Safety**: Strictly bounded to the root domain; never interacts with out-of-scope third-party domains.

### 3. Route & Endpoint Extraction
- **How it works**: Statically parses HTML responses, inline scripts, linked JavaScript files, and source maps to detect API endpoints, relative paths, and routing definitions.
- **Swagger / OpenAPI Detection**: Identifies references to OpenAPI specs, Swagger UI paths (`/swagger.json`, `/api-docs`, etc.), and API schemas.

### 4. Sensitive Data & Indicator Inspection
- **How it works**: Analyzes script contents and responses using regex pattern matching and structural validation.
- **Indicators Detected**:
  - **API Keys & Tokens**: Common secret patterns (Bearer tokens, AWS keys, Stripe keys, GitHub tokens, etc.).
  - **JWTs (JSON Web Tokens)**: Decodable auth tokens in client bundles.
  - **Contact & Network**: Email addresses, validated phone numbers (with strict prefix/length rules), and IPv4 addresses.

### 5. Source Map & Script Archaeology
- **How it works**: Fetches `.js` files and discovers source map references (`//# sourceMappingURL=...`). If available, parses the JSON source map to recover original source filenames and embedded code (`sourcesContent`).
- **Depth & Limits**: Follows imports up to a depth of 3 with strict per-file and total byte limits to prevent browser memory exhaustion.

### 6. Local Response Archiving (`IndexedDB`)
- **How it works**: Every HTTP response fetched during discovery or source inspection is automatically stored in a local IndexedDB database (`domein-response-archive`).
- **Capabilities**: Stores complete headers, status codes, timestamps, and full response bodies as Blobs. You can preview bodies, export individual records, export the entire database as a JSON bundle, or import archives across machines.

### 7. AWS Cloud Sync Pipeline
- **How it works**: Synchronizes scan summaries and archived responses to an AWS cloud backend (**API Gateway HTTP API → AWS Lambda → Amazon DynamoDB**).
- **Deduplication**: Generates deterministic SHA-256 fingerprints to update existing domain records without duplicating rows.
- **400 KB Guard**: Binds raw response bodies (< 150 KB) to strictly comply with DynamoDB's 400 KB item ceiling.
- **Background Drain**: Automatically flushes queued archive records in small batches without freezing the browser UI.

### 8. Tab-Scoped Exports & Quick Copy
- **Quick Copy (`#copyTab`)**: Copies all items displayed on the active tab (filtered or unfiltered) directly to the clipboard.
- **Export Dropdown**: Exports data specific to the active tab:
  - **Hosts**: Discovered subdomains and their responsiveness status.
  - **Routes**: Discovered endpoint paths, types, and sources.
  - **Data**: Sensitive indicator candidates and their context.
  - **Sources**: Scanned script files, source maps, and byte counts.
  - **Overview**: Full, comprehensive report.
  - Formats supported: **JSON**, **CSV**, and **TXT**.

---

## Keyword & Tag Glossary

When browsing scan results in the Domein panel, you will encounter the following status tags and keywords:

| Keyword / Tag | Section | Meaning | Details |
| :--- | :--- | :--- | :--- |
| **`LIVE`** / `RESPONDS` | Hosts / Subdomains | **Host is actively responding** | Domein sent an HTTP `GET` request and the host answered (e.g., 200, 301, 403, 404). The web server is online and reachable. |
| **`CT`** / `CT LOG` | Hosts / Subdomains | **Certificate Transparency record** | Subdomain was found in public SSL/TLS certificate logs (via `crt.sh` or `ctlogs.dev`), but did not answer an active HTTP GET probe (may be internal, VPN-only, or defunct). |
| **`SPEC`** | Routes / Endpoints | **OpenAPI / Swagger specification** | Route or file reference pointing to an API definition or documentation schema (e.g., `/api/v1/swagger.json`, `/v2/api-docs`). |
| **`MAP`** | Sources | **JavaScript Source Map** | A `.map` file found linked in a script bundle. Contains original developer source code or source file hierarchies. |
| **`SOURCE`** | Sources | **JavaScript / Asset File** | An inspected client-side script or bundle loaded by the application. |
| **`INDICATOR`** | Data / Findings | **Sensitive data candidate** | A string matching sensitive patterns: JWT, API key, AWS credential, phone number, email, or IPv4 address. |
| **`IN-SCOPE`** | Global | **Target domain boundary** | Only hosts and URLs that end with the configured root domain (e.g., `*.example.com`). Out-of-scope third-party requests are blocked. |
| **`ARCHIVE`** | Response Store | **Stored raw HTTP response** | The verbatim HTTP response (status, headers, body) captured and stored in extension IndexedDB. |

---

## Scope and limits

- Discovery is rooted in the exact registrable domain supplied by you. Results for unrelated domains are ignored.
- CT lookup is passive. Requests are GET-only and stay within the selected root domain. Each responding page is checked for routes and linked scripts; same-scope static hosts found in page or source content are queued too, up to 120 hosts total. Per host, Domein follows up to 40 same-scope script/source files (including relative and dynamic imports) and parses up to 5 source maps, with a maximum import depth of 3 and per-file/total byte limits. Source-map `sourcesContent` is searched locally; external mapped sources are fetched only when their URL remains in scope. There is no wordlist guessing, port scanning, authentication bypass, form submission, or arbitrary endpoint execution.
- Endpoint results are static references found in page and script text; this does not claim the routes are live.
- ID-like values and secret-shaped strings can be false positives. Treat findings as sensitive. When cloud sync is configured, findings are securely transmitted over HTTPS to your authenticated AWS backend.
- Phone findings currently use Rwanda’s numbering ranges for mobile and fixed lines, with exact length and prefix checks to avoid matching arbitrary digit strings as phones.
- API availability and response shapes at public CT services can change. The UI reports source errors instead of treating them as empty results.
- Source maps can be absent, truncated by configured size limits, or omit embedded original code. The scan reports the source/map counts and indicates when a cap was reached.

---

## Cloud Sync & AWS Free Tier Capacity

Domein can automatically synchronize captured scan reports and archived HTTP responses to an authenticated AWS backend (**API Gateway HTTP API → AWS Lambda → Amazon DynamoDB**).

### AWS Free Tier Allocations
- **Amazon DynamoDB**: **25 GB** disk storage completely free (Always Free).
- **AWS Lambda**: **1,000,000** free invocations per month (Always Free).
- **API Gateway (HTTP API)**: **1,000,000** calls/month free in the 12-month tier (~$1.00 per million thereafter).

### Storage Consumption Approximations
1. **Domain Scan Reports (Deduplicated)**:
   - Each unique domain's complete findings report (`subdomains`, `endpoints`, `indicators`, `swagger`) averages **~10 KB to 30 KB** in JSON.
   - Built-in deduplication updates existing records in DynamoDB by domain key (`id: root`), preventing redundant rows when re-scanning sites.
   - **10,000 unique domains** consume only **~0.25 GB** (~1% of your free 25 GB).
2. **Archived HTTP Responses**:
   - Each archived response payload (URL, headers, status, and bounded body text) averages **~15 KB to 25 KB**.
   - Body sizes are automatically bounded (< 150 KB) to strictly respect DynamoDB's 400 KB item ceiling.
   - A buffer of **~4,000 archived responses** occupies approximately **~75 MB to 85 MB** (only **~0.3%** of the 25 GB free tier).

### Capacity & Runway Projections

| Research Activity Level | Typical Rate | Data Added / Month | Estimated Time to Fill 25 GB |
| :--- | :--- | :--- | :--- |
| **Light** | 5–10 domains/day (~2,000 responses/mo) | ~45 MB / month | **~45 Years** |
| **Normal / Daily Research** | 20–40 domains/day (~10,000 responses/mo) | ~220 MB / month | **~9.5 Years** |
| **Heavy / Automated Crawling** | 100+ domains/day (~60,000 responses/mo) | ~1.4 GB / month | **~1.5 Years** |

> [!TIP]
> **Maintaining Zero Cost Indefinitely:** Enable **DynamoDB TTL (Time-To-Live)** on the `DomeinScans` table for records of type `archived-response`. DynamoDB will automatically purge raw HTTP responses older than 60–90 days for free, keeping domain reports permanently while ensuring your 25 GB storage never runs out.

---

This project is an independent implementation and does not copy FindSomething source code.

Interface icons use the locally bundled Lucide SVG sprite in `icons/ui/`; its ISC license is included alongside the assets. The extension badge and panel logo use the supplied `icons/logo.png` navy-and-green branding.

