# CyberCheck Bug-Fix Audit

This build was reviewed from the uploaded project archive.

## Fixed

- Added the missing extension icon assets referenced by `manifest.json`.
- Removed unused Next.js/Drizzle/PostgreSQL scaffold that conflicted with the plain HTML/CSS/JS + Flask + SQLite architecture.
- Made SQLite initialization run for both direct Flask execution and WSGI-style imports.
- Hardened URL parsing for explicit non-HTTP(S) schemes, malformed ports, IPv4/IPv6, credentials, and normalized paths.
- Corrected non-standard port detection so only actual non-standard ports are flagged.
- Added a credential-in-URL security finding.
- Prevented raw backend strings from being inserted into popup/QR result HTML.
- Reworked warning-result transport to use `chrome.storage.local` instead of putting JSON findings into the warning page URL.
- Made context menus recreate cleanly on install/startup.
- Added response-status handling for extension API calls.
- Added QR image scanning using the browser `BarcodeDetector` API when available, with URL-paste fallback.
- Added clipboard auto-check attempt when the popup opens plus a reliable user-triggered fallback. Manifest V3 does not expose a general background clipboard-change event.
- Added backend/demo dependencies and a README with Windows and Unix run instructions.
- Added analyzer smoke tests and JavaScript syntax checks.
- Removed stale generated Python cache files.

## Verification performed

- Python backend modules compile successfully.
- Analyzer smoke tests pass.
- SQLite schema initialization and insertion were tested.
- All extension JavaScript files pass Node syntax checking.
- All manifest-referenced extension files exist.
- The full Flask HTTP server could not be executed in this environment because Flask is not installed in the execution environment; the included `requirements.txt` installs it locally.

## Important runtime note

The backend is intentionally local and static: it parses URL strings and never visits submitted websites.
