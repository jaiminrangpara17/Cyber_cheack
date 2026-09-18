# MILESTONE 1: CyberCheck Technical Architecture

## What We Are Building
CyberCheck is a browser extension + Python backend that helps ordinary users evaluate suspicious links before trusting them. It has 5 core features:
1. Impersonation Detector
2. Smart Warning Levels
3. Right-click "Check Link"
4. Copy Link → Auto Check
5. QR Code → Safety Check

## Why It Is Needed
Phishing and impersonation attacks rely on user trust. Most users don't inspect URLs closely. CyberCheck provides explainable, visual security signals without requiring technical expertise.

---

## 1. Chrome Extension Manifest V3 Architecture

We use Manifest V3 (current Chrome standard):
- `manifest_version: 3`
- Service workers (not persistent background pages) for event handling
- `host_permissions` and `permissions` declared explicitly
- Popup, content scripts, and service worker communicate via `chrome.runtime.sendMessage`

Key permission rationale:
- `contextMenus`: For "Check link with CyberCheck" right-click
- `clipboardRead`: To detect copied URLs (only when user triggers action)
- `notifications`: For copy-link results
- `tabs` + `scripting`: To read current page URL for popup
- `storage`: To cache recent results
- `activeTab` / `host_permissions`: Only when needed for analysis

---

## 2. Popup Responsibilities
File: `extension/popup/popup.html` + CSS + JS
- Shows current page analysis
- Displays risk score, level (LOW/MEDIUM/HIGH/CRITICAL), findings
- Has a "Scan Current Page" button
- Clean, dark cybersecurity theme
- Communicates with service worker to fetch analysis from Flask API

---

## 3. Content Script Responsibilities
File: `extension/content/content.js`
- Injects a minimal, non-intrusive overlay when a user triggers analysis
- Can read selected text / link href from the page
- Does NOT collect unrelated page data
- Sends link data to service worker via message passing
- Styles isolated via `content.css`

---

## 4. Background Service Worker Responsibilities
File: `extension/background/service-worker.js`
- Handles `chrome.runtime.onInstalled` to register context menu
- Handles `chrome.contextMenus.onClicked` for right-click analysis
- Handles clipboard detection logic
- Manages fetch calls to Flask backend (`http://localhost:5000/api/scan`)
- Manages notifications for copy-link analysis
- Keeps no persistent state (Manifest V3: service workers sleep)
- Uses `chrome.storage.local` to persist last analysis temporarily

---

## 5. Communication: Extension ↔ Flask
- Extension uses `fetch()` to `http://localhost:5000/api/scan`
- Service worker sends JSON: `{ url: "...", source: "popup|context|clipboard|qr" }`
- Flask validates URL, runs analysis, returns JSON
- No API keys needed (local only)
- If Flask is down, extension shows graceful error

---

## 6. Right-Click Link Analysis Flow
1. User right-clicks a link
2. `service-worker.js` listens to `chrome.contextMenus.onClicked`
3. Service worker gets `linkUrl` from event info
4. Sends `POST /api/scan` with the URL
5. Flask analyzes, returns result
6. Service worker opens `warning.html` or sends notification
7. User sees risk score + impersonation info

---

## 7. Copied URL Analysis Flow
1. User copies a URL (or selects + copies link text)
2. The popup attempts to read the clipboard when it opens; Chrome does not provide a general background clipboard-changed event to Manifest V3 extensions, so an explicit "Check Clipboard" button is provided as the reliable fallback
3. If clipboard contains `http://` or `https://`, service worker sends it to `/api/scan`
4. Flask analyzes it
5. Service worker shows a `chrome.notifications` message with result
6. Only processes URL-like content; ignores unrelated clipboard text
7. No persistent clipboard logging

---

## 8. QR Code Analysis Flow
1. The popup can scan a QR-code image with the browser BarcodeDetector API when available, or the user can paste the decoded URL
2. More practically: user scans a QR, gets a URL, then uses popup or right-click to analyze
3. For compatibility, the popup also supports manual QR destination URL input
4. Flow: URL → `/api/scan` → result shows QR-specific label ("QR Code Analysis")
5. Backend treats it the same as any URL but tags `source: "qr"`

---

## 9. Impersonation Detection
File: `backend/analyzer/impersonation.py`
- Compares extracted domain against a small, hardcoded set of high-value brands (PayPal, Amazon, Google, Microsoft, Apple, etc.)
- Detects:
  - Character substitutions (`paypa1` vs `paypal`)
  - Lookalike domains (`amazon-security.com` vs `amazon.com`)
  - Brand keywords in unrelated domains (`paypal-login.xyz`)
  - Suspicious subdomains (`amazon.com.evil-site.com`)
- Reports as potential, not confirmed: "Possible impersonation of PayPal"
- Calculates similarity score (Levenshtein or basic diff)
- Only reports when similarity exceeds threshold AND domain does not exactly match brand domain

---

## 10. Smart Warning Levels
File: `backend/analyzer/risk_engine.py`
Thresholds:
- 0–20 → 🟢 LOW: "Looks okay. No major suspicious signals."
- 21–50 → 🟡 MEDIUM: "Something looks unusual."
- 51–80 → 🟠 HIGH: "Multiple suspicious signals. Check before continuing."
- 81–100 → 🔴 CRITICAL: "Strong suspicious indicators. Avoid entering sensitive info."

Score is derived from findings, not arbitrary:
- Each finding has a weight
- Total = sum(weights) / max_expected * 100
- Findings include: suspicious domain, impersonation, suspicious keywords, IP instead of domain, excessive subdomains, etc.

---

## 11. Required Chrome Permissions & Why
| Permission | Why Needed |
|------------|-----------|
| `contextMenus` | Right-click "Check link" |
| `clipboardRead` | Detect copied URLs (only on trigger) |
| `notifications` | Show scan results without opening popup |
| `tabs` | Read current tab URL for popup |
| `scripting` | Optional: inject content script |
| `storage` | Cache recent scan results temporarily |
| `host_permissions: ["<all_urls>"]` | Only if needed for scanning arbitrary links; we prefer `activeTab` + user action |

Privacy: We request only what is needed. We do not request `webRequest` blocking (not a blocker extension) or `browsingData`.

---

## 12. SQLite Database Design
File: `backend/database/models.py`
Table: `scans`
```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    normalized_url TEXT,
    domain TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    findings_json TEXT,
    impersonated_brand TEXT,
    source TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```
- Only stores analysis results, not user identity
- `findings_json` stores structured findings as JSON string
- Parameterized queries only (`?` placeholders)

---

## 13. REST API Design
File: `backend/app.py`

`POST /api/scan`
- Body: `{ url: string, source?: string }`
- Validates URL format (no execution, no visit)
- Returns: `{ url, normalized_url, domain, risk_score, risk_level, findings, impersonated_brand?, timestamp, source }`

`GET /api/history`
- Query params: `?limit=20`
- Returns array of recent scans
- No authentication required for demo (local only)

`GET /api/health`
- Returns `{ status: "ok", version: "1.0.0" }`

Validation:
- Reject URLs without scheme if ambiguous
- Reject non-HTTP(S) schemes
- Reject empty strings
- Sanitize URL output (escape for display)

---

## 14. Data Flow for Each Feature

**Popup:**
User → Popup HTML → JS reads tab URL → `fetch /api/scan` → Flask → Analyzer → SQLite (optional) → JSON → Popup renders result

**Right-Click:**
User → Context menu click → Service worker → `fetch /api/scan` → JSON → Service worker opens `warning.html` with result data

**Copy Link:**
Clipboard event / User trigger → Service worker detects URL-like text → `fetch /api/scan` → JSON → `chrome.notifications.create()` with result

**QR:**
User provides/scans URL → Popup input or manual paste → `fetch /api/scan` with `source: "qr"` → JSON → Display with "QR Analysis" label

**Impersonation:**
Flask receives URL → `url_parser.py` extracts domain → `impersonation.py` compares to brand list → `risk_engine.py` adds finding → Score updated → Response includes brand if match

---

## 15. Security & Privacy Risks
- **No URL execution:** Flask only parses URL strings; never calls `requests.get()` to visit them
- **No file downloads:** Not implemented
- **No user identity tracking:** SQLite has no `user_id` column
- **XSS prevention:** All URL outputs are escaped; HTML is generated safely (no `innerHTML` with raw URLs); content script uses `textContent`
- **Clipboard privacy:** Only checks clipboard when user explicitly triggers analysis; does not continuously monitor clipboard
- **Local only:** No external APIs; no data leaves localhost
- **Parameter SQL:** All database queries use parameterized statements
- **Malformed URLs:** `urllib.parse` handles safely; exceptions caught

---

## 16. Local Development Workflow
1. Clone repo
2. `python -m venv venv`
3. `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
4. `pip install -r requirements.txt`
5. `python backend/app.py` (Flask runs on `localhost:5000`)
6. Load `extension/` as unpacked extension in Chrome (`chrome://extensions/`)
7. Visit `http://localhost:5000/api/health` to verify backend
8. Open popup on any page to test

---

## 17. Recommended Milestone Order
**Milestone 1:** Architecture (this doc) — DONE after approval
**Milestone 2:** Backend Flask + SQLite + basic `/api/scan`
**Milestone 3:** Extension manifest + popup + health check
**Milestone 4:** Right-click context menu + service worker
**Milestone 5:** Clipboard detection + notification
**Milestone 6:** Impersonation detection + heuristics engine
**Milestone 7:** QR analysis mode + UI polish
**Milestone 8:** Integration testing + demo script
**Milestone 9:** README + student documentation

---

## Key Architectural Decisions
- **No React:** Plain HTML/CSS/JS for faster hackathon iteration and easier student understanding
- **No external APIs:** Everything runs locally; privacy preserved; no API key leaks
- **Explainable heuristics:** Every risk score is backed by findings; no black-box AI
- **Manifest V3:** Modern Chrome standard; service worker is lightweight
- **Incremental:** Each milestone produces a testable, working piece

---

## Common Questions
**Q: Why not use a web app instead of extension?**
A: The core value is checking whatever link the user is looking at *without leaving the page*. Extension provides context-menu, clipboard, and popup integration.

**Q: Why SQLite and not PostgreSQL?**
A: SQLite is file-based, zero-config, and sufficient for a demo backend. It aligns with hackathon simplicity.

**Q: Do we visit the analyzed websites?**
A: No. The analysis is static (URL parsing + heuristics). Visiting suspicious sites would be unsafe.

**Q: What if Flask is not running?**
A: Extension shows a graceful error in the popup: "CyberCheck service unavailable. Start backend to continue."

---

## Before Moving Forward
Verify you understand:
- [ ] Manifest V3 (service worker, not background page)
- [ ] Why each permission is needed
- [ ] Data flow: Popup ↔ Service Worker ↔ Flask ↔ SQLite
- [ ] Right-click = context menu event
- [ ] Copy-link = clipboard detection (user-triggered)
- [ ] QR = URL input tagged as `source: qr`
- [ ] Risk score = sum of weighted findings
- [ ] Impersonation = brand similarity check

---

# NEXT STEP: Wait for your approval to begin Milestone 2 (Backend Implementation)

Once approved, I will:
1. Create `backend/app.py`
2. Create `backend/analyzer/url_parser.py`, `heuristics.py`, `impersonation.py`, `risk_engine.py`
3. Create `backend/database/db.py` and `models.py`
4. Set up SQLite and basic endpoints
5. Run and verify `GET /api/health`
6. Provide exact commands, expected output, and debugging steps
