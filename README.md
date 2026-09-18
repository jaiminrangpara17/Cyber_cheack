# CyberCheck

CyberCheck is a Manifest V3 Chrome extension with a local Flask + SQLite backend for explainable URL safety analysis.

## Features

1. Impersonation Detector
2. Smart Warning Levels
3. Right-click "Check Link"
4. Copy Link → Automatically Check (popup-open attempt + explicit fallback)
5. QR Code → Website Safety Check (QR image scan when `BarcodeDetector` is available, plus URL paste fallback)

## Requirements

- Google Chrome
- Python 3.10+
- pip

## 1. Install backend

### Windows

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python backend\app.py
```

If PowerShell blocks activation, you can run:

```cmd
venv\Scripts\activate.bat
```

Then:

```cmd
python backend\app.py
```

The backend listens on:

`http://127.0.0.1:5000`

Verify it in a browser:

`http://127.0.0.1:5000/api/health`

Expected:

```json
{
  "service": "CyberCheck Backend",
  "status": "ok",
  "version": "1.0.0"
}
```

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python backend/app.py
```

## 2. Load the extension

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Pin CyberCheck to the toolbar

If you previously loaded an older CyberCheck build, use **Reload** after replacing the extension files.

## 3. Test the five features

### Popup

Open CyberCheck on an HTTP(S) page and click **Scan This Page**.

### Right-click

Right-click any link and choose:

**Check link with CyberCheck**

### Clipboard

Copy an HTTP(S) URL and open the CyberCheck popup. CyberCheck attempts to detect it automatically. If Chrome blocks clipboard access until a user gesture, click **Check Clipboard**.

Chrome does not expose a general background "clipboard changed" event to Manifest V3 extensions, so CyberCheck intentionally does not continuously monitor the clipboard.

### QR

Open the popup and either:
- choose a QR-code image using **Scan QR image**, or
- paste the QR destination URL and click **Check URL**.

The image scanner uses the browser's native `BarcodeDetector` API when available. If it is unavailable, use the URL-paste fallback.

### History

Open:

`http://127.0.0.1:5000/api/history`

## 4. Demo script

With the backend running:

```bash
python demo/test_all_features.py
```

The demo checks health, all five feature flows at the API level, and scan history.

## Architecture

```text
USER
  ↓
CHROME BROWSER
  ↓
CYBERCHECK EXTENSION
  ├── Popup
  ├── Content Script
  └── Service Worker
  ↓
FLASK REST API
  ↓
URL ANALYZER
  ├── Heuristics
  ├── Impersonation
  └── QR destination
  ↓
RISK ENGINE
  ↓
SQLITE
```

CyberCheck performs static URL analysis. The backend does not visit submitted URLs or download content from them.

## Important security note

Heuristic results are signals, not proof of malicious intent. A high score means the URL has suspicious characteristics that deserve attention; it does not prove that a site is malicious.
