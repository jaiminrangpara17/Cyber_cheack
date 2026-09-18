const API_URL = "http://127.0.0.1:5000";
const $ = (id) => document.getElementById(id);

function getRiskClass(score) {
  if (score >= 81) return "score-critical";
  if (score >= 51) return "score-high";
  if (score >= 21) return "score-medium";
  return "score-low";
}

function getLevelColor(level) {
  const map = {
    LOW: "#22c55e",
    MEDIUM: "#facc15",
    HIGH: "#fb923c",
    CRITICAL: "#f43f5e",
  };
  return map[level] || "#9ca3af";
}

function setStatus(message) {
  $("status").textContent = message;
}

async function fetchAnalysis(url, source) {
  try {
    const response = await fetch(`${API_URL}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, source }),
    });

    const data = await response.json();
    if (!response.ok) {
      return { error: data.error || `Backend returned HTTP ${response.status}.` };
    }
    return data;
  } catch {
    return { error: "CyberCheck service unavailable. Is the backend running?" };
  }
}

function renderFindings(findings) {
  const list = $("findingsList");
  list.replaceChildren();

  if (!Array.isArray(findings) || findings.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No suspicious signals detected.";
    list.appendChild(li);
    return;
  }

  findings.forEach((finding) => {
    const li = document.createElement("li");
    const dot = document.createElement("span");
    const text = document.createElement("span");

    const severity = String(finding.severity || "low").toLowerCase();
    dot.className = `dot dot-${severity}`;
    text.textContent = finding.message || "Suspicious signal detected.";

    li.append(dot, text);
    list.appendChild(li);
  });
}

function renderResult(data, target = "current") {
  const score = Number(data.risk_score);
  const safeScore = Number.isFinite(score) ? score : 0;
  const level = String(data.risk_level || "LOW").toUpperCase();

  if (target === "current") {
    const area = $("currentSite");
    area.className = `card current-site ${getRiskClass(safeScore)}`;
    $("currentUrl").textContent = data.url || data.normalized_url || "Unknown";
    $("scoreDisplay").textContent = String(safeScore);
    $("levelDisplay").textContent = level;
    $("levelDisplay").style.color = getLevelColor(level);
    $("findingsArea").style.display = "block";
    renderFindings(data.findings);
    setStatus(data.message || "Analysis complete.");
  }
}

function renderQrResult(data) {
  const result = $("qrResult");
  result.replaceChildren();
  result.style.display = "block";

  if (data.error) {
    const error = document.createElement("strong");
    error.className = "error-text";
    error.textContent = data.error;
    result.appendChild(error);
    return;
  }

  const heading = document.createElement("strong");
  heading.textContent = `Risk: ${data.risk_score}/100 — ${data.risk_level}`;

  const message = document.createElement("p");
  message.className = "qr-message";
  message.textContent = data.message || "";

  result.append(heading, message);

  if (data.impersonated_brand) {
    const brand = document.createElement("p");
    brand.className = "brand-warning";
    brand.textContent = `⚠ Possible impersonation: ${data.impersonated_brand}`;
    result.appendChild(brand);
  }

  if (Array.isArray(data.findings) && data.findings.length) {
    const list = document.createElement("ul");
    data.findings.slice(0, 4).forEach((finding) => {
      const item = document.createElement("li");
      item.textContent = finding.message || "Suspicious signal detected.";
      list.appendChild(item);
    });
    result.appendChild(list);
  }
}

async function scanCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || "";

  $("currentUrl").textContent = url || "No active tab";

  if (!/^https?:\/\//i.test(url)) {
    setStatus("Only HTTP(S) pages can be scanned.");
    return;
  }

  $("scanBtn").disabled = true;
  setStatus("Analyzing...");
  const data = await fetchAnalysis(url, "popup");
  $("scanBtn").disabled = false;

  if (data.error) {
    setStatus(data.error);
    return;
  }

  renderResult(data);
}

async function scanClipboard() {
  setStatus("Checking clipboard...");
  try {
    const text = await navigator.clipboard.readText();
    const url = text.trim();

    if (!/^https?:\/\//i.test(url)) {
      setStatus("Clipboard does not contain an HTTP(S) URL.");
      return;
    }

    const data = await fetchAnalysis(url, "clipboard");
    if (data.error) {
      setStatus(data.error);
      return;
    }

    renderResult(data);
  } catch {
    setStatus("Clipboard access was blocked. Click 'Check Clipboard' after copying a URL.");
  }
}

async function scanQrImage(file) {
  if (!file) return;

  const result = $("qrResult");
  result.style.display = "block";
  result.textContent = "Reading QR code...";

  if (!("BarcodeDetector" in window)) {
    result.textContent =
      "QR image scanning is not supported by this browser version. Paste the QR destination URL below instead.";
    return;
  }

  try {
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    const bitmap = await createImageBitmap(file);
    const codes = await detector.detect(bitmap);
    bitmap.close();

    const value = codes[0]?.rawValue?.trim();
    if (!value) {
      result.textContent = "No QR code containing a readable URL was found.";
      return;
    }

    $("qrUrl").value = value;
    const data = await fetchAnalysis(value, "qr");
    renderQrResult(data);
  } catch {
    result.textContent = "Could not read this QR image. Try a clearer image or paste its destination URL.";
  }
}

async function scanQrUrl() {
  let url = $("qrUrl").value.trim();
  if (!url) {
    $("qrResult").textContent = "Enter a URL first.";
    $("qrResult").style.display = "block";
    return;
  }

  if (!/^https?:\/\//i.test(url)) {
    url = `https://${url}`;
  }

  const data = await fetchAnalysis(url, "qr");
  renderQrResult(data);
}

async function tryAutoClipboardCheck() {
  // Chrome does not provide a background "clipboard changed" event to
  // extensions. We therefore attempt a read when the popup opens and provide
  // an explicit button as the reliable fallback.
  try {
    const text = (await navigator.clipboard.readText()).trim();
    if (/^https?:\/\//i.test(text)) {
      const data = await fetchAnalysis(text, "clipboard");
      if (!data.error) {
        renderResult(data);
        setStatus("Copied URL detected and checked.");
      }
    }
  } catch {
    // Expected when clipboard access requires a user gesture.
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  $("scanBtn").addEventListener("click", scanCurrentTab);
  $("clipboardBtn").addEventListener("click", scanClipboard);
  $("qrScanBtn").addEventListener("click", scanQrUrl);
  $("qrImage").addEventListener("change", (event) => scanQrImage(event.target.files?.[0]));

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    $("currentUrl").textContent = tab?.url || "No active tab";
  } catch {
    $("currentUrl").textContent = "Unable to read active tab.";
  }

  await tryAutoClipboardCheck();
});
