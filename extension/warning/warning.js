const params = new URLSearchParams(window.location.search);
const resultId = params.get("id");

const $ = (id) => document.getElementById(id);

function getLevelColor(level) {
  const map = {
    LOW: "#22c55e",
    MEDIUM: "#facc15",
    HIGH: "#fb923c",
    CRITICAL: "#f43f5e",
  };
  return map[level] || "#9ca3af";
}

function render(data) {
  const level = String(data.risk_level || "LOW").toUpperCase();
  const score = Number.isFinite(Number(data.risk_score)) ? Number(data.risk_score) : 0;
  const findings = Array.isArray(data.findings) ? data.findings : [];

  $("analyzedUrl").textContent = data.url || data.normalized_url || "Unknown";
  $("bigScore").textContent = String(score);
  $("bigLevel").textContent = level;
  $("bigLevel").style.color = getLevelColor(level);
  $("messageText").textContent = data.message || "";

  const alertBox = $("alertBox");
  alertBox.classList.add(level.toLowerCase());
  $("levelTitle").textContent = `Risk Level: ${level}`;

  const brand = data.impersonated_brand || "";
  if (brand) {
    $("brandName").textContent = brand;
    $("brandBox").style.display = "block";
  }

  const list = $("findingsList");
  list.replaceChildren();

  if (findings.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No suspicious signals were detected for this URL.";
    list.appendChild(li);
  } else {
    findings.forEach((finding) => {
      const li = document.createElement("li");
      li.textContent = finding.message || JSON.stringify(finding);
      list.appendChild(li);
    });
  }
}

async function loadResult() {
  if (!resultId) {
    $("messageText").textContent = "No analysis result was provided.";
    return;
  }

  try {
    const stored = await chrome.storage.local.get(resultId);
    const data = stored[resultId];
    if (!data) {
      $("messageText").textContent = "This analysis result has expired.";
      return;
    }
    render(data);
    await chrome.storage.local.remove(resultId);
  } catch {
    $("messageText").textContent = "Unable to load the analysis result.";
  }
}

$("closeBtn").addEventListener("click", (event) => {
  event.preventDefault();
  window.close();
});

loadResult();
