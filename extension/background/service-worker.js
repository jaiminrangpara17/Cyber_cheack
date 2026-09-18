const API_URL = "http://127.0.0.1:5000";

function registerContextMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "checkLink",
      title: "Check link with CyberCheck",
      contexts: ["link"],
    });
    chrome.contextMenus.create({
      id: "checkSelection",
      title: "Check selected text with CyberCheck",
      contexts: ["selection"],
    });
    chrome.contextMenus.create({
      id: "checkPage",
      title: "Check current page with CyberCheck",
      contexts: ["page"],
    });
  });
}

chrome.runtime.onInstalled.addListener(registerContextMenus);
chrome.runtime.onStartup.addListener(registerContextMenus);

async function analyzeUrl(url, source = "context") {
  if (!url || !/^https?:\/\//i.test(url)) {
    return { error: "Only HTTP(S) URLs can be analyzed." };
  }

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
  } catch (error) {
    return { error: "CyberCheck service unavailable. Is the backend running?" };
  }
}

async function openWarning(data) {
  if (!data || data.error) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "CyberCheck",
      message: data?.error || "Unable to analyze the URL.",
    });
    return;
  }

  // Store the complete result instead of putting JSON into the warning page URL.
  const resultId = `result_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  await chrome.storage.local.set({ [resultId]: data });

  const warningUrl = chrome.runtime.getURL(
    `warning/warning.html?id=${encodeURIComponent(resultId)}`
  );
  await chrome.tabs.create({ url: warningUrl });

  // Keep local storage small.
  const keys = await chrome.storage.local.get(null);
  const resultKeys = Object.keys(keys).filter((key) => key.startsWith("result_"));
  if (resultKeys.length > 10) {
    resultKeys
      .sort()
      .slice(0, resultKeys.length - 10)
      .forEach((key) => chrome.storage.local.remove(key));
  }
}

chrome.contextMenus.onClicked.addListener(async (info) => {
  let url = "";

  if (info.menuItemId === "checkLink") {
    url = info.linkUrl || "";
  } else if (info.menuItemId === "checkSelection") {
    const text = (info.selectionText || "").trim();
    if (/^https?:\/\//i.test(text)) {
      url = text;
    } else if (/^[^\s/]+\.[^\s/]+/.test(text)) {
      url = `https://${text}`;
    }
  } else if (info.menuItemId === "checkPage") {
    // Page URL is read from the context-menu event's tab.
    url = info.pageUrl || "";
  }

  if (!url) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "CyberCheck",
      message: "No HTTP(S) URL was found to analyze.",
    });
    return;
  }

  const result = await analyzeUrl(url, "context");
  await openWarning(result);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "analyzeUrl") return;

  analyzeUrl(message.url, message.source || "content")
    .then(sendResponse)
    .catch(() => sendResponse({ error: "Analysis failed." }));

  return true;
});
