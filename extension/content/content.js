/* CyberCheck Content Script */
/* Minimal, non-intrusive overlay for analysis results */

console.log("CyberCheck content script loaded");

// Listen for messages from service worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "getLinkUrl") {
    const link = document.querySelector(`a[href="${message.href}"]`);
    sendResponse({ url: link ? link.href : null });
    return true;
  }
  if (message.type === "highlightLink") {
    // Optional: add a temporary highlight to a link being analyzed
    const links = document.querySelectorAll("a");
    links.forEach(a => {
      if (a.href === message.url) {
        a.style.outline = "2px solid #22d3ee";
        a.style.outlineOffset = "2px";
        setTimeout(() => { a.style.outline = ""; a.style.outlineOffset = ""; }, 2000);
      }
    });
    sendResponse({ ok: true });
    return true;
  }
});
