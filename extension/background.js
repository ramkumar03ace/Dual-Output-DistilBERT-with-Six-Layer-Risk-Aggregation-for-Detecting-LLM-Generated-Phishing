/* ============================================
   Hybrid AI Defence — Background Service Worker
   ============================================ */

// Extension install/update handler
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[Hybrid AI Defence] Extension installed successfully.');
  } else if (details.reason === 'update') {
    console.log(`[Hybrid AI Defence] Extension updated to v${chrome.runtime.getManifest().version}`);
  }
});
