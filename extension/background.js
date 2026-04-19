/* ============================================
   Dual-Output-DistilBERT-with-Six-Layer-Risk-Aggregation-for-Detecting-LLM-Generated-Phishing — Background Service Worker
   ============================================ */

// Extension install/update handler
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[Dual-Output-DistilBERT-with-Six-Layer-Risk-Aggregation-for-Detecting-LLM-Generated-Phishing] Extension installed successfully.');
  } else if (details.reason === 'update') {
    console.log(`[Dual-Output-DistilBERT-with-Six-Layer-Risk-Aggregation-for-Detecting-LLM-Generated-Phishing] Extension updated to v${chrome.runtime.getManifest().version}`);
  }
});
