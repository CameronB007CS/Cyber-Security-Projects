// Grab the current active tab and read its URL
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0].url;

  // Display the URL in the popup so the user knows whats being scanned
  document.getElementById('url-display').textContent = url;

  // Placeholder status for now - Phase 2 will replace this with real detection
  document.getElementById('status').textContent = '✅ SAFE (placeholder)';
});
