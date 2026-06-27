// Content script - injected into every page the user visits
// Has access to the page DOM (links, forms, inputs etc)
// Phase 2: will extract page features and pass them to background.js for analysis
console.log('PhishGuard content script loaded on:', window.location.href);
