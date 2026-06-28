// ---- HEURISTIC ENGINE ----
// Each rule checks for a known phishing pattern and adds to a risk score
// The higher the score, the more likely the URL is malicious

function analyseURL(url) {
  let score = 0;
  let flags = [];

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    const fullURL = url.toLowerCase();

    // Rule 1: HTTP instead of HTTPS
    // Legitimate sites almost always use HTTPS
    if (parsed.protocol === 'http:') {
      score += 20;
      flags.push('⚠ No HTTPS');
    }

    // Rule 2: IP address used instead of domain name
    // Phishers use raw IPs to avoid registering a domain
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
      score += 30;
      flags.push('⚠ IP address used as domain');
    }

    // Rule 3: Excessive subdomains
    // e.g. login.paypal.secure.verify.evil.com
    const subdomains = hostname.split('.').length - 2;
    if (subdomains > 2) {
      score += 20;
      flags.push('⚠ Excessive subdomains');
    }

    // Rule 4: Suspicious keywords in URL
    // Common in phishing URLs trying to appear legitimate
    const suspiciousWords = [
      'login', 'verify', 'secure', 'account', 'update',
      'bank', 'confirm', 'password', 'signin', 'ebayisapi',
      'webscr', 'paypal', 'support'
    ];
    suspiciousWords.forEach(word => {
      if (fullURL.includes(word)) {
        score += 10;
        flags.push(`⚠ Suspicious keyword: "${word}"`);
      }
    });

    // Rule 5: Unusually long domain name
    // Legit domains are short, phishing domains pad them out
    if (hostname.length > 30) {
      score += 15;
      flags.push('⚠ Unusually long domain');
    }

    // Rule 6: @ symbol in URL
    // Browsers ignore everything before @ — classic phishing trick
    // e.g. https://google.com@evil.com actually goes to evil.com
    if (url.includes('@')) {
      score += 25;
      flags.push('⚠ @ symbol detected in URL');
    }

    // Rule 7: Too many special characters
    // Hyphens and dots used to mimic legitimate domains
    const specialChars = (hostname.match(/[-_.]/g) || []).length;
    if (specialChars > 3) {
      score += 15;
      flags.push('⚠ Excessive special characters');
    }

    // Rule 8: Lookalike characters
    // e.g. paypa1.com, rn mimicking m, 0 instead of o
    const lookalikes = /[0-9](?=.*[a-z])|rn|vv/;
    if (lookalikes.test(hostname)) {
      score += 20;
      flags.push('⚠ Possible lookalike characters');
    }

  } catch (e) {
    // If URL can't be parsed at all, that's suspicious
    score += 50;
    flags.push('⚠ URL could not be parsed');
  }

  return { score, flags };
}

// ---- POPUP LOGIC ----
// Runs when the user clicks the extension icon
// Grabs the current tab URL, runs it through the engine, displays the result

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0].url;
  document.getElementById('url-display').textContent = url;

  const { score, flags } = analyseURL(url);

  const statusEl = document.getElementById('status');

  // Score thresholds:
  // 0-20  = Safe
  // 21-49 = Suspicious
  // 50+   = Likely phishing
  if (score >= 50) {
    statusEl.textContent = '🚨 PHISHING DETECTED';
    statusEl.style.color = '#ff4444';
    statusEl.style.borderColor = '#ff4444';
  } else if (score >= 21) {
    statusEl.textContent = '⚠ SUSPICIOUS';
    statusEl.style.color = '#ffaa00';
    statusEl.style.borderColor = '#ffaa00';
  } else {
    statusEl.textContent = '✅ LOOKS SAFE';
    statusEl.style.color = '#00ff99';
    statusEl.style.borderColor = '#00ff99';
  }

  // Display risk score
  const scoreEl = document.createElement('div');
  scoreEl.style.cssText = 'text-align:center; margin-top:8px; font-size:12px; color:#888;';
  scoreEl.textContent = `Risk Score: ${score}/100`;
  document.body.appendChild(scoreEl);

  // Display individual flags if any
  if (flags.length > 0) {
    const flagsEl = document.createElement('div');
    flagsEl.style.cssText = 'margin-top:10px; font-size:11px; color:#ffaa00;';
    flagsEl.innerHTML = flags.join('<br>');
    document.body.appendChild(flagsEl);
  }
});
