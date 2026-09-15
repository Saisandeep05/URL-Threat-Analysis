/**
 * SentinelXAI - Explainable URL Threat Intelligence Dashboard
 * Handles URL analysis, localStorage history ("Keep the link"), and dynamic UI updates.
 */

// State Management
const STATE = {
  currentResult: null,
  history: [],
  isScanning: false
};

const STORAGE_KEY = 'sentinel_scan_ledger_v1';

// DOM Elements
const elements = {
  // Navigation & Status
  statusDot: document.querySelector('.status-dot'),
  statusText: document.getElementById('statusText'),
  toggleHistoryBtn: document.getElementById('toggleHistoryBtn'),
  historyCount: document.getElementById('historyCount'),
  historySidebar: document.getElementById('historySidebar'),
  mainLayout: document.querySelector('.main-layout'),

  // Search & Input
  analyzeForm: document.getElementById('analyzeForm'),
  urlInput: document.getElementById('urlInput'),
  clearInputBtn: document.getElementById('clearInputBtn'),
  analyzeBtn: document.getElementById('analyzeBtn'),
  btnText: document.querySelector('.btn-text'),
  btnLoader: document.querySelector('.btn-loader'),
  quickTags: document.querySelectorAll('.quick-tag'),

  // Progress & Alert States
  analysisProgress: document.getElementById('analysisProgress'),
  progressFill: document.getElementById('progressFill'),
  progressStepText: document.getElementById('progressStepText'),
  progressPct: document.getElementById('progressPct'),
  emptyState: document.getElementById('emptyState'),
  errorAlert: document.getElementById('errorAlert'),
  errorTitle: document.getElementById('errorTitle'),
  errorMessage: document.getElementById('errorMessage'),
  closeErrorBtn: document.getElementById('closeErrorBtn'),

  // Results Dashboard
  resultsDashboard: document.getElementById('resultsDashboard'),
  verdictCard: document.getElementById('verdictCard'),
  verdictBadge: document.getElementById('verdictBadge'),
  scanTimestamp: document.getElementById('scanTimestamp'),
  displayUrl: document.getElementById('displayUrl'),
  xaiSummary: document.getElementById('xaiSummary'),
  gaugeMeter: document.getElementById('gaugeMeter'),
  gaugeNumber: document.getElementById('gaugeNumber'),

  // Action Buttons
  saveLinkBtn: document.getElementById('saveLinkBtn'),
  copyJsonBtn: document.getElementById('copyJsonBtn'),
  rescanBtn: document.getElementById('rescanBtn'),

  // Metrics
  statMalicious: document.getElementById('statMalicious'),
  statSuspicious: document.getElementById('statSuspicious'),
  statHarmless: document.getElementById('statHarmless'),
  statUndetected: document.getElementById('statUndetected'),
  statTotal: document.getElementById('statTotal'),

  // Evidence & Details
  reasonsList: document.getElementById('reasonsList'),
  positiveSignalsList: document.getElementById('positiveSignalsList'),
  flaggedEnginesSection: document.getElementById('flaggedEnginesSection'),
  flaggedEnginesList: document.getElementById('flaggedEnginesList'),
  anatomyGrid: document.getElementById('anatomyGrid'),

  // History Ledger
  historyList: document.getElementById('historyList'),
  historySearchInput: document.getElementById('historySearchInput'),
  clearAllHistoryBtn: document.getElementById('clearAllHistoryBtn')
};

// ==========================================================================
// Initialization
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  loadHistory();
  checkApiHealth();
  attachEventListeners();

  // If there is history, auto-select the latest scanned link to show results immediately!
  if (STATE.history.length > 0) {
    displayResult(STATE.history[0]);
  }
});

// ==========================================================================
// Event Handlers
// ==========================================================================

function attachEventListeners() {
  // Form submission
  elements.analyzeForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const url = elements.urlInput.value.trim();
    if (url) {
      runAnalysis(url);
    }
  });

  // Input typing and clear button
  elements.urlInput.addEventListener('input', () => {
    elements.clearInputBtn.style.display = elements.urlInput.value ? 'block' : 'none';
  });

  elements.clearInputBtn.addEventListener('click', () => {
    elements.urlInput.value = '';
    elements.clearInputBtn.style.display = 'none';
    elements.urlInput.focus();
  });

  // Sample buttons
  elements.quickTags.forEach(tag => {
    tag.addEventListener('click', () => {
      const sampleUrl = tag.getAttribute('data-url');
      elements.urlInput.value = sampleUrl;
      elements.clearInputBtn.style.display = 'block';
      runAnalysis(sampleUrl);
    });
  });

  // Close error alert
  elements.closeErrorBtn.addEventListener('click', hideError);

  // Toggle History Sidebar
  elements.toggleHistoryBtn.addEventListener('click', () => {
    elements.historySidebar.classList.toggle('collapsed');
    elements.mainLayout.classList.toggle('history-hidden');
  });

  // Filter History Search
  elements.historySearchInput.addEventListener('input', (e) => {
    renderHistoryList(e.target.value.trim().toLowerCase());
  });

  // Clear All History
  elements.clearAllHistoryBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all saved links?')) {
      STATE.history = [];
      saveHistory();
      renderHistoryList();
    }
  });

  // Copy Scanned URL
  elements.displayUrl.addEventListener('click', () => {
    if (STATE.currentResult && STATE.currentResult.url) {
      navigator.clipboard.writeText(STATE.currentResult.url);
      flashButton(elements.displayUrl, '✓ URL Copied');
    }
  });

  // Copy Full JSON Report
  elements.copyJsonBtn.addEventListener('click', () => {
    if (STATE.currentResult) {
      navigator.clipboard.writeText(JSON.stringify(STATE.currentResult, null, 2));
      const span = elements.copyJsonBtn.querySelector('span');
      const orig = span.textContent;
      span.textContent = 'Copied JSON!';
      setTimeout(() => { span.textContent = orig; }, 1800);
    }
  });

  // Re-scan current URL
  elements.rescanBtn.addEventListener('click', () => {
    if (STATE.currentResult && STATE.currentResult.url) {
      elements.urlInput.value = STATE.currentResult.url;
      runAnalysis(STATE.currentResult.url);
    }
  });

  // Bookmark / Save current Link
  elements.saveLinkBtn.addEventListener('click', () => {
    if (STATE.currentResult) {
      saveLinkToLedger(STATE.currentResult);
      elements.saveLinkBtn.classList.add('active');
      const span = elements.saveLinkBtn.querySelector('span');
      span.textContent = 'Saved in Ledger';
    }
  });
}

// ==========================================================================
// API Communication & Scanning
// ==========================================================================

async function checkApiHealth() {
  try {
    let res = await fetch('/api/health');
    if (!res.ok) {
      res = await fetch('/health');
    }
    const data = await res.json();
    if (data.status === 'healthy') {
      elements.statusDot.className = 'status-dot online';
      elements.statusText.textContent = data.has_api_key ? 'API Connected' : 'Missing API Key';
    } else {
      throw new Error(data.message);
    }
  } catch (err) {
    elements.statusDot.className = 'status-dot offline';
    elements.statusText.textContent = 'API Offline';
  }
}

async function runAnalysis(rawUrl) {
  if (STATE.isScanning) return;
  STATE.isScanning = true;
  hideError();

  // Update UI to loading
  setLoadingState(true);
  startProgressAnimation();

  try {
    let response = await fetch('/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: rawUrl })
    });

    // If 404 or 405 from router, fallback to /analyze directly
    if (response.status === 404 || response.status === 405) {
      response = await fetch('/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: rawUrl })
      });
    }

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || 'Analysis request failed from server');
    }

    // Success: save into history ledger and render
    STATE.currentResult = data;
    saveLinkToLedger(data);
    displayResult(data);

  } catch (err) {
    console.error('Scan error:', err);
    showError('Security Analysis Failed', err.message);
  } finally {
    STATE.isScanning = false;
    setLoadingState(false);
    stopProgressAnimation();
  }
}

// ==========================================================================
// Progress Indicator Simulation
// ==========================================================================

let progressTimer = null;

function startProgressAnimation() {
  elements.analysisProgress.style.display = 'block';
  elements.progressFill.style.width = '15%';
  elements.progressPct.textContent = '15%';
  elements.progressStepText.textContent = '1/4: Parsing lexical structure & domain heuristics...';

  const steps = [
    { pct: '40%', text: '2/4: Querying VirusTotal intelligence cloud...', delay: 1200 },
    { pct: '75%', text: '3/4: Aggregating 70+ vendor consensus verdicts...', delay: 2800 },
    { pct: '92%', text: '4/4: Synthesizing Explainable AI (XAI) insights...', delay: 4500 }
  ];

  steps.forEach(step => {
    progressTimer = setTimeout(() => {
      if (STATE.isScanning) {
        elements.progressFill.style.width = step.pct;
        elements.progressPct.textContent = step.pct;
        elements.progressStepText.textContent = step.text;
      }
    }, step.delay);
  });
}

function stopProgressAnimation() {
  if (progressTimer) clearTimeout(progressTimer);
  elements.progressFill.style.width = '100%';
  elements.progressPct.textContent = '100%';
  setTimeout(() => {
    elements.analysisProgress.style.display = 'none';
  }, 300);
}

function setLoadingState(loading) {
  elements.analyzeBtn.disabled = loading;
  elements.btnText.style.display = loading ? 'none' : 'inline';
  elements.btnLoader.style.display = loading ? 'inline-block' : 'none';
}

// ==========================================================================
// Display Result & Render Dashboard
// ==========================================================================

function displayResult(result) {
  if (!result) return;
  STATE.currentResult = result;

  // Hide empty state, show results
  elements.emptyState.style.display = 'none';
  elements.resultsDashboard.style.display = 'block';

  // 1. Verdict & Header
  const classification = result.classification || 'UNKNOWN';
  elements.verdictBadge.textContent = classification;
  elements.displayUrl.textContent = result.url || 'Unknown Target';
  elements.scanTimestamp.textContent = result.analyzed_at || 'Just scanned';
  elements.xaiSummary.textContent = result.summary || 'Security analysis complete.';

  // Classification styling
  elements.verdictCard.className = 'card verdict-card';
  if (classification === 'MALICIOUS') {
    elements.verdictCard.classList.add('verdict-malicious');
  } else if (classification === 'SUSPICIOUS') {
    elements.verdictCard.classList.add('verdict-suspicious');
  } else {
    elements.verdictCard.classList.add('verdict-safe');
  }

  // 2. Risk Score Gauge
  updateRiskGauge(result.risk_score || 0);

  // 3. Consensus Metrics
  elements.statMalicious.textContent = result.malicious || 0;
  elements.statSuspicious.textContent = result.suspicious || 0;
  elements.statHarmless.textContent = result.harmless || 0;
  elements.statUndetected.textContent = result.undetected || 0;
  elements.statTotal.textContent = result.total_engines || 0;

  // 4. Explainable Reasons (Why this decision was made)
  elements.reasonsList.innerHTML = '';
  const reasons = result.reasons || [];
  if (reasons.length === 0) {
    elements.reasonsList.innerHTML = '<li>No negative risk indicators detected on this URL.</li>';
  } else {
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      elements.reasonsList.appendChild(li);
    });
  }

  // 5. Positive Safe Signals
  elements.positiveSignalsList.innerHTML = '';
  const signals = result.positive_signals || [];
  if (signals.length === 0) {
    elements.positiveSignalsList.innerHTML = '<li>No specific positive integrity signals logged.</li>';
  } else {
    signals.forEach(s => {
      const li = document.createElement('li');
      li.textContent = s;
      elements.positiveSignalsList.appendChild(li);
    });
  }

  // 6. Flagged Security Engines
  const maliciousEngines = result.malicious_engines || [];
  const suspiciousEngines = result.suspicious_engines || [];
  const allFlagged = [...maliciousEngines, ...suspiciousEngines];

  if (allFlagged.length > 0) {
    elements.flaggedEnginesSection.style.display = 'block';
    elements.flaggedEnginesList.innerHTML = '';

    maliciousEngines.forEach(eng => {
      const badge = document.createElement('span');
      badge.className = 'engine-badge';
      badge.textContent = eng;
      elements.flaggedEnginesList.appendChild(badge);
    });

    suspiciousEngines.forEach(eng => {
      const badge = document.createElement('span');
      badge.className = 'engine-badge suspicious';
      badge.textContent = eng;
      elements.flaggedEnginesList.appendChild(badge);
    });
  } else {
    elements.flaggedEnginesSection.style.display = 'none';
  }

  // 7. Structural Anatomy Inspector
  renderAnatomyGrid(result.features || {});

  // Highlight active item in sidebar
  highlightActiveHistoryItem(result.url);
}

function updateRiskGauge(score) {
  elements.gaugeNumber.textContent = `${score}%`;
  const circumference = 314; // 2 * Math.PI * 50
  const offset = circumference - (score / 100) * circumference;
  elements.gaugeMeter.style.strokeDashoffset = offset;

  if (score >= 20) {
    elements.gaugeMeter.style.stroke = '#f43f5e';
    elements.gaugeNumber.style.color = '#f43f5e';
  } else if (score > 0) {
    elements.gaugeMeter.style.stroke = '#f59e0b';
    elements.gaugeNumber.style.color = '#f59e0b';
  } else {
    elements.gaugeMeter.style.stroke = '#10b981';
    elements.gaugeNumber.style.color = '#10b981';
  }
}

function renderAnatomyGrid(feat) {
  elements.anatomyGrid.innerHTML = '';

  const items = [
    { label: 'Protocol', val: feat.https ? 'HTTPS (Secure)' : 'HTTP (Insecure)', isBad: !feat.https },
    { label: 'IP Destination', val: feat.has_ip ? 'Yes (Suspicious)' : 'No (Normal Domain)', isBad: feat.has_ip },
    { label: '@ Obfuscation', val: feat.has_at ? 'Detected' : 'None', isBad: feat.has_at },
    { label: 'Custom Port', val: feat.has_port ? 'Explicit Port Used' : 'Standard Port', isBad: feat.has_port },
    { label: 'URL Length', val: `${feat.url_length || 0} chars`, isBad: (feat.url_length || 0) > 100 },
    { label: 'Subdomains', val: `${feat.subdomains || 0} levels`, isBad: (feat.subdomains || 0) >= 3 },
    { label: 'Domain Hyphens', val: `${feat.hyphens || 0}`, isBad: (feat.hyphens || 0) >= 2 },
    { label: 'Keyword Flags', val: feat.suspicious_keywords && feat.suspicious_keywords.length ? feat.suspicious_keywords.join(', ') : 'None', isBad: feat.suspicious_keywords && feat.suspicious_keywords.length > 0 }
  ];

  items.forEach(item => {
    const div = document.createElement('div');
    div.className = 'anatomy-item';
    div.innerHTML = `
      <span class="anatomy-key">${item.label}</span>
      <span class="anatomy-val ${item.isBad ? 'val-bad' : 'val-good'}">${item.val}</span>
    `;
    elements.anatomyGrid.appendChild(div);
  });
}

// ==========================================================================
// History Ledger Management ("Keep the Link")
// ==========================================================================

function loadHistory() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      STATE.history = JSON.parse(saved);
    }
  } catch (e) {
    console.error('Failed to parse history from localStorage', e);
    STATE.history = [];
  }
  renderHistoryList();
}

function saveHistory() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(STATE.history));
  } catch (e) {
    console.error('Failed to write history to localStorage', e);
  }
  updateHistoryBadge();
}

function saveLinkToLedger(result) {
  if (!result || !result.url) return;

  // Filter out duplicate if existing to move it to the top
  STATE.history = STATE.history.filter(item => item.url.toLowerCase() !== result.url.toLowerCase());

  // Add to beginning of history
  STATE.history.unshift({
    ...result,
    saved_at: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  });

  // Limit to 40 items
  if (STATE.history.length > 40) {
    STATE.history = STATE.history.slice(0, 40);
  }

  saveHistory();
  renderHistoryList();
}

function renderHistoryList(filterQuery = '') {
  elements.historyList.innerHTML = '';
  updateHistoryBadge();

  const filtered = STATE.history.filter(item => {
    if (!filterQuery) return true;
    return item.url.toLowerCase().includes(filterQuery) ||
           (item.classification && item.classification.toLowerCase().includes(filterQuery));
  });

  if (filtered.length === 0) {
    elements.historyList.innerHTML = `
      <div class="history-empty-hint">
        ${filterQuery ? 'No matching saved links found.' : 'No saved links yet.<br>Every link you analyze will be stored here so you can revisit the results anytime.'}
      </div>
    `;
    return;
  }

  filtered.forEach(item => {
    const div = document.createElement('div');
    div.className = 'history-item';
    div.dataset.url = item.url;

    if (STATE.currentResult && STATE.currentResult.url === item.url) {
      div.classList.add('active');
    }

    const badgeClass = item.classification === 'MALICIOUS' ? 'badge-malicious' :
                       item.classification === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-safe';

    div.innerHTML = `
      <div class="history-item-top">
        <span class="history-badge-small ${badgeClass}">${item.classification || 'CLEAN'}</span>
        <span class="history-score">${item.risk_score || 0}% Risk</span>
      </div>
      <div class="history-url" title="${item.url}">${item.url}</div>
      <div class="history-footer">
        <span>${item.saved_at || item.analyzed_at || 'Saved'}</span>
        <div class="history-item-actions">
          <button class="btn-history-del" title="Remove link from ledger">✕</button>
        </div>
      </div>
    `;

    // Click to display results
    div.addEventListener('click', (e) => {
      if (e.target.classList.contains('btn-history-del')) {
        e.stopPropagation();
        removeHistoryItem(item.url);
        return;
      }
      displayResult(item);
    });

    elements.historyList.appendChild(div);
  });
}

function removeHistoryItem(url) {
  STATE.history = STATE.history.filter(i => i.url !== url);
  saveHistory();
  renderHistoryList();
}

function highlightActiveHistoryItem(url) {
  const items = document.querySelectorAll('.history-item');
  items.forEach(item => {
    if (item.dataset.url === url) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });
}

function updateHistoryBadge() {
  elements.historyCount.textContent = STATE.history.length;
}

// ==========================================================================
// Utilities
// ==========================================================================

function showError(title, msg) {
  elements.errorTitle.textContent = title;
  elements.errorMessage.textContent = msg;
  elements.errorAlert.style.display = 'flex';
}

function hideError() {
  elements.errorAlert.style.display = 'none';
}

function flashButton(btn, text) {
  const orig = btn.textContent;
  btn.textContent = text;
  setTimeout(() => { btn.textContent = orig; }, 1500);
}
