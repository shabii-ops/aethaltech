/**
 * SENTINEL AI - Main Frontend Application Logic
 */

let chartRiskInstance = null;
let chartCategoryInstance = null;
let chartSentimentInstance = null;

let currentExplorerPage = 1;
let currentInputType = 'text';

document.addEventListener('DOMContentLoaded', async () => {
  initTheme();
  initIcons();
  setupNavigation();
  setupAnalyzer();
  setupExplorer();
  setupBulkUpload();
  setupGlobalActions();

  // Load initial data
  await loadScenarios();
  await refreshDashboard();
  await refreshExplorer();
});

function initTheme() {
  const savedTheme = localStorage.getItem('aethel_theme') || 'dark';
  applyTheme(savedTheme);

  const btnToggle = document.getElementById('btnThemeToggle');
  if (btnToggle) {
    btnToggle.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const nextTheme = current === 'light' ? 'dark' : 'light';
      applyTheme(nextTheme);
    });
  }
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('aethel_theme', theme);

  const icon = document.getElementById('themeToggleIcon');
  const text = document.getElementById('themeToggleText');
  const btn = document.getElementById('btnThemeToggle');

  if (icon && text) {
    if (theme === 'light') {
      icon.setAttribute('data-lucide', 'moon');
      text.textContent = 'Dark Mode';
      if (btn) btn.setAttribute('title', 'Switch to Cyber Dark Mode');
    } else {
      icon.setAttribute('data-lucide', 'sun');
      text.textContent = 'Light Mode';
      if (btn) btn.setAttribute('title', 'Switch to Elegant White Light Theme');
    }
  }
  initIcons();
  updateChartThemes(theme);
}

function updateChartThemes(theme) {
  const textColor = theme === 'light' ? '#475569' : '#94a3b8';
  const gridColor = theme === 'light' ? 'rgba(0, 0, 0, 0.06)' : 'rgba(255, 255, 255, 0.05)';
  const barColor = theme === 'light' ? '#0284c7' : '#00f2fe';

  if (chartRiskInstance) {
    if (chartRiskInstance.options?.plugins?.legend?.labels) {
      chartRiskInstance.options.plugins.legend.labels.color = textColor;
    }
    chartRiskInstance.update();
  }

  if (chartCategoryInstance) {
    if (chartCategoryInstance.options?.scales?.x?.ticks) {
      chartCategoryInstance.options.scales.x.ticks.color = textColor;
    }
    if (chartCategoryInstance.options?.scales?.y?.ticks) {
      chartCategoryInstance.options.scales.y.ticks.color = textColor;
    }
    if (chartCategoryInstance.options?.scales?.y?.grid) {
      chartCategoryInstance.options.scales.y.grid.color = gridColor;
    }
    if (chartCategoryInstance.data?.datasets?.[0]) {
      chartCategoryInstance.data.datasets[0].backgroundColor = barColor;
    }
    chartCategoryInstance.update();
  }

  if (chartSentimentInstance) {
    if (chartSentimentInstance.options?.plugins?.legend?.labels) {
      chartSentimentInstance.options.plugins.legend.labels.color = textColor;
    }
    chartSentimentInstance.update();
  }
}

function initIcons() {
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

// =========================================================================
// NAVIGATION VIEW SWITCHING
// =========================================================================
function setupNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const viewPanels = document.querySelectorAll('.view-panel');

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const view = item.getAttribute('data-view');

      navItems.forEach(n => n.classList.remove('active'));
      item.classList.add('active');

      viewPanels.forEach(p => {
        p.classList.remove('active');
        if (p.id === `view-${view}`) {
          p.classList.add('active');
        }
      });

      if (view === 'dashboard') {
        refreshDashboard();
      } else if (view === 'explorer') {
        refreshExplorer();
      }
      initIcons();
    });
  });

  const btnViewAll = document.getElementById('btnViewAllExplorer');
  if (btnViewAll) {
    btnViewAll.addEventListener('click', () => {
      document.querySelector('[data-view="explorer"]').click();
    });
  }
}

// =========================================================================
// EXECUTIVE SCENARIO SELECTOR (STREAMLINED)
// =========================================================================
async function loadScenarios() {
  const select = document.getElementById('scenarioPresetSelect');
  const btnRun = document.getElementById('btnRunSelectedScenario');
  const chips = document.querySelectorAll('.quick-chip');
  if (!select) return;

  try {
    const scenarios = await API.getScenarios();
    select.innerHTML = '<option value="">-- Select Official Hackathon Scenario --</option>';

    scenarios.forEach(sc => {
      const opt = document.createElement('option');
      opt.value = sc.id;
      opt.textContent = `${sc.title} (${sc.category})`;
      select.appendChild(opt);
    });

    // Default to mandatory E2E scenario
    select.value = 'combined_threat';

    if (btnRun) {
      btnRun.onclick = async () => {
        const selectedId = select.value;
        if (!selectedId) {
          showToast('Please select a scenario to test', 'info');
          return;
        }
        const sc = scenarios.find(s => s.id === selectedId);
        if (sc) {
          document.getElementById('analysisInput').value = sc.input;
          document.getElementById('sourceInput').value = `Demo: ${sc.title}`;
          await executeAnalysis(sc.input, 'text', `Demo: ${sc.title}`);
        }
      };
    }

    chips.forEach(chip => {
      chip.onclick = async () => {
        chips.forEach(c => c.classList.remove('active-chip'));
        chip.classList.add('active-chip');
        const id = chip.getAttribute('data-id');
        select.value = id;
        const sc = scenarios.find(s => s.id === id);
        if (sc) {
          document.getElementById('analysisInput').value = sc.input;
          document.getElementById('sourceInput').value = `Demo: ${sc.title}`;
          await executeAnalysis(sc.input, 'text', `Demo: ${sc.title}`);
        }
      };
    });

    initIcons();
  } catch (err) {
    console.error('Failed to load scenarios:', err);
  }
}

// =========================================================================
// LIVE ANALYZER & PIPELINE
// =========================================================================
function setupAnalyzer() {
  const form = document.getElementById('analyzerForm');
  const inputEl = document.getElementById('analysisInput');
  const inputLabel = document.getElementById('inputLabel');
  const btnClear = document.getElementById('btnClearInput');
  const inputTabs = document.querySelectorAll('.input-tab');

  inputTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      inputTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentInputType = tab.getAttribute('data-type');

      if (currentInputType === 'url') {
        inputLabel.textContent = 'Enter URL to Inspect';
        inputEl.placeholder = 'e.g. http://194.26.29.112:8080/novapay/login.php or https://novapay-security-verify.com/login';
      } else if (currentInputType === 'email') {
        inputLabel.textContent = 'Enter Sender Email or Email Body';
        inputEl.placeholder = 'e.g. security-alert@novapay-fraud-center.xyz or full email header';
      } else {
        inputLabel.textContent = 'Enter Customer Message or Transcript';
        inputEl.placeholder = 'Paste customer complaint, message, or suspicious text here...';
      }
    });
  });

  btnClear.addEventListener('click', () => {
    inputEl.value = '';
    document.getElementById('outputContent').classList.add('hidden');
    document.getElementById('outputPlaceholder').classList.remove('hidden');
    resetStepper();
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = inputEl.value.trim();
    if (!text) return;
    const source = document.getElementById('sourceInput').value;
    await executeAnalysis(text, currentInputType, source);
  });

  // Toggle raw json
  const btnToggleJson = document.getElementById('btnToggleJson');
  const rawJsonPre = document.getElementById('rawJsonCode');
  btnToggleJson.addEventListener('click', () => {
    rawJsonPre.classList.toggle('hidden');
  });
}

async function executeAnalysis(text, type, source) {
  const domain = document.getElementById('companyDomainInput').value.trim() || 'novapay.io';
  const submitBtn = document.getElementById('btnSubmitAnalysis');
  submitBtn.disabled = true;

  const outputCard = document.getElementById('analyzerOutputCard');
  if (outputCard) {
    outputCard.classList.remove('scanning-active');
    void outputCard.offsetWidth;
    outputCard.classList.add('scanning-active');
  }

  animateStepper();

  try {
    const result = await API.analyze(text, type, source, domain);
    renderAnalysisResult(result);
    showToast('Analysis completed and persisted to database.', 'success');
    refreshDashboard();
    refreshExplorer();
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  } finally {
    submitBtn.disabled = false;
    setTimeout(() => {
      if (outputCard) outputCard.classList.remove('scanning-active');
    }, 1500);
  }
}

function renderAnalysisResult(item) {
  document.getElementById('outputPlaceholder').classList.add('hidden');
  const content = document.getElementById('outputContent');
  content.classList.remove('hidden');

  const risk = item.riskAssessment;
  const cust = item.customerIntelligence;
  const sec = item.securityAnalysis;
  const riskColor = getRiskColor(risk.riskLevel);

  // 1. Top Risk Banner & Animated Radial Speedometer
  const circle = document.getElementById('riskGaugeCircle');
  const numberEl = document.getElementById('riskGaugeNumber');
  if (circle) {
    const totalLength = 251.2;
    const score = Math.min(100, Math.max(0, risk.riskScore || 0));
    const offset = totalLength * (1 - (score / 100));
    circle.style.strokeDashoffset = offset;
    circle.style.stroke = riskColor;
    circle.style.filter = `drop-shadow(0 0 10px ${riskColor})`;
  }
  if (numberEl) {
    numberEl.textContent = risk.riskScore;
    numberEl.style.color = riskColor;
  }

  // Update live telemetry ticker
  const feedEl = document.getElementById('telemetryLiveFeed');
  if (feedEl) {
    feedEl.textContent = `ALERT: ${risk.riskLevel} (${risk.riskScore}/100) - ${cust.category.toUpperCase()}`;
    feedEl.style.color = riskColor;
  }

  const riskBadge = document.getElementById('riskLevelBadge');
  riskBadge.textContent = risk.riskLevel;
  riskBadge.className = `risk-level-badge risk-${risk.riskLevel.toLowerCase()}`;

  const banner = document.getElementById('riskSummaryBanner');
  banner.style.borderLeftColor = riskColor;

  document.getElementById('riskScoreVal').innerHTML = `${risk.riskScore}<span>/100</span>`;
  document.getElementById('riskActionText').textContent = risk.recommendedAction;

  // 2. Customer Intelligence Card
  document.getElementById('custCategory').textContent = cust.category;
  
  const prioEl = document.getElementById('custPriority');
  prioEl.textContent = cust.priority;
  prioEl.className = `chip-v badge ${cust.priority === 'URGENT' ? 'badge-crimson' : cust.priority === 'HIGH' ? 'badge-amber' : 'badge-outline'}`;

  const sentEl = document.getElementById('custSentiment');
  sentEl.textContent = `${cust.sentiment} (${cust.sentimentScore > 0 ? '+' : ''}${cust.sentimentScore})`;
  sentEl.className = `chip-v badge ${cust.sentiment === 'Frustrated' ? 'badge-crimson' : cust.sentiment === 'Negative' ? 'badge-amber' : cust.sentiment === 'Positive' ? 'badge-emerald' : 'badge-outline'}`;

  document.getElementById('custSummary').textContent = cust.summary || 'Summary unavailable.';

  // Key Issues
  const issuesContainer = document.getElementById('custKeyIssues');
  issuesContainer.innerHTML = '';
  (cust.keyIssues || []).forEach(issue => {
    const span = document.createElement('span');
    span.className = 'tag-item';
    span.textContent = issue;
    issuesContainer.appendChild(span);
  });

  // Keywords
  const kwContainer = document.getElementById('custKeywords');
  kwContainer.innerHTML = '';
  (cust.extractedKeywords || []).forEach(kw => {
    const span = document.createElement('span');
    span.className = 'tag-item';
    span.textContent = kw;
    kwContainer.appendChild(span);
  });

  // 3. Security Intelligence Card
  const secThreatType = document.getElementById('secThreatType');
  secThreatType.textContent = sec.threatType;
  secThreatType.className = `chip-v badge ${sec.hasThreat ? 'badge-crimson' : 'badge-outline'}`;

  document.getElementById('secIndicatorsCount').textContent = `${sec.indicatorsCount} found`;
  document.getElementById('secThreatScore').textContent = `${sec.threatScore}/100`;

  const indList = document.getElementById('secIndicatorsList');
  indList.innerHTML = '';
  if (sec.indicators && sec.indicators.length > 0) {
    sec.indicators.forEach(ind => {
      const row = document.createElement('div');
      row.className = 'indicator-row';
      row.style.borderLeftColor = getSeverityColor(ind.severity);
      row.innerHTML = `
        <div class="indicator-title">
          <span>${escapeHtml(ind.indicator)}</span>
          <span class="badge badge-sm badge-${ind.severity}">${ind.severity}</span>
        </div>
        <div class="indicator-evidence">${escapeHtml(ind.evidence)}</div>
      `;
      indList.appendChild(row);
    });
  } else {
    indList.innerHTML = '<div style="font-size:0.78rem; color:var(--text-muted);">No security indicators detected. Interaction conforms to standard operations.</div>';
  }

  // Deconstructed entities (URLs & emails)
  const entList = document.getElementById('secEntitiesList');
  entList.innerHTML = '';
  const pre = item.preprocessed || {};
  if ((pre.urls && pre.urls.length > 0) || (pre.emails && pre.emails.length > 0)) {
    (pre.urls || []).forEach(u => {
      const div = document.createElement('div');
      div.className = 'indicator-row';
      div.innerHTML = `
        <div class="indicator-title"><span>URL: ${escapeHtml(u.hostname)}</span><span class="badge badge-info">${u.protocol}</span></div>
        <div class="indicator-evidence">${escapeHtml(u.normalized)} (HTTPS: ${u.isHttps ? 'YES' : 'NO'}, IP: ${u.isIP ? 'YES' : 'NO'}, Shortener: ${u.isShortener ? 'YES' : 'NO'})</div>
      `;
      entList.appendChild(div);
    });

    (pre.emails || []).forEach(em => {
      const div = document.createElement('div');
      div.className = 'indicator-row';
      div.innerHTML = `
        <div class="indicator-title"><span>Email: ${escapeHtml(em.email)}</span><span class="badge badge-info">Domain: ${escapeHtml(em.domain)}</span></div>
      `;
      entList.appendChild(div);
    });
  } else {
    entList.innerHTML = '<div style="font-size:0.78rem; color:var(--text-muted);">No external links or email addresses extracted from input.</div>';
  }

  // 4. Reasons List
  const reasonsList = document.getElementById('riskReasonsList');
  reasonsList.innerHTML = '';
  (risk.reasons || []).forEach(r => {
    const li = document.createElement('li');
    li.textContent = r;
    reasonsList.appendChild(li);
  });

  // 5. Raw JSON
  document.getElementById('rawJsonCode').textContent = JSON.stringify(item, null, 2);

  initIcons();
}

function animateStepper() {
  const steps = ['validation', 'preprocessing', 'customer', 'security', 'risk'];
  steps.forEach((s, idx) => {
    const el = document.getElementById(`step-${s}`);
    setTimeout(() => {
      if (el) el.classList.add('active');
    }, idx * 120);
  });
}

function resetStepper() {
  const steps = ['validation', 'preprocessing', 'customer', 'security', 'risk'];
  steps.forEach(s => {
    const el = document.getElementById(`step-${s}`);
    if (el) el.classList.remove('active');
  });
}

// =========================================================================
// EXECUTIVE SOC DASHBOARD
// =========================================================================
async function refreshDashboard() {
  try {
    const stats = await API.getStats();

    // KPI Values
    document.getElementById('kpiTotalIncidents').textContent = stats.total;
    document.getElementById('kpiThreatsCount').textContent = stats.threatCount;
    document.getElementById('kpiThreatRate').textContent = `${stats.threatRate}% threat density`;

    const critHigh = (stats.riskBreakdown?.CRITICAL || 0) + (stats.riskBreakdown?.HIGH || 0);
    document.getElementById('kpiCriticalCount').textContent = critHigh;

    document.getElementById('kpiFrustratedCount').textContent = stats.sentimentBreakdown?.Frustrated || 0;
    document.getElementById('navIncidentCount').textContent = stats.total;

    // Header updates
    if (stats.config) {
      document.getElementById('headerTargetDomain').textContent = stats.config.companyDomain;
      const engineChip = document.getElementById('headerEngineMode');
      if (stats.config.aiActive) {
        engineChip.innerHTML = '<i data-lucide="sparkles" class="chip-icon"></i> <span>Gemini AI + Security Rules</span>';
      } else {
        engineChip.innerHTML = '<i data-lucide="shield-check" class="chip-icon"></i> <span>Deterministic Rules Engine</span>';
      }
    }

    // Render Charts
    renderCharts(stats);

    // Recent Threats Table
    renderRecentThreats(stats.recentThreats || []);
    initIcons();
  } catch (err) {
    console.error('Failed to refresh dashboard stats:', err);
  }
}

function renderCharts(stats) {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const textColor = isLight ? '#475569' : '#94a3b8';
  const gridColor = isLight ? 'rgba(0, 0, 0, 0.06)' : 'rgba(255, 255, 255, 0.05)';
  const barColor = isLight ? '#0284c7' : '#00f2fe';

  // Chart 1: Risk Tiers Doughnut
  const ctxRisk = document.getElementById('chartRisk');
  if (ctxRisk) {
    const rb = stats.riskBreakdown || {};
    if (chartRiskInstance) chartRiskInstance.destroy();

    chartRiskInstance = new Chart(ctxRisk, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [rb.CRITICAL || 0, rb.HIGH || 0, rb.MEDIUM || 0, rb.LOW || 0],
          backgroundColor: ['#ff3366', '#ffab00', '#00f2fe', '#00e676'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: textColor, font: { family: "'Plus Jakarta Sans', sans-serif", size: 11, weight: '600' } } }
        }
      }
    });
  }

  // Chart 2: Category Bar
  const ctxCat = document.getElementById('chartCategory');
  if (ctxCat) {
    const cb = stats.categoryBreakdown || {};
    const labels = Object.keys(cb);
    const data = Object.values(cb);
    if (chartCategoryInstance) chartCategoryInstance.destroy();

    chartCategoryInstance = new Chart(ctxCat, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Incidents',
          data,
          backgroundColor: barColor,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: textColor, font: { family: "'Plus Jakarta Sans', sans-serif", size: 10, weight: '500' } }, grid: { display: false } },
          y: { ticks: { color: textColor, font: { family: "'Plus Jakarta Sans', sans-serif", size: 10 }, precision: 0 }, grid: { color: gridColor } }
        }
      }
    });
  }

  // Chart 3: Sentiment Polar / Pie
  const ctxSent = document.getElementById('chartSentiment');
  if (ctxSent) {
    const sb = stats.sentimentBreakdown || {};
    if (chartSentimentInstance) chartSentimentInstance.destroy();

    chartSentimentInstance = new Chart(ctxSent, {
      type: 'pie',
      data: {
        labels: ['Frustrated', 'Negative', 'Neutral', 'Positive'],
        datasets: [{
          data: [sb.Frustrated || 0, sb.Negative || 0, sb.Neutral || 0, sb.Positive || 0],
          backgroundColor: ['#ff3366', '#ffab00', '#64748b', '#00e676'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: textColor, font: { family: "'Plus Jakarta Sans', sans-serif", size: 11, weight: '600' } } }
        }
      }
    });
  }
}

function renderRecentThreats(threats) {
  const tbody = document.getElementById('recentThreatsTbody');
  tbody.innerHTML = '';

  if (threats.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted);">No high-risk threats detected.</td></tr>';
    return;
  }

  threats.forEach(t => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${t.id.substring(0, 10)}</code></td>
      <td>${new Date(t.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td>
      <td><span class="badge badge-crimson">${escapeHtml(t.securityAnalysis?.threatType || 'Threat')}</span></td>
      <td>${escapeHtml(t.customerIntelligence?.category || 'General')}</td>
      <td><span class="badge badge-${t.riskAssessment?.riskLevel.toLowerCase()}">${t.riskAssessment?.riskLevel}</span></td>
      <td style="max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
        ${escapeHtml(t.securityAnalysis?.indicators?.[0]?.indicator || 'Suspicious payload')}
      </td>
      <td>
        <select class="status-select" data-id="${t.id}">
          <option value="Open" ${t.status === 'Open' ? 'selected' : ''}>Open</option>
          <option value="In Investigation" ${t.status === 'In Investigation' ? 'selected' : ''}>Investigating</option>
          <option value="Resolved" ${t.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
          <option value="Escalated" ${t.status === 'Escalated' ? 'selected' : ''}>Escalated</option>
        </select>
      </td>
      <td>
        <button class="btn btn-outline btn-sm btn-inspect" data-id="${t.id}">Inspect</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  attachTableActionListeners(tbody);
}

// =========================================================================
// INCIDENT & TICKET EXPLORER
// =========================================================================
function setupExplorer() {
  const searchInput = document.getElementById('explorerSearchInput');
  const catFilter = document.getElementById('filterCategory');
  const riskFilter = document.getElementById('filterRisk');
  const sentFilter = document.getElementById('filterSentiment');
  const statusFilter = document.getElementById('filterStatus');
  const threatOnly = document.getElementById('filterThreatOnly');
  const btnReset = document.getElementById('btnResetFilters');

  let debounceTimer;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      currentExplorerPage = 1;
      refreshExplorer();
    }, 280);
  });

  [catFilter, riskFilter, sentFilter, statusFilter, threatOnly].forEach(ctrl => {
    ctrl.addEventListener('change', () => {
      currentExplorerPage = 1;
      refreshExplorer();
    });
  });

  btnReset.addEventListener('click', () => {
    searchInput.value = '';
    catFilter.value = 'all';
    riskFilter.value = 'all';
    sentFilter.value = 'all';
    statusFilter.value = 'all';
    threatOnly.checked = false;
    currentExplorerPage = 1;
    refreshExplorer();
  });

  document.getElementById('btnPrevPage').addEventListener('click', () => {
    if (currentExplorerPage > 1) {
      currentExplorerPage--;
      refreshExplorer();
    }
  });

  document.getElementById('btnNextPage').addEventListener('click', () => {
    currentExplorerPage++;
    refreshExplorer();
  });

  // Modal close
  document.getElementById('btnModalClose').addEventListener('click', () => {
    document.getElementById('incidentModalOverlay').classList.add('hidden');
  });

  document.getElementById('incidentModalOverlay').addEventListener('click', (e) => {
    if (e.target.id === 'incidentModalOverlay') {
      document.getElementById('incidentModalOverlay').classList.add('hidden');
    }
  });
}

async function refreshExplorer() {
  const params = {
    search: document.getElementById('explorerSearchInput').value.trim(),
    category: document.getElementById('filterCategory').value,
    risk: document.getElementById('filterRisk').value,
    sentiment: document.getElementById('filterSentiment').value,
    status: document.getElementById('filterStatus').value,
    threatOnly: document.getElementById('filterThreatOnly').checked,
    page: currentExplorerPage,
    limit: 15
  };

  try {
    const data = await API.getIncidents(params);
    renderExplorerTable(data);
  } catch (err) {
    console.error('Failed to load explorer items:', err);
  }
}

function renderExplorerTable(data) {
  const tbody = document.getElementById('explorerTbody');
  tbody.innerHTML = '';

  document.getElementById('explorerResultsCount').textContent = `Showing ${data.items.length} of ${data.total} recorded incidents`;
  document.getElementById('paginationIndicator').textContent = `Page ${data.page} of ${data.totalPages}`;

  document.getElementById('btnPrevPage').disabled = data.page <= 1;
  document.getElementById('btnNextPage').disabled = data.page >= data.totalPages;

  if (data.items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding: 40px; color:var(--text-muted);">No records match the active search or filter criteria.</td></tr>';
    return;
  }

  data.items.forEach(item => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${item.id.substring(0, 9)}</code></td>
      <td>${new Date(item.createdAt).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</td>
      <td><span class="badge badge-info">${escapeHtml(item.customerIntelligence?.category || 'General')}</span></td>
      <td><span class="badge badge-${item.customerIntelligence?.sentiment?.toLowerCase()}">${item.customerIntelligence?.sentiment}</span></td>
      <td><span class="badge badge-${item.riskAssessment?.riskLevel?.toLowerCase()}">${item.riskAssessment?.riskLevel}</span></td>
      <td>${item.securityAnalysis?.hasThreat ? '<span class="badge badge-crimson">THREAT</span>' : '<span style="color:var(--emerald);">Clean</span>'}</td>
      <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
        ${escapeHtml(item.customerIntelligence?.summary || item.inputText)}
      </td>
      <td>
        <select class="status-select" data-id="${item.id}">
          <option value="Open" ${item.status === 'Open' ? 'selected' : ''}>Open</option>
          <option value="In Investigation" ${item.status === 'In Investigation' ? 'selected' : ''}>Investigating</option>
          <option value="Resolved" ${item.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
          <option value="Escalated" ${item.status === 'Escalated' ? 'selected' : ''}>Escalated</option>
        </select>
      </td>
      <td>
        <button class="btn btn-outline btn-sm btn-inspect" data-id="${item.id}">View</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  attachTableActionListeners(tbody);
}

function attachTableActionListeners(container) {
  // Status select changes
  container.querySelectorAll('.status-select').forEach(sel => {
    sel.addEventListener('change', async (e) => {
      const id = sel.getAttribute('data-id');
      const newStatus = sel.value;
      try {
        await API.updateIncidentStatus(id, newStatus);
        showToast(`Incident status updated to "${newStatus}"`, 'success');
      } catch (err) {
        showToast(`Failed to update status: ${err.message}`, 'error');
      }
    });
  });

  // Inspect buttons
  container.querySelectorAll('.btn-inspect').forEach(btn => {
    btn.addEventListener('click', async () => {
      const id = btn.getAttribute('data-id');
      try {
        const item = await API.getIncidentById(id);
        openIncidentModal(item);
      } catch (err) {
        showToast(`Could not open incident: ${err.message}`, 'error');
      }
    });
  });
}

function openIncidentModal(item) {
  document.getElementById('modalIncidentId').textContent = `Incident ID: ${item.id}`;
  document.getElementById('modalIncidentDate').textContent = `Recorded: ${new Date(item.createdAt).toLocaleString()} | Source: ${item.source || 'Direct'}`;

  const body = document.getElementById('modalIncidentBody');
  body.innerHTML = `
    <div class="risk-summary-banner" style="border-left-color:${getRiskColor(item.riskAssessment?.riskLevel)}; margin-bottom:16px;">
      <div>
        <span class="risk-label">RISK LEVEL</span>
        <div class="risk-level-badge" style="color:${getRiskColor(item.riskAssessment?.riskLevel)}">${item.riskAssessment?.riskLevel} (${item.riskAssessment?.riskScore}/100)</div>
      </div>
      <div style="flex:1; margin-left: 20px;">
        <div class="action-header"><i data-lucide="shield-alert"></i> RECOMMENDED ACTION:</div>
        <div class="action-text">${escapeHtml(item.riskAssessment?.recommendedAction || '')}</div>
      </div>
    </div>

    <div class="form-group">
      <label>Raw Customer Input / Payload:</label>
      <div style="background:var(--bg-card); padding:12px; border-radius:6px; font-size:0.85rem; line-height:1.45; border:1px solid var(--border-color);">
        ${escapeHtml(item.inputText)}
      </div>
    </div>

    <div class="output-subgrid" style="margin-top:16px;">
      <div class="intel-card">
        <div class="intel-card-header">Customer Intelligence</div>
        <div class="intel-metrics">
          <div class="metric-chip"><span>Category:</span> <strong>${item.customerIntelligence?.category}</strong></div>
          <div class="metric-chip"><span>Sentiment:</span> <strong>${item.customerIntelligence?.sentiment}</strong></div>
          <div class="metric-chip"><span>Priority:</span> <strong>${item.customerIntelligence?.priority}</strong></div>
        </div>
        <p class="summary-text">${escapeHtml(item.customerIntelligence?.summary || '')}</p>
      </div>

      <div class="intel-card">
        <div class="intel-card-header">Security Intelligence</div>
        <div class="intel-metrics">
          <div class="metric-chip"><span>Threat Detected:</span> <strong>${item.securityAnalysis?.hasThreat ? 'YES' : 'NO'}</strong></div>
          <div class="metric-chip"><span>Threat Type:</span> <strong>${item.securityAnalysis?.threatType}</strong></div>
        </div>
        <div class="indicators-list">
          ${(item.securityAnalysis?.indicators || []).map(ind => `
            <div class="indicator-row" style="border-left-color:${getSeverityColor(ind.severity)}">
              <div class="indicator-title"><span>${escapeHtml(ind.indicator)}</span> <span class="badge">${ind.severity}</span></div>
              <div class="indicator-evidence">${escapeHtml(ind.evidence)}</div>
            </div>
          `).join('')}
        </div>
      </div>
    </div>

    <div class="reasoning-block" style="margin-top:16px;">
      <span class="block-label">Contributing Risk Factors:</span>
      <ul class="reasoning-list">
        ${(item.riskAssessment?.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
      </ul>
    </div>
  `;

  document.getElementById('incidentModalOverlay').classList.remove('hidden');
  initIcons();
}

// =========================================================================
// BULK UPLOAD (CSV / JSON)
// =========================================================================
function setupBulkUpload() {
  // CSV Setup
  const csvDrop = document.getElementById('csvDropZone');
  const csvFile = document.getElementById('csvFileInput');
  const btnProcessCsv = document.getElementById('btnProcessCsv');
  const csvStatus = document.getElementById('csvUploadStatus');
  let selectedCsvFile = null;

  csvDrop.addEventListener('click', () => csvFile.click());
  csvFile.addEventListener('change', () => {
    if (csvFile.files.length > 0) {
      selectedCsvFile = csvFile.files[0];
      csvStatus.innerHTML = `<span style="color:var(--cyan); font-weight:600;">Selected: ${selectedCsvFile.name} (${Math.round(selectedCsvFile.size / 1024)} KB)</span>`;
      btnProcessCsv.disabled = false;
    }
  });

  btnProcessCsv.addEventListener('click', async () => {
    if (!selectedCsvFile) return;
    btnProcessCsv.disabled = true;
    csvStatus.innerHTML = '<span style="color:var(--amber);">Processing CSV dataset through intelligence pipeline...</span>';
    try {
      const res = await API.uploadCsv(selectedCsvFile);
      csvStatus.innerHTML = `<span style="color:var(--emerald); font-weight:600;">${res.message}</span>`;
      showToast(`Processed ${res.count} records from CSV`, 'success');
      refreshDashboard();
      refreshExplorer();
    } catch (err) {
      csvStatus.innerHTML = `<span style="color:var(--crimson);">${err.message}</span>`;
      showToast(`CSV Upload Error: ${err.message}`, 'error');
    } finally {
      btnProcessCsv.disabled = false;
    }
  });

  // JSON Setup
  const jsonDrop = document.getElementById('jsonDropZone');
  const jsonFile = document.getElementById('jsonFileInput');
  const btnProcessJson = document.getElementById('btnProcessJson');
  const jsonStatus = document.getElementById('jsonUploadStatus');
  let selectedJsonFile = null;

  jsonDrop.addEventListener('click', () => jsonFile.click());
  jsonFile.addEventListener('change', () => {
    if (jsonFile.files.length > 0) {
      selectedJsonFile = jsonFile.files[0];
      jsonStatus.innerHTML = `<span style="color:var(--purple); font-weight:600;">Selected: ${selectedJsonFile.name} (${Math.round(selectedJsonFile.size / 1024)} KB)</span>`;
      btnProcessJson.disabled = false;
    }
  });

  btnProcessJson.addEventListener('click', async () => {
    if (!selectedJsonFile) return;
    btnProcessJson.disabled = true;
    jsonStatus.innerHTML = '<span style="color:var(--amber);">Processing JSON payload through intelligence pipeline...</span>';
    try {
      const res = await API.uploadJson(selectedJsonFile);
      jsonStatus.innerHTML = `<span style="color:var(--emerald); font-weight:600;">${res.message}</span>`;
      showToast(`Processed ${res.count} records from JSON`, 'success');
      refreshDashboard();
      refreshExplorer();
    } catch (err) {
      jsonStatus.innerHTML = `<span style="color:var(--crimson);">${err.message}</span>`;
      showToast(`JSON Upload Error: ${err.message}`, 'error');
    } finally {
      btnProcessJson.disabled = false;
    }
  });
}

// =========================================================================
// GLOBAL ACTIONS & UTILITIES
// =========================================================================
function setupGlobalActions() {
  // Re-seed
  document.getElementById('btnQuickSeed').addEventListener('click', async () => {
    const btn = document.getElementById('btnQuickSeed');
    btn.disabled = true;
    showToast('Re-seeding 100+ comprehensive dataset across all categories...', 'info');
    try {
      const res = await API.seedDatabase();
      showToast(res.message, 'success');
      await refreshDashboard();
      await refreshExplorer();
    } catch (err) {
      showToast(`Seeding failed: ${err.message}`, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  // Export
  document.getElementById('btnExportData').addEventListener('click', () => {
    window.location.href = '/api/export?format=csv';
  });
}

function showToast(msg, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast-msg toast-${type}`;
  toast.innerHTML = `
    <i data-lucide="${type === 'success' ? 'check-circle' : type === 'error' ? 'alert-octagon' : 'info'}"></i>
    <span>${escapeHtml(msg)}</span>
  `;
  container.appendChild(toast);
  initIcons();

  setTimeout(() => {
    toast.remove();
  }, 4000);
}

function getRiskColor(level) {
  if (level === 'CRITICAL') return 'var(--crimson)';
  if (level === 'HIGH') return 'var(--amber)';
  if (level === 'MEDIUM') return 'var(--cyan)';
  return 'var(--emerald)';
}

function getSeverityColor(sev) {
  if (sev === 'critical') return 'var(--crimson)';
  if (sev === 'high') return 'var(--amber)';
  if (sev === 'medium') return 'var(--cyan)';
  return 'var(--emerald)';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
