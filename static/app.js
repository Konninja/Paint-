(function () {
  'use strict';

  // ─── State ──────────────────────────────────────────────────────
  const state = {
    activeType: 'email',
    activeTaskId: null,
    pollingInterval: null,
    history: JSON.parse(localStorage.getItem('osint_history') || '[]'),
  };

  // ─── DOM refs ──────────────────────────────────────────────────
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  const queryBtns = $$('.query-btn');
  const queryInput = $('#queryInput');
  const searchBtn = $('#searchBtn');
  const queryLabel = $('#queryLabel');
  const resultsArea = $('#resultsArea');
  const placeholder = $('#placeholder');
  const statusBar = $('#statusBar');
  const statusText = $('#statusText');
  const statusIndicator = $('#statusIndicator');
  const progressFill = $('#progressFill');
  const historyList = $('#historyList');

  // ─── API Config ─────────────────────────────────────────────────
  async function fetchApiStatus() {
    try {
      const res = await fetch('/api/config');
      const config = await res.json();
      const mapping = { shodan: 'dot-shodan', hunter: 'dot-hunter', dehashed: 'dot-dehashed', virustotal: 'dot-virustotal' };
      for (const [key, dotId] of Object.entries(mapping)) {
        const dot = document.getElementById(dotId);
        if (dot) dot.className = 'api-dot ' + (config[key] ? 'online' : 'offline');
      }
    } catch {}
  }

  // ─── History ────────────────────────────────────────────────────
  function saveHistory() { localStorage.setItem('osint_history', JSON.stringify(state.history)); }

  function renderHistory() {
    if (!historyList) return;
    if (state.history.length === 0) {
      historyList.innerHTML = '<p style="opacity:0.6;font-size:0.85rem">No queries yet</p>';
      return;
    }
    historyList.innerHTML = state.history.slice().reverse().slice(0, 15).map((h) =>
      '<div class="history-item" data-type="' + h.type + '" data-target="' + h.target + '">' +
      '<span class="history-type">' + h.type + '</span>' +
      '<span class="history-target">' + escapeHtml(h.target) + '</span>' +
      '<span class="history-time">' + new Date(h.time).toLocaleString() + '</span></div>'
    ).join('');
    document.querySelectorAll('.history-item').forEach((el) => {
      el.addEventListener('click', () => { doSearch(el.dataset.type, el.dataset.target); });
    });
  }

  // ─── UI Helpers ─────────────────────────────────────────────────
  function setActiveType(type) {
    state.activeType = type;
    const labels = { email: 'Email', username: 'Username', phone: 'Phone', domain: 'Domain', ip: 'IP Address' };
    queryLabel.textContent = labels[type] || 'Email';
    queryInput.placeholder = 'Enter ' + queryLabel.textContent + '...';
    queryInput.type = type === 'email' ? 'email' : type === 'phone' ? 'tel' : 'text';
    queryBtns.forEach((b) => b.classList.toggle('active', b.dataset.type === type));
  }

  function escapeHtml(str) {
    if (!str) return '';
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function kv(obj, ...only) {
    if (!obj) return '';
    const keys = only.length ? only : Object.keys(obj);
    let html = '<table class="kv-table">';
    keys.forEach((k) => {
      const v = obj[k];
      if (v !== undefined && v !== null && v !== '') {
        html += '<tr><td class="kv-key">' + k.replace(/_/g, ' ') + '</td><td class="kv-val">' + escapeHtml(String(v)) + '</td></tr>';
      }
    });
    html += '</table>';
    return html;
  }

  // ─── Show Results ──────────────────────────────────────────────
  function showResults(type, results) {
    placeholder.style.display = 'none';
    if (!results || typeof results !== 'object' || Object.keys(results).length === 0) {
      resultsArea.innerHTML = '<div class="error-box"><p>No intelligence data returned for this target.</p></div>';
      return;
    }
    let html = '<div class="results-grid">';

    // Email
    if (type === 'email') {
      if (results.hunter_verification) html += '<div class="result-card"><h3>📧 Email Verification</h3>' + kv(results.hunter_verification, 'result', 'score', 'webmail', 'disposable', 'accept_all') + '</div>';
      if (results.gravatar) html += '<div class="result-card"><h3>👤 Gravatar</h3><img src="' + escapeHtml(results.gravatar) + '" alt="Avatar" style="border-radius:50%;width:80px;height:80px"/></div>';
      if (results.emailrep) html += '<div class="result-card"><h3>📊 EmailRep</h3>' + kv(results.emailrep, 'reputation', 'suspicious', 'details', 'malicious_activity', 'credentials_leaked') + '</div>';
      if (results.mx_records) html += '<div class="result-card"><h3>📬 MX Records</h3>' + results.mx_records.map((m) => '<p>' + escapeHtml(m) + '</p>').join('') + '</div>';
      if (results.dehashed) html += '<div class="result-card"><h3>🔑 Dehashed</h3><pre style="max-height:200px;overflow:auto">' + escapeHtml(JSON.stringify(results.dehashed, null, 2)) + '</pre></div>';
      if (results.social_profiles) html += '<div class="result-card"><h3>🌐 Social Profiles</h3>' + results.social_profiles.map((s) => '<p><a href="' + escapeHtml(s.url) + '" target="_blank">' + escapeHtml(s.name || s.url) + '</a></p>').join('') + '</div>';
      if (results.social_media) html += '<div class="result-card"><h3>📱 Social Media</h3>' + results.social_media.map((s) => '<p><a href="' + escapeHtml(s.url) + '" target="_blank">' + escapeHtml(s.name || s.url) + '</a></p>').join('') + '</div>';
      if (results.google_mentions) html += '<div class="result-card"><h3>🔍 Google Mentions</h3>' + results.google_mentions.map((g) => '<p><a href="' + escapeHtml(g) + '" target="_blank">' + escapeHtml(g) + '</a></p>').join('') + '</div>';
    }

    // Username
    if (type === 'username') {
      if (results.social_media) html += '<div class="result-card"><h3>📱 Social Media</h3>' + results.social_media.map((s) => '<p><a href="' + escapeHtml(s.url) + '" target="_blank">' + escapeHtml(s.name || s.url) + '</a></p>').join('') + '</div>';
      if (results.social_profiles) html += '<div class="result-card"><h3>🌐 Social Profiles</h3>' + results.social_profiles.map((s) => '<p><a href="' + escapeHtml(s.url) + '" target="_blank">' + escapeHtml(s.name || s.url) + '</a></p>').join('') + '</div>';
      if (results.google_mentions) html += '<div class="result-card"><h3>🔍 Google Mentions</h3>' + results.google_mentions.map((g) => '<p><a href="' + escapeHtml(g) + '" target="_blank">' + escapeHtml(g) + '</a></p>').join('') + '</div>';
    }

    // Phone
    if (type === 'phone') {
      if (results.country) html += '<div class="result-card"><h3>🌍 Country</h3><p>' + escapeHtml(results.country) + '</p></div>';
      if (results.carrier) html += '<div class="result-card"><h3>📡 Carrier</h3><p>' + escapeHtml(results.carrier) + '</p></div>';
      if (results.number_type) html += '<div class="result-card"><h3>🔢 Number Type</h3><p>' + escapeHtml(results.number_type) + '</p></div>';
      if (results.timezones) html += '<div class="result-card"><h3>🕐 Timezones</h3><p>' + escapeHtml(results.timezones) + '</p></div>';
      if (results.social_media) html += '<div class="result-card"><h3>📱 Social Media</h3>' + results.social_media.map((s) => '<p><a href="' + escapeHtml(s.url) + '" target="_blank">' + escapeHtml(s.name || s.url) + '</a></p>').join('') + '</div>';
    }

    // Domain
    if (type === 'domain') {
      if (results.dns_records) html += '<div class="result-card"><h3>🌐 DNS Records</h3><pre style="max-height:200px;overflow:auto">' + escapeHtml(JSON.stringify(results.dns_records, null, 2)) + '</pre></div>';
      if (results.whois) html += '<div class="result-card"><h3>📋 WHOIS</h3><pre style="max-height:200px;overflow:auto">' + escapeHtml(results.whois) + '</pre></div>';
      if (results.virustotal) html += '<div class="result-card"><h3>🛡️ VirusTotal</h3>' + kv(results.virustotal) + '</div>';
      if (results.security_headers) html += '<div class="result-card"><h3>🔒 Security Headers</h3>' + kv(results.security_headers) + '</div>';
      if (results.technology && results.technology.length) html += '<div class="result-card"><h3>⚙️ Technology Stack</h3><ul>' + results.technology.map((t) => '<li>' + escapeHtml(t) + '</li>').join('') + '</ul></div>';
      if (results.subdomains && results.subdomains.length) html += '<div class="result-card"><h3>📂 Subdomains</h3><ul>' + results.subdomains.map((s) => '<li>' + escapeHtml(s) + '</li>').join('') + '</ul></div>';
      if (results.open_ports && results.open_ports.length) html += '<div class="result-card"><h3>🔌 Open Ports</h3><ul>' + results.open_ports.map((p) => '<li>Port ' + escapeHtml(String(p)) + '</li>').join('') + '</ul></div>';
      if (results.wayback && results.wayback.length) html += '<div class="result-card"><h3>📜 Wayback Machine</h3><ul>' + results.wayback.map((w) => '<li><a href="https://web.archive.org/web/' + w.date + '/' + encodeURIComponent(w.url) + '" target="_blank">' + escapeHtml(w.date) + ' — ' + escapeHtml(w.url) + '</a></li>').join('') + '</ul></div>';
      if (results.zone_transfer && results.zone_transfer.length) html += '<div class="result-card"><h3>⚠️ Zone Transfer</h3><ul>' + results.zone_transfer.map((z) => '<li>' + escapeHtml(z) + '</li>').join('') + '</ul></div>';
    }

    // IP
    if (type === 'ip') {
      if (results.hostname) html += '<div class="result-card"><h3>🏠 Hostname</h3><p>' + escapeHtml(results.hostname) + '</p></div>';
      if (results.geo) html += '<div class="result-card"><h3>🌍 Geolocation</h3>' + kv(results.geo) + '</div>';
      if (results.reverse_dns && results.reverse_dns.length) html += '<div class="result-card"><h3>🔄 Reverse DNS</h3><ul>' + results.reverse_dns.map((r) => '<li>' + escapeHtml(r) + '</li>').join('') + '</ul></div>';
      if (results.shodan) {
        let sh = kv(results.shodan, 'org', 'isp', 'os', 'hostnames');
        if (results.shodan.services) {
          sh += '<h4>Services:</h4><ul>';
          results.shodan.services.forEach((s) => { sh += '<li>Port ' + s.port + ' — ' + escapeHtml(s.service || s.name || '?') + '</li>'; });
          sh += '</ul>';
        }
        if (results.shodan.vulns && results.shodan.vulns.length) {
          sh += '<h4>Vulnerabilities:</h4><ul>';
          results.shodan.vulns.forEach((v) => { sh += '<li>' + escapeHtml(v) + '</li>'; });
          sh += '</ul>';
        }
        html += '<div class="result-card"><h3>⚡ Shodan</h3>' + sh + '</div>';
      }
      if (results.virustotal) html += '<div class="result-card"><h3>🛡️ VirusTotal</h3>' + kv(results.virustotal) + '</div>';
      if (results.open_ports && results.open_ports.length) html += '<div class="result-card"><h3>🔌 Open Ports</h3><ul>' + results.open_ports.map((p) => '<li>Port ' + escapeHtml(String(p)) + '</li>').join('') + '</ul></div>';
      if (results.banners) {
        let bh = '';
        Object.entries(results.banners).forEach(([port, banner]) => { bh += '<p><strong>Port ' + escapeHtml(port) + ':</strong> ' + escapeHtml(banner) + '</p>'; });
        html += '<div class="result-card"><h3>📡 Service Banners</h3>' + bh + '</div>';
      }
      if (results.rdap) {
        let rh = '';
        if (results.rdap.handle) rh += '<p><strong>Handle:</strong> ' + escapeHtml(results.rdap.handle) + '</p>';
        if (results.rdap.name) rh += '<p><strong>Org:</strong> ' + escapeHtml(results.rdap.name) + '</p>';
        if (results.rdap.org_name) rh += '<p><strong>Org Name:</strong> ' + escapeHtml(results.rdap.org_name) + '</p>';
        if (results.rdap.country) rh += '<p><strong>Country:</strong> ' + escapeHtml(results.rdap.country) + '</p>';
        if (results.rdap.emails && results.rdap.emails.length) rh += '<p><strong>Emails:</strong> ' + results.rdap.emails.map((e) => escapeHtml(e)).join(', ') + '</p>';
        if (rh) html += '<div class="result-card"><h3>📋 RDAP</h3>' + rh + '</div>';
      }
      if (results.abuse_score) html += '<div class="result-card"><h3>🚨 AbuseIPDB</h3><p>Confidence Score: ' + escapeHtml(results.abuse_score) + '</p></div>';
    }

    // Fallback for any raw data keys
    const skip = ['hunter_verification','gravatar','emailrep','mx_records','dehashed','social_profiles','social_media','google_mentions','parsed','country','carrier','number_type','timezones','dns_records','whois','virustotal','security_headers','technology','subdomains','open_ports','wayback','zone_transfer','hostname','geo','reverse_dns','shodan','banners','rdap','abuse_score'];
    Object.keys(results).filter((k) => !skip.includes(k)).forEach((k) => {
      const v = results[k];
      if (v && typeof v === 'object' && !Array.isArray(v)) html += '<div class="result-card"><h3>📎 ' + escapeHtml(k.replace(/_/g, ' ')) + '</h3>' + kv(v) + '</div>';
      else if (v && Array.isArray(v) && v.length) html += '<div class="result-card"><h3>📎 ' + escapeHtml(k.replace(/_/g, ' ')) + '</h3><ul>' + v.map((item) => typeof item === 'string' ? '<li>' + escapeHtml(item) + '</li>' : '').join('') + '</ul></div>';
    });

    html += '</div>';
    if (!html || html === '<div class="results-grid"></div>') html = '<div class="error-box"><p>No intelligence data returned for this target.</p></div>';
    resultsArea.innerHTML = html;
  }

  // ─── Error ──────────────────────────────────────────────────────
  function showError(msg) {
    resultsArea.innerHTML = '<div class="error-box">⚠️ ' + escapeHtml(msg || 'An unknown error occurred') + '</div>';
    placeholder.style.display = 'none';
  }

  // ─── doSearch ──────────────────────────────────────────────────
  async function doSearch(type, target) {
    showStatus('running', 'Starting lookup...');
    placeholder.style.display = 'none';
    resultsArea.innerHTML = '<div class="loading"><div class="spinner"></div><p>Searching...</p></div>';
    try {
      const res = await fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, target }),
      });
      const data = await res.json();
      if (!res.ok) { showError(data.error); hideStatus(); return; }
      state.activeTaskId = data.task_id;
      state.history.push({ type, target, time: new Date().toISOString() });
      saveHistory();
      renderHistory();
      pollTask(data.task_id);
    } catch (err) {
      showError('Network error — could not reach the server.');
      hideStatus();
    }
  }

  // ─── pollTask ──────────────────────────────────────────────────
  function pollTask(taskId) {
    if (state.pollingInterval) clearInterval(state.pollingInterval);
    state.pollingInterval = setInterval(async () => {
      try {
        const res = await fetch('/api/status/' + taskId);
        const data = await res.json();
        if (data.status === 'completed') {
          clearInterval(state.pollingInterval);
          state.pollingInterval = null;
          state.activeTaskId = null;
          showStatus('completed', 'Lookup completed');
          setTimeout(hideStatus, 3000);
          if (data.result) showResults(data.type || state.activeType, data.result);
        } else if (data.status === 'failed') {
          clearInterval(state.pollingInterval);
          state.pollingInterval = null;
          state.activeTaskId = null;
          showError(data.error || 'Lookup failed');
          hideStatus();
        } else {
          showStatus('running', 'Searching... (' + (data.progress || 'processing') + ')');
        }
      } catch {
        clearInterval(state.pollingInterval);
        state.pollingInterval = null;
        showError('Lost connection to server while polling.');
        hideStatus();
      }
    }, 2000);
  }

  // ─── Status bar ─────────────────────────────────────────────────
  function showStatus(status, msg) {
    if (!statusBar || !statusText || !statusIndicator || !progressFill) return;
    statusBar.style.display = 'flex';
    statusText.textContent = msg || '';
    statusIndicator.className = 'status-indicator ' + status;
    progressFill.style.width = status === 'running' ? '60%' : '100%';
  }

  function hideStatus() {
    if (!statusBar) return;
    statusBar.style.display = 'none';
  }

  // ─── Event Handlers ─────────────────────────────────────────────
  queryBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      setActiveType(btn.dataset.type);
      if (queryInput.value.trim()) doSearch(btn.dataset.type, queryInput.value.trim());
    });
  });

  searchBtn.addEventListener('click', () => {
    const target = queryInput.value.trim();
    if (target) doSearch(state.activeType, target);
  });

  queryInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const target = queryInput.value.trim();
      if (target) doSearch(state.activeType, target);
    }
  });

  // ─── Tab nav (prevent page reload) ──────────────────────────────
  document.querySelectorAll('.nav-links a').forEach((a) => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      document.querySelectorAll('.nav-links a').forEach((x) => x.classList.remove('active'));
      a.classList.add('active');
    });
  });

  // ─── Init ───────────────────────────────────────────────────────
  setActiveType('email');
  fetchApiStatus();
  renderHistory();
  hideStatus();
})();
