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
      const mapping = {
        shodan: 'dot-shodan',
        hunter: 'dot-hunter',
        dehashed: 'dot-dehashed',
        virustotal: 'dot-virustotal',
      };
      for (const [key, dotId] of Object.entries(mapping)) {
        const dot = document.getElementById(dotId);
        if (dot) {
          dot.className = 'api-dot ' + (config[key] ? 'online' : 'offline');
        }
      }
    } catch {
      // Offline dots stay
    }
  }

  // ─── History ────────────────────────────────────────────────────
  function saveHistory() {
    localStorage.setItem('osint_history', JSON.stringify(state.history));
  }

  function renderHistory() {
    if (!historyList) return;
    if (state.history.length === 0) {
      historyList.innerHTML =
        '<div style="color:#3a4a6a;font-size:0.85em;text-align:center;padding:20px;">No queries yet</div>';
      return;
    }
    historyList.innerHTML = state.history
      .slice()
      .reverse()
      .slice(0, 15)
      .map(
        (h) =>
          `<div class="history-item" data-type="${h.type}" data-target="${h.target}">
            <span class="h-type">${h.type}</span>
            <span class="h-target">${escapeHtml(h.target)}</span>
            <span class="h-status">${h.status}</span>
          </div>`
      )
      .join('');
    historyList.querySelectorAll('.history-item').forEach((el) => {
      el.addEventListener('click', () => {
        const type = el.dataset.type;
        const target = el.dataset.target;
        state.activeType = type;
        setActiveType(type);
        queryInput.value = target;
        doSearch(type, target);
      });
    });
  }

  function addToHistory(type, target, status) {
    state.history.unshift({ type, target, status, time: Date.now() });
    if (state.history.length > 50) state.history.pop();
    saveHistory();
    renderHistory();
  }

  // ─── Helpers ────────────────────────────────────────────────────
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function setActiveType(type) {
    state.activeType = type;
    queryBtns.forEach((btn) => btn.classList.toggle('active', btn.dataset.type === type));
    queryLabel.textContent = type.charAt(0).toUpperCase() + type.slice(1);
    queryInput.placeholder = getPlaceholder(type);
    queryInput.focus();
  }

  function getPlaceholder(type) {
    const map = {
      email: 'user@example.com',
      username: 'johndoe',
      phone: '+14155551234',
      domain: 'example.com',
      ip: '8.8.8.8',
    };
    return map[type] || 'Enter target...';
  }

  // ─── UI Status ──────────────────────────────────────────────────
  function setStatus(text, progress) {
    statusBar.style.display = 'flex';
    statusText.textContent = text;
    if (progress !== undefined) {
      progressFill.style.width = Math.min(progress, 100) + '%';
    }
  }

  function hideStatus() {
    statusBar.style.display = 'none';
    progressFill.style.width = '0%';
  }

  function showSpinner(area) {
    area.innerHTML =
      '<div class="placeholder"><div class="spinner" style="width:32px;height:32px;"></div><p>Gathering intelligence...</p></div>';
  }

  // ─── Search ─────────────────────────────────────────────────────
  function doSearch(type, target) {
    if (!target) return;

    // Clear any existing polling
    if (state.pollingInterval) {
      clearInterval(state.pollingInterval);
      state.pollingInterval = null;
    }

    searchBtn.disabled = true;
    searchBtn.textContent = 'Searching...';
    placeholder.style.display = 'none';
    showSpinner(resultsArea);
    setStatus('Queuing lookup...', 5);
    addToHistory(type, target, 'running');

    fetch('/api/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, target }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.error) {
          showError(data.error);
          searchBtn.disabled = false;
          searchBtn.textContent = 'Search';
          hideStatus();
          addToHistory(type, target, 'error');
          return;
        }
        state.activeTaskId = data.task_id;
        setStatus('Lookup queued — polling for results...', 10);
        pollTask(data.task_id, type);
      })
      .catch((err) => {
        showError('Network error: could not reach server');
        searchBtn.disabled = false;
        searchBtn.textContent = 'Search';
        hideStatus();
        addToHistory(type, target, 'error');
      });
  }

  // ─── Poll Task ──────────────────────────────────────────────────
  function pollTask(taskId, type) {
    if (state.pollingInterval) {
      clearInterval(state.pollingInterval);
    }

    let attempts = 0;
    const maxAttempts = 90; // 90 * 2s = 3 min timeout

    state.pollingInterval = setInterval(() => {
      attempts++;

      fetch(`/api/status/${taskId}`)
        .then((r) => r.json())
        .then((task) => {
          if (task.error) {
            clearInterval(state.pollingInterval);
            state.pollingInterval = null;
            showError(task.error);
            searchBtn.disabled = false;
            searchBtn.textContent = 'Search';
            hideStatus();
            addToHistory(type, '?', 'error');
            return;
          }

          // Update progress
          const progress = task.progress || 0;
          setStatus(
            `Status: ${task.status} — ${task.message || 'Working...'}`,
            progress
          );

          // Complete
          if (task.status === 'complete') {
            clearInterval(state.pollingInterval);
            state.pollingInterval = null;
            searchBtn.disabled = false;
            searchBtn.textContent = 'Search';
            hideStatus();
            addToHistory(type, task.target || '?', 'complete');
            showResults(type, task.results || {});
            return;
          }

          // Error
          if (task.status === 'error') {
            clearInterval(state.pollingInterval);
            state.pollingInterval = null;
            searchBtn.disabled = false;
            searchBtn.textContent = 'Search';
            hideStatus();
            addToHistory(type, task.target || '?', 'error');
            showError(task.message || 'Lookup failed');
            return;
          }

          // Timeout
          if (attempts >= maxAttempts) {
            clearInterval(state.pollingInterval);
            state.pollingInterval = null;
            searchBtn.disabled = false;
            searchBtn.textContent = 'Search';
            hideStatus();
            showError('Lookup timed out after 3 minutes');
            addToHistory(type, '?', 'timeout');
          }
        })
        .catch(() => {
          if (attempts >= maxAttempts) {
            clearInterval(state.pollingInterval);
            state.pollingInterval = null;
            searchBtn.disabled = false;
            searchBtn.textContent = 'Search';
            hideStatus();
            showError('Connection lost during lookup');
            addToHistory(type, '?', 'error');
          }
        });
    }, 2000);
  }

  // ─── Show Results ──────────────────────────────────────────────
  function showResults(type, results) {
    if (!results || Object.keys(results).length === 0) {
      resultsArea.innerHTML =
        '<div class="placeholder"><p>No intelligence data returned for this target.</p></div>';
      return;
    }

    let html = '';

    function kv(obj, ...only) {
      const keys = only.length ? only : Object.keys(obj);
      let tbl = '';
      keys.forEach((k) => {
        const v = obj[k];
        if (v === undefined || v === null || v === '') return;
        const val = typeof v === 'object' ? JSON.stringify(v) : String(v);
        tbl += `<tr><td><strong>${escapeHtml(k.replace(/_/g, ' '))}</strong></td><td>${escapeHtml(val)}</td></tr>`;
      });
      return tbl ? `<table class="result-table">${tbl}</table>` : '';
    }

    // Email results
    if (type === 'email') {
      if (results.hunter_verification) {
        html += `<div class="result-section"><h3>📧 Hunter Verification</h3>${kv(results.hunter_verification)}</div>`;
      }
      if (results.gravatar) {
        html += `<div class="result-section"><h3>👤 Gravatar</h3>${kv(results.gravatar)}</div>`;
      }
      if (results.emailrep) {
        html += `<div class="result-section"><h3>⚠️ EmailRep</h3>${kv(results.emailrep)}</div>`;
      }
      if (results.mx_records && results.mx_records.length) {
        html += `<div class="result-section"><h3>📬 MX Records</h3><div class="list-compact">`;
        results.mx_records.forEach((m) => { html += `<span class="item">${escapeHtml(m)}</span>`; });
        html += `</div></div>`;
      }
      if (results.dehashed && Object.keys(results.dehashed).length) {
        html += `<div class="result-section"><h3>🔑 Dehashed</h3>${kv(results.dehashed)}</div>`;
      }
      if (results.social_profiles && results.social_profiles.length) {
        html += `<div class="result-section"><h3>🌐 Social Profiles</h3><div class="list-compact">`;
        results.social_profiles.forEach((p) => { html += `<span class="item">${escapeHtml(p)}</span>`; });
        html += `</div></div>`;
      }
      if (results.social_media && results.social_media.length) {
        html += `<div class="result-section"><h3>📱 Social Media</h3><div class="list-compact">`;
        results.social_media.forEach((s) => { html += `<span class="item">${escapeHtml(s)}</span>`; });
        html += `</div></div>`;
      }
      if (results.google_mentions && results.google_mentions.length) {
        html += `<div class="result-section"><h3>🔍 Google Mentions</h3><div class="list-compact">`;
        results.google_mentions.forEach((g) => { html += `<span class="item">${escapeHtml(g)}</span>`; });
        html += `</div></div>`;
      }
    }

    // Phone results
    if (type === 'phone') {
      if (results.parsed) {
        html += `<div class="result-section"><h3>🔢 Parsed Number</h3>${kv(results.parsed)}</div>`;
      }
      if (results.country) {
        html += `<div class="result-section"><h3>🌍 Country</h3><p>${escapeHtml(results.country)}</p></div>`;
      }
      if (results.carrier) {
        html += `<div class="result-section"><h3>📡 Carrier</h3><p>${escapeHtml(results.carrier)}</p></div>`;
      }
      if (results.number_type) {
        html += `<div class="result-section"><h3>📞 Number Type</h3><p>${escapeHtml(results.number_type)}</p></div>`;
      }
      if (results.timezones && results.timezones.length) {
        html += `<div class="result-section"><h3>🕐 Timezones</h3><div class="list-compact">`;
        results.timezones.forEach((t) => { html += `<span class="item">${escapeHtml(t)}</span>`; });
        html += `</div></div>`;
      }
    }

    // Domain results
    if (type === 'domain') {
      if (results.dns_records && Object.keys(results.dns_records).length) {
        let dnsHtml = '';
        Object.entries(results.dns_records).forEach(([key, vals]) => {
          if (vals && vals.length) {
            dnsHtml += `<tr><td><strong>${escapeHtml(key.toUpperCase())}</strong></td><td>${vals.map(v => escapeHtml(String(v))).join(', ')}</td></tr>`;
          }
        });
        if (dnsHtml) {
          html += `<div class="result-section"><h3>🌐 DNS Records</h3><table class="result-table">${dnsHtml}</table></div>`;
        }
      }
      if (results.whois) {
        html += `<div class="result-section"><h3>📋 WHOIS</h3>${kv(results.whois)}</div>`;
      }
      if (results.virustotal) {
        html += `<div class="result-section"><h3>🛡️ VirusTotal</h3>${kv(results.virustotal)}</div>`;
      }
      if (results.security_headers) {
        html += `<div class="result-section"><h3>🔒 Security Headers</h3>${kv(results.security_headers)}</div>`;
      }
      if (results.technology && results.technology.length) {
        html += `<div class="result-section"><h3>⚙️ Technology Stack</h3><div class="list-compact">`;
        results.technology.forEach((t) => { html += `<span class="item">${escapeHtml(t)}</span>`; });
        html += `</div></div>`;
      }
      if (results.subdomains && results.subdomains.length) {
        html += `<div class="result-section"><h3>🔗 Subdomains (${results.subdomains.length})</h3><div class="list-compact">`;
        results.subdomains.forEach((s) => { html += `<span class="item">${escapeHtml(s)}</span>`; });
        html += `</div></div>`;
      }
      if (results.open_ports && results.open_ports.length) {
        html += `<div class="result-section"><h3>🔌 Open Ports</h3><div class="list-compact">`;
        results.open_ports.forEach((p) => { html += `<span class="item">Port ${escapeHtml(String(p))}</span>`; });
        html += `</div></div>`;
      }
      if (results.wayback && results.wayback.length) {
        html += `<div class="result-section"><h3>📜 Wayback Machine Snapshots</h3><div class="list-compact">`;
        results.wayback.forEach((w) => {
          html += `<span class="item"><a href="https://web.archive.org/web/${w.date}/${escapeHtml(w.url)}" target="_blank">${escapeHtml(w.date)} — ${escapeHtml(w.url)}</a></span>`;
        });
        html += `</div></div>`;
      }
      if (results.zone_transfer && results.zone_transfer.length) {
        html += `<div class="result-section"><h3>⚠️ Zone Transfer (Successful!)</h3><div class="list-compact">`;
        results.zone_transfer.forEach((z) => { html += `<span class="item">${escapeHtml(z)}</span>`; });
        html += `</div></div>`;
      }
    }

    // IP results
    if (type === 'ip') {
      if (results.hostname) {
        html += `<div class="result-section"><h3>🏠 Hostname</h3><table class="result-table"><tr><td><strong>PTR</strong></td><td>${escapeHtml(results.hostname)}</td></tr></table></div>`;
      }
      if (results.geo) {
        html += `<div class="result-section"><h3>🌍 Geolocation</h3>${kv(results.geo)}</div>`;
      }
      if (results.reverse_dns && results.reverse_dns.length) {
        html += `<div class="result-section"><h3>🔄 Reverse DNS</h3><div class="list-compact">`;
        results.reverse_dns.forEach((r) => html += `<span class="item">${escapeHtml(r)}</span>`);
        html += `</div></div>`;
      }
      if (results.shodan) {
        html += `<div class="result-section"><h3>⚡ Shodan</h3>${kv(results.shodan, 'org', 'isp', 'os', 'hostnames')}`;
        if (results.shodan.services) {
          html += `<p><strong>Services:</strong></p><div class="list-compact">`;
          results.shodan.services.forEach((s) => {
            html += `<span class="item">Port ${s.port} — ${escapeHtml(s.service || s.name || '?')}</span>`;
          });
          html += `</div>`;
        }
        if (results.shodan.vulns && results.shodan.vulns.length) {
          html += `<p><strong>Vulnerabilities:</strong></p><div class="list-compact">`;
          results.shodan.vulns.forEach((v) => { html += `<span class="item">${escapeHtml(v)}</span>`; });
          html += `</div>`;
        }
        html += `</div>`;
      }
      if (results.virustotal) {
        html += `<div class="result-section"><h3>🛡️ VirusTotal</h3>${kv(results.virustotal)}</div>`;
      }
      if (results.open_ports && results.open_ports.length) {
        html += `<div class="result-section"><h3>🔌 Open Ports (${results.open_ports.length})</h3><div class="list-compact">`;
        results.open_ports.forEach((p) => { html += `<span class="item">Port ${escapeHtml(String(p))}</span>`; });
        html += `</div></div>`;
      }
      if (results.banners) {
        html += `<div class="result-section"><h3>📡 Service Banners</h3><table class="result-table">`;
        Object.entries(results.banners).forEach(([port, banner]) => {
          html += `<tr><td><strong>Port ${escapeHtml(port)}</strong></td><td>${escapeHtml(banner)}</td></tr>`;
        });
        html += `</table></div>`;
      }
      if (results.rdap) {
        let rdapHtml = '';
        if (results.rdap.handle) rdapHtml += `<tr><td><strong>Handle</strong></td><td>${escapeHtml(results.rdap.handle)}</td></tr>`;
        if (results.rdap.name) rdapHtml += `<tr><td><strong>Org</strong></td><td>${escapeHtml(results.rdap.name)}</td></tr>`;
        if (results.rdap.org_name) rdapHtml += `<tr><td><strong>Org Name</strong></td><td>${escapeHtml(results.rdap.org_name)}</td></tr>`;
        if (results.rdap.country) rdapHtml += `<tr><td><strong>Country</strong></td><td>${escapeHtml(results.rdap.country)}</td></tr>`;
        if (results.rdap.emails && results.rdap.emails.length) {
          rdapHtml += `<tr><td><strong>Emails</strong></td><td>${results.rdap.emails.map(e => escapeHtml(e)).join(', ')}</td></tr>`;
        }
        if (rdapHtml) {
          html += `<div class="result-section"><h3>📋 RDAP</h3><table class="result-table">${rdapHtml}</table></div>`;
        }
      }
      if (results.abuse_score) {
        html += `<div class="result-section"><h3>🚨 AbuseIPDB</h3><table class="result-table"><tr><td><strong>Confidence Score</strong></td><td>${escapeHtml(results.abuse_score)}</td></tr></table></div>`;
      }
    }

    // Fallback for any raw data not caught above
    const rawKeys = Object.keys(results).filter(
      (k) =>
        ![
          'hunter_verification', 'gravatar', 'emailrep', 'mx_records', 'dehashed',
          'social_profiles', 'social_media', 'google_mentions', 'parsed', 'country',
          'carrier', 'number_type', 'timezones', 'dns_records', 'whois', 'virustotal',
          'security_headers', 'technology', 'subdomains', 'open_ports', 'wayback',
          'zone_transfer', 'hostname', 'geo', 'reverse_dns', 'shodan', 'banners',
          'rdap', 'abuse_score',
        ].includes(k)
    );

    rawKeys.forEach((k) => {
      const v = results[k];
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        html += `<div class="result-section"><h3>📎 ${escapeHtml(k.replace(/_/g, ' '))}</h3>${kv(v)}</div>`;
      } else if (v && Array.isArray(v) && v.length) {
        html += `<div class="result-section"><h3>📎 ${escapeHtml(k.replace(/_/g, ' '))}</h3><div class="list-compact">`;
        v.forEach((item) => {
          if (typeof item === 'string') html += `<span class="item">${escapeHtml(item)}</span>`;
        });
        html += `</div></div>`;
      }
    });

    if (!html) {
      html = '<div class="placeholder"><p>No intelligence data returned for this target.</p></div>';
    }

    resultsArea.innerHTML = html;
  }

  // ─── Error ──────────────────────────────────────────────────────
  function showError(msg) {
    const errorMsg = msg || 'An unknown error occurred';
    resultsArea.innerHTML = `<div class="error-box">⚠️ ${escapeHtml(errorMsg)}</div>`;
    placeholder.style.display = 'none';
  }

  // ─── Event Handlers ─────────────────────────────────────────────
  queryBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      setActiveType(btn.dataset.type);
      if (queryInput.value.trim()) {
        doSearch(btn.dataset.type, queryInput.value.trim());
      }
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
