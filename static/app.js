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
      historyList.innerHTML = '<div class="history-empty">No queries yet</div>';
      return;
    }
    historyList.innerHTML = state.history
      .slice()
      .reverse()
      .slice(0, 15)
      .map(
        (h) =>
          `<div class="history-item" data-type="${escapeHtml(h.type)}" data-target="${escapeHtml(h.target)}">
            <span class="history-type">${escapeHtml(h.type)}</span>
            <span class="history-target">${escapeHtml(h.target)}</span>
            <span class="history-time">${h.time ? new Date(h.time).toLocaleString() : ''}</span>
          </div>`
      )
      .join('');
    document.querySelectorAll('.history-item').forEach((item) => {
      item.addEventListener('click', () => {
        const type = item.dataset.type;
        const target = item.dataset.target;
        setActiveType(type);
        queryInput.value = target;
        doSearch(type, target);
      });
    });
  }

  // ─── Utility ────────────────────────────────────────────────────
  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  function kv(obj, ...priority) {
    if (!obj) return '';
    let html = '<table class="kv-table">';
    const keys = priority.length ? priority.filter((k) => k in obj) : Object.keys(obj);
    keys.forEach((k) => {
      const v = obj[k];
      if (v === null || v === undefined) return;
      const val =
        typeof v === 'object' ? JSON.stringify(v) : String(v);
      if (val.length > 200) return;
      html += `<tr><td class="kv-key">${escapeHtml(k.replace(/_/g, ' '))}</td><td class="kv-val">${escapeHtml(val)}</td></tr>`;
    });
    html += '</table>';
    return html;
  }

  // ─── Status Bar ─────────────────────────────────────────────────
  function showStatus(msg) {
    if (statusBar) statusBar.style.display = 'flex';
    if (statusText) statusText.textContent = msg;
    if (statusIndicator) {
      statusIndicator.className = 'spinner';
    }
  }

  function hideStatus() {
    if (statusBar) statusBar.style.display = 'none';
    if (progressFill) progressFill.style.width = '0%';
  }

  function setProgress(pct) {
    if (progressFill) progressFill.style.width = Math.min(pct, 100) + '%';
  }

  // ─── Active Type ────────────────────────────────────────────────
  function setActiveType(type) {
    state.activeType = type;
    queryBtns.forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.type === type);
    });
    const labels = {
      email: 'Enter email address',
      username: 'Enter username',
      domain: 'Enter domain (e.g. example.com)',
      ip: 'Enter IP address',
      phone: 'Enter phone number (with country code)',
    };
    if (queryLabel) queryLabel.textContent = labels[type] || 'Enter target';
    if (queryInput) queryInput.placeholder = labels[type] || 'Enter target';
    queryInput.focus();
  }

  // ─── POLL TASK — polls /api/status/<task_id> every 2s ───────────
  function pollTask(taskId) {
    // Clear any existing poll
    if (state.pollingInterval) {
      clearInterval(state.pollingInterval);
      state.pollingInterval = null;
    }

    state.pollingInterval = setInterval(async () => {
      try {
        const res = await fetch(`/api/status/${taskId}`);
        if (!res.ok) {
          // 404 means task not found — stop polling
          if (res.status === 404) {
            clearInterval(state.pollingInterval);
            state.pollingInterval = null;
            showError('Task not found. It may have expired.');
            return;
          }
          throw new Error(`Status check failed: ${res.status}`);
        }
        const data = await res.json();

        if (data.status === 'processing') {
          showStatus(`Processing... ${data.progress || ''}`);
          if (data.progress_pct) setProgress(data.progress_pct);
        } else if (data.status === 'complete' || data.status === 'completed') {
          clearInterval(state.pollingInterval);
          state.pollingInterval = null;
          hideStatus();
          if (data.result) {
            showResults(data.result, state.activeType);
          } else {
            showError('Task completed but no results returned.');
          }
        } else if (data.status === 'error' || data.status === 'failed') {
          clearInterval(state.pollingInterval);
          state.pollingInterval = null;
          hideStatus();
          showError(data.error || 'Task failed with an unknown error.');
        }
        // status === 'queued' — keep waiting
      } catch (err) {
        // Network error — keep polling unless it's a definitive failure
        console.error('Poll error:', err);
      }
    }, 2000);
  }

  // ─── DO SEARCH — sends target to /api/lookup, then starts polling ─
  async function doSearch(type, target) {
    if (!target || !target.trim()) {
      showError('Target cannot be empty');
      return;
    }

    // Clear previous results
    resultsArea.innerHTML = '';
    placeholder.style.display = 'none';
    showStatus(`Looking up ${escapeHtml(target)}...`);

    // Cancel any existing poll
    if (state.pollingInterval) {
      clearInterval(state.pollingInterval);
      state.pollingInterval = null;
    }

    try {
      const res = await fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, target: target.trim() }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        showError(errData.error || `Server error: ${res.status}`);
        return;
      }

      const data = await res.json();

      if (data.status === 'complete' || data.status === 'completed') {
        // Synchronous completion
        hideStatus();
        if (data.result) {
          showResults(data.result, type);
        } else {
          showError('No results returned.');
        }
        return;
      }

      if (data.task_id) {
        state.activeTaskId = data.task_id;
        showStatus('Task queued — waiting for results...');
        // Start polling
        pollTask(data.task_id);
      } else {
        showError('No task_id returned from server.');
      }
    } catch (err) {
      showError('Network error: could not reach server.');
    }
  }

  // ─── Show Results ───────────────────────────────────────────────
  function showResults(results, type) {
    if (!results) {
      showError('No results returned.');
      return;
    }

    // Save to history
    const target = queryInput.value.trim();
    if (target) {
      state.history.push({ type, target, time: Date.now() });
      if (state.history.length > 100) state.history.shift();
      saveHistory();
      renderHistory();
    }

    let html = `<div class="results-header">Results for ${escapeHtml(target || '')} (${escapeHtml(type)})</div>`;

    // ─── Email ──────────────────────────────────────────────────
    if (type === 'email') {
      if (results.hunter_verification) {
        html += `<div class="result-section"><h3>🛡️ Hunter Verification</h3>${kv(results.hunter_verification)}</div>`;
      }
      if (results.gravatar) {
        html += `<div class="result-section"><h3>👤 Gravatar</h3>${kv(results.gravatar)}</div>`;
      }
      if (results.emailrep) {
        html += `<div class="result-section"><h3>📊 EmailRep</h3>${kv(results.emailrep)}</div>`;
      }
      if (results.mx_records && results.mx_records.length) {
        html += `<div class="result-section"><h3>📧 MX Records</h3><ul>${results.mx_records.map((m) => `<li>${escapeHtml(m)}</li>`).join('')}</ul></div>`;
      }
      if (results.dehashed) {
        html += `<div class="result-section"><h3>🔓 Dehashed</h3>${kv(results.dehashed)}</div>`;
      }
      if (results.social_profiles && results.social_profiles.length) {
        html += `<div class="result-section"><h3>🌐 Social Profiles</h3><ul>${results.social_profiles.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ul></div>`;
      }
    }

    // ─── Username ───────────────────────────────────────────────
    if (type === 'username') {
      if (results.social_media && Object.keys(results.social_media).length) {
        html += `<div class="result-section"><h3>🌍 Social Media</h3>${kv(results.social_media)}</div>`;
      }
      if (results.google_mentions && results.google_mentions.length) {
        html += `<div class="result-section"><h3>🔍 Google Mentions</h3><ul>${results.google_mentions.map((g) => `<li>${escapeHtml(g)}</li>`).join('')}</ul></div>`;
      }
    }

    // ─── Phone ──────────────────────────────────────────────────
    if (type === 'phone') {
      if (results.parsed) {
        html += `<div class="result-section"><h3>📞 Parsed Number</h3>${kv(results.parsed)}</div>`;
      }
      if (results.country) {
        html += `<div class="result-section"><h3>🌍 Country</h3><p>${escapeHtml(results.country)}</p></div>`;
      }
      if (results.carrier) {
        html += `<div class="result-section"><h3>📡 Carrier</h3><p>${escapeHtml(results.carrier)}</p></div>`;
      }
      if (results.number_type) {
        html += `<div class="result-section"><h3>🏷️ Type</h3><p>${escapeHtml(results.number_type)}</p></div>`;
      }
      if (results.timezones && results.timezones.length) {
        html += `<div class="result-section"><h3>🕐 Timezones</h3><ul>${results.timezones.map((t) => `<li>${escapeHtml(t)}</li>`).join('')}</ul></div>`;
      }
    }

    // ─── Domain ─────────────────────────────────────────────────
    if (type === 'domain') {
      if (results.dns_records && Object.keys(results.dns_records).length) {
        html += `<div class="result-section"><h3>🌐 DNS Records</h3>${kv(results.dns_records)}</div>`;
      }
      if (results.whois) {
        html += `<div class="result-section"><h3>📋 WHOIS</h3>${kv(results.whois)}</div>`;
      }
      if (results.virustotal) {
        html += `<div class="result-section"><h3>🛡️ VirusTotal</h3>${kv(results.virustotal)}</div>`;
      }
      if (results.security_headers && Object.keys(results.security_headers).length) {
        html += `<div class="result-section"><h3>🔒 Security Headers</h3>${kv(results.security_headers)}</div>`;
      }
      if (results.technology && results.technology.length) {
        html += `<div class="result-section"><h3>⚙️ Technology Stack</h3><ul>${results.technology.map((t) => `<li>${escapeHtml(t)}</li>`).join('')}</ul></div>`;
      }
      if (results.subdomains && results.subdomains.length) {
        html += `<div class="result-section"><h3>📂 Subdomains (${results.subdomains.length})</h3><ul>${results.subdomains.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ul></div>`;
      }
      if (results.open_ports && results.open_ports.length) {
        html += `<div class="result-section"><h3>🔌 Open Ports</h3><ul>${results.open_ports.map((p) => `<li>Port ${escapeHtml(String(p))}</li>`).join('')}</ul></div>`;
      }
      if (results.wayback && results.wayback.length) {
        html += `<div class="result-section"><h3>📜 Wayback Machine</h3><ul>${results.wayback.map((w) => `<li><a href="https://web.archive.org/web/${w.date}/${encodeURIComponent(w.url)}" target="_blank">${escapeHtml(w.date)} — ${escapeHtml(w.url)}</a></li>`).join('')}</ul></div>`;
      }
      if (results.zone_transfer && results.zone_transfer.length) {
        html += `<div class="result-section"><h3>⚠️ Zone Transfer</h3><ul>${results.zone_transfer.map((z) => `<li>${escapeHtml(z)}</li>`).join('')}</ul></div>`;
      }
    }

    // ─── IP ─────────────────────────────────────────────────────
    if (type === 'ip') {
      if (results.hostname) {
        html += `<div class="result-section"><h3>🏠 Hostname</h3><p>${escapeHtml(results.hostname)}</p></div>`;
      }
      if (results.geo) {
        html += `<div class="result-section"><h3>🌍 Geolocation</h3>${kv(results.geo)}</div>`;
      }
      if (results.reverse_dns && results.reverse_dns.length) {
        html += `<div class="result-section"><h3>🔄 Reverse DNS</h3><ul>${results.reverse_dns.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul></div>`;
      }
      if (results.shodan) {
        let shodanHtml = kv(results.shodan, 'org', 'isp', 'os', 'hostnames');
        if (results.shodan.services) {
          shodanHtml += '<h4>Services:</h4><ul>';
          results.shodan.services.forEach((s) => {
            shodanHtml += `<li>Port ${s.port} — ${escapeHtml(s.service || s.name || '?')}</li>`;
          });
          shodanHtml += '</ul>';
        }
        if (results.shodan.vulns && results.shodan.vulns.length) {
          shodanHtml += '<h4>Vulnerabilities:</h4><ul>';
          results.shodan.vulns.forEach((v) => {
            shodanHtml += `<li>${escapeHtml(v)}</li>`;
          });
          shodanHtml += '</ul>';
        }
        html += `<div class="result-section"><h3>⚡ Shodan</h3>${shodanHtml}</div>`;
      }
      if (results.virustotal) {
        html += `<div class="result-section"><h3>🛡️ VirusTotal</h3>${kv(results.virustotal)}</div>`;
      }
      if (results.open_ports && results.open_ports.length) {
        html += `<div class="result-section"><h3>🔌 Open Ports (${results.open_ports.length})</h3><ul>${results.open_ports.map((p) => `<li>Port ${escapeHtml(String(p))}</li>`).join('')}</ul></div>`;
      }
      if (results.banners) {
        let bannerHtml = '';
        Object.entries(results.banners).forEach(([port, banner]) => {
          bannerHtml += `<p><strong>Port ${escapeHtml(port)}:</strong> ${escapeHtml(banner)}</p>`;
        });
        html += `<div class="result-section"><h3>📡 Service Banners</h3>${bannerHtml}</div>`;
      }
      if (results.rdap) {
        let rdapHtml = '';
        if (results.rdap.handle) rdapHtml += `<p><strong>Handle:</strong> ${escapeHtml(results.rdap.handle)}</p>`;
        if (results.rdap.name) rdapHtml += `<p><strong>Org:</strong> ${escapeHtml(results.rdap.name)}</p>`;
        if (results.rdap.org_name) rdapHtml += `<p><strong>Org Name:</strong> ${escapeHtml(results.rdap.org_name)}</p>`;
        if (results.rdap.country) rdapHtml += `<p><strong>Country:</strong> ${escapeHtml(results.rdap.country)}</p>`;
        if (results.rdap.emails && results.rdap.emails.length) {
          rdapHtml += `<p><strong>Emails:</strong> ${results.rdap.emails.map((e) => escapeHtml(e)).join(', ')}</p>`;
        }
        if (rdapHtml) html += `<div class="result-section"><h3>📋 RDAP</h3>${rdapHtml}</div>`;
      }
      if (results.abuse_score) {
        html += `<div class="result-section"><h3>🚨 AbuseIPDB</h3><p><strong>Confidence Score:</strong> ${escapeHtml(results.abuse_score)}</p></div>`;
      }
    }

    // ─── Fallback for any raw data keys ──────────────────────────
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
        html += `<div class="result-section"><h3>📎 ${escapeHtml(k.replace(/_/g, ' '))}</h3><ul>${v.map((item) => typeof item === 'string' ? `<li>${escapeHtml(item)}</li>` : '').join('')}</ul></div>`;
      }
    });

    if (!html) {
      html = '<div class="result-section"><p>No intelligence data returned for this target.</p></div>';
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
