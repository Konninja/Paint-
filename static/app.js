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
    area.innerHTML = `<div class="placeholder"><div class="spinner" style="width:32px;height:32px;"></div><p>Gathering intelligence...</p></div>`;
  }

  // ─── Search ─────────────────────────────────────────────────────
  function doSearch(type, target) {
    if (!target) return;
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
        setStatus('Processing...', 10);
        startPolling(data.task_id, type, target);
      })
      .catch((err) => {
        showError('Network error: ' + err.message);
        searchBtn.disabled = false;
        searchBtn.textContent = 'Search';
        hideStatus();
        addToHistory(type, target, 'error');
      });
  }

  // ─── Polling ────────────────────────────────────────────────────
  function startPolling(taskId, type, target) {
    if (state.pollingInterval) clearInterval(state.pollingInterval);
    state.pollingInterval = setInterval(() => pollTask(taskId, type, target), 800);
  }

  function pollTask(taskId, type, target) {
    fetch('/api/status/' + taskId)
      .then((r) => r.json())
      .then((task) => {
        if (task.error) {
          clearInterval(state.pollingInterval);
          state.pollingInterval = null;
          showError(task.error);
          searchBtn.disabled = false;
          searchBtn.textContent = 'Search';
          hideStatus();
          addToHistory(type, target, 'error');
          return;
        }

        setStatus(
          task.status === 'running' ? 'Analyzing...' : task.status === 'complete' ? 'Complete' : 'Error',
          task.progress || 0
        );

        if (task.status === 'complete') {
          clearInterval(state.pollingInterval);
          state.pollingInterval = null;
          renderResults(task.results, type, target);
          searchBtn.disabled = false;
          searchBtn.textContent = 'Search';
          setTimeout(hideStatus, 2000);
          addToHistory(type, target, 'done');
        } else if (task.status === 'error') {
          clearInterval(state.pollingInterval);
          state.pollingInterval = null;
          showError(task.error || 'Unknown error occurred');
          searchBtn.disabled = false;
          searchBtn.textContent = 'Search';
          hideStatus();
          addToHistory(type, target, 'error');
        }
      })
      .catch(() => {});
  }

  // ─── Render Results ─────────────────────────────────────────────
  function renderResults(results, type, target) {
    if (!results || results.error) {
      showError(results ? results.error : 'No results returned');
      return;
    }

    let html = '';

    // Helper: key-value table
    const kv = (obj, keys) => {
      if (!obj) return '';
      return Object.entries(obj)
        .filter(([, v]) => v !== null && v !== undefined && v !== '')
        .map(([k, v]) => {
          const label = k.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
          let val = v;
          if (typeof v === 'object') val = `<pre class="code-block">${escapeHtml(JSON.stringify(v, null, 2))}</pre>`;
          else if (typeof v === 'boolean') val = v ? '<span class="tag tag-success">Yes</span>' : '<span class="tag tag-danger">No</span>';
          else val = escapeHtml(String(v));
          return `<tr><th>${label}</th><td>${val}</td></tr>`;
        })
        .join('');
    };

    // Email results
    if (type === 'email') {
      if (results.hunter_verification) {
        html += `<div class="result-section"><h3>🔍 Hunter.io Verification</h3><table class="result-table">${kv(results.hunter_verification)}</table></div>`;
      }
      if (results.gravatar) {
        html += `<div class="result-section"><h3>🪐 Gravatar</h3><table class="result-table">${kv(results.gravatar)}</table></div>`;
      }
      if (results.emailrep) {
        html += `<div class="result-section"><h3>📊 EmailRep.io</h3><table class="result-table">${kv(results.emailrep)}</table></div>`;
      }
      if (results.mx_records) {
        const rows = results.mx_records.map(
          (mx) => `<tr><th>MX</th><td>${escapeHtml(mx.host)} (priority ${mx.priority})</td></tr>`
        ).join('');
        html += `<div class="result-section"><h3>📧 MX Records</h3><table class="result-table">${rows}</table></div>`;
      }
      if (results.dehashed) {
        html += `<div class="result-section"><h3>⚠️ Dehashed Breach Data</h3><p style="color:var(--danger);margin-bottom:10px;">${results.dehashed.total} entries found</p>`;
        if (results.dehashed.entries) {
          html += results.dehashed.entries.map((e) =>
            `<div class="code-block">
              ${e.email ? 'Email: ' + escapeHtml(e.email) : ''}
              ${e.username ? ' | User: ' + escapeHtml(e.username) : ''}
              ${e.password ? ' | Pass: ' + escapeHtml(e.password) : ''}
              ${e.name ? ' | Name: ' + escapeHtml(e.name) : ''}
              ${e.database_name ? ' | DB: ' + escapeHtml(e.database_name) : ''}
            </div>`
          ).join('');
        }
        html += `</div>`;
      }
      if (results.social_profiles) {
        const links = Object.entries(results.social_profiles).filter(([, v]) => v);
        if (links.length) {
          html += `<div class="result-section"><h3>🔗 Social Profiles</h3><div class="list-compact">`;
          links.forEach(([site, url]) => {
            html += `<a href="${escapeHtml(url)}" target="_blank" class="item" style="color:var(--accent);text-decoration:none;">${escapeHtml(site)}</a>`;
          });
          html += `</div></div>`;
        }
      }
    }

    // Username results
    if (type === 'username') {
      if (results.social_media && Object.keys(results.social_media).length) {
        html += `<div class="result-section"><h3>🔗 Social Media Profiles Found</h3><div class="list-compact">`;
        Object.entries(results.social_media).forEach(([name, url]) => {
          html += `<a href="${escapeHtml(url)}" target="_blank" class="item" style="color:var(--accent);text-decoration:none;">${escapeHtml(name)}</a>`;
        });
        html += `</div></div>`;
      } else {
        html += `<div class="result-section"><h3>🔗 Social Media</h3><p style="color:var(--text-secondary);">No social media profiles found</p></div>`;
      }
      if (results.dehashed) {
        html += `<div class="result-section"><h3>⚠️ Dehashed Breach Data</h3><p style="color:var(--danger);margin-bottom:10px;">${results.dehashed.total} entries found</p>`;
        if (results.dehashed.entries) {
          html += results.dehashed.entries.map((e) =>
            `<div class="code-block">
              ${e.email ? 'Email: ' + escapeHtml(e.email) : ''}
              ${e.name ? ' | Name: ' + escapeHtml(e.name) : ''}
              ${e.password ? ' | Pass: ' + escapeHtml(e.password) : ''}
              ${e.database_name ? ' | DB: ' + escapeHtml(e.database_name) : ''}
            </div>`
          ).join('');
        }
        html += `</div>`;
      }
      if (results.google_mentions && results.google_mentions.length) {
        html += `<div class="result-section"><h3>🌐 Google Mentions</h3><div class="list-compact">`;
        results.google_mentions.forEach((url) => {
          html += `<a href="${escapeHtml(url)}" target="_blank" class="item" style="color:var(--accent);text-decoration:none;max-width:300px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(url)}</a>`;
        });
        html += `</div></div>`;
      }
    }

    // Phone results
    if (type === 'phone') {
      if (results.parsed) {
        html += `<div class="result-section"><h3>📞 Phone Number Details</h3><table class="result-table">${kv(results.parsed)}</table></div>`;
      }
      if (results.country) {
        html += `<div class="result-section"><h3>🌍 Location</h3><table class="result-table"><tr><th>Country</th><td>${escapeHtml(results.country)}</td></tr><tr><th>Carrier</th><td>${escapeHtml(results.carrier || 'Unknown')}</td></tr><tr><th>Type</th><td>${escapeHtml(results.number_type || 'Unknown')}</td></tr></table></div>`;
      }
      if (results.dehashed) {
        html += `<div class="result-section"><h3>⚠️ Dehashed Breach Data</h3><p style="color:var(--danger);margin-bottom:10px;">${results.dehashed.total} entries found</p>`;
        if (results.dehashed.entries) {
          html += results.dehashed.entries.map((e) =>
            `<div class="code-block">
              ${e.name ? 'Name: ' + escapeHtml(e.name) : ''}
              ${e.email ? ' | Email: ' + escapeHtml(e.email) : ''}
              ${e.address ? ' | Address: ' + escapeHtml(e.address) : ''}
              ${e.database_name ? ' | DB: ' + escapeHtml(e.database_name) : ''}
            </div>`
          ).join('');
        }
        html += `</div>`;
      }
    }

    // Domain results
    if (type === 'domain') {
      if (results.dns_records) {
        const dnsHtml = Object.entries(results.dns_records)
          .filter(([, v]) => v.length)
          .map(([rtype, records]) =>
            `<tr><th>${rtype}</th><td>${records.map((r) => `<span class="item" style="font-family:monospace;">${escapeHtml(String(r))}</span>`).join(' ')}</td></tr>`
          ).join('');
        if (dnsHtml) {
          html += `<div class="result-section"><h3>🌐 DNS Records</h3><table class="result-table">${dnsHtml}</table></div>`;
        }
      }
      if (results.whois) {
        html += `<div class="result-section"><h3>📋 WHOIS</h3><table class="result-table">${kv(results.whois)}</table></div>`;
      }
      if (results.virustotal) {
        html += `<div class="result-section"><h3>🛡️ VirusTotal</h3><table class="result-table">${kv(results.virustotal)}</table></div>`;
      }
      if (results.security_headers && !results.security_headers.error) {
        html += `<div class="result-section"><h3>🔒 Security Headers</h3><table class="result-table">${kv(results.security_headers)}</table></div>`;
      }
      if (results.technology && results.technology.length) {
        html += `<div class="result-section"><h3>⚙️ Technology Stack</h3><div class="list-compact">`;
        results.technology.forEach((t) => {
          html += `<span class="item">${escapeHtml(t)}</span>`;
        });
        html += `</div></div>`;
      }
      if (results.subdomains && results.subdomains.length) {
        html += `<div class="result-section"><h3>🔗 Subdomains (${results.subdomains.length})</h3><div class="list-compact">`;
        results.subdomains.forEach((s) => {
          html += `<span class="item">${escapeHtml(s)}</span>`;
        });
        html += `</div></div>`;
      }
      if (results.open_ports && results.open_ports.length) {
        html += `<div class="result-section"><h3>🔌 Open Ports</h3><div class="list-compact">`;
        results.open_ports.forEach((p) => {
          html += `<span class="item">Port ${p}</span>`;
        });
        html += `</div></div>`;
      }
      if (results.wayback && results.wayback.length) {
        html += `<div class="result-section"><h3>📜 Wayback Machine Snapshots</h3><div class="list-compact">`;
        results.wayback.forEach((w) => {
          html += `<div class="code-block" style="margin:2px 0;font-size:0.75rem;">
            <a href="https://web.archive.org/web/${w.date}/${escapeHtml(w.url)}" target="_blank" style="color:var(--accent);">
              ${escapeHtml(w.date)} — ${escapeHtml(w.url)}
            </a>
          </div>`;
        });
        html += `</div></div>`;
      }
      if (results.zone_transfer && results.zone_transfer.length) {
        html += `<div class="result-section"><h3>⚠️ Zone Transfer (Successful!)</h3><div class="list-compact">`;
        results.zone_transfer.forEach((z) => {
          html += `<span class="item">${escapeHtml(z)}</span>`;
        });
        html += `</div></div>`;
      }
    }

    // IP results
    if (type === 'ip') {
      if (results.hostname) {
        html += `<div class="result-section"><h3>🏠 Hostname</h3><table class="result-table"><tr><th>PTR</th><td>${escapeHtml(results.hostname)}</td></tr></table></div>`;
      }
      if (results.geo) {
        html += `<div class="result-section"><h3>🌍 Geolocation</h3><table class="result-table">${kv(results.geo)}</table></div>`;
      }
      if (results.reverse_dns && results.reverse_dns.length) {
        html += `<div class="result-section"><h3>🔄 Reverse DNS</h3><div class="list-compact">`;
        results.reverse_dns.forEach((r) => html += `<span class="item">${escapeHtml(r)}</span>`);
        html += `</div></div>`;
      }
      if (results.shodan) {
        html += `<div class="result-section"><h3>⚡ Shodan</h3><table class="result-table">${kv(results.shodan, 'org', 'isp', 'os', 'hostnames')}</table>`;
        if (results.shodan.services) {
          html += `<div style="margin-top:8px;"><strong>Services:</strong><div class="list-compact">`;
          results.shodan.services.forEach((s) => {
            html += `<span class="item">Port ${s.port} — ${escapeHtml(s.service || s.name || '?')}</span>`;
          });
          html += `</div></div>`;
        }
        if (results.shodan.vulns && results.shodan.vulns.length) {
          html += `<div style="margin-top:8px;"><strong>Vulnerabilities:</strong><div class="list-compact">`;
          results.shodan.vulns.forEach((v) => {
            html += `<span class="tag tag-danger">${escapeHtml(v)}</span>`;
          });
          html += `</div></div>`;
        }
        html += `</div>`;
      }
      if (results.virustotal) {
        html += `<div class="result-section"><h3>🛡️ VirusTotal</h3><table class="result-table">${kv(results.virustotal)}</table></div>`;
      }
      if (results.open_ports && results.open_ports.length) {
        html += `<div class="result-section"><h3>🔌 Open Ports (${results.open_ports.length})</h3><div class="list-compact">`;
        results.open_ports.forEach((p) => {
          html += `<span class="item">Port ${p}</span>`;
        });
        html += `</div></div>`;
      }
      if (results.banners) {
        html += `<div class="result-section"><h3>📡 Service Banners</h3><table class="result-table">`;
        Object.entries(results.banners).forEach(([port, banner]) => {
          html += `<tr><th>Port ${port}</th><td class="code-block">${escapeHtml(banner)}</td></tr>`;
        });
        html += `</table></div>`;
      }
      if (results.rdap) {
        let rdapHtml = '';
        if (results.rdap.handle) rdapHtml += `<tr><th>Handle</th><td>${escapeHtml(results.rdap.handle)}</td></tr>`;
        if (results.rdap.name) rdapHtml += `<tr><th>Org</th><td>${escapeHtml(results.rdap.name)}</td></tr>`;
        if (results.rdap.org_name) rdapHtml += `<tr><th>Org Name</th><td>${escapeHtml(results.rdap.org_name)}</td></tr>`;
        if (results.rdap.country) rdapHtml += `<tr><th>Country</th><td>${escapeHtml(results.rdap.country)}</td></tr>`;
        if (results.rdap.emails && results.rdap.emails.length) {
          rdapHtml += `<tr><th>Emails</th><td>${results.rdap.emails.map(e => escapeHtml(e)).join(', ')}</td></tr>`;
        }
        if (rdapHtml) {
          html += `<div class="result-section"><h3>📋 RDAP</h3><table class="result-table">${rdapHtml}</table></div>`;
        }
      }
      if (results.abuse_score) {
        html += `<div class="result-section"><h3>🚨 AbuseIPDB</h3><table class="result-table"><tr><th>Confidence Score</th><td>${escapeHtml(results.abuse_score)}</td></tr></table></div>`;
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
        html += `<div class="result-section"><h3>📎 ${escapeHtml(k.replace(/_/g, ' '))}</h3><table class="result-table">${kv(v)}</table></div>`;
      } else if (v && Array.isArray(v) && v.length) {
        html += `<div class="result-section"><h3>📎 ${escapeHtml(k.replace(/_/g, ' '))}</h3><div class="list-compact">`;
        v.forEach((item) => {
          if (typeof item === 'string') html += `<span class="item">${escapeHtml(item)}</span>`;
        });
        html += `</div></div>`;
      }
    });

    if (!html) {
      html = `<div class="placeholder"><p>No intelligence data returned for this target.</p></div>`;
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
