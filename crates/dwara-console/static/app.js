// dwara console v2 -- CRUD + fleet views (Enterprise)
// Fetches from the admin API (same origin, mTLS listener).
// No build step, no dependencies, vanilla JS.

(function () {
  'use strict';

  var currentView = 'overview';
  var refreshTimer = null;
  var REFRESH_INTERVAL = 5000; // 5 seconds

  // --- API helpers ---

  function fetchJSON(path) {
    return fetch(path, { headers: { 'Accept': 'application/json' } })
      .then(function (resp) {
        if (!resp.ok) throw new Error('HTTP ' + resp.status + ' for ' + path);
        return resp.json();
      });
  }

  function fetchText(path) {
    return fetch(path).then(function (resp) {
      if (!resp.ok) throw new Error('HTTP ' + resp.status + ' for ' + path);
      return resp.text();
    });
  }

  // --- Rendering ---

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        if (k === 'class') node.className = attrs[k];
        else if (k === 'text') node.textContent = attrs[k];
        else node.setAttribute(k, attrs[k]);
      }
    }
    if (children) {
      if (typeof children === 'string') node.textContent = children;
      else if (Array.isArray(children))
        children.forEach(function (c) { if (c) node.appendChild(c); });
      else if (children) node.appendChild(children);
    }
    return node;
  }

  function card(title, bodyNode, refreshHandler) {
    var header = el('div', {}, [
      el('h2', { text: title }),
    ]);
    if (refreshHandler) {
      var btn = el('button', { class: 'refresh-btn', text: 'Refresh' });
      btn.addEventListener('click', refreshHandler);
      header.appendChild(btn);
    }
    var c = el('div', { class: 'card' }, [header, bodyNode]);
    return c;
  }

  function renderError(msg) {
    var content = document.getElementById('content');
    content.innerHTML = '';
    content.appendChild(el('div', { class: 'error-msg', text: msg }));
  }

  function setLastRefresh() {
    document.getElementById('last-refresh').textContent =
      'Updated ' + new Date().toLocaleTimeString();
  }

  function setStatusBadge(status) {
    var badge = document.getElementById('status-badge');
    badge.className = status;
    badge.textContent = status;
  }

  // --- Views ---

  function renderOverview() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var grid = el('div', { class: 'stat-grid' });
    content.appendChild(card('Gateway Overview', grid));

    // Fetch health + stats + config_dump in parallel.
    Promise.all([fetchJSON('/health'), fetchJSON('/stats'), fetchJSON('/config_dump')])
      .then(function (results) {
        var health = results[0];
        var stats = results[1];
        var config = results[2];

        // Health status: /health returns {ready, config_generation, upstreams}.
        var isReady = health.ready !== false;
        var healthStatus = isReady ? 'ok' : 'degraded';
        setStatusBadge(isReady ? 'healthy' : 'unhealthy');

        grid.appendChild(makeStat('Status', healthStatus));
        grid.appendChild(makeStat('Active Requests', stats.active_requests || 0));
        grid.appendChild(makeStat('Config Generation', health.config_generation || 'n/a'));
        grid.appendChild(makeStat('Routes', (config.routes || []).length));
        grid.appendChild(makeStat('Listeners', (config.listeners || []).length));
        grid.appendChild(makeStat('Upstreams', Object.keys(health.upstreams || {}).length));

        setLastRefresh();
      })
      .catch(function (err) {
        setStatusBadge('unhealthy');
        grid.appendChild(makeStat('Error', err.message));
      });
  }

  function makeStat(label, value) {
    return el('div', { class: 'stat' }, [
      el('div', { class: 'stat-label', text: label }),
      el('div', { class: 'stat-value', text: String(value) }),
    ]);
  }

  function formatUptime(secs) {
    if (!secs) return 'n/a';
    var h = Math.floor(secs / 3600);
    var m = Math.floor((secs % 3600) / 60);
    return h + 'h ' + m + 'm';
  }

  function renderRoutes() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var tableWrap = el('div');
    content.appendChild(card('Routes', tableWrap, renderRoutes));
    tableWrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    fetchJSON('/config_dump')
      .then(function (config) {
        tableWrap.innerHTML = '';
        var routes = config.routes || [];
        if (routes.length === 0) {
          tableWrap.appendChild(el('p', { text: 'No routes configured.' }));
          return;
        }
        var table = el('table');
        table.appendChild(el('thead', {}, el('tr', {}, [
          el('th', { text: 'Name' }),
          el('th', { text: 'Path' }),
          el('th', { text: 'Service' }),
          el('th', { text: 'Methods' }),
        ])));
        var tbody = el('tbody');
        routes.forEach(function (r) {
          var pathMatch = r.match && r.match.path;
          var pathStr = '';
          if (pathMatch) {
            pathStr = (pathMatch.type || '') + ': ' + (pathMatch.value || '');
          }
          var methods = (r.match && r.match.methods) || ['*'];
          tbody.appendChild(el('tr', {}, [
            el('td', { text: r.name || '' }),
            el('td', { text: pathStr }),
            el('td', { text: r.service || '' }),
            el('td', { text: methods.join(', ') }),
          ]));
        });
        table.appendChild(tbody);
        tableWrap.appendChild(table);
        setLastRefresh();
      })
      .catch(function (err) {
        tableWrap.innerHTML = '';
        tableWrap.appendChild(el('div', { class: 'error-msg', text: err.message }));
      });
  }

  function renderUpstreams() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var tableWrap = el('div');
    content.appendChild(card('Upstreams / Services', tableWrap, renderUpstreams));
    tableWrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    fetchJSON('/health')
      .then(function (health) {
        tableWrap.innerHTML = '';
        var upstreams = health.upstreams || {};
        var rows = [];
        for (var upName in upstreams) {
          if (!Object.prototype.hasOwnProperty.call(upstreams, upName)) continue;
          var endpoints = upstreams[upName].endpoints || {};
          for (var addr in endpoints) {
            if (!Object.prototype.hasOwnProperty.call(endpoints, addr)) continue;
            rows.push({ service: upName, address: addr, health: endpoints[addr] });
          }
        }
        if (rows.length === 0) {
          tableWrap.appendChild(el('p', { text: 'No upstream data available.' }));
          return;
        }
        var table = el('table');
        table.appendChild(el('thead', {}, el('tr', {}, [
          el('th', { text: 'Service' }),
          el('th', { text: 'Address' }),
          el('th', { text: 'Health' }),
        ])));
        var tbody = el('tbody');
        rows.forEach(function (u) {
          var healthClass = 'health-ok';
          if (u.health === 'down') healthClass = 'health-down';
          else if (u.health === 'degraded' || u.health === 'half_open') healthClass = 'health-degraded';
          else if (u.health === 'ejected') healthClass = 'health-down';
          tbody.appendChild(el('tr', {}, [
            el('td', { text: u.service || '' }),
            el('td', { text: u.address || '' }),
            el('td', { class: healthClass, text: u.health || 'unknown' }),
          ]));
        });
        table.appendChild(tbody);
        tableWrap.appendChild(table);
        setLastRefresh();
      })
      .catch(function (err) {
        tableWrap.innerHTML = '';
        tableWrap.appendChild(el('div', { class: 'error-msg', text: err.message }));
      });
  }

  function renderHealth() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var wrap = el('div');
    content.appendChild(card('Health', wrap, renderHealth));
    wrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    fetchJSON('/health')
      .then(function (health) {
        wrap.innerHTML = '';
        var pre = el('pre');
        pre.textContent = JSON.stringify(health, null, 2);
        wrap.appendChild(pre);

        var status = health.ready ? 'ok' : 'degraded';
        setStatusBadge(health.ready ? 'healthy' : 'unhealthy');
        setLastRefresh();
      })
      .catch(function (err) {
        wrap.innerHTML = '';
        wrap.appendChild(el('div', { class: 'error-msg', text: err.message }));
        setStatusBadge('unhealthy');
      });
  }

  function renderAnalytics() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var wrap = el('div');
    content.appendChild(card('Analytics Top-N', wrap, renderAnalytics));
    wrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    // /analytics/top requires kind + from_ms + to_ms epoch-millisecond bounds.
    var now = Date.now();
    var fromMs = now - 3600000; // last 1 hour
    var toMs = now;
    fetchJSON('/analytics/top?kind=routes&from_ms=' + fromMs + '&to_ms=' + toMs + '&limit=10')
      .then(function (data) {
        wrap.innerHTML = '';
        var pre = el('pre');
        pre.textContent = JSON.stringify(data, null, 2);
        wrap.appendChild(pre);
        setLastRefresh();
      })
      .catch(function (err) {
        wrap.innerHTML = '';
        wrap.appendChild(el('div', { class: 'error-msg', text: err.message }));
      });
  }

  function renderConfig() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var wrap = el('div');
    content.appendChild(card('Current Config (YAML)', wrap, renderConfig));
    wrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    // /config returns the YAML text (application/yaml); /config_dump
    // returns the typed JSON. Display the YAML for readability.
    fetchText('/config')
      .then(function (yaml) {
        wrap.innerHTML = '';
        var pre = el('pre');
        pre.textContent = yaml;
        wrap.appendChild(pre);
        setLastRefresh();
      })
      .catch(function (err) {
        wrap.innerHTML = '';
        wrap.appendChild(el('div', { class: 'error-msg', text: err.message }));
      });
  }

  // --- DW-118: Fleet view ---

  function renderFleet() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var wrap = el('div');
    content.appendChild(card('Fleet Operations', wrap, renderFleet));
    wrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    // Fetch skew + status in parallel.
    Promise.all([fetchJSON('/fleet/skew'), fetchJSON('/fleet/status')])
      .then(function (results) {
        var skew = results[0];
        var status = results[1];
        wrap.innerHTML = '';

        // Skew check card.
        var skewCard = el('div', { class: 'fleet-card' });
        skewCard.appendChild(el('h3', { text: 'Version Skew Check' }));
        var skewClass = skew.compatible ? 'skew-ok' : 'skew-bad';
        skewCard.appendChild(el('div', { class: 'label', text: 'Policy' }));
        skewCard.appendChild(el('div', { class: 'value', text: skew.skew_policy || 'n/a' }));
        skewCard.appendChild(el('div', { class: 'label', text: 'Controller Version' }));
        skewCard.appendChild(
          el('div', { class: 'value' }, [
            el('span', { class: 'version-badge current', text: skew.controller_version || 'n/a' }),
          ])
        );
        skewCard.appendChild(el('div', { class: 'label', text: 'This Instance' }));
        skewCard.appendChild(
          el('div', { class: 'value' }, [
            el(
              'span',
              { class: 'version-badge ' + (skew.compatible ? 'current' : 'skewed') },
              skew.this_version || 'n/a'
            ),
          ])
        );
        skewCard.appendChild(el('div', { class: 'label', text: 'Compatible' }));
        skewCard.appendChild(
          el('div', { class: 'value ' + skewClass, text: skew.compatible ? 'yes' : 'no' })
        );

        // Fleet status card.
        var statusCard = el('div', { class: 'fleet-card' });
        statusCard.appendChild(el('h3', { text: 'Fleet Status' }));
        statusCard.appendChild(el('div', { class: 'label', text: 'Enabled' }));
        statusCard.appendChild(
          el('div', { class: 'value', text: status.enabled ? 'yes' : 'no' })
        );
        statusCard.appendChild(el('div', { class: 'label', text: 'Stale Timeout (s)' }));
        statusCard.appendChild(
          el('div', { class: 'value', text: String(status.stale_timeout_secs || 'n/a') })
        );

        if (status.upgrade) {
          var up = status.upgrade;
          statusCard.appendChild(el('div', { class: 'label', text: 'Skew Policy' }));
          statusCard.appendChild(el('div', { class: 'value', text: up.skew || 'n/a' }));
          statusCard.appendChild(el('div', { class: 'label', text: 'Max Concurrent' }));
          statusCard.appendChild(
            el('div', { class: 'value', text: String(up.max_concurrent || 0) })
          );
          statusCard.appendChild(el('div', { class: 'label', text: 'Halt on Failure' }));
          statusCard.appendChild(
            el('div', { class: 'value', text: up.halt_on_failure ? 'yes' : 'no' })
          );

          if (up.order && up.order.length > 0) {
            statusCard.appendChild(el('div', { class: 'label', text: 'Upgrade Order' }));
            var orderList = el('ol');
            up.order.forEach(function (entry) {
              var labels = Object.keys(entry.labels || {})
                .map(function (k) {
                  return k + '=' + entry.labels[k];
                })
                .join(', ');
              orderList.appendChild(
                el('li', {}, entry.name + ' (' + labels + ')')
              );
            });
            statusCard.appendChild(orderList);
          }
        }

        var grid = el('div', { class: 'fleet-grid' });
        grid.appendChild(skewCard);
        grid.appendChild(statusCard);
        wrap.appendChild(grid);
        setLastRefresh();
      })
      .catch(function (err) {
        wrap.innerHTML = '';
        if (err.message && err.message.indexOf('404') >= 0) {
          wrap.appendChild(
            el('div', { class: 'error-msg', text: 'Fleet operations not configured (no fleet: block in config).' })
          );
        } else {
          wrap.appendChild(el('div', { class: 'error-msg', text: err.message }));
        }
      });
  }

  // --- DW-118: Config editor with validation preview ---

  var editorState = { yaml: '', dirty: false };

  function renderEditor() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var wrap = el('div');
    content.appendChild(card('Config Editor', wrap));

    // Toolbar.
    var toolbar = el('div', { class: 'editor-toolbar' });
    var validateBtn = el('button', { class: 'btn', text: 'Validate' });
    var publishBtn = el('button', { class: 'btn primary', text: 'Publish' });
    var resetBtn = el('button', { class: 'btn', text: 'Reset to Current' });
    toolbar.appendChild(validateBtn);
    toolbar.appendChild(publishBtn);
    toolbar.appendChild(resetBtn);
    wrap.appendChild(toolbar);

    // Textarea.
    var textarea = el('textarea', { class: 'editor-area' });
    textarea.setAttribute('spellcheck', 'false');
    wrap.appendChild(textarea);

    // Validation preview area.
    var preview = el('div');
    wrap.appendChild(preview);

    // Load current config as YAML from /config (application/yaml).
    fetchText('/config')
      .then(function (yaml) {
        textarea.value = yaml;
        editorState.yaml = yaml;
        editorState.dirty = false;
        setLastRefresh();
      })
      .catch(function (err) {
        textarea.value = '# Failed to load config: ' + err.message;
      });

    // Validate button: POST /config/validate (no publish).
    validateBtn.addEventListener('click', function () {
      var body = textarea.value;
      preview.innerHTML = '';
      preview.appendChild(el('div', { class: 'stat-label', text: 'Validating...' }));
      fetch('/config/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'text/yaml' },
        body: body,
      })
        .then(function (resp) {
          return resp.json().then(function (data) {
            return { status: resp.status, data: data };
          });
        })
        .then(function (result) {
          renderValidationPreview(preview, result);
        })
        .catch(function (err) {
          preview.innerHTML = '';
          preview.appendChild(
            el('div', { class: 'validation-preview invalid', text: 'Validation request failed: ' + err.message })
          );
        });
    });

    // Publish button: PATCH /config.
    publishBtn.addEventListener('click', function () {
      if (!confirm('Publish this config? This replaces the live gateway config.')) return;
      var body = textarea.value;
      preview.innerHTML = '';
      preview.appendChild(el('div', { class: 'stat-label', text: 'Publishing...' }));
      fetch('/config', {
        method: 'PATCH',
        headers: { 'Content-Type': 'text/yaml' },
        body: body,
      })
        .then(function (resp) {
          return resp.json().then(function (data) {
            return { status: resp.status, data: data };
          });
        })
        .then(function (result) {
          if (result.status >= 200 && result.status < 300) {
            preview.appendChild(
              el('div', { class: 'validation-preview valid', text: 'Config published successfully (generation ' + (result.data.generation || '?') + ').' })
            );
            editorState.yaml = body;
            editorState.dirty = false;
          } else {
            var msg = (result.data && result.data.error && result.data.error.message) || 'Unknown error';
            preview.appendChild(
              el('div', { class: 'validation-preview invalid', text: 'Publish failed: ' + msg })
            );
          }
        })
        .catch(function (err) {
          preview.appendChild(
            el('div', { class: 'validation-preview invalid', text: 'Publish request failed: ' + err.message })
          );
        });
    });

    // Reset button: reload current config.
    resetBtn.addEventListener('click', function () {
      fetchText('/config')
        .then(function (yaml) {
          textarea.value = yaml;
          editorState.yaml = yaml;
          editorState.dirty = false;
          preview.innerHTML = '';
        })
        .catch(function (err) {
          preview.innerHTML = '';
          preview.appendChild(
            el('div', { class: 'validation-preview invalid', text: 'Reset failed: ' + err.message })
          );
        });
    });
  }

  function renderValidationPreview(container, result) {
    container.innerHTML = '';
    if (result.status === 400) {
      var msg = (result.data && result.data.error && result.data.error.message) || 'Parse error';
      container.appendChild(
        el('div', { class: 'validation-preview invalid' }, [
          el('div', { text: 'Parse error: ' + msg }),
        ])
      );
      return;
    }
    var data = result.data || {};
    var valid = data.valid !== false;
    var issues = data.issues || [];
    var cls = valid ? 'valid' : 'invalid';
    var summary = valid
      ? 'Config is valid (' + issues.length + ' issues).'
      : 'Config has ' + issues.length + ' validation issue(s):';

    var previewDiv = el('div', { class: 'validation-preview ' + cls });
    previewDiv.appendChild(el('div', { text: summary }));
    if (!valid) {
      issues.forEach(function (issue) {
        var issueDiv = el('div', { class: 'validation-issue' });
        issueDiv.appendChild(
          el('span', { class: 'field', text: issue.entity + '.' + issue.name + '.' + issue.field })
        );
        issueDiv.appendChild(el('span', { text: ' — ' + issue.message }));
        previewDiv.appendChild(issueDiv);
      });
    }
    container.appendChild(previewDiv);
  }

  // --- DW-118: Workspace switcher ---

  function initWorkspaceSwitcher() {
    var select = document.getElementById('workspace-switcher');
    if (!select) return;
    // Fetch workspaces from the admin API (DW-067). The endpoint
    // returns the list of workspaces the caller has access to.
    fetchJSON('/workspaces')
      .then(function (data) {
        var workspaces = data.workspaces || [];
        select.innerHTML = '';
        workspaces.forEach(function (ws) {
          var opt = el('option', { value: ws.name || ws.id || '', text: ws.name || ws.id || 'unknown' });
          select.appendChild(opt);
        });
        if (workspaces.length === 0) {
          select.appendChild(el('option', { value: '', text: 'default' }));
        }
      })
      .catch(function () {
        // Workspaces not configured (OSS or no ent license) — keep
        // the default option.
        select.innerHTML = '';
        select.appendChild(el('option', { value: '', text: 'default' }));
      });
    select.addEventListener('change', function () {
      var ws = select.value;
      // Refresh the current view when the workspace changes.
      var renderer = views[currentView];
      if (renderer) renderer();
    });
  }

  // --- Navigation ---

  var views = {
    overview: renderOverview,
    routes: renderRoutes,
    upstreams: renderUpstreams,
    health: renderHealth,
    analytics: renderAnalytics,
    fleet: renderFleet,
    config: renderConfig,
    editor: renderEditor,
  };

  function switchView(view) {
    currentView = view;
    document.querySelectorAll('.nav-btn').forEach(function (btn) {
      btn.classList.toggle('active', btn.dataset.view === view);
    });
    var renderer = views[view];
    if (renderer) renderer();
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    refreshTimer = setInterval(function () {
      var renderer = views[currentView];
      if (renderer) renderer();
    }, REFRESH_INTERVAL);
  }

  function stopAutoRefresh() {
    if (refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    }
  }

  // --- Init ---

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.nav-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        switchView(btn.dataset.view);
      });
    });
    initWorkspaceSwitcher();
    setStatusBadge('connecting');
    switchView('overview');
    startAutoRefresh();
  });
})();
