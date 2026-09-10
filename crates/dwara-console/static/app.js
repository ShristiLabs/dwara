// dwara console v3 -- live charts, CRUD flows, AI ops (#226)
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

  // --- #226: Live charts view ---

  var liveState = { history: [], maxPoints: 60 };

  function renderLive() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var wrap = el('div');
    content.appendChild(card('Live Dashboard', wrap, renderLive));
    wrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    // Fetch dashboard summary + live stats in parallel.
    Promise.all([
      fetchJSON('/analytics/dashboard').catch(function () { return {}; }),
      fetchJSON('/analytics/live').catch(function () { return {}; }),
      fetchJSON('/stats').catch(function () { return {}; }),
    ])
      .then(function (results) {
        var dashboard = results[0] || {};
        var live = results[1] || {};
        var stats = results[2] || {};
        wrap.innerHTML = '';

        // Stat cards row.
        var grid = el('div', { class: 'stat-grid' });
        grid.appendChild(makeStat('Active Requests', stats.active_requests || 0));
        grid.appendChild(makeStat('RPS', live.rps || (dashboard.summary && dashboard.summary.rps) || 0));
        grid.appendChild(makeStat('p50 (ms)', live.p50_ms || (dashboard.summary && dashboard.summary.p50_ms) || 'n/a'));
        grid.appendChild(makeStat('p95 (ms)', live.p95_ms || (dashboard.summary && dashboard.summary.p95_ms) || 'n/a'));
        grid.appendChild(makeStat('p99 (ms)', live.p99_ms || (dashboard.summary && dashboard.summary.p99_ms) || 'n/a'));
        grid.appendChild(makeStat('Error Rate', (live.error_rate || 0).toFixed(2) + '%'));
        wrap.appendChild(grid);

        // Latency sparkline chart.
        var chartCard = el('div', { class: 'chart-card' });
        chartCard.appendChild(el('h3', { text: 'Latency Trend (ms)' }));
        var canvas = el('canvas');
        canvas.width = 800;
        canvas.height = 200;
        canvas.className = 'live-chart';
        chartCard.appendChild(canvas);

        // Track history for the sparkline.
        var point = {
          p50: live.p50_ms || 0,
          p95: live.p95_ms || 0,
          p99: live.p99_ms || 0,
          ts: Date.now(),
        };
        liveState.history.push(point);
        if (liveState.history.length > liveState.maxPoints) {
          liveState.history.shift();
        }
        drawLatencyChart(canvas, liveState.history);
        wrap.appendChild(chartCard);

        // Per-route live table.
        if (live.routes) {
          var routesCard = el('div', { class: 'chart-card' });
          routesCard.appendChild(el('h3', { text: 'Per-Route Live' }));
          var table = el('table');
          table.appendChild(el('thead', {}, el('tr', {}, [
            el('th', { text: 'Route' }),
            el('th', { text: 'RPS' }),
            el('th', { text: 'p50 (ms)' }),
            el('th', { text: 'p95 (ms)' }),
            el('th', { text: 'Errors' }),
          ])));
          var tbody = el('tbody');
          var routeData = live.routes || [];
          if (Array.isArray(routeData)) {
            routeData.forEach(function (r) {
              tbody.appendChild(el('tr', {}, [
                el('td', { text: r.route || r.name || '' }),
                el('td', { text: String(r.rps || 0) }),
                el('td', { text: String(r.p50_ms || 0) }),
                el('td', { text: String(r.p95_ms || 0) }),
                el('td', { text: String(r.errors || 0) }),
              ]));
            });
          }
          table.appendChild(tbody);
          routesCard.appendChild(table);
          wrap.appendChild(routesCard);
        }

        setLastRefresh();
      })
      .catch(function (err) {
        wrap.innerHTML = '';
        wrap.appendChild(el('div', { class: 'error-msg', text: err.message }));
      });
  }

  function drawLatencyChart(canvas, history) {
    var ctx = canvas.getContext('2d');
    var w = canvas.width;
    var h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    if (history.length < 2) {
      ctx.fillStyle = '#8b949e';
      ctx.font = '14px sans-serif';
      ctx.fillText('Collecting data...', 10, h / 2);
      return;
    }

    // Find max value for scaling.
    var maxVal = 0;
    history.forEach(function (p) {
      maxVal = Math.max(maxVal, p.p99, p.p95, p.p50);
    });
    if (maxVal === 0) maxVal = 1;
    var padding = 10;
    var chartW = w - padding * 2;
    var chartH = h - padding * 2;

    // Draw grid lines.
    ctx.strokeStyle = '#30363d';
    ctx.lineWidth = 1;
    for (var i = 0; i <= 4; i++) {
      var y = padding + (chartH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padding, y);
      ctx.lineTo(w - padding, y);
      ctx.stroke();
    }

    // Draw lines for p50, p95, p99.
    var series = [
      { key: 'p50', color: '#3fb950', label: 'p50' },
      { key: 'p95', color: '#d29922', label: 'p95' },
      { key: 'p99', color: '#f85149', label: 'p99' },
    ];
    series.forEach(function (s) {
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 2;
      ctx.beginPath();
      history.forEach(function (p, i) {
        var x = padding + (chartW / (history.length - 1)) * i;
        var y = padding + chartH - (p[s.key] / maxVal) * chartH;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    });

    // Legend.
    ctx.font = '12px sans-serif';
    var legendX = w - 120;
    series.forEach(function (s, i) {
      ctx.fillStyle = s.color;
      ctx.fillRect(legendX, 5 + i * 18, 12, 12);
      ctx.fillStyle = '#c9d1d9';
      ctx.fillText(s.label, legendX + 18, 14 + i * 18);
    });
  }

  // --- #226: CRUD flows ---

  function sendJSON(method, path, body) {
    return fetch(path, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    }).then(function (resp) {
      return resp.json().then(function (data) {
        return { status: resp.status, data: data, ok: resp.ok };
      });
    });
  }

  function renderCrudEntity(entityName, entityLabel, columns) {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var wrap = el('div');
    var refreshFn = function () { renderCrudEntity(entityName, entityLabel, columns); };
    content.appendChild(card(entityLabel + ' (CRUD)', wrap, refreshFn));
    wrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    // Toolbar with "Create" button.
    var toolbar = el('div', { class: 'crud-toolbar' });
    var createBtn = el('button', { class: 'btn primary', text: '+ Create ' + entityLabel });
    toolbar.appendChild(createBtn);
    wrap.appendChild(toolbar);

    var tableWrap = el('div');
    wrap.appendChild(tableWrap);

    function loadTable() {
      tableWrap.innerHTML = '';
      tableWrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));
      fetchJSON('/' + entityName)
        .then(function (data) {
          tableWrap.innerHTML = '';
          var items = data[entityName] || data.items || data || [];
          if (!Array.isArray(items)) items = [];
          if (items.length === 0) {
            tableWrap.appendChild(el('p', { text: 'No ' + entityLabel.toLowerCase() + ' configured.' }));
            return;
          }
          var table = el('table');
          var headers = columns.map(function (c) { return el('th', { text: c.label }); });
          headers.push(el('th', { text: 'Actions' }));
          table.appendChild(el('thead', {}, el('tr', {}, headers)));
          var tbody = el('tbody');
          items.forEach(function (item) {
            var cells = columns.map(function (c) {
              var val = item[c.field];
              if (typeof val === 'object' && val !== null) val = JSON.stringify(val);
              return el('td', { text: String(val || '') });
            });
            // Action buttons.
            var actionCell = el('td');
            var editBtn = el('button', { class: 'btn small', text: 'Edit' });
            var delBtn = el('button', { class: 'btn small danger', text: 'Delete' });
            editBtn.addEventListener('click', function () {
              openEditDialog(entityName, entityLabel, item, columns, loadTable);
            });
            delBtn.addEventListener('click', function () {
              if (confirm('Delete ' + entityLabel + ' "' + item.name + '"?')) {
                sendJSON('DELETE', '/' + entityName + '/' + item.name)
                  .then(function (result) {
                    if (result.ok) loadTable();
                    else showCrudError(tableWrap, 'Delete failed: ' + (result.data && result.data.error && result.data.error.message || 'Unknown'));
                  })
                  .catch(function (err) { showCrudError(tableWrap, 'Delete failed: ' + err.message); });
              }
            });
            actionCell.appendChild(editBtn);
            actionCell.appendChild(delBtn);
            cells.push(actionCell);
            tbody.appendChild(el('tr', {}, cells));
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

    createBtn.addEventListener('click', function () {
      openCreateDialog(entityName, entityLabel, columns, loadTable);
    });

    loadTable();
  }

  function openCreateDialog(entityName, entityLabel, columns, onSuccess) {
    var overlay = el('div', { class: 'modal-overlay' });
    var modal = el('div', { class: 'modal' });
    modal.appendChild(el('h3', { text: 'Create ' + entityLabel }));
    var textarea = el('textarea', { class: 'editor-area' });
    textarea.setAttribute('spellcheck', 'false');
    textarea.placeholder = 'Enter ' + entityLabel + ' JSON here...\nExample:\n{"name": "my-' + entityLabel + '"}';
    modal.appendChild(textarea);
    var btnRow = el('div', { class: 'modal-buttons' });
    var cancelBtn = el('button', { class: 'btn', text: 'Cancel' });
    var saveBtn = el('button', { class: 'btn primary', text: 'Create' });
    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(saveBtn);
    modal.appendChild(btnRow);
    var errorDiv = el('div', { class: 'error-msg' });
    modal.appendChild(errorDiv);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    cancelBtn.addEventListener('click', function () { document.body.removeChild(overlay); });
    saveBtn.addEventListener('click', function () {
      var body;
      try { body = JSON.parse(textarea.value); }
      catch (e) {
        errorDiv.textContent = 'Invalid JSON: ' + e.message;
        return;
      }
      sendJSON('POST', '/' + entityName, body)
        .then(function (result) {
          if (result.ok) {
            document.body.removeChild(overlay);
            onSuccess();
          } else {
            errorDiv.textContent = 'Create failed: ' + (result.data && result.data.error && result.data.error.message || 'Unknown');
          }
        })
        .catch(function (err) { errorDiv.textContent = 'Create failed: ' + err.message; });
    });
  }

  function openEditDialog(entityName, entityLabel, item, columns, onSuccess) {
    var overlay = el('div', { class: 'modal-overlay' });
    var modal = el('div', { class: 'modal' });
    modal.appendChild(el('h3', { text: 'Edit ' + entityLabel + ': ' + (item.name || '') }));
    var textarea = el('textarea', { class: 'editor-area' });
    textarea.setAttribute('spellcheck', 'false');
    textarea.value = JSON.stringify(item, null, 2);
    modal.appendChild(textarea);
    var btnRow = el('div', { class: 'modal-buttons' });
    var cancelBtn = el('button', { class: 'btn', text: 'Cancel' });
    var saveBtn = el('button', { class: 'btn primary', text: 'Save' });
    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(saveBtn);
    modal.appendChild(btnRow);
    var errorDiv = el('div', { class: 'error-msg' });
    modal.appendChild(errorDiv);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    cancelBtn.addEventListener('click', function () { document.body.removeChild(overlay); });
    saveBtn.addEventListener('click', function () {
      var body;
      try { body = JSON.parse(textarea.value); }
      catch (e) {
        errorDiv.textContent = 'Invalid JSON: ' + e.message;
        return;
      }
      sendJSON('PUT', '/' + entityName + '/' + (item.name || ''), body)
        .then(function (result) {
          if (result.ok) {
            document.body.removeChild(overlay);
            onSuccess();
          } else {
            errorDiv.textContent = 'Save failed: ' + (result.data && result.data.error && result.data.error.message || 'Unknown');
          }
        })
        .catch(function (err) { errorDiv.textContent = 'Save failed: ' + err.message; });
    });
  }

  function showCrudError(container, msg) {
    var existing = container.querySelector('.error-msg');
    if (existing) existing.remove();
    container.appendChild(el('div', { class: 'error-msg', text: msg }));
  }

  function renderRoutesCrud() {
    renderCrudEntity('routes', 'Route', [
      { field: 'name', label: 'Name' },
      { field: 'service', label: 'Service' },
      { field: 'match', label: 'Match' },
    ]);
  }

  function renderUpstreamsCrud() {
    renderCrudEntity('upstreams', 'Upstream', [
      { field: 'name', label: 'Name' },
      { field: 'endpoints', label: 'Endpoints' },
    ]);
  }

  function renderServicesCrud() {
    renderCrudEntity('services', 'Service', [
      { field: 'name', label: 'Name' },
      { field: 'upstream', label: 'Upstream' },
    ]);
  }

  function renderConsumersCrud() {
    renderCrudEntity('consumers', 'Consumer', [
      { field: 'name', label: 'Name' },
    ]);
  }

  function renderPoliciesCrud() {
    renderCrudEntity('policies', 'Policy', [
      { field: 'name', label: 'Name' },
    ]);
  }

  // --- #226: AI Ops view ---

  function renderAiOps() {
    var content = document.getElementById('content');
    content.innerHTML = '';
    var wrap = el('div');
    content.appendChild(card('AI Operations', wrap, renderAiOps));
    wrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    Promise.all([
      fetchJSON('/ai/credential-pools').catch(function () { return {}; }),
      fetchJSON('/mcp/sessions').catch(function () { return {}; }),
      fetchJSON('/mcp/tools').catch(function () { return {}; }),
      fetchJSON('/experiments/prompt-overrides').catch(function () { return {}; }),
    ])
      .then(function (results) {
        var pools = results[0] || {};
        var sessions = results[1] || {};
        var tools = results[2] || {};
        var overrides = results[3] || {};
        wrap.innerHTML = '';

        // Credential pools card.
        var poolsCard = el('div', { class: 'chart-card' });
        poolsCard.appendChild(el('h3', { text: 'AI Credential Pools' }));
        var poolList = pools.pools || pools || [];
        if (Array.isArray(poolList) && poolList.length > 0) {
          var poolTable = el('table');
          poolTable.appendChild(el('thead', {}, el('tr', {}, [
            el('th', { text: 'Pool' }),
            el('th', { text: 'Provider' }),
            el('th', { text: 'Active' }),
            el('th', { text: 'Exhausted' }),
            el('th', { text: 'Cooldown' }),
          ])));
          var poolTbody = el('tbody');
          poolList.forEach(function (p) {
            poolTbody.appendChild(el('tr', {}, [
              el('td', { text: p.name || p.pool || '' }),
              el('td', { text: p.provider || '' }),
              el('td', { text: String(p.active || p.active_count || 0) }),
              el('td', { text: String(p.exhausted || p.exhausted_count || 0) }),
              el('td', { text: String(p.cooldown || p.cooldown_secs || 0) + 's' }),
            ]));
          });
          poolTable.appendChild(poolTbody);
          poolsCard.appendChild(poolTable);
        } else {
          poolsCard.appendChild(el('p', { text: 'No AI credential pools configured.' }));
        }
        wrap.appendChild(poolsCard);

        // MCP sessions card.
        var mcpCard = el('div', { class: 'chart-card' });
        mcpCard.appendChild(el('h3', { text: 'MCP Sessions' }));
        var sessionList = sessions.sessions || sessions || [];
        if (Array.isArray(sessionList) && sessionList.length > 0) {
          var sessTable = el('table');
          sessTable.appendChild(el('thead', {}, el('tr', {}, [
            el('th', { text: 'Session ID' }),
            el('th', { text: 'Status' }),
            el('th', { text: 'Tools' }),
          ])));
          var sessTbody = el('tbody');
          sessionList.forEach(function (s) {
            sessTbody.appendChild(el('tr', {}, [
              el('td', { text: s.id || s.session_id || '' }),
              el('td', { text: s.status || 'active' }),
              el('td', { text: String((s.tools || []).length) }),
            ]));
          });
          sessTable.appendChild(sessTbody);
          mcpCard.appendChild(sessTable);
        } else {
          mcpCard.appendChild(el('p', { text: 'No active MCP sessions.' }));
        }
        wrap.appendChild(mcpCard);

        // MCP tools card.
        var toolsCard = el('div', { class: 'chart-card' });
        toolsCard.appendChild(el('h3', { text: 'MCP Tools' }));
        var toolList = tools.tools || tools || [];
        if (Array.isArray(toolList) && toolList.length > 0) {
          var toolTable = el('table');
          toolTable.appendChild(el('thead', {}, el('tr', {}, [
            el('th', { text: 'Tool' }),
            el('th', { text: 'Description' }),
          ])));
          var toolTbody = el('tbody');
          toolList.forEach(function (t) {
            toolTbody.appendChild(el('tr', {}, [
              el('td', { text: t.name || '' }),
              el('td', { text: t.description || '' }),
            ]));
          });
          toolTable.appendChild(toolTbody);
          toolsCard.appendChild(toolTable);
        } else {
          toolsCard.appendChild(el('p', { text: 'No MCP tools registered.' }));
        }
        wrap.appendChild(toolsCard);

        // Experiment overrides card.
        var expCard = el('div', { class: 'chart-card' });
        expCard.appendChild(el('h3', { text: 'Experiment Prompt Overrides' }));
        var overrideList = overrides.overrides || overrides || [];
        if (Array.isArray(overrideList) && overrideList.length > 0) {
          var ovTable = el('table');
          ovTable.appendChild(el('thead', {}, el('tr', {}, [
            el('th', { text: 'Route' }),
            el('th', { text: 'Override' }),
          ])));
          var ovTbody = el('tbody');
          overrideList.forEach(function (o) {
            ovTbody.appendChild(el('tr', {}, [
              el('td', { text: o.route || o.key || '' }),
              el('td', { text: JSON.stringify(o.value || o.override || '') }),
            ]));
          });
          ovTable.appendChild(ovTbody);
          expCard.appendChild(ovTable);
        } else {
          expCard.appendChild(el('p', { text: 'No experiment overrides active.' }));
        }
        wrap.appendChild(expCard);

        setLastRefresh();
      })
      .catch(function (err) {
        wrap.innerHTML = '';
        wrap.appendChild(el('div', { class: 'error-msg', text: err.message }));
      });
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
    live: renderLive,
    routes: renderRoutesCrud,
    upstreams: renderUpstreamsCrud,
    health: renderHealth,
    analytics: renderAnalytics,
    aiops: renderAiOps,
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
