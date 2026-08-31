// dwara console v1 -- read-only SPA
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

    // Fetch health + stats in parallel.
    Promise.all([fetchJSON('/health'), fetchJSON('/stats')])
      .then(function (results) {
        var health = results[0];
        var stats = results[1];

        // Health status.
        var healthStatus = health.status || 'unknown';
        setStatusBadge(healthStatus === 'ok' ? 'healthy' : 'unhealthy');

        grid.appendChild(makeStat('Status', healthStatus));
        grid.appendChild(makeStat('Active Requests', stats.active_requests || 0));
        grid.appendChild(makeStat('Uptime', formatUptime(health.uptime_secs)));
        grid.appendChild(makeStat('Config Epoch', health.config_epoch || 'n/a'));
        grid.appendChild(makeStat('Routes', health.routes || 0));
        grid.appendChild(makeStat('Listeners', health.listeners || 0));

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

    fetchJSON('/config')
      .then(function (config) {
        tableWrap.innerHTML = '';
        var routes = (config.gateway && config.gateway.routes) || [];
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
          tbody.appendChild(el('tr', {}, [
            el('td', { text: r.name || '' }),
            el('td', { text: (r.match && r.match.path) || '' }),
            el('td', { text: r.service || '' }),
            el('td', { text: (r.methods || ['*']).join(', ') }),
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

    fetchJSON('/stats')
      .then(function (stats) {
        tableWrap.innerHTML = '';
        var upstreams = stats.upstreams || [];
        if (upstreams.length === 0) {
          tableWrap.appendChild(el('p', { text: 'No upstream data available.' }));
          return;
        }
        var table = el('table');
        table.appendChild(el('thead', {}, el('tr', {}, [
          el('th', { text: 'Service' }),
          el('th', { text: 'Address' }),
          el('th', { text: 'Health' }),
          el('th', { text: 'Requests' }),
          el('th', { text: 'Errors' }),
        ])));
        var tbody = el('tbody');
        upstreams.forEach(function (u) {
          var healthClass = 'health-ok';
          if (u.health === 'down') healthClass = 'health-down';
          else if (u.health === 'degraded') healthClass = 'health-degraded';
          tbody.appendChild(el('tr', {}, [
            el('td', { text: u.service || '' }),
            el('td', { text: u.address || '' }),
            el('td', { class: healthClass, text: u.health || 'unknown' }),
            el('td', { text: u.requests || 0 }),
            el('td', { text: u.errors || 0 }),
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

        var status = health.status || 'unknown';
        setStatusBadge(status === 'ok' ? 'healthy' : 'unhealthy');
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

    fetchJSON('/analytics/top?limit=10')
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
    content.appendChild(card('Current Config', wrap, renderConfig));
    wrap.appendChild(el('div', { class: 'stat-label', text: 'Loading...' }));

    fetchText('/config_dump')
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

  // --- Navigation ---

  var views = {
    overview: renderOverview,
    routes: renderRoutes,
    upstreams: renderUpstreams,
    health: renderHealth,
    analytics: renderAnalytics,
    config: renderConfig,
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
    setStatusBadge('connecting');
    switchView('overview');
    startAutoRefresh();
  });
})();
