'use strict';

let refreshTimer = null;

// Cached data refreshes every 5 min on the collector; older than 3x is stale.
const STALE_MS = 3 * 300 * 1000;

// Units as FortiAnalyzer reports them are UNCONFIRMED (no SD-WAN data in the lab
// yet): values are shown as received, with these labels. Revisit after the first
// real capture.
const UNITS = { latency: 'ms', jitter: 'ms', packetloss: '%', bw: '' };

const NO_DATA_MESSAGE = 'No SD-WAN data from this FortiAnalyzer in the last 24h. ' +
  'SD-WAN performance SLA health checks and SLA logging must be enabled on the FortiGate.';

function escHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtNum(n) {
  if (n === null || n === undefined || Number.isNaN(Number(n))) return '—';
  const v = Number(n);
  return Number.isInteger(v) ? String(v) : v.toFixed(1);
}

function fmtStat(stat, unit) {
  if (!stat) return '—';
  return escHtml(fmtNum(stat.latest) + (unit ? ' ' + unit : ''));
}

function renderSparkline(points) {
  if (!Array.isArray(points) || points.length < 2) return '<span class="text-muted">—</span>';
  const w = 120, h = 28;
  const vals = points.map((p) => Number(p[1]));
  const min = Math.min(...vals), max = Math.max(...vals);
  const span = max - min || 1;
  const coords = vals.map((v, i) => {
    const x = (i / (vals.length - 1)) * w;
    const y = h - 2 - ((v - min) / span) * (h - 4);
    return x.toFixed(1) + ',' + y.toFixed(1);
  });
  return `<svg class="sdwan-spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="24h trend"><polyline fill="none" stroke="currentColor" stroke-width="1.5" points="${coords.join(' ')}"/></svg>`;
}

function slaBadge(status) {
  if (status === 'ok') return '<span class="sdwan-badge sdwan-ok">OK</span>';
  if (status === 'fail') return '<span class="sdwan-badge sdwan-fail">FAIL</span>';
  return '<span class="text-muted">—</span>';
}

function viewStatusLine(views) {
  const parts = Object.entries(views || {}).map(([name, v]) => `${escHtml(name)}: ${escHtml(v.status)}`);
  return parts.length ? `<div class="text-muted sdwan-views">${parts.join(' &bull; ')}</div>` : '';
}

function summaryStrip(interfaces) {
  const withSla = interfaces.filter((i) => i.sla_met_pct !== null && i.sla_met_pct !== undefined);
  const sla = withSla.length
    ? fmtNum(withSla.reduce((a, i) => a + i.sla_met_pct, 0) / withSla.length) + '%'
    : '—';
  const worst = (key) => {
    const vals = interfaces.map((i) => i[key] && i[key].latest).filter((v) => v !== null && v !== undefined);
    return vals.length ? fmtNum(Math.max(...vals)) : '—';
  };
  return `<div class="sdwan-summary">
    <span><strong>${interfaces.length}</strong> interfaces</span>
    <span>SLA met <strong>${escHtml(sla)}</strong></span>
    <span>Worst latency <strong>${escHtml(worst('latency'))}</strong> ${UNITS.latency}</span>
    <span>Worst loss <strong>${escHtml(worst('packetloss'))}</strong> ${UNITS.packetloss}</span>
  </div>`;
}

function renderInterfaces(interfaces) {
  const rows = interfaces.map((i) => `<tr>
    <td>${escHtml(i.device)}</td>
    <td>${escHtml(i.interface)}</td>
    <td>${slaBadge(i.sla_status)}</td>
    <td>${fmtStat(i.latency, UNITS.latency)}</td>
    <td>${fmtStat(i.jitter, UNITS.jitter)}</td>
    <td>${fmtStat(i.packetloss, UNITS.packetloss)}</td>
    <td>${fmtStat(i.in_bw, UNITS.bw)} / ${fmtStat(i.out_bw, UNITS.bw)}</td>
    <td>${renderSparkline(i.series && i.series.latency)}</td>
  </tr>`).join('');
  return `${summaryStrip(interfaces)}
  <div class="table-scroll"><table class="data-table">
    <thead><tr><th>Device</th><th>Interface</th><th>SLA</th><th>Latency</th><th>Jitter</th><th>Loss</th><th>In / Out</th><th>24h latency</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function renderTarget(t) {
  let stale = '';
  if (t.collected_at) {
    const age = Date.now() - new Date(t.collected_at).getTime();
    if (age > STALE_MS) stale = ' <span class="text-danger">(stale)</span>';
  }
  let body;
  if (t.state === 'error') {
    body = `<div class="alert alert-danger">${escHtml(t.error || 'SD-WAN poll failed')}</div>`;
  } else if (t.state === 'no_data' || !(t.interfaces || []).length) {
    body = `<div class="empty-state">${escHtml(NO_DATA_MESSAGE)}</div>${viewStatusLine(t.views)}`;
  } else {
    body = renderInterfaces(t.interfaces) + viewStatusLine(t.views);
  }
  return `<section class="sdwan-target">
    <div class="card-title">${escHtml(t.label)}</div>
    <div class="card-subtitle">${escHtml(t.host)} &bull; ADOM ${escHtml(t.adom)}${stale}</div>
    ${body}
  </section>`;
}

async function loadSdwan() {
  const root = document.getElementById('sdwanRoot');
  try {
    const resp = await fetch('/api/sdwan');
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    if (!data || !Array.isArray(data.targets)) {
      root.innerHTML = `<div class="alert alert-danger">Error: ${escHtml(JSON.stringify(data))}</div>`;
      return;
    }
    if (data.targets.length === 0) {
      root.innerHTML = '<div class="loading-placeholder">No SD-WAN data collected yet. The collector polls every few minutes; check that a FortiAnalyzer target is configured under Admin &rarr; FAZ Targets.</div>';
      return;
    }
    root.innerHTML = data.targets.map(renderTarget).join('');
    document.getElementById('lastUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (err) {
    root.innerHTML = `<div class="alert alert-danger">Failed to load: ${escHtml(err.message)}</div>`;
  }
}

function scheduleRefresh(seconds) {
  clearInterval(refreshTimer);
  if (seconds > 0) refreshTimer = setInterval(loadSdwan, seconds * 1000);
}

document.getElementById('refreshBtn').addEventListener('click', loadSdwan);
document.getElementById('autoRefresh').addEventListener('change', function () {
  scheduleRefresh(parseInt(this.value, 10));
});

loadSdwan();
scheduleRefresh(parseInt(document.getElementById('autoRefresh').value, 10));
