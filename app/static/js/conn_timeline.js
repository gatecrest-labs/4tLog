'use strict';

// Connection Timeline. The server sends flows: one count per (lane, bucket,
// verdict, peer, port, policy), with lookup tables for lanes, peers, ports and
// policies (see app/conn_timeline.py). Everything on the page is derived from
// those flows here, so a click on a peer or a port re-filters the whole picture
// without another FortiAnalyzer call. Hand-drawn SVG, no chart library.
//
// Every string from FortiAnalyzer (device names, policy names, addresses) is
// untrusted and goes through escHtml.

const VERDICTS = ['allowed', 'denied', 'other'];
const TOP_N = 10;
const DETAIL_N = 5;
const MAX_LANES = 40;
// Log Search's advanced filters are AND'd, so "allowed" is "none of the actions that are not
// allowed": the denies, and ip-conn (a connection that failed: counted as other, not allowed).
const NOT_ALLOWED_ACTIONS = ['deny', 'block', 'dropped', 'ip-conn'];
const REASONS = {
  cap: 'the row cap',
  deadline: 'the time limit',
  cancelled: 'cancel',
  incomplete: 'FortiAnalyzer returning fewer logs than it counted',
  burst: 'a burst of logs in one second that FortiAnalyzer would not hand over in full',
};

function escHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtCount(n) {
  return Number(n || 0).toLocaleString('en-US');
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

function fmtTime(ms, withDate) {
  const d = new Date(ms);
  const t = `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  if (!withDate) return t;
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${t}`;
}

function fmtTimeSec(ms) {
  const d = new Date(ms);
  return `${fmtTime(ms, true)}:${pad2(d.getSeconds())}`;
}

function windowLabel(result) {
  const presets = { '15m': 'last 15m', '1h': 'last 1h', '4h': 'last 4h', '24h': 'last 24h', '7d': 'last 7d' };
  if (result.preset && presets[result.preset]) return presets[result.preset];
  return `${fmtTime(Date.parse(result.start), true)} to ${fmtTime(Date.parse(result.end), true)}`;
}

function emptyCounts() {
  return { allowed: 0, denied: 0, other: 0, total: 0 };
}

function addCount(c, verdict, n) {
  c[VERDICTS[verdict]] += n;
  c.total += n;
}

function flowPasses(f, filter) {
  if (filter && filter.peer != null && f[3] !== filter.peer) return false;
  if (filter && filter.port != null && f[4] !== filter.port) return false;
  return true;
}

function topList(map, n) {
  return [...map.entries()]
    .map(([idx, c]) => ({ idx, ...c }))
    .sort((a, b) => b.total - a.total || a.idx - b.idx)
    .slice(0, n);
}

// Everything the panels show, with the peer/port filter applied. The top
// peers list ignores the peer filter (so the others stay clickable), and the
// top ports list ignores the port filter, the same way.
function summarize(result, filter) {
  const nLanes = result.lanes.length;
  const nBuckets = result.buckets;
  const cells = Array.from({ length: nLanes }, () => Array.from({ length: nBuckets }, emptyCounts));
  const laneTotals = Array.from({ length: nLanes }, emptyCounts);
  const peers = new Map();
  const ports = new Map();
  const policies = new Map();
  const totals = emptyCounts();
  for (const f of result.flows) {
    const [lane, bucket, verdict, peer, port, policy, count] = f;
    if (filter == null || filter.port == null || port === filter.port) {
      if (!peers.has(peer)) peers.set(peer, emptyCounts());
      addCount(peers.get(peer), verdict, count);
    }
    if (filter == null || filter.peer == null || peer === filter.peer) {
      if (!ports.has(port)) ports.set(port, emptyCounts());
      addCount(ports.get(port), verdict, count);
    }
    if (!flowPasses(f, filter)) continue;
    addCount(cells[lane][bucket], verdict, count);
    addCount(laneTotals[lane], verdict, count);
    addCount(totals, verdict, count);
    if (!policies.has(policy)) policies.set(policy, emptyCounts());
    addCount(policies.get(policy), verdict, count);
  }
  let maxCell = 0;
  for (const row of cells) for (const c of row) if (c.total > maxCell) maxCell = c.total;
  return {
    cells,
    laneTotals,
    totals,
    maxCell,
    peers: topList(peers, TOP_N).map((p) => ({ ...p, ip: result.peers[p.idx] })),
    ports: topList(ports, TOP_N).map((p) => ({ ...p, label: result.ports[p.idx].label, service: result.ports[p.idx].service })),
    policies: topList(policies, Infinity).map((p) => ({ ...p, ...result.policies[p.idx], idx: p.idx })),
  };
}

// The busiest lanes first only when there are too many to draw; otherwise
// lanes keep the server's order (first log seen, a rough hint of path order).
function visibleLanes(result, summary, showAll) {
  const all = result.lanes.map((_, i) => i).filter((i) => summary.laneTotals[i].total > 0);
  if (showAll || all.length <= MAX_LANES) return { lanes: all, hidden: 0 };
  const busiest = [...all].sort((a, b) => summary.laneTotals[b].total - summary.laneTotals[a].total).slice(0, MAX_LANES);
  const keep = new Set(busiest);
  return { lanes: all.filter((i) => keep.has(i)), hidden: all.length - MAX_LANES };
}

function bucketRange(result, bucket) {
  const start = Date.parse(result.start) + bucket * result.bucket_seconds * 1000;
  const end = Math.min(start + result.bucket_seconds * 1000, Date.parse(result.end));
  return { start, end };
}

const GEOM = { labelW: 200, chartW: 760, laneH: 34, axisH: 24, barPad: 3 };

function renderChart(result, summary, opts) {
  const o = opts || {};
  const { lanes, hidden } = visibleLanes(result, summary, o.showAll);
  if (lanes.length === 0) {
    return '<div class="ct-empty">No matching traffic logs in this window.</div>';
  }
  const { labelW, chartW, laneH, axisH, barPad } = GEOM;
  const width = labelW + chartW;
  const height = lanes.length * laneH + axisH;
  const cellW = chartW / result.buckets;
  const max = summary.maxCell || 1;
  const parts = [];
  parts.push(`<svg class="ct-svg" viewBox="0 0 ${width} ${height}" width="100%" role="img" aria-label="Connection timeline, one lane per firewall">`);
  parts.push('<defs><pattern id="ctHatch" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><line x1="0" y1="0" x2="0" y2="4" class="ct-hatch-line"/></pattern></defs>');

  lanes.forEach((laneIdx, row) => {
    const lane = result.lanes[laneIdx];
    const y = row * laneH;
    const t = summary.laneTotals[laneIdx];
    parts.push(`<rect class="ct-lane-bg${row % 2 ? ' ct-lane-alt' : ''}" x="0" y="${y}" width="${width}" height="${laneH}"/>`);
    parts.push(`<text class="ct-lane-label" x="6" y="${y + laneH / 2 - 2}">${escHtml(lane.label)}</text>`);
    parts.push(`<text class="ct-lane-sub" x="6" y="${y + laneH / 2 + 11}">${fmtCount(t.allowed)} allowed · ${fmtCount(t.denied)} denied</text>`);
    for (let b = 0; b < result.buckets; b++) {
      const c = summary.cells[laneIdx][b];
      if (c.total === 0) continue;
      const x = labelW + b * cellW;
      const usable = laneH - 2 * barPad;
      const hAllowed = (c.allowed / max) * usable;
      const hDenied = (c.denied / max) * usable;
      const hOther = (c.other / max) * usable;
      const bottom = y + laneH - barPad;
      const w = Math.max(cellW - 1, 1).toFixed(2);
      const xs = x.toFixed(2);
      const r = bucketRange(result, b);
      const tip = `${lane.label}\n${fmtTimeSec(r.start)} to ${fmtTimeSec(r.end)}\n` +
        `Allowed ${fmtCount(c.allowed)}, denied ${fmtCount(c.denied)}` +
        (c.other ? `, other ${fmtCount(c.other)}` : '') + (o.topPort ? `\nTop port ${o.topPort(laneIdx, b)}` : '');
      const sel = o.selected && o.selected.lane === laneIdx && o.selected.bucket === b ? ' ct-selected' : '';
      parts.push(`<g class="ct-cell${sel}" data-lane="${laneIdx}" data-bucket="${b}"><title>${escHtml(tip)}</title>`);
      parts.push(`<rect class="ct-hit" x="${xs}" y="${y}" width="${w}" height="${laneH}" data-lane="${laneIdx}" data-bucket="${b}"/>`);
      let top = bottom;
      if (hAllowed > 0) {
        top -= Math.max(hAllowed, 1);
        parts.push(`<rect class="ct-allowed" x="${xs}" y="${top.toFixed(2)}" width="${w}" height="${Math.max(hAllowed, 1).toFixed(2)}" data-lane="${laneIdx}" data-bucket="${b}" data-verdict="allowed"/>`);
      }
      if (hDenied > 0) {
        const h = Math.max(hDenied, 1);
        top -= h;
        parts.push(`<rect class="ct-denied" x="${xs}" y="${top.toFixed(2)}" width="${w}" height="${h.toFixed(2)}" data-lane="${laneIdx}" data-bucket="${b}" data-verdict="denied"/>`);
        parts.push(`<rect class="ct-denied-hatch" x="${xs}" y="${top.toFixed(2)}" width="${w}" height="${h.toFixed(2)}" fill="url(#ctHatch)" data-lane="${laneIdx}" data-bucket="${b}" data-verdict="denied"/>`);
      }
      if (hOther > 0) {
        const h = Math.max(hOther, 1);
        top -= h;
        parts.push(`<rect class="ct-other" x="${xs}" y="${top.toFixed(2)}" width="${w}" height="${h.toFixed(2)}" data-lane="${laneIdx}" data-bucket="${b}" data-verdict="other"/>`);
      }
      parts.push('</g>');
    }
  });

  const cov = result.coverage || {};
  if (!cov.complete && cov.reason !== 'running') {
    // Time ranges that were not fetched: the gaps (parallel builds can leave several),
    // or everything after "through" for an older result.
    const startMs = Date.parse(result.start);
    const spanMs = Date.parse(result.end) - startMs;
    const gaps = Array.isArray(cov.gaps) && cov.gaps.length
      ? cov.gaps.map((g) => [Date.parse(g[0]), Date.parse(g[1])])
      : (cov.through ? [[Date.parse(cov.through), Date.parse(result.end)]] : []);
    for (const [from, to] of gaps) {
      const x0 = labelW + Math.min(Math.max((from - startMs) / spanMs, 0), 1) * chartW;
      const x1 = labelW + Math.min(Math.max((to - startMs) / spanMs, 0), 1) * chartW;
      if (x1 - x0 < 0.5) continue;
      parts.push(`<rect class="ct-not-fetched" x="${x0.toFixed(2)}" y="0" width="${(x1 - x0).toFixed(2)}" height="${lanes.length * laneH}"><title>Not fetched: ${escHtml(fmtTimeSec(from))} to ${escHtml(fmtTimeSec(to))}</title></rect>`);
    }
  }

  const axisY = lanes.length * laneH;
  const span = Date.parse(result.end) - Date.parse(result.start);
  const withDate = span > 24 * 3600 * 1000;
  const ticks = 6;
  for (let i = 0; i <= ticks; i++) {
    const x = labelW + (i / ticks) * chartW;
    const ms = Date.parse(result.start) + (i / ticks) * span;
    const anchor = i === 0 ? 'start' : i === ticks ? 'end' : 'middle';
    parts.push(`<line class="ct-tick" x1="${x.toFixed(2)}" y1="0" x2="${x.toFixed(2)}" y2="${axisY + 4}"/>`);
    parts.push(`<text class="ct-axis" x="${x.toFixed(2)}" y="${axisY + 17}" text-anchor="${anchor}">${escHtml(fmtTime(ms, withDate))}</text>`);
  }
  parts.push('</svg>');
  if (hidden > 0) {
    parts.push(`<div class="ct-more">${fmtCount(hidden)} quieter firewall(s) not drawn. <button type="button" class="btn-link" id="ctShowAll">Show all</button></div>`);
  }
  return parts.join('');
}

function renderHeader(result) {
  return `<strong>${escHtml(result.host)}</strong> · ${escHtml(result.direction_label)} · ${escHtml(windowLabel(result))}` +
    ` <span class="text-muted">on ${escHtml(result.target)}` +
    (result.adom ? `, ADOM ${escHtml(result.adom)}` : '') +
    (result.device && result.device !== 'All_FortiGate' ? `, firewall ${escHtml(result.device)}` : '') +
    (result.verdict_filter && result.verdict_filter !== 'all' ? `, ${escHtml(result.verdict_filter)} only` : '') +
    '</span>';
}

function renderCoverage(result) {
  const cov = result.coverage || {};
  if (cov.reason === 'running') {
    const of = cov.matched != null ? ` of ${fmtCount(cov.matched)}${cov.matched_final ? '' : '+'} matched` : '';
    return `<div class="ct-coverage alert alert-info">Still fetching: ${fmtCount(cov.fetched)}${of} log(s) so far. This picture fills in as more arrive.</div>`;
  }
  const matched = cov.matched;
  if (cov.complete) {
    const n = matched != null ? matched : cov.fetched;
    return `<div class="ct-coverage ct-coverage-ok">Complete: built from all ${fmtCount(n)} matched log(s).</div>`;
  }
  const of = matched != null ? ` of ${fmtCount(matched)}${cov.matched_final ? '' : '+'} matched` : '';
  const through = cov.through ? ` (through ${escHtml(fmtTimeSec(Date.parse(cov.through)))})` : '';
  const why = REASONS[cov.reason] || 'a limit';
  const more = cov.resumable
    ? ' <button type="button" class="btn btn-sm btn-primary" id="ctContinue">Continue</button> reads only what is missing and adds it to this picture.'
    : '';
  return `<div class="ct-coverage alert alert-warning">Partial: built from ${fmtCount(cov.fetched)}${of} log(s)${through}, stopped by ${escHtml(why)}. ` +
    `Time not covered is greyed out.${more} The Quick summary above counts sessions for the whole window. You can also narrow the window, pick one firewall, or show allowed or denied only.</div>`;
}

function renderFilter(result, filter) {
  const parts = [];
  if (filter.peer != null) parts.push(`peer <strong>${escHtml(result.peers[filter.peer])}</strong>`);
  if (filter.port != null) parts.push(`port <strong>${escHtml(result.ports[filter.port].label)}</strong>`);
  if (!parts.length) return '';
  return `Showing only ${parts.join(' and ')}. <button type="button" class="btn-link" id="ctClearFilter">Show everything</button>`;
}

function countCells(c, withOther) {
  return `<td class="ct-num">${fmtCount(c.allowed)}</td><td class="ct-num ct-num-denied">${fmtCount(c.denied)}</td>` +
    (withOther ? `<td class="ct-num">${fmtCount(c.other)}</td>` : '');
}

// Failed connections and unfamiliar actions are neither allowed nor denied: their column only
// appears when there are some, so nothing a table lists can quietly go missing.
const hasOther = (items) => items.some((i) => i.other > 0);
const otherHead = (withOther) => (withOther ? '<th>Other</th>' : '');

function renderTopTable(items, kind, activeIdx) {
  if (!items.length) return '<div class="text-muted">None</div>';
  const withOther = hasOther(items);
  const rows = items.map((it) => {
    const text = kind === 'peer'
      ? escHtml(it.ip)
      : escHtml(it.label) + (it.service ? ` <span class="text-muted">${escHtml(it.service)}</span>` : '');
    const active = activeIdx === it.idx ? ' ct-active' : '';
    return `<tr class="ct-pick${active}" data-kind="${kind}" data-idx="${it.idx}"><td>${text}</td>${countCells(it, withOther)}</tr>`;
  }).join('');
  return `<table class="data-table ct-table"><thead><tr><th>${kind === 'peer' ? 'Peer IP' : 'Port'}</th><th>Allowed</th><th>Denied</th>${otherHead(withOther)}</tr></thead><tbody>${rows}</tbody></table>`;
}

function renderPolicies(result, summary) {
  if (!summary.policies.length) return '<div class="text-muted">None</div>';
  const withOther = hasOther(summary.policies);
  const rows = summary.policies.map((p) => `<tr><td>${escHtml(result.lanes[p.lane].label)}</td>` +
    `<td>${escHtml(p.policyid || '—')}</td><td>${escHtml(p.label)}</td>${countCells(p, withOther)}</tr>`).join('');
  return `<div class="table-scroll"><table class="data-table ct-table"><thead><tr><th>Firewall</th><th>Policy ID</th><th>Policy</th><th>Allowed</th><th>Denied</th>${otherHead(withOther)}</tr></thead><tbody>${rows}</tbody></table></div>`;
}

// One firewall and bucket: counts, top ports, peers and policies, all from
// the flows already on the page (no new FortiAnalyzer call).
function cellDetail(result, filter, lane, bucket, verdict) {
  const counts = emptyCounts();
  const ports = new Map();
  const peers = new Map();
  const policies = new Map();
  const want = verdict ? VERDICTS.indexOf(verdict) : -1;
  for (const f of result.flows) {
    if (f[0] !== lane || f[1] !== bucket || !flowPasses(f, filter)) continue;
    if (want >= 0 && f[2] !== want) continue;
    addCount(counts, f[2], f[6]);
    for (const [map, idx] of [[ports, f[4]], [peers, f[3]], [policies, f[5]]]) {
      if (!map.has(idx)) map.set(idx, emptyCounts());
      addCount(map.get(idx), f[2], f[6]);
    }
  }
  return {
    counts,
    ports: topList(ports, DETAIL_N).map((p) => ({ ...p, label: result.ports[p.idx].label })),
    peers: topList(peers, DETAIL_N).map((p) => ({ ...p, label: result.peers[p.idx] })),
    policies: topList(policies, DETAIL_N).map((p) => ({ ...p, label: result.policies[p.idx].label })),
  };
}

function topPortOf(result, filter, lane, bucket) {
  const d = cellDetail(result, filter, lane, bucket, null);
  return d.ports.length ? d.ports[0].label : '—';
}

function logSearchPortValue(port) {
  if ((port.proto === 'tcp' || port.proto === 'udp') && /^\d+$/.test(port.port) && port.port !== '0') {
    return `${port.proto}:${port.port}`;
  }
  return port.service || '';
}

// Links into Log Search for one slice. Log Search ANDs its source and
// destination boxes, so "either direction" needs two links.
function logSearchLinks(result, lane, bucket, verdict, filter) {
  const r = bucketRange(result, bucket);
  const laneMeta = result.lanes[lane];
  const peer = filter && filter.peer != null ? result.peers[filter.peer] : '';
  const port = filter && filter.port != null ? logSearchPortValue(result.ports[filter.port]) : '';
  const sides = result.direction === 'either' ? ['src', 'dst'] : [result.direction];
  return sides.map((side) => {
    const p = new URLSearchParams();
    p.set('target', result.target);
    if (result.adom) p.set('adom', result.adom);
    p.set('logtype', 'traffic');
    p.set('device', laneMeta.devid || 'All_FortiGate');
    p.set('start', new Date(r.start).toISOString());
    p.set('end', new Date(r.end).toISOString());
    if (side === 'src') {
      p.set('src', result.host);
      if (peer) p.set('dst', peer);
    } else {
      p.set('dst', result.host);
      if (peer) p.set('src', peer);
    }
    if (port) p.set('ports', port);
    if (verdict === 'denied') p.append('filter', 'action==deny');
    if (verdict === 'allowed') NOT_ALLOWED_ACTIONS.forEach((a) => p.append('filter', `action!=${a}`));
    p.set('run', '1');
    const label = sides.length > 1 ? `Open in Log Search (${side === 'src' ? 'as source' : 'as destination'})` : 'Open in Log Search';
    return { label, href: `/log-search?${p.toString()}` };
  });
}

function renderDetail(result, filter, sel) {
  const lane = result.lanes[sel.lane];
  const r = bucketRange(result, sel.bucket);
  const d = cellDetail(result, filter, sel.lane, sel.bucket, sel.verdict);
  const list = (items) => items.length
    ? `<ul>${items.map((i) => `<li>${escHtml(i.label)} <span class="text-muted">${fmtCount(i.total)}</span></li>`).join('')}</ul>`
    : '<div class="text-muted">None</div>';
  const links = logSearchLinks(result, sel.lane, sel.bucket, sel.verdict, filter)
    .map((l) => `<a class="btn btn-sm btn-secondary" href="${escHtml(l.href)}">${escHtml(l.label)}</a>`).join(' ');
  const which = sel.verdict ? `${escHtml(sel.verdict)} only` : 'all actions';
  return `<div class="ct-detail-head"><strong>${escHtml(lane.label)}</strong> · ${escHtml(fmtTimeSec(r.start))} to ${escHtml(fmtTimeSec(r.end))} · ${which}` +
    ' <button type="button" class="btn-link" id="ctCloseDetail">Close</button></div>' +
    `<div class="ct-detail-counts">Allowed ${fmtCount(d.counts.allowed)} · Denied ${fmtCount(d.counts.denied)}` +
    (d.counts.other ? ` · Other ${fmtCount(d.counts.other)}` : '') + '</div>' +
    `<div class="ct-detail-grid"><div><h4>Ports</h4>${list(d.ports)}</div><div><h4>Peers</h4>${list(d.peers)}</div><div><h4>Policies</h4>${list(d.policies)}</div></div>` +
    `<div class="ct-detail-links">${links}</div>`;
}

// ── Selected-peer picture ────────────────────────────────────────────────────
// Source IP, the firewalls in the middle, destination IP and the ports seen,
// plus a small graph of when the traffic was there. Built from result.paths
// (one row per peer, role, firewall, port and bucket), so it is separate for
// "host talked to peer" and "peer talked to host".

const ROLE_NAMES = ['host is the source', 'host is the destination'];

function fmtDuration(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

function peerPaths(result, filter) {
  if (!filter || filter.peer == null || !result.paths) return [];
  const roles = [0, 1].map((role) => ({
    role,
    total: 0,
    lanes: new Map(),
    ports: new Map(),
    buckets: new Array(result.buckets).fill(0),
    bucketVerdicts: Array.from({ length: result.buckets }, () => [0, 0, 0]),  // allowed, denied, other
    first: null,
    last: null,
  }));
  for (const [peer, role, lane, port, bucket, count, first, last, ...verdicts] of result.paths) {
    if (peer !== filter.peer) continue;
    if (filter.port != null && port !== filter.port) continue;
    const r = roles[role];
    // Older results carry no verdict split: all of it counts as allowed.
    const split = verdicts.length === 3 ? verdicts : [count, 0, 0];
    r.total += count;
    const fw = r.lanes.get(lane) || { count: 0, allowed: 0, denied: 0, other: 0 };
    fw.count += count;
    fw.allowed += split[0];
    fw.denied += split[1];
    fw.other += split[2];
    r.lanes.set(lane, fw);
    r.ports.set(port, (r.ports.get(port) || 0) + count);
    r.buckets[bucket] += count;
    split.forEach((n, i) => { r.bucketVerdicts[bucket][i] += n; });
    if (r.first == null || first < r.first) r.first = first;
    if (r.last == null || last > r.last) r.last = last;
  }
  return roles.filter((r) => r.total > 0).map((r) => ({
    ...r,
    lanes: [...r.lanes.entries()].map(([idx, fw]) => ({ idx, ...fw })).sort((a, b) => b.count - a.count || a.idx - b.idx),
    ports: [...r.ports.entries()].map(([idx, count]) => ({ idx, count })).sort((a, b) => b.count - a.count || a.idx - b.idx),
  }));
}

// Log Search on this peer over the whole timeline window, for one firewall.
// Opened in a new window, so it is a plain link.
function peerDetailsHref(result, role, peerIdx, laneIdx, portIdx) {
  const p = new URLSearchParams();
  const peer = result.peers[peerIdx];
  p.set('target', result.target);
  if (result.adom) p.set('adom', result.adom);
  p.set('logtype', 'traffic');
  p.set('device', result.lanes[laneIdx].devid || 'All_FortiGate');
  p.set('start', new Date(Date.parse(result.start)).toISOString());
  p.set('end', new Date(Date.parse(result.end)).toISOString());
  p.set(role === 0 ? 'src' : 'dst', result.host);
  p.set(role === 0 ? 'dst' : 'src', peer);
  if (portIdx != null) p.set('ports', logSearchPortValue(result.ports[portIdx]));
  p.set('run', '1');
  return `/log-search?${p.toString()}`;
}

function renderPathDiagram(result, rp, srcIp, dstIp) {
  const MAX_FW = 6;
  const MAX_PORTS = 6;
  const fws = rp.lanes.slice(0, MAX_FW);
  const extraFw = rp.lanes.length - fws.length;
  const rowH = 44;
  const boxH = 34;
  const height = Math.max(fws.length, 1) * rowH + 16;
  const midY = height / 2;
  const W = 760;
  const ipW = 170;
  const fwX = 300;
  const fwW = 200;
  const parts = [`<svg class="ct-path-svg" viewBox="0 0 ${W} ${height}" width="100%" role="img" aria-label="${escHtml(srcIp)} to ${escHtml(dstIp)} through ${fws.length} firewall(s)">`];
  parts.push('<defs><marker id="ctArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="ct-path-arrowhead"/></marker></defs>');
  parts.push(`<rect class="ct-path-ip" x="0" y="${midY - 22}" width="${ipW}" height="44" rx="6"/><text class="ct-path-ip-text" x="${ipW / 2}" y="${midY - 3}" text-anchor="middle">${escHtml(srcIp)}</text><text class="ct-path-sub" x="${ipW / 2}" y="${midY + 12}" text-anchor="middle">source</text>`);
  parts.push(`<rect class="ct-path-ip" x="${W - ipW}" y="${midY - 22}" width="${ipW}" height="44" rx="6"/><text class="ct-path-ip-text" x="${W - ipW / 2}" y="${midY - 3}" text-anchor="middle">${escHtml(dstIp)}</text><text class="ct-path-sub" x="${W - ipW / 2}" y="${midY + 12}" text-anchor="middle">destination</text>`);
  fws.forEach((fw, i) => {
    const cy = 8 + i * rowH + rowH / 2 - 4;
    const label = result.lanes[fw.idx].label;
    parts.push(`<line class="ct-path-line" x1="${ipW}" y1="${midY}" x2="${fwX}" y2="${cy}" marker-end="url(#ctArrow)"/>`);
    parts.push(`<line class="ct-path-line" x1="${fwX + fwW}" y1="${cy}" x2="${W - ipW}" y2="${midY}" marker-end="url(#ctArrow)"/>`);
    parts.push(`<rect class="ct-path-fw" x="${fwX}" y="${cy - boxH / 2}" width="${fwW}" height="${boxH}" rx="6"/>`);
    parts.push(`<text class="ct-path-fw-text" x="${fwX + fwW / 2}" y="${cy - 2}" text-anchor="middle">${escHtml(label.length > 26 ? `${label.slice(0, 25)}…` : label)}<title>${escHtml(label)}</title></text>`);
    parts.push(`<text class="ct-path-sub" x="${fwX + fwW / 2}" y="${cy + 11}" text-anchor="middle">${fmtCount(fw.count)} connection log(s)</text>`);
  });
  parts.push('</svg>');
  const ports = rp.ports.slice(0, MAX_PORTS)
    .map((o) => `<span class="ct-port-chip">${escHtml(result.ports[o.idx].label)}${result.ports[o.idx].service ? ` <span class="text-muted">${escHtml(result.ports[o.idx].service)}</span>` : ''} <span class="text-muted">×${fmtCount(o.count)}</span></span>`)
    .join(' ');
  const morePorts = rp.ports.length > MAX_PORTS ? ` <span class="text-muted">+${rp.ports.length - MAX_PORTS} more</span>` : '';
  const moreFw = extraFw > 0 ? `<div class="text-muted">${extraFw} quieter firewall(s) not drawn; see the Policies table.</div>` : '';
  return `<div class="ct-path-diagram">${parts.join('')}</div>${moreFw}<div class="ct-path-ports"><strong>Ports seen:</strong> ${ports}${morePorts}</div>`;
}

function renderPathGraph(result, rp) {
  const W = 760;
  const H = 70;
  const padL = 4;
  const n = result.buckets;
  const cw = (W - padL * 2) / n;
  const max = Math.max(...rp.buckets, 1);
  const startMs = Date.parse(result.start);
  const spanMs = Date.parse(result.end) - startMs;
  const bars = [];
  rp.buckets.forEach((c, b) => {
    if (!c) return;
    const h = Math.max((c / max) * (H - 14), 2);
    const r = bucketRange(result, b);
    const [allowed, denied, other] = rp.bucketVerdicts[b];
    const detail = `${fmtTimeSec(r.start)} to ${fmtTimeSec(r.end)}: ${fmtCount(c)} log(s)` +
      ` (${fmtCount(allowed)} allowed, ${fmtCount(denied)} denied${other ? `, ${fmtCount(other)} other` : ''})`;
    // Stacked from the axis up: allowed, then denied, then other, each in its own colour.
    let y = H - 12;
    [['ct-allowed', allowed], ['ct-denied', denied], ['ct-other', other]].forEach(([cls, n]) => {
      if (!n) return;
      const seg = Math.max((n / c) * h, 1);
      y -= seg;
      bars.push(`<rect class="${cls}" x="${(padL + b * cw).toFixed(2)}" y="${y.toFixed(2)}" width="${Math.max(cw - 1, 1).toFixed(2)}" height="${seg.toFixed(2)}"><title>${escHtml(detail)}</title></rect>`);
    });
  });
  const withDate = spanMs > 24 * 3600 * 1000;
  const axis = `<line class="ct-tick" x1="${padL}" y1="${H - 12}" x2="${W - padL}" y2="${H - 12}"/>` +
    `<text class="ct-axis" x="${padL}" y="${H - 1}">${escHtml(fmtTime(startMs, withDate))}</text>` +
    `<text class="ct-axis" x="${W - padL}" y="${H - 1}" text-anchor="end">${escHtml(fmtTime(startMs + spanMs, withDate))}</text>`;
  const firstMs = rp.first * 1000;
  const lastMs = rp.last * 1000;
  const active = rp.buckets.filter((c) => c > 0).length;
  const summary = `First seen ${escHtml(fmtTimeSec(firstMs))}, last seen ${escHtml(fmtTimeSec(lastMs))}` +
    ` (${escHtml(fmtDuration(lastMs - firstMs))} span), active in ${active} of ${n} intervals`;
  return `<div class="ct-path-summary">${summary}</div>` +
    `<svg class="ct-path-graph" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="How long this traffic has been seen">${bars.join('')}${axis}</svg>`;
}

function renderPeerPath(result, filter) {
  const roles = peerPaths(result, filter);
  if (!roles.length) return '';
  const peerIp = result.peers[filter.peer];
  const sections = roles.map((rp) => {
    const srcIp = rp.role === 0 ? result.host : peerIp;
    const dstIp = rp.role === 0 ? peerIp : result.host;
    const withOther = hasOther(rp.lanes);
    const rows = rp.lanes.map((fw) => {
      const href = peerDetailsHref(result, rp.role, filter.peer, fw.idx, filter.port);
      return `<tr><td>${escHtml(result.lanes[fw.idx].label)}</td>${countCells(fw, withOther)}` +
        `<td><a class="btn btn-sm btn-secondary ct-details" href="${escHtml(href)}" target="_blank" rel="noopener">Details</a></td></tr>`;
    }).join('');
    return `<div class="ct-path-role"><h4>${escHtml(srcIp)} → ${escHtml(dstIp)} <span class="text-muted">(${ROLE_NAMES[rp.role]})</span></h4>` +
      renderPathDiagram(result, rp, srcIp, dstIp) + renderPathGraph(result, rp) +
      `<table class="data-table ct-table ct-path-table"><thead><tr><th>Firewall</th><th>Allowed</th><th>Denied</th>${otherHead(withOther)}<th>Log Search</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }).join('');
  return `<h3 class="ct-section-title">Path for ${escHtml(peerIp)}</h3>${sections}`;
}

// ── Quick summary (FortiView, in seconds, counted in sessions) ───────────────

const SUMMARY_SECTIONS = ['peers', 'policies', 'applications', 'countries'];

function summaryPanel(title, sec, renderBody) {
  let body;
  if (!sec || sec.status === 'loading') body = '<p class="text-muted">Loading…</p>';
  else if (sec.status === 'unavailable') body = '<p class="text-muted">Not available on this FortiAnalyzer.</p>';
  else if (sec.status === 'error') body = `<p class="ct-summary-error">${escHtml(sec.message || 'Could not load this section.')}</p>`;
  else body = renderBody(sec.data || {});
  return `<div class="ct-summary-section"><h4>${title}</h4>${body}</div>`;
}

function summaryTable(headers, rows) {
  if (!rows.length) return '<p class="text-muted">No sessions in this window.</p>';
  const head = headers.map((h) => `<th>${h}</th>`).join('');
  return `<div class="table-scroll"><table class="data-table ct-table"><thead><tr>${head}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}

const summaryCounts = (r) => `<td>${fmtCount(r.allowed)}</td><td class="ct-denied-text">${fmtCount(r.denied)}</td>`;

function renderSummary(summary) {
  const sections = (summary && summary.sections) || {};
  const policies = sections.policies;
  let totals = '';
  if (policies && policies.status === 'ok' && policies.data) {
    const d = policies.data;
    const fw = (d.firewalls || []).map((f) => `<li>${escHtml(f.firewall)}: ${fmtCount(f.allowed)} allowed, ${fmtCount(f.denied)} denied</li>`).join('');
    totals = `<div class="ct-summary-totals"><span><strong>${fmtCount((d.totals || {}).allowed)}</strong> allowed</span>` +
      `<span><strong class="ct-denied-text">${fmtCount((d.totals || {}).denied)}</strong> denied</span></div>` +
      (fw ? `<ul class="ct-summary-firewalls">${fw}</ul>` : '');
  }
  const peers = summaryPanel('Top peers', sections.peers, (d) => {
    const rows = d.rows || [];
    const cut = d.truncated ? `Showing the top ${fmtCount(rows.length)} of at least ${fmtCount(d.reported_total || d.total)} peers (FortiAnalyzer has more).`
      : (d.total > rows.length ? `Showing the top ${fmtCount(rows.length)} of ${fmtCount(d.total)} peers.` : '');
    return summaryTable(['Peer IP', 'Allowed', 'Denied'], rows.map((r) => `<tr><td>${escHtml(r.peer)}</td>${summaryCounts(r)}</tr>`)) +
      (cut ? `<p class="text-muted">${cut}</p>` : '');
  });
  const pols = summaryPanel('Policies', policies, (d) => summaryTable(['Firewall', 'Policy ID', 'Policy', 'Allowed', 'Denied'],
    (d.rows || []).map((r) => `<tr><td>${escHtml(r.firewall)}</td><td>${escHtml(r.policy_id || '—')}</td><td>${escHtml(r.policy)}</td>${summaryCounts(r)}</tr>`)));
  const apps = summaryPanel('Applications', sections.applications, (d) => summaryTable(['Application', 'Category', 'Allowed', 'Denied'],
    (d.rows || []).map((r) => `<tr><td>${escHtml(r.app)}</td><td>${escHtml(r.category)}</td>${summaryCounts(r)}</tr>`)));
  const countries = summaryPanel('Countries', sections.countries, (d) => summaryTable(['Country', 'Allowed', 'Denied'],
    (d.rows || []).map((r) => `<tr><td>${escHtml(r.country)}</td>${summaryCounts(r)}</tr>`)));
  return '<h3 class="ct-section-title">Quick summary</h3>' +
    '<p class="text-muted ct-summary-unit">Sessions, counted by FortiAnalyzer, not logs: one connection can write several logs, so these numbers differ from the timeline below. Ports and the time chart come only from the timeline.</p>' +
    totals + `<div class="ct-summary-grid">${peers}${pols}${apps}${countries}</div>`;
}

// A new Build ends the old summary: stop its loader (late answers are ignored) and clear the
// panel, so a failed start never leaves another host's summary on screen.
function clearSummary(loader, panel) {
  loader.stop();
  panel.classList.add('hidden');
  panel.innerHTML = '';
}

// Starts the four sections for a build, a few requests at a time, and reports every change.
// Answers that belong to an earlier start (or arrive after stop) are ignored.
function createSummaryLoader(fetchSection, onUpdate, opts) {
  const concurrency = (opts && opts.concurrency) || 3;
  let run = 0;
  function start(payload) {
    const id = ++run;
    const summary = { payload, sections: {} };
    SUMMARY_SECTIONS.forEach((s) => { summary.sections[s] = { status: 'loading' }; });
    const queue = SUMMARY_SECTIONS.slice();
    let inFlight = 0;
    const emit = () => { if (id === run) onUpdate(summary); };
    const pump = () => {
      while (id === run && inFlight < concurrency && queue.length) {
        const section = queue.shift();
        inFlight += 1;
        fetchSection(section, payload).then((data) => {
          if (id !== run) return;
          summary.sections[section] = data && data.unavailable
            ? { status: 'unavailable', message: data.unavailable }
            : { status: 'ok', data };
        }, (err) => {
          if (id !== run) return;
          summary.sections[section] = { status: 'error', message: String((err && err.message) || err) };
        }).then(() => { inFlight -= 1; emit(); pump(); });
      }
    };
    emit();
    pump();
    return summary;
  }
  return { start, stop() { run += 1; } };
}

// ── Page controller ──────────────────────────────────────────────────────────

function initPage() {
  const $ = (id) => document.getElementById(id);
  const form = $('ctForm');
  const state = { result: null, filter: { peer: null, port: null }, selected: null, showAll: false, jobId: null, timer: null };
  const summaryLoader = createSummaryLoader(async (section, payload) => {
    const resp = await fetch('/api/conn-timeline/summary', {
      method: 'POST',  // the page's fetch wrapper adds the CSRF header
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, section }),
    });
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.error || 'Could not load this section.');
    return body;
  }, (summary) => {
    $('ctSummary').classList.remove('hidden');
    $('ctSummary').innerHTML = renderSummary(summary);
  });

  function showError(msg) {
    const box = $('ctError');
    box.textContent = msg;
    box.classList.toggle('hidden', !msg);
  }

  // The target's configured ADOM, by target label (the ADOM picker's default).
  let targetAdoms = {};

  async function loadAdoms() {
    const select = $('ctAdom');
    const target = $('ctTarget').value;
    const fallback = targetAdoms[target] || 'root';
    select.innerHTML = `<option value="${escHtml(fallback)}">${escHtml(fallback)}</option>`;
    if (target) {
      try {
        const resp = await fetch(`/api/conn-timeline/adoms?target=${encodeURIComponent(target)}`);
        const body = resp.ok ? await resp.json() : null;
        if (body && Array.isArray(body.adoms) && body.adoms.length) {
          const def = body.default || fallback;
          const names = body.adoms.map((a) => a.name);
          if (!names.includes(def)) names.unshift(def);
          select.innerHTML = names.map((n) => `<option value="${escHtml(n)}">${escHtml(n)}</option>`).join('');
          select.value = def;
        }
      } catch {
        // keep the configured ADOM
      }
    }
    await loadDevices();
  }

  async function loadDevices() {
    const select = $('ctDevice');
    const allOption = '<option value="All_FortiGate" selected>All FortiGates</option>';
    const target = $('ctTarget').value;
    select.innerHTML = allOption;
    if (!target) return;
    try {
      const resp = await fetch(`/api/conn-timeline/devices?target=${encodeURIComponent(target)}&adom=${encodeURIComponent($('ctAdom').value)}`);
      const devices = resp.ok ? await resp.json() : [];
      if (Array.isArray(devices)) {
        select.innerHTML = allOption + devices.map((d) => `<option value="${escHtml(d.devid)}">${escHtml(d.name || d.devid)}</option>`).join('');
      }
    } catch {
      // keep "All FortiGates"
    }
  }

  async function loadTargets() {
    const select = $('ctTarget');
    try {
      const resp = await fetch('/api/conn-timeline/targets');
      if (resp.status === 401) { location.href = '/login'; return; }
      const targets = await resp.json();
      select.innerHTML = targets.map((t) => `<option value="${escHtml(t.label)}">${escHtml(t.label)} (${escHtml(t.host)})</option>`).join('');
      targetAdoms = Object.fromEntries(targets.map((t) => [t.label, t.adom]));
      await loadAdoms();
    } catch {
      select.innerHTML = '<option value="">(unable to load targets)</option>';
    }
  }

  function render() {
    const result = state.result;
    if (!result) return;
    const summary = summarize(result, state.filter);
    $('ctResult').classList.remove('hidden');
    $('ctHeader').innerHTML = renderHeader(result);
    $('ctCoverage').innerHTML = renderCoverage(result);
    const filterHtml = renderFilter(result, state.filter);
    $('ctFilter').innerHTML = filterHtml;
    $('ctFilter').classList.toggle('hidden', !filterHtml);
    $('ctChart').innerHTML = renderChart(result, summary, {
      showAll: state.showAll,
      selected: state.selected,
      topPort: (lane, bucket) => topPortOf(result, state.filter, lane, bucket),
    });
    $('ctPeers').innerHTML = renderTopTable(summary.peers, 'peer', state.filter.peer);
    $('ctPorts').innerHTML = renderTopTable(summary.ports, 'port', state.filter.port);
    $('ctPolicies').innerHTML = renderPolicies(result, summary);
    const pathHtml = renderPeerPath(result, state.filter);
    $('ctPeerPath').innerHTML = pathHtml;
    $('ctPeerPath').classList.toggle('hidden', !pathHtml);
    const detail = $('ctDetail');
    if (state.selected) {
      detail.innerHTML = renderDetail(result, state.filter, state.selected);
      detail.classList.remove('hidden');
    } else {
      detail.classList.add('hidden');
    }
  }

  // Draw what has arrived so far. Firewall rows can reorder as more logs come in, so
  // a selected slice is kept only while its firewall is still on the same row.
  function applyPartial(partial) {
    const sel = state.selected;
    const label = sel && state.result ? state.result.lanes[sel.lane] && state.result.lanes[sel.lane].label : null;
    state.result = partial;
    if (sel && !(partial.lanes[sel.lane] && partial.lanes[sel.lane].label === label)) state.selected = null;
    render();
  }

  function setBusy(busy, text) {
    $('ctBuildBtn').disabled = busy;
    $('ctCancelBtn').classList.toggle('hidden', !busy);
    $('ctProgress').textContent = text || '';
  }

  function progressText(p) {
    if (!p) return 'Starting…';
    const matched = p.matched != null ? ` of ${fmtCount(p.matched)}${p.matched_final ? '' : '+'} matched` : '';
    if (p.phase === 'counting') return `Fetched ${fmtCount(p.fetched)}${matched} logs, reading the final count…`;
    if (p.phase === 'splitting') return `Fetched ${fmtCount(p.fetched)}${matched} logs, splitting a burst of logs that share one second…`;
    if (p.fetched) return `Fetched ${fmtCount(p.fetched)}${matched} logs…`;
    return 'Searching FortiAnalyzer…';
  }

  async function poll() {
    if (!state.jobId) return;
    try {
      const resp = await fetch(`/api/conn-timeline/${encodeURIComponent(state.jobId)}`);
      const body = await resp.json();
      if (!resp.ok) throw new Error(body.error || 'Timeline lookup failed.');
      if (body.status === 'running') {
        setBusy(true, progressText(body.progress));
        if (body.partial) applyPartial(body.partial);
        state.timer = setTimeout(poll, 1000);
        return;
      }
      state.jobId = null;
      state.doneJobId = body.id;  // what Continue refers to
      setBusy(false, '');
      if (body.status === 'failed') { showError(body.error || 'Timeline failed.'); return; }
      if (body.result) {
        state.result = body.result;  // the filter chosen while it filled in stays
        state.selected = null;
        render();
      }
      if (body.status === 'cancelled') $('ctProgress').textContent = 'Cancelled. Showing what was fetched.';
    } catch (exc) {
      state.jobId = null;
      setBusy(false, '');
      showError(exc.message || 'Timeline failed.');
    }
  }

  function windowPayload() {
    const preset = $('ctPreset').value;
    if (preset !== 'custom') return { preset };
    const s = $('ctStart').value;
    const e = $('ctEnd').value;
    return {
      start_time: s ? new Date(s).toISOString() : '',
      end_time: e ? new Date(e).toISOString() : '',
    };
  }

  async function build(ev) {
    ev.preventDefault();
    showError('');
    if (state.jobId) return;
    clearSummary(summaryLoader, $('ctSummary'));
    state.result = null;
    state.filter = { peer: null, port: null };
    state.selected = null;
    state.showAll = false;
    $('ctResult').classList.add('hidden');
    const payload = {
      target: $('ctTarget').value,
      adom: $('ctAdom').value,
      host: $('ctHost').value.trim(),
      direction: $('ctDirection').value,
      device: $('ctDevice').value,
      verdict: $('ctVerdict').value,
      ...windowPayload(),
    };
    setBusy(true, 'Starting…');
    try {
      const resp = await fetch('/api/conn-timeline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const body = await resp.json();
      if (!resp.ok) { setBusy(false, ''); showError(body.error || 'Could not start the timeline.'); return; }
      state.jobId = body.job_id;
      summaryLoader.start(payload);  // beside the raw build, not instead of it
      poll();
    } catch {
      setBusy(false, '');
      showError('Could not start the timeline. Please try again.');
    }
  }

  // Reads what a partial build did not reach, into the same picture. The picture stays
  // on screen and fills in; the new job's result replaces it when it ends.
  async function continueBuild() {
    showError('');
    if (state.jobId || !state.doneJobId) return;
    setBusy(true, 'Continuing…');
    try {
      const resp = await fetch(`/api/conn-timeline/${encodeURIComponent(state.doneJobId)}/continue`, {
        method: 'POST',  // the page's fetch wrapper adds the CSRF header
      });
      const body = await resp.json();
      if (!resp.ok) { setBusy(false, ''); showError(body.error || 'Could not continue the timeline.'); return; }
      state.jobId = body.job_id;
      poll();
    } catch {
      setBusy(false, '');
      showError('Could not continue the timeline. Please try again.');
    }
  }

  async function cancel() {
    if (!state.jobId) return;
    try {
      await fetch(`/api/conn-timeline/${encodeURIComponent(state.jobId)}`, { method: 'DELETE' });
    } catch {
      // the next poll reports the outcome
    }
  }

  function onClick(ev) {
    const el = ev.target;
    if (el.id === 'ctContinue') { continueBuild(); return; }
    if (el.id === 'ctShowAll') { state.showAll = true; render(); return; }
    if (el.id === 'ctClearFilter') { state.filter = { peer: null, port: null }; state.selected = null; render(); return; }
    if (el.id === 'ctCloseDetail') { state.selected = null; render(); return; }
    const pick = el.closest && el.closest('.ct-pick');
    if (pick) {
      const kind = pick.dataset.kind;
      const idx = Number(pick.dataset.idx);
      state.filter[kind] = state.filter[kind] === idx ? null : idx;
      state.selected = null;
      render();
      return;
    }
    if (el.dataset && el.dataset.lane != null && el.dataset.bucket != null) {
      state.selected = { lane: Number(el.dataset.lane), bucket: Number(el.dataset.bucket), verdict: el.dataset.verdict || null };
      render();
      $('ctDetail').scrollIntoView({ block: 'nearest' });
    }
  }

  const presetSelect = $('ctPreset');
  presetSelect.value = form.dataset.defaultPreset || '1h';
  presetSelect.addEventListener('change', () => $('ctCustomRow').classList.toggle('hidden', presetSelect.value !== 'custom'));
  $('ctTarget').addEventListener('change', loadAdoms);
  $('ctAdom').addEventListener('change', loadDevices);
  form.addEventListener('submit', build);
  $('ctCancelBtn').addEventListener('click', cancel);
  $('ctResult').addEventListener('click', onClick);
  document.querySelectorAll('.ct-demo-host').forEach((btn) => btn.addEventListener('click', async () => {
    $('ctHost').value = btn.dataset.ip;
    if ($('ctTarget').value !== btn.dataset.target) {
      $('ctTarget').value = btn.dataset.target;
      await loadAdoms();
    }
  }));
  loadTargets();
}

if (typeof document !== 'undefined' && document.getElementById('ctForm')) {
  initPage();
}
