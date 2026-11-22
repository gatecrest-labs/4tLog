'use strict';

(function () {

const SECTIONS = [
  {
    id: 'overview',
    label: 'Overview',
    html: `
<h3>What is 4tlog?</h3>
<p>4tlog is a read-only tool for monitoring and searching FortiAnalyzer appliances — no configuration changes are ever made to any device.</p>
<h3>Navigation</h3>
<ul>
  <li><strong>Dashboard</strong> — live health cards (status, version, serial, disk, CPU/mem) for each configured FortiAnalyzer appliance.</li>
  <li><strong>Log Search</strong> — targeted traffic-log search by source/destination IP, port/service, time range, and advanced fields, with CSV/JSON export.</li>
  <li><strong>Connection Timeline</strong> — where one IP address talked, through which firewalls, and whether each connection was allowed or denied, as swim lanes over time.</li>
  <li><strong>Admin</strong> — manage users, groups/tab permissions, FAZ targets, and view system logs (admins only).</li>
</ul>
`,
  },
  {
    id: 'dashboard',
    label: 'Dashboard',
    tab: 'dashboard',
    html: `
<h3>Health cards</h3>
<p>Each card shows a FortiAnalyzer appliance's connectivity status, hostname, version, serial, disk usage, and (if SNMP is enabled) CPU/memory gauges. Data refreshes on a background timer — the page never blocks waiting on a live device call.</p>
<h3>Status colors</h3>
<div class="help-status-list">
  <span class="status-dot green"></span> <span><strong>Green</strong> — reachable, metrics within normal range (or SNMP disabled).</span>
  <span class="status-dot yellow"></span> <span><strong>Yellow</strong> — CPU or memory elevated (warn threshold).</span>
  <span class="status-dot red"></span> <span><strong>Red</strong> — CPU or memory critical.</span>
  <span class="status-dot gray"></span> <span><strong>Gray</strong> — first poll still pending.</span>
</div>
<p>An "offline" card with a red error message means the last poll failed — check the message for whether it's a connection issue or a permission error on the FortiAnalyzer side.</p>
`,
  },
  {
    id: 'log_search',
    label: 'Log Search',
    tab: 'log_search',
    html: `
<h3>Required filters</h3>
<p>At least one of Source IP or Destination IP must be filled in — searches with both left blank (or both set to <code>ANY</code>/<code>ALL</code>) are blocked to keep queries targeted and fast.</p>
<h3>IP formats</h3>
<p>Each IP box accepts a comma-separated list of single IPs, CIDR blocks (<code>10.1.1.0/24</code>), or explicit ranges (<code>10.1.1.1-10.1.1.10</code>) — IPv4 or IPv6. Leaving a box blank, or typing <code>ANY</code> or <code>ALL</code>, means "no filter on this field" — useful when you want to fix only one side (e.g. any source, but destination <code>8.8.8.8</code>).</p>
<h3>Port/Service formats</h3>
<p>Accepts a port number (<code>443</code>), <code>tcp:443</code>/<code>udp:53</code>, a range (<code>tcp:1000-1200</code>), or a bare service name (<code>HTTPS</code>). Leave blank to match any port/service.</p>
<h3>Advanced filters</h3>
<p>Use "+ Add filter" to add extra field/operator/value rows beyond the basics — narrows the search further.</p>
<h3>Results table</h3>
<p>Date/Time, Source, Destination, Port, Action, and Firewall are always shown as the first six columns, in that order, when present — any other returned fields follow alphabetically. Use "Show" to pick how many rows appear per page (10/25/50/100) and the &laquo;/&lsaquo;/&rsaquo;/&raquo; controls to move between pages.</p>
<h3>Refine filter</h3>
<p>Once results load, use the filter box above the table to narrow them further without re-running the search — no need to wait on FortiAnalyzer again. Choose <strong>Contains</strong> for a plain substring match or <strong>Regex</strong> for a regular expression, and check <strong>Negate</strong> to keep only rows that <em>don't</em> match (e.g. everything except <code>8.8.8.8</code>). It matches against every column's value, filters live as you type, and narrows pagination, the row count, and both exports to what's currently matched.</p>
<h3>Columns</h3>
<p>Click "Columns" above the table to show or hide any of the non-pinned fields returned by a search — the six pinned columns above can't be hidden. Your choices are remembered in this browser across future searches and log types.</p>
<h3>Export</h3>
<p>"Export CSV"/"Export JSON" download the currently-loaded and currently-filtered results (up to the result cap) — including only the columns currently shown — not just the page on screen.</p>
`,
  },
  {
    id: 'conn_timeline',
    label: 'Connection Timeline',
    tab: 'conn_timeline',
    html: `
<h3>What it shows</h3>
<p>Enter one IP address (IPv4 or IPv6; hostnames aren't looked up) and a time window. The timeline reads that address's raw traffic logs from FortiAnalyzer and draws one lane per firewall (and VDOM) that logged it. Each bar is one time slice: green for allowed, red with hatching for denied, gray for any other action. Bars are scaled to the busiest slice on the chart.</p>
<h3>Direction</h3>
<p><strong>Either direction</strong> matches the address as source or destination; the "peer" is always the other side. Pick <strong>As source</strong> or <strong>As destination</strong> to narrow it.</p>
<h3>Time window</h3>
<p>One hour by default, seven days at most. Longer windows use wider slices (up to 3 hours each on a 7-day view).</p>
<h3>Complete or partial</h3>
<p>A timeline is built from at most 20,000 logs, and stops after about 90 seconds. The line above the chart says whether it saw every matched log or only the first part. When it's partial, the time after the last log it read is greyed out. Narrow the window, pick one firewall, or show only allowed or denied traffic to see all of it.</p>
<h3>Drilling in</h3>
<p>Click a bar to see that slice's ports, peers and policies, with a link that opens Log Search on exactly those logs. Click a row in Top peers or Top ports to filter the whole page to it; click it again to clear. The Policies table lists each firewall's policy ID and name with allowed and denied counts; policy 0 is the implicit deny.</p>
<h3>Audit</h3>
<p>Every timeline build is written to the app log: who looked at which address, when, and how much of the traffic the picture covered.</p>
`,
  },
  {
    id: 'admin',
    label: 'Admin',
    adminOnly: true,
    html: `
<h3>Groups &amp; tab permissions</h3>
<p>Groups control which tabs a user can see (<strong>allowed_tabs</strong>) and, optionally, which FortiAnalyzer targets/ADOMs they can view on the Dashboard and Log Search (<strong>adom_restrict</strong> + <strong>allowed_adoms</strong>).</p>
<h3>FAZ Targets</h3>
<p>Each target is one FortiAnalyzer appliance/ADOM: label, host, ADOM, bearer token, and optional per-target SNMP credential overrides. Edits take effect on the next poll cycle without an app restart.</p>
<h3>Logs</h3>
<p>The Logs sub-tab shows the app's own in-memory log buffer — useful for diagnosing a failed poll or search without shell access to the container.</p>
`,
  },
];

const allowed = new Set(window._helpAllowedTabs || []);
const isAdmin = Boolean(window._helpIsAdmin);

function visibleSections() {
  return SECTIONS.filter((s) => {
    if (s.adminOnly) return isAdmin;
    if (s.tab) return allowed.has(s.tab);
    return true;
  });
}

function buildPanel() {
  const sections = visibleSections();
  if (!sections.length) return;

  const tabBtns = sections.map((s, i) =>
    `<button class="help-tab${i === 0 ? ' active' : ''}" data-tab="${s.id}">${s.label}</button>`
  ).join('');
  const tabPanes = sections.map((s, i) =>
    `<div class="help-pane${i === 0 ? ' active' : ''}" id="help-pane-${s.id}">${s.html}</div>`
  ).join('');

  const panel = document.createElement('div');
  panel.id = 'helpPanel';
  panel.className = 'help-panel hidden';
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-modal', 'true');
  panel.setAttribute('aria-label', 'Help');
  panel.innerHTML = `
<div class="help-panel-inner">
  <div class="help-header">
    <span class="help-title">&#10067; Help &amp; Guide</span>
    <button class="help-close" id="helpClose" aria-label="Close help">&times;</button>
  </div>
  <div class="help-tabs">${tabBtns}</div>
  <div class="help-body">${tabPanes}</div>
</div>`;
  document.body.appendChild(panel);

  const backdrop = document.createElement('div');
  backdrop.id = 'helpBackdrop';
  backdrop.className = 'help-backdrop hidden';
  document.body.appendChild(backdrop);
}

function wirePanel() {
  const panel = document.getElementById('helpPanel');
  const backdrop = document.getElementById('helpBackdrop');
  const btn = document.getElementById('helpBtn');
  if (!panel) return;

  function open() {
    panel.classList.remove('hidden');
    backdrop.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }
  function close() {
    panel.classList.add('hidden');
    backdrop.classList.add('hidden');
    document.body.style.overflow = '';
  }

  btn.addEventListener('click', open);
  document.getElementById('helpClose').addEventListener('click', close);
  backdrop.addEventListener('click', close);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });

  panel.querySelectorAll('.help-tab').forEach((tab) => {
    tab.addEventListener('click', function () {
      panel.querySelectorAll('.help-tab').forEach((t) => t.classList.remove('active'));
      panel.querySelectorAll('.help-pane').forEach((p) => p.classList.remove('active'));
      this.classList.add('active');
      document.getElementById(`help-pane-${this.dataset.tab}`).classList.add('active');
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('helpBtn')) return;
  buildPanel();
  wirePanel();
});

})();
