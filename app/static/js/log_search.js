'use strict';

let currentRows = [];
let currentFields = [];
let currentColumns = [];
let visibleRows = [];
let currentPage = 1;
let pageSize = 25;

// The 6 columns below are always shown first, in this order, when their
// underlying raw field(s) exist in the result set — the rest of the
// returned fields follow in their existing (alphabetical) order. Each
// virtual column merges one or more raw FortiAnalyzer fields into a single
// display value (e.g. Source = srcip, plus a resolved name if the row has
// one). Field-name fallbacks here are defensive: confirmed live traffic
// logs only return srcip/dstip, no resolved name field, so srcname/srchost
// are untested guesses for logs that do resolve names.
const VIRTUAL_COLUMNS = [
  {
    key: 'datetime',
    label: 'Date/Time',
    sourceFields: ['date', 'time', 'itime', 'eventtime'],
    render(row) {
      if (row.date != null && row.time != null) return `${row.date} ${row.time}`;
      for (const f of ['itime', 'eventtime', 'date']) {
        if (row[f] != null) return String(row[f]);
      }
      return '';
    },
  },
  {
    key: 'source',
    label: 'Source',
    sourceFields: ['srcip', 'srcname', 'srchost'],
    render(row) {
      const name = row.srcname || row.srchost;
      if (name && row.srcip) return `${name} (${row.srcip})`;
      return name || row.srcip || '';
    },
  },
  {
    key: 'destination',
    label: 'Destination',
    sourceFields: ['dstip', 'dstname', 'dsthost'],
    render(row) {
      const name = row.dstname || row.dsthost;
      if (name && row.dstip) return `${name} (${row.dstip})`;
      return name || row.dstip || '';
    },
  },
  {
    key: 'port',
    label: 'Port',
    sourceFields: ['dstport', 'service'],
    render(row) {
      if (row.dstport != null && row.service) return `${row.dstport}/${row.service}`;
      if (row.dstport != null) return String(row.dstport);
      return row.service || '';
    },
  },
  {
    key: 'action',
    label: 'Action',
    sourceFields: ['action'],
    render(row) { return row.action != null ? String(row.action) : ''; },
  },
  {
    key: 'firewall',
    label: 'Firewall',
    sourceFields: ['devname', 'devid'],
    render(row) { return row.devname || row.devid || ''; },
  },
];

function buildColumns(fields) {
  const fieldSet = new Set(fields);
  const consumed = new Set();
  const columns = [];
  for (const vc of VIRTUAL_COLUMNS) {
    const present = vc.sourceFields.filter((f) => fieldSet.has(f));
    if (present.length === 0) continue;
    present.forEach((f) => consumed.add(f));
    columns.push({ key: vc.key, label: vc.label, isVirtual: true, render: vc.render });
  }
  const rest = fields.filter((f) => !consumed.has(f));
  for (const f of rest) {
    columns.push({ key: f, label: f, isVirtual: false, raw: f });
  }
  return columns;
}

function cellValue(column, row) {
  return column.isVirtual ? column.render(row) : row[column.raw];
}

function escHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const HIDDEN_COLUMNS_KEY = 'logSearchHiddenColumns';

function loadHiddenColumns() {
  try {
    const raw = localStorage.getItem(HIDDEN_COLUMNS_KEY);
    return new Set(raw ? JSON.parse(raw) : []);
  } catch {
    return new Set();
  }
}

function saveHiddenColumns() {
  try {
    localStorage.setItem(HIDDEN_COLUMNS_KEY, JSON.stringify([...hiddenColumns]));
  } catch {
    // Storage unavailable or quota exceeded — hiddenColumns stays in-memory
    // only for this page session; renderPage() below still runs.
  }
}

let hiddenColumns = loadHiddenColumns();

function renderedColumns() {
  return currentColumns.filter((c) => c.isVirtual || !hiddenColumns.has(c.raw));
}

function renderColumnsPopover() {
  const popover = document.getElementById('columnsPopover');
  const nonPinned = currentColumns.filter((c) => !c.isVirtual);
  if (nonPinned.length === 0) {
    popover.innerHTML = '<div class="columns-popover-empty">No extra columns</div>';
    return;
  }
  popover.innerHTML = nonPinned.map((c) => `
    <label>
      <input type="checkbox" class="column-toggle" data-field="${escHtml(c.raw)}" ${hiddenColumns.has(c.raw) ? '' : 'checked'} />
      ${escHtml(c.label)}
    </label>
  `).join('');
  popover.querySelectorAll('.column-toggle').forEach((cb) => {
    cb.addEventListener('change', () => {
      const field = cb.dataset.field;
      if (cb.checked) hiddenColumns.delete(field);
      else hiddenColumns.add(field);
      saveHiddenColumns();
      renderPage();
    });
  });
}

function toFazTime(date) {
  // Send an unambiguous UTC instant — the backend (FAZClient.local_time_range)
  // converts this to the target appliance's own configured timezone before
  // submitting the search, since FortiAnalyzer interprets time-range.start/end
  // in its own local time, not UTC and not the browser's local time (a naive
  // browser-local timestamp broke as soon as the browser and the appliance
  // were in different timezones — confirmed live).
  return date.toISOString();
}

function presetToRange(preset) {
  const end = new Date();
  const start = new Date(end);
  const match = preset.match(/^(\d+)([mhd])$/);
  if (!match) return null;
  const amount = parseInt(match[1], 10);
  if (match[2] === 'm') start.setMinutes(start.getMinutes() - amount);
  if (match[2] === 'h') start.setHours(start.getHours() - amount);
  if (match[2] === 'd') start.setDate(start.getDate() - amount);
  return { start: toFazTime(start), end: toFazTime(end) };
}

async function loadTargets() {
  const select = document.getElementById('targetSelect');
  try {
    const resp = await fetch('/api/log-search/targets');
    if (resp.status === 401) { location.href = '/login'; return; }
    const targets = await resp.json();
    if (!Array.isArray(targets)) {
      select.innerHTML = '<option value="">(unable to load targets)</option>';
      return;
    }
    select.innerHTML = targets.map((t) => `<option value="${escHtml(t.label)}">${escHtml(t.label)} (${escHtml(t.host)})</option>`).join('');
    await loadDevices();
  } catch {
    select.innerHTML = '<option value="">(unable to load targets)</option>';
  }
}

async function loadDevices() {
  const deviceSelect = document.getElementById('deviceInput');
  const target = document.getElementById('targetSelect').value;
  const allOption = '<option value="All_FortiGate" selected>All_FortiGate</option>';
  if (!target) {
    deviceSelect.innerHTML = allOption;
    return;
  }
  try {
    const resp = await fetch(`/api/log-search/devices?target=${encodeURIComponent(target)}`);
    if (!resp.ok) { deviceSelect.innerHTML = allOption; return; }
    const devices = await resp.json();
    if (!Array.isArray(devices) || devices.length === 0) {
      deviceSelect.innerHTML = allOption;
      return;
    }
    deviceSelect.innerHTML = allOption + devices.map((d) =>
      `<option value="${escHtml(d.devid)}">${escHtml(d.name || d.devid)}${d.platform ? ' (' + escHtml(d.platform) + ')' : ''}</option>`
    ).join('');
  } catch {
    deviceSelect.innerHTML = allOption;
  }
}

function addFilterRow() {
  const container = document.getElementById('extraFilters');
  const row = document.createElement('div');
  row.className = 'extra-filter-row';
  row.innerHTML = `
    <input type="text" class="form-control filter-field" placeholder="field (e.g. action)" />
    <select class="form-select filter-op">
      <option value="==">==</option>
      <option value="!=">!=</option>
    </select>
    <input type="text" class="form-control filter-value" placeholder="value" />
    <button type="button" class="btn btn-sm btn-secondary remove-filter-btn">Remove</button>
  `;
  row.querySelector('.remove-filter-btn').addEventListener('click', () => row.remove());
  container.appendChild(row);
}

function collectExtraFilters() {
  return Array.from(document.querySelectorAll('#extraFilters .extra-filter-row')).map((row) => ({
    field: row.querySelector('.filter-field').value.trim(),
    op: row.querySelector('.filter-op').value,
    value: row.querySelector('.filter-value').value.trim(),
  })).filter((f) => f.field && f.value);
}

function rowMatches(row, term, mode) {
  // Search over both the rendered virtual-column text (so pinned-column
  // labels/formatted values like "443/HTTPS" remain matchable as a combined
  // string) AND every raw field value in the row (so fields a virtual
  // column's render() consumed-but-didn't-emit — e.g. devid when devname is
  // present — stay searchable regardless of column visibility/consumption).
  const haystack = [
    ...currentColumns.filter((c) => c.isVirtual).map((c) => String(cellValue(c, row) ?? '')),
    ...Object.values(row).map((v) => String(v ?? '')),
  ].join(' ␟ ');
  if (mode === 'regex') {
    return new RegExp(term, 'i').test(haystack);
  }
  return haystack.toLowerCase().includes(term.toLowerCase());
}

function applyRefineFilter() {
  const term = document.getElementById('refineFilterInput').value.trim();
  const mode = document.getElementById('refineFilterMode').value;
  const negate = document.getElementById('refineFilterNegate').checked;
  const errBox = document.getElementById('refineFilterError');
  errBox.classList.add('hidden');

  if (!term) {
    visibleRows = currentRows;
    currentPage = 1;
    renderPage();
    return;
  }

  try {
    visibleRows = currentRows.filter((row) => {
      const matched = rowMatches(row, term, mode);
      return negate ? !matched : matched;
    });
  } catch (exc) {
    errBox.textContent = mode === 'regex' ? `Invalid regex: ${exc.message}` : 'Filter error';
    errBox.classList.remove('hidden');
    return;
  }
  currentPage = 1;
  renderPage();
}

function totalPages() {
  return Math.max(1, Math.ceil(visibleRows.length / pageSize));
}

function goToPage(page) {
  currentPage = Math.min(Math.max(1, page), totalPages());
  renderPage();
}

function renderPage() {
  const headerRow = document.getElementById('resultsHeaderRow');
  const body = document.getElementById('resultsBody');
  const columns = renderedColumns();
  headerRow.innerHTML = columns.map((c) => `<th>${escHtml(c.label)}</th>`).join('');

  const start = (currentPage - 1) * pageSize;
  const pageRows = visibleRows.slice(start, start + pageSize);
  body.innerHTML = pageRows.map((row) =>
    `<tr>${columns.map((c) => `<td>${escHtml(cellValue(c, row))}</td>`).join('')}</tr>`
  ).join('');

  const total = visibleRows.length;
  const pages = totalPages();
  document.getElementById('resultsSummary').textContent = total === 0
    ? 'No results'
    : `Showing ${start + 1}–${Math.min(start + pageSize, total)} of ${total}`;
  document.getElementById('pageIndicator').textContent = `Page ${currentPage} of ${pages}`;
  document.getElementById('firstPageBtn').disabled = currentPage <= 1;
  document.getElementById('prevPageBtn').disabled = currentPage <= 1;
  document.getElementById('nextPageBtn').disabled = currentPage >= pages;
  document.getElementById('lastPageBtn').disabled = currentPage >= pages;
}

function renderResults(result) {
  currentRows = result.rows;
  currentFields = result.fields;
  currentColumns = buildColumns(currentFields);
  visibleRows = currentRows;
  document.getElementById('refineFilterInput').value = '';
  document.getElementById('refineFilterMode').value = 'contains';
  document.getElementById('refineFilterNegate').checked = false;
  document.getElementById('refineFilterError').classList.add('hidden');
  renderColumnsPopover();
  currentPage = 1;
  renderPage();
  document.getElementById('truncatedBanner').classList.toggle('hidden', !result.truncated);
  document.getElementById('exportCsvBtn').disabled = currentRows.length === 0;
  document.getElementById('exportJsonBtn').disabled = currentRows.length === 0;
}

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportCsv() {
  const columns = renderedColumns();
  const header = columns.map((c) => c.label).join(',');
  const lines = visibleRows.map((row) =>
    columns.map((c) => `"${String(cellValue(c, row) ?? '').replace(/"/g, '""')}"`).join(',')
  );
  downloadBlob([header, ...lines].join('\n'), 'log_search_results.csv', 'text/csv');
}

function exportJson() {
  downloadBlob(JSON.stringify(visibleRows, null, 2), 'log_search_results.json', 'application/json');
}

async function runSearch(e) {
  e.preventDefault();
  const errBox = document.getElementById('searchError');
  errBox.classList.add('hidden');

  const preset = document.getElementById('timePreset').value;
  let start_time, end_time;
  if (preset === 'custom') {
    // <input type="datetime-local"> values represent browser-local time
    // with no timezone/seconds (e.g. "2026-07-25T14:30"). Run them through
    // the same Date -> toFazTime() conversion presets use so both paths
    // consistently send a UTC-based timestamp with seconds — otherwise
    // preset and custom searches silently target different time windows
    // on any FortiAnalyzer appliance not running in UTC.
    const startValue = document.getElementById('startTime').value;
    const endValue = document.getElementById('endTime').value;
    start_time = startValue ? toFazTime(new Date(startValue)) : '';
    end_time = endValue ? toFazTime(new Date(endValue)) : '';
  } else {
    const range = presetToRange(preset);
    start_time = range.start;
    end_time = range.end;
  }

  const payload = {
    target: document.getElementById('targetSelect').value,
    logtype: document.getElementById('logtypeSelect').value,
    device: document.getElementById('deviceInput').value,
    start_time,
    end_time,
    source_ips: document.getElementById('sourceIps').value,
    destination_ips: document.getElementById('destIps').value,
    ports: document.getElementById('ports').value,
    extra_filters: collectExtraFilters(),
  };

  const searchBtn = document.getElementById('searchBtn');
  searchBtn.disabled = true;
  searchBtn.textContent = 'Searching…';
  try {
    const resp = await fetch('/api/log-search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    let body;
    try {
      body = await resp.json();
    } catch {
      errBox.textContent = 'Search failed — please try again.';
      errBox.classList.remove('hidden');
      return;
    }
    if (!resp.ok) {
      errBox.textContent = body.error || 'Search failed.';
      errBox.classList.remove('hidden');
      return;
    }
    renderResults(body);
  } catch {
    errBox.textContent = 'Search failed — please try again.';
    errBox.classList.remove('hidden');
  } finally {
    searchBtn.disabled = false;
    searchBtn.textContent = 'Search';
  }
}

document.getElementById('timePreset').addEventListener('change', function () {
  document.getElementById('customTimeRow').classList.toggle('hidden', this.value !== 'custom');
});
document.getElementById('targetSelect').addEventListener('change', loadDevices);
document.getElementById('addFilterBtn').addEventListener('click', addFilterRow);
document.getElementById('searchForm').addEventListener('submit', runSearch);
document.getElementById('exportCsvBtn').addEventListener('click', exportCsv);
document.getElementById('exportJsonBtn').addEventListener('click', exportJson);
document.getElementById('pageSizeSelect').addEventListener('change', function () {
  pageSize = parseInt(this.value, 10);
  goToPage(1);
});
document.getElementById('firstPageBtn').addEventListener('click', () => goToPage(1));
document.getElementById('prevPageBtn').addEventListener('click', () => goToPage(currentPage - 1));
document.getElementById('nextPageBtn').addEventListener('click', () => goToPage(currentPage + 1));
document.getElementById('lastPageBtn').addEventListener('click', () => goToPage(totalPages()));
document.getElementById('refineFilterInput').addEventListener('input', applyRefineFilter);
document.getElementById('refineFilterMode').addEventListener('change', applyRefineFilter);
document.getElementById('refineFilterNegate').addEventListener('change', applyRefineFilter);
document.getElementById('columnsBtn').addEventListener('click', (e) => {
  e.stopPropagation();
  document.getElementById('columnsPopover').classList.toggle('hidden');
});
document.addEventListener('click', (e) => {
  const picker = document.querySelector('.columns-picker');
  if (picker && !picker.contains(e.target)) {
    document.getElementById('columnsPopover').classList.add('hidden');
  }
});

// Links from other tabs (the Connection Timeline's "Open in Log Search")
// arrive as query parameters: target, logtype, device, src, dst, ports,
// start/end (ISO instants), repeated filter=field==value / field!=value, and
// run=1 to search straight away. Anything that doesn't parse is ignored.
function pad2(n) {
  return String(n).padStart(2, '0');
}

function toLocalInputValue(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}` +
    `T${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

function parseFilterParam(raw) {
  const m = String(raw).match(/^([A-Za-z0-9_-]+)(==|!=)(.+)$/);
  return m ? { field: m[1], op: m[2], value: m[3] } : null;
}

function selectOption(select, value, label) {
  if (!Array.from(select.options).some((o) => o.value === value)) {
    const opt = document.createElement('option');
    opt.value = value;
    opt.textContent = label || value;
    select.appendChild(opt);
  }
  select.value = value;
}

async function applyQueryParams() {
  const params = new URLSearchParams(location.search);
  if (![...params.keys()].length) return;
  const targetSelect = document.getElementById('targetSelect');
  const target = params.get('target');
  if (target && Array.from(targetSelect.options).some((o) => o.value === target) && targetSelect.value !== target) {
    targetSelect.value = target;
    await loadDevices();
  }
  const logtype = params.get('logtype');
  const logtypeSelect = document.getElementById('logtypeSelect');
  if (logtype && Array.from(logtypeSelect.options).some((o) => o.value === logtype)) logtypeSelect.value = logtype;
  const device = params.get('device');
  if (device) selectOption(document.getElementById('deviceInput'), device);
  if (params.has('src')) document.getElementById('sourceIps').value = params.get('src');
  if (params.has('dst')) document.getElementById('destIps').value = params.get('dst');
  if (params.has('ports')) document.getElementById('ports').value = params.get('ports');
  const start = toLocalInputValue(params.get('start') || '');
  const end = toLocalInputValue(params.get('end') || '');
  if (start && end) {
    document.getElementById('timePreset').value = 'custom';
    document.getElementById('customTimeRow').classList.remove('hidden');
    document.getElementById('startTime').value = start;
    document.getElementById('endTime').value = end;
  }
  params.getAll('filter').map(parseFilterParam).filter(Boolean).forEach((f) => {
    addFilterRow();
    const rows = document.querySelectorAll('#extraFilters .extra-filter-row');
    const row = rows[rows.length - 1];
    row.querySelector('.filter-field').value = f.field;
    row.querySelector('.filter-op').value = f.op;
    row.querySelector('.filter-value').value = f.value;
  });
  if (params.get('run') === '1' && targetSelect.value) {
    const form = document.getElementById('searchForm');
    if (typeof form.requestSubmit === 'function') form.requestSubmit();
    else runSearch({ preventDefault() {} });
  }
}

renderPage();
loadTargets().then(applyQueryParams);
