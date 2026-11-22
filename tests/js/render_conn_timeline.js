// Test harness for app/static/js/conn_timeline.js, driven by
// tests/test_conn_timeline_page_render.py. Reads [{name, result, filter,
// selected, showAll}] as JSON on stdin; prints {name: {...rendered parts}}.
const fs = require('fs');
const vm = require('vm');

const ctx = { console, Date, Math, Number, String, JSON, Array, Object, Map, Set, URLSearchParams, Infinity };
vm.createContext(ctx);
const src = fs.readFileSync(process.argv[2], 'utf8');
vm.runInContext(src + `
;globalThis.__ct = { summarize, renderChart, renderCoverage, renderHeader, renderFilter,
  renderTopTable, renderPolicies, renderDetail, logSearchLinks, visibleLanes };`, ctx);
const ct = ctx.__ct;

const cases = JSON.parse(fs.readFileSync(0, 'utf8'));
const out = {};
for (const c of cases) {
  const filter = c.filter || { peer: null, port: null };
  const summary = ct.summarize(c.result, filter);
  const sel = c.selected || null;
  out[c.name] = {
    totals: summary.totals,
    maxCell: summary.maxCell,
    peers: summary.peers,
    ports: summary.ports,
    policies: summary.policies,
    lanesShown: ct.visibleLanes(c.result, summary, c.showAll).lanes,
    chart: ct.renderChart(c.result, summary, { showAll: c.showAll, selected: sel }),
    coverage: ct.renderCoverage(c.result),
    header: ct.renderHeader(c.result),
    filter: ct.renderFilter(c.result, filter),
    peersTable: ct.renderTopTable(summary.peers, 'peer', filter.peer),
    portsTable: ct.renderTopTable(summary.ports, 'port', filter.port),
    policiesTable: ct.renderPolicies(c.result, summary),
    detail: sel ? ct.renderDetail(c.result, filter, sel) : null,
    links: sel ? ct.logSearchLinks(c.result, sel.lane, sel.bucket, sel.verdict, filter) : null,
  };
}
process.stdout.write(JSON.stringify(out));
