// Test harness for app/static/js/conn_timeline.js, driven by
// tests/test_conn_timeline_page_render.py. Reads [{name, result, filter,
// selected, showAll}] as JSON on stdin; prints {name: {...rendered parts}}.
// A case with `summary` renders the Quick summary panel for that state; a case with
// `loader` runs a scripted scenario of the summary loader ('concurrency', 'stale', 'stop').
const fs = require('fs');
const vm = require('vm');

const ctx = { console, Date, Math, Number, String, JSON, Array, Object, Map, Set, URLSearchParams, Infinity };
vm.createContext(ctx);
const src = fs.readFileSync(process.argv[2], 'utf8');
vm.runInContext(src + `
;globalThis.__ct = { summarize, renderChart, renderCoverage, renderHeader, renderFilter,
  renderTopTable, renderPolicies, renderDetail, logSearchLinks, visibleLanes, renderPeerPath, peerPaths,
  renderSummary, createSummaryLoader };`, ctx);
const ct = ctx.__ct;

// Scripted loader scenarios: every fetch is a promise the scenario resolves by hand.
async function tick() { await new Promise((r) => setTimeout(r, 0)); }
function scriptedFetch() {
  const pending = [];
  const fetchSection = (section, payload) => new Promise((resolve, reject) => {
    pending.push({ section, payload, resolve, reject });
  });
  return { pending, fetchSection };
}
async function runLoader(name) {
  const { pending, fetchSection } = scriptedFetch();
  const updates = [];
  const loader = ct.createSummaryLoader(fetchSection, (s) => updates.push({
    tag: s.payload.tag,
    statuses: Object.fromEntries(Object.entries(s.sections).map(([k, v]) => [k, v.status])),
  }), { concurrency: 3 });
  if (name === 'concurrency') {
    loader.start({ tag: 'one' });
    await tick();
    const firstWave = pending.map((p) => p.section);
    pending[0].resolve({ rows: [] });
    await tick();
    return { firstWave, afterOne: pending.map((p) => p.section), updates };
  }
  if (name === 'stale') {
    loader.start({ tag: 'one' });
    await tick();
    const oldWave = pending.splice(0, pending.length);
    loader.start({ tag: 'two' });
    await tick();
    const marker = updates.length;
    oldWave.forEach((p) => p.resolve({ rows: [{ peer: 'OLD' }] }));
    await tick();
    return { updatesAfterOldAnswers: updates.length - marker, tags: updates.map((u) => u.tag) };
  }
  if (name === 'stop') {
    loader.start({ tag: 'one' });
    await tick();
    loader.stop();
    const marker = updates.length;
    pending.forEach((p) => p.resolve({ rows: [] }));
    await tick();
    return { updatesAfterStop: updates.length - marker };
  }
  if (name === 'outcomes') {
    loader.start({ tag: 'one' });
    await tick();
    pending[0].resolve({ rows: [{ peer: 'x' }] });
    pending[1].resolve({ unavailable: 'Cannot find FortiView' });
    pending[2].reject(new Error('FortiAnalyzer said no'));
    await tick();
    return { last: updates[updates.length - 1], calls: pending.map((p) => p.section) };
  }
  throw new Error('unknown loader scenario ' + name);
}

(async () => {
const cases = JSON.parse(fs.readFileSync(0, 'utf8'));
const out = {};
for (const c of cases) {
  if (c.summary) { out[c.name] = { summary: ct.renderSummary(c.summary) }; continue; }
  if (c.loader) { out[c.name] = await runLoader(c.loader); continue; }
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
    peerPath: ct.renderPeerPath(c.result, filter),
    links: sel ? ct.logSearchLinks(c.result, sel.lane, sel.bucket, sel.verdict, filter) : null,
  };
}
process.stdout.write(JSON.stringify(out));
})();
