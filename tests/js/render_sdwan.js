// Test harness for app/static/js/sdwan.js, driven by tests/test_sdwan_page_render.py.
// Reads [{name, target, pollInterval}] as JSON on stdin; prints {name: html} as JSON.
const fs = require('fs');
const vm = require('vm');

const el = () => ({ addEventListener() {}, value: '60', textContent: '', innerHTML: '' });
const ctx = {
  document: { getElementById: el },
  fetch: async () => ({ ok: true, status: 200, json: async () => ({ targets: [] }) }),
  setInterval() {}, clearInterval() {}, location: {},
  console, Date, Math, Number, String, JSON, Array, Object,
};
vm.createContext(ctx);
const src = fs.readFileSync(process.argv[2], 'utf8');
vm.runInContext(src + '\n;globalThis.__renderTarget = renderTarget;', ctx);

const cases = JSON.parse(fs.readFileSync(0, 'utf8'));
const out = {};
for (const c of cases) out[c.name] = ctx.__renderTarget(c.target, c.pollInterval);
process.stdout.write(JSON.stringify(out));
