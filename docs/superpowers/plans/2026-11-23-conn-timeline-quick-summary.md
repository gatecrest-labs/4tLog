# Connection Timeline Quick Summary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Quick summary panel on the Connection Timeline, filled in seconds from FortiView (peers, policies with allowed/denied totals and per-firewall totals, applications, countries), beside the raw build.

**Architecture:** A stateless endpoint `POST /api/conn-timeline/summary` returns one section per call, built by a new `app/conn_timeline_summary.py` from FortiView runs (`FAZClient.run_fortiview_page`). The page starts the four sections when Build is pressed, three requests at a time, and renders them as they arrive with pure functions in `conn_timeline.js`. Demo mode derives the same FortiView rows from its own synthetic traffic logs.

**Tech Stack:** Flask, pytest, ruff, vanilla JS (tested through the node harness in `tests/js/`).

**Spec:** `docs/superpowers/specs/2026-11-23-conn-timeline-quick-summary-design.md` (findings: `docs/conn-timeline-fortiview.md`)

## Global Constraints

- Counts are **sessions**, labelled "sessions, counted by FortiAnalyzer"; never merge them into the raw timeline's tables.
- FortiView `offset` goes in the **submit**, not only the fetch; `count-total: true` returns `total-count-all`.
- Filter strings: `srcip==<host>` (host as source, peers are `top-destinations` rows), `dstip==<host>` (host as destination, peers are `top-sources` rows). "either" runs both.
- Real row values are **strings** (`'6748'`); fields: `top-destinations` `dstip`; `top-sources` `srcip`; `session_pass`, `session_block`, `sessions` on all session views; `policy-hits` `policy`, `agg_policyid`, `counts`, `count_pass`, `count_block`, `fortigate`; `top-applications` `app_group`, `appcat`; `top-countries` `dstcountry` (host as source) or `srccountry` (host as destination).
- A view the appliance lacks (`Cannot find FortiView`) or a filter it rejects (`not supported`) makes that section `unavailable`; other sections still render.
- Demo mode must never reach a real FortiAnalyzer or write configuration (`tests/test_demo_mode.py` pins this).
- The repository is public: no real addresses, serials or device names in tests, docs or the changelog.
- Project commands: `uv run ruff check .`, `uv run ruff format <paths>` (never `.`: it rewrites old docs), `uv run pytest -q`. Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## Review Focus

1. A host with no sessions in the window: every section is empty, not an error (Task 2 test).
2. More peers than the peer cap: the response says `truncated` and the true `total` (Task 2 test).
3. An appliance lacking a view or rejecting a filter: only that section is `unavailable` (Tasks 2 and 3 tests).
4. FortiAnalyzer strings containing HTML (peer, policy and application names): escaped in the panel (Task 5 test).
5. An answer for an older Build arriving after a new Build started: ignored (Task 5 test).

---

### Task 1: `FAZClient.run_fortiview_page`

**Files:**
- Modify: `app/faz_client.py` (next to `run_fortiview`, ~line 629)
- Test: `tests/test_faz_client.py` (use its `_client(monkeypatch, responses)` helper, as the `run_fortiview` tests do)

**Interfaces:**
- Produces: `FAZClient.run_fortiview_page(self, adom: str, view: str, time_range: tuple[str, str], *, filter: str | None = None, devices: list[dict] | None = None, limit: int = 1000, offset: int = 0, poll_interval: float = 1.0, timeout: float = 60.0) -> tuple[list[dict], int | None]`. Returns the rows and the result's `total-count-all` (None if absent). Existing `run_fortiview` is unchanged.

- [ ] **Step 1: Write failing tests** `test_run_fortiview_page_sends_offset_and_count_total_on_the_submit` (assert `calls[0]["json"]["params"][0]` has `"offset": 1000`, `"count-total": True`, `"device": [{"devid": "All_FortiGate"}]`, and the fetch params carry `"offset": 1000`), `test_run_fortiview_page_returns_rows_and_total` (poll once at percentage 40, then 100 with `"total-count-all": 1054` → returns `(rows, 1054)`), `test_run_fortiview_page_deletes_the_task` (a third call with `method == "delete"` and url ending `/run/<tid>`; a failing delete response must not raise), `test_run_fortiview_page_times_out` (never reaches 100 with `timeout=0` → `FAZError` mentioning the view).
- [ ] **Step 2: Run** `uv run pytest tests/test_faz_client.py -q -k run_fortiview_page` — expect FAIL (`AttributeError`).
- [ ] **Step 3: Implement** as above, following `run_fortiview`'s submit, poll and unwrap shape; the delete is best effort in a `finally`.
- [ ] **Step 4: Run** the same command and `uv run ruff check .` — expect PASS.
- [ ] **Step 5: Commit** `git add app/faz_client.py tests/test_faz_client.py && git commit -m "Add run_fortiview_page: offset and total count for FortiView runs"`.

### Task 2: `app/conn_timeline_summary.py`

**Files:**
- Create: `app/conn_timeline_summary.py`
- Test: `tests/test_conn_timeline_summary.py`

**Interfaces:**
- Consumes: `client.run_fortiview_page(adom, view, time_range, filter=..., devices=..., limit=..., offset=...)` from Task 1; `FAZError` from `app.faz_client`.
- Produces:
  - `SECTIONS = ("peers", "policies", "applications", "countries")`, `PEER_CAP = 2000` (most peer rows read per role), `PEER_ROWS = 100` (most returned).
  - `roles(direction: str) -> tuple[str, ...]`: `"either"` → `("src", "dst")`, `"src"` → `("src",)`, `"dst"` → `("dst",)`.
  - `role_filter(host: str, role: str) -> str`: `srcip==<host>` for `"src"`, `dstip==<host>` for `"dst"`.
  - `summarize(client, section: str, host: str, direction: str, time_range: tuple[str, str], devices: list[dict] | None) -> dict`, raising `ValueError` for an unknown section. Result shapes (all counts `int`):
    - `peers`: `{"rows": [{"peer", "allowed", "denied", "sessions", "roles": ["src"|"dst", ...]}], "total": int, "truncated": bool}`, rows merged by peer across roles, sorted by `sessions` desc then peer, at most `PEER_ROWS`; `total` is the number of distinct peers read; `truncated` is true if any role's `total-count-all` exceeded the rows read (`PEER_CAP`).
    - `policies`: `{"rows": [{"firewall", "policy_id", "policy", "allowed", "denied", "hits"}], "totals": {"allowed", "denied"}, "firewalls": [{"firewall", "allowed", "denied"}]}`; rows merged by `(firewall, policy_id)` across roles, sorted by `hits` desc; totals and firewalls summed from the same rows.
    - `applications`: `{"rows": [{"app", "category", "allowed", "denied", "sessions"}]}` from `top-applications`, merged by `(app, category)`.
    - `countries`: `{"rows": [{"country", "allowed", "denied", "sessions"}]}`, country from `dstcountry` (role `"src"`) or `srccountry` (role `"dst"`), merged by country.
    - Any section: `{"unavailable": "<reason>"}` (no rows) when a run raises `FAZError` whose message contains `Cannot find FortiView` or `not supported`; other `FAZError`s propagate.

- [ ] **Step 1: Write failing tests** with a `FakeClient` whose `run_fortiview_page` returns canned `(rows, total)` per `(view, filter)` and records calls: `test_either_direction_merges_a_peer_seen_in_both_roles` (peer in `top-destinations` 10 pass/2 block and in `top-sources` 5 pass/0 block → one row allowed 15, denied 2, sessions 17, roles `["src","dst"]`), `test_direction_src_runs_only_the_destination_report` (calls == `[("top-destinations", "srcip==10.1.1.2")]`), `test_peers_are_paged_with_offset_until_the_total_or_the_cap` (total 1057 → second call has `offset=1000`), `test_more_peers_than_the_cap_are_flagged_truncated` (total-count-all 5000 → `truncated` true, `total` == rows read), `test_a_host_with_no_sessions_gives_empty_sections` (every section: `rows == []`, `policies["totals"] == {"allowed": 0, "denied": 0}`, no `unavailable`), `test_policies_give_totals_and_per_firewall_totals`, `test_applications_and_countries_use_the_confirmed_field_names` (strings like `'36'` become ints), `test_a_missing_view_makes_only_that_section_unavailable` (`FAZError("Cannot find FortiView 'top-applications'")` → `{"unavailable": ...}`; `peers` unaffected), `test_an_unsupported_filter_is_unavailable`, `test_other_faz_errors_propagate`, `test_unknown_section_is_refused`, `test_devices_are_passed_through`.
- [ ] **Step 2: Run** `uv run pytest tests/test_conn_timeline_summary.py -q` — expect FAIL (module missing).
- [ ] **Step 3: Implement** the module as specified; one small `_int(value) -> int` helper (None, `""` or junk → 0); peers read with `limit=1000` pages until `offset >= min(total, PEER_CAP)` or a page is empty.
- [ ] **Step 4: Run** the tests and `uv run ruff check .` — expect PASS.
- [ ] **Step 5: Commit** `git add app/conn_timeline_summary.py tests/test_conn_timeline_summary.py && git commit -m "Add the Connection Timeline summary: FortiView sections for one IP"`.

### Task 3: `POST /api/conn-timeline/summary`

**Files:**
- Modify: `app/routes/conn_timeline_routes.py`, `app/config.py`, `.env.example`
- Test: `tests/test_conn_timeline_routes.py` (extend the `faz` fixture's `_CtxFAZ` fake with a `run_fortiview_page` returning small canned rows and `local_time_range` if missing)

**Interfaces:**
- Consumes: `summarize`, `SECTIONS` (Task 2); existing `parse_host`, `parse_device`, `parse_window`, `parse_adom`, `with_adom`, `check_adom_access`, `_client_for`, `_iso`, `app_log`.
- Produces: `POST /api/conn-timeline/summary` (tab-required, CSRF like the other POSTs). Body: `target`, `adom`, `host`, `direction` (default `either`), `device` (default `All_FortiGate`), window fields as for a build, `section`. 200 → `summarize(...)` result plus `"section"`, `"units": "sessions"`, `"seconds": float`. 400 bad input or unknown section; 404 unknown target; 429 when `Config.CONN_TIMELINE_SUMMARY_MAX_CONCURRENT` (default 4, env `CONN_TIMELINE_SUMMARY_MAX_CONCURRENT`) summaries already run (non-blocking `BoundedSemaphore`); 502 on `FAZError` / connection errors (`{"error": ...}`). An `unavailable` section is a normal 200. Audit: `app_log("INFO", "conn_timeline", "Timeline summary", by, target, adom, host, direction, section, seconds)`.

- [ ] **Step 1: Write failing tests**: `test_summary_returns_a_section_with_units_and_seconds`, `test_summary_defaults_to_one_hour_and_either_direction` (assert the filters the fake saw include both `srcip==` and `dstip==`), `test_summary_rejects_an_unknown_section_and_bad_input` (400s with the build's messages), `test_summary_for_an_unavailable_view_is_a_200_with_unavailable`, `test_summary_faz_error_is_a_502`, `test_restricted_user_cannot_summarize_another_target` (as `carol` on `Primary` → the same denial as a build), `test_summary_needs_csrf`, `test_summary_is_audited`, `test_summary_is_refused_over_the_concurrency_limit` (set the config to 0 → 429).
- [ ] **Step 2: Run** `uv run pytest tests/test_conn_timeline_routes.py -q -k summary` — expect FAIL.
- [ ] **Step 3: Implement** `api_summary()` reusing the build's input handling (factor a shared helper only if it removes duplication); `time_range = client.local_time_range(_iso(start), _iso(end))`; `devices = [{"devid": device}]`; add the config key and the `.env.example` line with a comment.
- [ ] **Step 4: Run** the whole file `uv run pytest tests/test_conn_timeline_routes.py -q` and ruff — expect PASS.
- [ ] **Step 5: Commit** `git commit -m "Add POST /api/conn-timeline/summary"` (add the changed files).

### Task 4: Demo mode answers the summary views

**Files:**
- Modify: `app/demo_faz.py` (`_fortiview_rows` ~line 744, `_task` ~line 956)
- Test: `tests/test_conn_timeline_demo.py` (uses its `app`, `demo_on`, `no_network`, `_login` fixtures)

**Interfaces:**
- Produces: when a demo FortiView run for `top-destinations`, `top-sources`, `policy-hits`, `top-applications` or `top-countries` carries a filter containing `srcip==` or `dstip==`, the rows are **derived from the demo's own traffic logs** (`generate_logs(site_host, "traffic", devid, compile_filter(filt), start, end, limit=100_000, newest_first=False)` with `devid` from `params["device"][0]["devid"]`, default `All_FortiGate`), one session per log row, `app.conn_timeline.verdict(action)` deciding pass (allowed) or block (denied), with the same string-valued fields as the real views (Global Constraints; app name from the row's `app` else `service`, category from `appcat` else `""`). `top-countries` without such a filter keeps its existing synthetic shape. FortiView task fetches honour `offset` and return `total-count-all` (the full row count) beside the existing `total-count`.

- [ ] **Step 1: Write failing tests**: `test_demo_summary_peers_match_the_raw_timeline` (build the raw timeline for `10.10.10.53` over the preset and fetch `peers` via the endpoint; the busiest peer is the same, and total sessions equal the timeline's logs within the rows generated), `test_demo_summary_sections_all_answer` (each of the four sections returns rows for `10.10.20.50` and no `unavailable`), `test_demo_summary_pages_with_offset_and_reports_the_total`, `test_demo_summary_for_a_quiet_host_is_empty`, and in `tests/test_demo_mode.py`'s existing no-network style: `test_demo_summary_never_reaches_the_network` (the `no_network` fixture is active for all of the above).
- [ ] **Step 2: Run** `uv run pytest tests/test_conn_timeline_demo.py -q -k summary` — expect FAIL.
- [ ] **Step 3: Implement** the derivation as a small private function in `demo_faz.py` that groups and counts; keep the existing view branches untouched.
- [ ] **Step 4: Run** `uv run pytest tests/test_conn_timeline_demo.py tests/test_demo_mode.py -q` and ruff — expect PASS.
- [ ] **Step 5: Commit** `git commit -m "Answer the Connection Timeline summary views in demo mode"`.

### Task 5: The panel

**Files:**
- Modify: `app/templates/conn_timeline.html`, `app/static/js/conn_timeline.js`, the page's stylesheet (find with `grep -rl "ct-coverage" app/static`)
- Modify: `tests/js/render_conn_timeline.js` (expose `renderSummary` and the loader through `globalThis.__ct`; add a `summary` case input and a `loader` scenario)
- Test: `tests/test_conn_timeline_page_render.py`

**Interfaces:**
- Produces (JS, pure, no DOM):
  - `renderSummary(summary) -> string` where `summary = {host, direction, sections: {peers|policies|applications|countries: {status: 'loading'|'ok'|'unavailable'|'error', data?, message?}}}`; renders the allowed/denied totals and per-firewall totals (from `sections.policies.data`), then peers, policies, applications, countries as small tables; a loading section shows "Loading…", `unavailable` shows "Not available on this FortiAnalyzer", `error` shows the message; `data.truncated` adds "Showing the top N of M peers"; every string from FortiAnalyzer goes through `escHtml`; the unit note "sessions, counted by FortiAnalyzer, not logs" is always present.
  - `createSummaryLoader(fetchSection, onUpdate, {concurrency = 3}) -> {start(payload), stop()}`: `start` begins a new run for the four sections in order (peers, policies, applications, countries), at most `concurrency` in flight, calling `onUpdate(summary)` on every change; answers that belong to an earlier `start` (or after `stop`) are ignored.
- Page: a `<div id="ctSummary" class="hidden">` between the form and `#ctResult`; Build calls `loader.start(payload)` with the same payload as the raw build, then shows the panel; the partial coverage banner adds "The Quick summary above counts sessions for the whole window." when `cov.complete` is false.

- [ ] **Step 1: Write failing tests** in `test_conn_timeline_page_render.py` using the harness: `test_summary_renders_totals_and_tables`, `test_summary_states_loading_unavailable_and_error`, `test_summary_says_when_peers_are_cut_off`, `test_summary_escapes_strings_from_fortianalyzer` (peer, policy, app and firewall = an `<img onerror>` string → no raw `<img` in the output, `&lt;img` present), `test_summary_always_states_its_unit`, `test_partial_banner_points_at_the_summary`, `test_loader_keeps_three_requests_in_flight` (scripted fetch promises, record the maximum concurrent), `test_loader_ignores_answers_from_an_older_run` (start, start again, resolve the first run's fetches last → `onUpdate` never shows them), `test_loader_stop_ignores_late_answers`.
- [ ] **Step 2: Run** `uv run pytest tests/test_conn_timeline_page_render.py -q` — expect FAIL.
- [ ] **Step 3: Implement** the functions, the template block, the styles (reuse `ct-` table classes), the Build wiring (`fetchSection(section, payload)` POSTs to `/api/conn-timeline/summary` with `{...payload, section}` and rejects with the response's `error`), and `node --check`.
- [ ] **Step 4: Run** `node --check app/static/js/conn_timeline.js && uv run pytest tests/test_conn_timeline_page_render.py -q` and ruff — expect PASS.
- [ ] **Step 5: Commit** `git commit -m "Add the Quick summary panel to the Connection Timeline"`.

### Task 6: Docs, live check, container

**Files:**
- Modify: `docs/superpowers/specs/2026-11-23-conn-timeline-quick-summary-design.md` (totals and per-firewall totals ride on the `policies` response, so the sections are peers, policies, applications, countries), `docs/conn-timeline-fortiview.md` (link the feature), `changelog.md`, `CLAUDE.md` (one line under "What 4tlog Does" for the summary)

- [ ] **Step 1: Live check** (read-only, real appliance): call `summarize` for each section with a busy host over 3 hours through a short script using `FAZClient`; expect peers `total` near the FortiView `total-count-all`, `policies` totals equal to the `top-sources` session sum, each section in under 10 s, nothing `unavailable`.
- [ ] **Step 2: Docs and changelog** (what it shows, sessions not logs, the endpoint, `CONN_TIMELINE_SUMMARY_MAX_CONCURRENT`).
- [ ] **Step 3: Full verification:** `uv run ruff check . && uv run pytest -q` — expect all pass; `bash scripts/check-sensitive-strings.sh`.
- [ ] **Step 4: Commit** the docs; then `docker compose build app && docker compose up -d app collector` and confirm `docker compose ps` healthy and `curl -sk -o /dev/null -w "%{http_code}" https://localhost:8300/login` is 200.
