# External API: /external/api/log-usage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /external/api/log-usage` to 4tlog's external API — a bearer-token-authenticated endpoint that runs a `policyid`-scoped FortiAnalyzer traffic-log search across a requested device set and returns only the aggregated distinct source IPs, destination IPs, and destination ports observed, for the sibling app 4thealth-plus's Log-Based Rule Review feature.

**Architecture:** Pure validation/resolution/aggregation helper functions in `app/routes/external_api_routes.py`, each independently unit-testable, composed by one orchestration function that the Flask route calls after the existing auth/feature-gate. No changes to `app/faz_client.py` — the endpoint calls existing `FAZClient` methods (`get_devices`, `local_time_range`, `search_logs`) once per resolved device, sequentially (no batched multi-device search — see spec).

**Tech Stack:** Flask, `app.faz_client.FAZClient`, `app.faz_targets.list_targets`, pytest + `unittest.mock`/`monkeypatch` (this repo's existing `_client()`-style mocking pattern from `tests/test_faz_client.py`).

**Spec:** `docs/superpowers/specs/2026-09-23-log-usage-endpoint-design.md`

## Global Constraints

- `days` is validated as an integer in [1, 60] and **rejected** (400) if out of range — this endpoint does not clamp, unlike its 4thealth-plus caller.
- Every failure mode degrades to a JSON error with the exact status codes in the spec's error table — never a raw 500: `503` (feature disabled), `401` (bad/missing token), `400` (invalid request field), `404` (no FAZ target for ADOM), `502` (every device search failed).
- Zero matching devices (ADOM known, names not found) and zero log rows are **not** errors — both return `200` with empty result arrays.
- A `FAZError` on one device's search is non-fatal — recorded in `device_errors`, does not stop other devices.
- `search_logs()` is called once per resolved device — never assume or attempt a batched multi-device call (unconfirmed FAZ behavior).
- Device name matching against `FAZClient.get_devices()` is case-insensitive, matched on `name` (not `devid`).
- ADOM matching against `faz_targets.json` entries is case-insensitive, matched on each entry's own `adom` field.
- New code follows this repo's existing test patterns exactly: the `_client(monkeypatch, responses)` mock helper style from `tests/test_faz_client.py` for `FAZClient`-level tests, and the `app`/`client` fixture + `_enable_and_token()` helper from `tests/test_external_api_routes.py` for route-level tests.

## Review Focus

- A `policyid` sent as a JSON boolean (`true`/`false`) is a Python `int` subtype and must be rejected as invalid, not silently accepted as `1`/`0`.
- A device name that matches on one FAZ target but not another (in a multi-target-per-ADOM deployment) must end up in `devices_queried`, not `devices_not_found` — "not found" only applies to a name absent from every matched target.
- A `FAZError` raised while searching one device in a multi-device request must not prevent the other devices' results from being aggregated and returned.
- `days` sent as `0`, `61`, a float, a string, or missing must be rejected with `400`, never silently coerced or clamped.
- The `truncated` flag must become `true` if ANY device's search hits `limit`, not just the last one processed — an aggregation-order bug here would silently under-report truncation.

---

## Task 1: Request validation — `_validate_log_usage_request`

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Test: `tests/test_external_api_log_usage_validation.py`

**Interfaces:**
- Produces: `_validate_log_usage_request(data: dict) -> tuple[dict | None, str | None]` — returns `(normalized_request, None)` on success where `normalized_request = {"adom": str, "devices": list[str], "policyid": int, "days": int}`, or `(None, error_message)` on failure.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_external_api_log_usage_validation.py
from app.routes.external_api_routes import _validate_log_usage_request


def test_valid_request_normalizes():
    req, err = _validate_log_usage_request({
        "adom": " Enterprise Services ", "devices": ["FW-DC-01", " FW-DC-02 "],
        "policyid": 123, "days": 30,
    })
    assert err is None
    assert req == {
        "adom": "Enterprise Services", "devices": ["FW-DC-01", "FW-DC-02"],
        "policyid": 123, "days": 30,
    }


def test_missing_adom_rejected():
    req, err = _validate_log_usage_request({"devices": ["FW1"], "policyid": 1, "days": 1})
    assert req is None
    assert "adom" in err


def test_blank_adom_rejected():
    req, err = _validate_log_usage_request({
        "adom": "   ", "devices": ["FW1"], "policyid": 1, "days": 1,
    })
    assert req is None
    assert "adom" in err


def test_missing_devices_rejected():
    req, err = _validate_log_usage_request({"adom": "A", "policyid": 1, "days": 1})
    assert req is None
    assert "devices" in err


def test_empty_devices_list_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": [], "policyid": 1, "days": 1,
    })
    assert req is None
    assert "devices" in err


def test_non_string_device_entry_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1", 42], "policyid": 1, "days": 1,
    })
    assert req is None
    assert "devices" in err


def test_missing_policyid_rejected():
    req, err = _validate_log_usage_request({"adom": "A", "devices": ["FW1"], "days": 1})
    assert req is None
    assert "policyid" in err


def test_zero_policyid_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 0, "days": 1,
    })
    assert req is None
    assert "policyid" in err


def test_negative_policyid_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": -5, "days": 1,
    })
    assert req is None
    assert "policyid" in err


def test_boolean_policyid_rejected():
    """A JSON bool is a Python int subtype -- must not be silently accepted."""
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": True, "days": 1,
    })
    assert req is None
    assert "policyid" in err


def test_days_zero_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 0,
    })
    assert req is None
    assert "days" in err


def test_days_61_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 61,
    })
    assert req is None
    assert "days" in err


def test_days_float_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 30.5,
    })
    assert req is None
    assert "days" in err


def test_days_string_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": "30",
    })
    assert req is None
    assert "days" in err


def test_days_boundaries_accepted():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 1,
    })
    assert err is None
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 60,
    })
    assert err is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_log_usage_validation.py -v`
Expected: FAIL with `ImportError: cannot import name '_validate_log_usage_request'`

- [ ] **Step 3: Implement `_validate_log_usage_request` in `app/routes/external_api_routes.py`**

Add near the top of the file, after the existing `_gate()`/`_authenticate()` helpers:

```python
def _validate_log_usage_request(data: dict) -> tuple[dict | None, str | None]:
    """Validate and normalize a /external/api/log-usage request body.

    Returns (normalized_request, None) on success, or (None, error_message)
    on the first validation failure. Rejects out-of-range `days` rather
    than clamping it -- this endpoint is a contract boundary; the caller
    owns its own input hygiene."""
    adom = str(data.get("adom") or "").strip()
    if not adom:
        return None, "adom is required"

    devices = data.get("devices")
    if (
        not isinstance(devices, list)
        or not devices
        or not all(isinstance(d, str) and d.strip() for d in devices)
    ):
        return None, "devices must be a non-empty list of strings"

    policyid = data.get("policyid")
    if not isinstance(policyid, int) or isinstance(policyid, bool) or policyid <= 0:
        return None, "policyid must be a positive integer"

    days = data.get("days")
    if not isinstance(days, int) or isinstance(days, bool) or not (1 <= days <= 60):
        return None, "days must be an integer between 1 and 60"

    return {
        "adom": adom,
        "devices": [d.strip() for d in devices],
        "policyid": policyid,
        "days": days,
    }, None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_log_usage_validation.py -v`
Expected: PASS (15 tests)

- [ ] **Step 5: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_log_usage_validation.py
git commit -m "$(cat <<'EOF'
feat: add request validation for /external/api/log-usage

Pure function, no route wiring yet -- validates and normalizes the
request body per the endpoint's spec, rejecting out-of-range days
rather than clamping.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 2: Target and device resolution helpers

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Test: `tests/test_external_api_log_usage_resolution.py`

**Interfaces:**
- Consumes: `app.faz_targets.list_targets() -> list[dict]` (existing; each entry has `label`, `host`, `adom`, `token`, optional SNMP fields). `FAZClient.get_devices() -> list[dict]` (existing; each entry `{devid, name, platform}`).
- Produces: `_match_targets_for_adom(adom: str) -> list[dict]`; `_resolve_devices_for_target(client, requested_names: list[str]) -> tuple[dict[str, str], list[str]]` — returns `({name: devid, ...}, [names_not_found_on_this_target])`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_external_api_log_usage_resolution.py
from unittest.mock import MagicMock

from app.routes.external_api_routes import (
    _match_targets_for_adom,
    _resolve_devices_for_target,
)


def test_match_targets_for_adom_case_insensitive(monkeypatch):
    targets = [
        {"label": "Primary", "host": "1.2.3.4", "adom": "Enterprise Services"},
        {"label": "Secondary", "host": "5.6.7.8", "adom": "root"},
    ]
    monkeypatch.setattr(
        "app.routes.external_api_routes.list_targets", lambda: targets
    )
    matched = _match_targets_for_adom("enterprise services")
    assert matched == [targets[0]]


def test_match_targets_for_adom_no_match(monkeypatch):
    monkeypatch.setattr(
        "app.routes.external_api_routes.list_targets",
        lambda: [{"label": "Primary", "host": "1.2.3.4", "adom": "root"}],
    )
    assert _match_targets_for_adom("Enterprise Services") == []


def test_match_targets_for_adom_multiple_matches(monkeypatch):
    targets = [
        {"label": "A", "host": "1.1.1.1", "adom": "Shared"},
        {"label": "B", "host": "2.2.2.2", "adom": "shared"},
    ]
    monkeypatch.setattr(
        "app.routes.external_api_routes.list_targets", lambda: targets
    )
    assert _match_targets_for_adom("Shared") == targets


def test_resolve_devices_for_target_all_found():
    client = MagicMock()
    client.get_devices.return_value = [
        {"devid": "SN001", "name": "FW-DC-01", "platform": "FortiGate-60F"},
        {"devid": "SN002", "name": "FW-DC-02", "platform": "FortiGate-60F"},
    ]
    resolved, not_found = _resolve_devices_for_target(client, ["FW-DC-01", "FW-DC-02"])
    assert resolved == {"FW-DC-01": "SN001", "FW-DC-02": "SN002"}
    assert not_found == []


def test_resolve_devices_for_target_case_insensitive():
    client = MagicMock()
    client.get_devices.return_value = [
        {"devid": "SN001", "name": "FW-DC-01", "platform": "x"},
    ]
    resolved, not_found = _resolve_devices_for_target(client, ["fw-dc-01"])
    assert resolved == {"fw-dc-01": "SN001"}
    assert not_found == []


def test_resolve_devices_for_target_partial_match():
    client = MagicMock()
    client.get_devices.return_value = [
        {"devid": "SN001", "name": "FW-DC-01", "platform": "x"},
    ]
    resolved, not_found = _resolve_devices_for_target(client, ["FW-DC-01", "FW-DC-99"])
    assert resolved == {"FW-DC-01": "SN001"}
    assert not_found == ["FW-DC-99"]


def test_resolve_devices_for_target_none_found():
    client = MagicMock()
    client.get_devices.return_value = []
    resolved, not_found = _resolve_devices_for_target(client, ["FW-DC-01"])
    assert resolved == {}
    assert not_found == ["FW-DC-01"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_log_usage_resolution.py -v`
Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement in `app/routes/external_api_routes.py`**

Add the import near the top of the file, alongside the existing imports:

```python
from app.faz_targets import list_targets
```

Add the two functions after `_validate_log_usage_request`:

```python
def _match_targets_for_adom(adom: str) -> list[dict]:
    """Case-insensitive match against each faz_targets entry's own 'adom'
    field -- the same mapping the app already maintains for internal
    Log Search."""
    adom_lower = adom.lower()
    return [t for t in list_targets() if str(t.get("adom", "")).lower() == adom_lower]


def _resolve_devices_for_target(client, requested_names: list[str]) -> tuple[dict, list]:
    """Match requested device names against one target's device list,
    case-insensitively on name. Returns ({requested_name: devid, ...},
    [requested names not found on this target])."""
    devices = client.get_devices()
    by_name_lower = {
        d["name"].lower(): d["devid"]
        for d in devices
        if d.get("name") and d.get("devid")
    }
    resolved: dict[str, str] = {}
    not_found: list[str] = []
    for name in requested_names:
        devid = by_name_lower.get(name.lower())
        if devid:
            resolved[name] = devid
        else:
            not_found.append(name)
    return resolved, not_found
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_log_usage_resolution.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_log_usage_resolution.py
git commit -m "$(cat <<'EOF'
feat: add ADOM/device resolution helpers for log-usage endpoint

_match_targets_for_adom matches faz_targets.json entries by their own
adom field; _resolve_devices_for_target matches requested device
names against one target's live device list, case-insensitively.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 3: Single-device search + row aggregation

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Test: `tests/test_external_api_log_usage_search.py`

**Interfaces:**
- Consumes: `FAZClient.local_time_range(start_iso, end_iso) -> tuple[str, str]` (existing); `FAZClient.search_logs(...) -> {"rows": [...], "fields": [...], "truncated": bool}` (existing); `app.faz_client.FAZError` (existing).
- Produces: `_search_one_device(client, devid: str, policyid: int, start_iso: str, end_iso: str, days: int) -> dict` returning `{"local_start": str, "local_end": str, "srcips": set[str], "dstips": set[str], "dstports": set, "log_count": int, "truncated": bool}` on success, or raises `FAZError` (propagated, caller catches it).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_external_api_log_usage_search.py
from unittest.mock import MagicMock

import pytest

from app.faz_client import FAZError
from app.routes.external_api_routes import _search_one_device


def _client(rows, truncated=False, local_range=("2026-08-24T00:00:00", "2026-09-23T00:00:00")):
    client = MagicMock()
    client.local_time_range.return_value = local_range
    client.search_logs.return_value = {"rows": rows, "fields": [], "truncated": truncated}
    return client


def test_search_one_device_aggregates_rows():
    client = _client([
        {"srcip": "10.1.1.5", "dstip": "10.2.2.10", "dstport": 443},
        {"srcip": "10.1.1.6", "dstip": "10.2.2.10", "dstport": 8443},
    ])
    result = _search_one_device(client, "SN001", 123, "2026-08-24T00:00:00", "2026-09-23T00:00:00", 30)
    assert result["srcips"] == {"10.1.1.5", "10.1.1.6"}
    assert result["dstips"] == {"10.2.2.10"}
    assert result["dstports"] == {443, 8443}
    assert result["log_count"] == 2
    assert result["truncated"] is False
    assert result["local_start"] == "2026-08-24T00:00:00"
    assert result["local_end"] == "2026-09-23T00:00:00"


def test_search_one_device_truncated_flag_passed_through():
    client = _client([{"srcip": "10.1.1.5"}], truncated=True)
    result = _search_one_device(client, "SN001", 123, "a", "b", 30)
    assert result["truncated"] is True


def test_search_one_device_skips_rows_missing_fields():
    client = _client([{"srcip": "10.1.1.5"}, {"dstip": "10.2.2.10"}, {}])
    result = _search_one_device(client, "SN001", 123, "a", "b", 30)
    assert result["srcips"] == {"10.1.1.5"}
    assert result["dstips"] == {"10.2.2.10"}
    assert result["dstports"] == set()
    assert result["log_count"] == 3


def test_search_one_device_builds_correct_filter_expression():
    client = _client([])
    _search_one_device(client, "SN001", 456, "a", "b", 30)
    call_kwargs = client.search_logs.call_args.kwargs
    assert call_kwargs["filter_expression"] == "policyid==456"
    assert call_kwargs["device"] == "SN001"
    assert call_kwargs["logtype"] == "traffic"


def test_search_one_device_propagates_faz_error():
    client = MagicMock()
    client.local_time_range.return_value = ("a", "b")
    client.search_logs.side_effect = FAZError("boom")
    with pytest.raises(FAZError, match="boom"):
        _search_one_device(client, "SN001", 123, "a", "b", 30)


def test_search_one_device_empty_dstport_not_added():
    """A row with dstport=0 is a legitimate value and must be kept;
    a row with no dstport key at all must not add None to the set."""
    client = _client([{"dstport": 0}, {}])
    result = _search_one_device(client, "SN001", 123, "a", "b", 30)
    assert result["dstports"] == {0}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_log_usage_search.py -v`
Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement `_search_one_device` in `app/routes/external_api_routes.py`**

Add near the top of the file, alongside the other new imports:

```python
from app.config import Config
from app.faz_client import FAZError
```

Add the function after `_resolve_devices_for_target`:

```python
def _search_one_device(
    client, devid: str, policyid: int, start_iso: str, end_iso: str, days: int
) -> dict:
    """Run one policyid-scoped traffic-log search against one device and
    return its aggregated contribution. Raises FAZError on failure --
    callers decide whether that's fatal to the overall request."""
    local_start, local_end = client.local_time_range(start_iso, end_iso)
    result = client.search_logs(
        logtype="traffic",
        device=devid,
        filter_expression=f"policyid=={policyid}",
        start_time=local_start,
        end_time=local_end,
        limit=Config.LOG_SEARCH_MAX_RESULTS,
        poll_interval=Config.LOG_SEARCH_POLL_INTERVAL,
        timeout=Config.LOG_SEARCH_TIMEOUT,
    )
    rows = result.get("rows", [])
    srcips: set = set()
    dstips: set = set()
    dstports: set = set()
    for row in rows:
        if row.get("srcip"):
            srcips.add(str(row["srcip"]))
        if row.get("dstip"):
            dstips.add(str(row["dstip"]))
        if "dstport" in row and row["dstport"] is not None:
            dstports.add(row["dstport"])
    return {
        "local_start": local_start,
        "local_end": local_end,
        "srcips": srcips,
        "dstips": dstips,
        "dstports": dstports,
        "log_count": len(rows),
        "truncated": bool(result.get("truncated")),
    }
```

Note: `days` is accepted as a parameter but not used inside this function's
body — it's part of the interface for symmetry with the caller's
time-window computation and to keep the function's signature self-documenting
about what window it's implicitly operating within (the caller passes
already-computed `start_iso`/`end_iso`). Do not remove it; Task 4's caller
relies on this exact signature.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_log_usage_search.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_log_usage_search.py
git commit -m "$(cat <<'EOF'
feat: add single-device search + aggregation for log-usage endpoint

_search_one_device runs one policyid-scoped traffic-log search
against one resolved device and returns its distinct srcip/dstip/
dstport contribution plus row count and truncation flag. FAZError
propagates uncaught -- the orchestrator (Task 4) decides fatality.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 4: Orchestration across targets and devices

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Test: `tests/test_external_api_log_usage_orchestration.py`

**Interfaces:**
- Consumes: `_match_targets_for_adom`, `_resolve_devices_for_target`, `_search_one_device` (Task 2/3); `app.faz_client.FAZClient`, `FAZError`.
- Produces: `_run_log_usage_search(req: dict, faz_client_factory) -> tuple[dict | None, str | None, int]` — `req` is the normalized dict from `_validate_log_usage_request`; `faz_client_factory` is a `Callable[[dict], FAZClient]` (injected so tests can substitute a fake client without hitting the network — production callers pass a real factory). Returns `(response_dict, None, 200)` on success, or `(None, error_message, status_code)` on failure. `response_dict` matches the spec's response shape: `{policyid, days, time_range, srcips, dstips, dstports, log_count, truncated, devices_queried, devices_not_found, device_errors}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_external_api_log_usage_orchestration.py
from unittest.mock import MagicMock

from app.faz_client import FAZError
from app.routes.external_api_routes import _run_log_usage_search

_REQ = {"adom": "Enterprise Services", "devices": ["FW-DC-01"], "policyid": 123, "days": 30}


def _target(adom="Enterprise Services", host="1.2.3.4"):
    return {"label": "Primary", "host": host, "adom": adom, "token": "t"}


def _fake_client(devices, search_result=None, search_error=None):
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.get_devices.return_value = devices
    client.local_time_range.return_value = ("a", "b")
    if search_error is not None:
        client.search_logs.side_effect = search_error
    else:
        client.search_logs.return_value = search_result or {
            "rows": [], "fields": [], "truncated": False,
        }
    return client


def test_no_matching_target_returns_404(monkeypatch):
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [])
    response, error, status = _run_log_usage_search(_REQ, faz_client_factory=lambda t: None)
    assert response is None
    assert status == 404
    assert "Enterprise Services" in error


def test_happy_path_single_target_single_device(monkeypatch):
    monkeypatch.setattr(
        "app.routes.external_api_routes.list_targets", lambda: [_target()]
    )
    client = _fake_client(
        devices=[{"devid": "SN001", "name": "FW-DC-01", "platform": "x"}],
        search_result={
            "rows": [{"srcip": "10.1.1.5", "dstip": "10.2.2.10", "dstport": 443}],
            "fields": [],
            "truncated": False,
        },
    )
    response, error, status = _run_log_usage_search(_REQ, faz_client_factory=lambda t: client)
    assert error is None
    assert status == 200
    assert response["srcips"] == ["10.1.1.5"]
    assert response["dstips"] == ["10.2.2.10"]
    assert response["dstports"] == [443]
    assert response["log_count"] == 1
    assert response["truncated"] is False
    assert response["devices_queried"] == ["FW-DC-01"]
    assert response["devices_not_found"] == []
    assert response["device_errors"] == {}
    assert response["policyid"] == 123
    assert response["days"] == 30


def test_device_not_found_on_only_target(monkeypatch):
    monkeypatch.setattr(
        "app.routes.external_api_routes.list_targets", lambda: [_target()]
    )
    client = _fake_client(devices=[])
    response, error, status = _run_log_usage_search(_REQ, faz_client_factory=lambda t: client)
    assert error is None
    assert status == 200
    assert response["devices_queried"] == []
    assert response["devices_not_found"] == ["FW-DC-01"]
    assert response["srcips"] == []


def test_device_found_on_second_target_not_first(monkeypatch):
    targets = [_target(host="1.1.1.1"), _target(host="2.2.2.2")]
    monkeypatch.setattr(
        "app.routes.external_api_routes.list_targets", lambda: targets
    )
    client_miss = _fake_client(devices=[])
    client_hit = _fake_client(
        devices=[{"devid": "SN001", "name": "FW-DC-01", "platform": "x"}],
        search_result={"rows": [{"srcip": "10.1.1.5"}], "fields": [], "truncated": False},
    )
    factory_calls = {"1.1.1.1": client_miss, "2.2.2.2": client_hit}
    response, error, status = _run_log_usage_search(
        _REQ, faz_client_factory=lambda t: factory_calls[t["host"]]
    )
    assert error is None
    assert response["devices_queried"] == ["FW-DC-01"]
    assert response["devices_not_found"] == []
    assert response["srcips"] == ["10.1.1.5"]


def test_one_device_faz_error_does_not_block_others(monkeypatch):
    monkeypatch.setattr(
        "app.routes.external_api_routes.list_targets", lambda: [_target()]
    )
    req = {**_REQ, "devices": ["FW-DC-01", "FW-DC-02"]}
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.get_devices.return_value = [
        {"devid": "SN001", "name": "FW-DC-01", "platform": "x"},
        {"devid": "SN002", "name": "FW-DC-02", "platform": "x"},
    ]
    client.local_time_range.return_value = ("a", "b")

    def fake_search_logs(**kwargs):
        if kwargs["device"] == "SN001":
            raise FAZError("device unreachable")
        return {"rows": [{"srcip": "10.1.1.6"}], "fields": [], "truncated": False}

    client.search_logs.side_effect = fake_search_logs
    response, error, status = _run_log_usage_search(req, faz_client_factory=lambda t: client)
    assert error is None
    assert status == 200
    assert response["devices_queried"] == ["FW-DC-02"]
    assert response["device_errors"] == {"FW-DC-01": "device unreachable"}
    assert response["srcips"] == ["10.1.1.6"]


def test_all_devices_error_returns_502(monkeypatch):
    monkeypatch.setattr(
        "app.routes.external_api_routes.list_targets", lambda: [_target()]
    )
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.get_devices.return_value = [{"devid": "SN001", "name": "FW-DC-01", "platform": "x"}]
    client.local_time_range.return_value = ("a", "b")
    client.search_logs.side_effect = FAZError("boom")
    response, error, status = _run_log_usage_search(_REQ, faz_client_factory=lambda t: client)
    assert response is None
    assert status == 502
    assert "boom" in error


def test_truncated_true_if_any_device_truncated(monkeypatch):
    monkeypatch.setattr(
        "app.routes.external_api_routes.list_targets", lambda: [_target()]
    )
    req = {**_REQ, "devices": ["FW-DC-01", "FW-DC-02"]}
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.get_devices.return_value = [
        {"devid": "SN001", "name": "FW-DC-01", "platform": "x"},
        {"devid": "SN002", "name": "FW-DC-02", "platform": "x"},
    ]
    client.local_time_range.return_value = ("a", "b")

    def fake_search_logs(**kwargs):
        truncated = kwargs["device"] == "SN002"
        return {"rows": [], "fields": [], "truncated": truncated}

    client.search_logs.side_effect = fake_search_logs
    response, error, status = _run_log_usage_search(req, faz_client_factory=lambda t: client)
    assert response["truncated"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_log_usage_orchestration.py -v`
Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement `_run_log_usage_search` in `app/routes/external_api_routes.py`**

Add the import near the top of the file:

```python
import datetime
```

(If `datetime` is already imported in this file for another reason, skip re-adding it.)

Add the function after `_search_one_device`:

```python
def _run_log_usage_search(req: dict, faz_client_factory) -> tuple[dict | None, str | None, int]:
    """Execute the full log-usage search across every FAZ target matching
    req['adom']. faz_client_factory(target_dict) -> FAZClient (or a
    context-manager-compatible fake in tests) is injected so this function
    never constructs a real FAZClient itself.

    Returns (response, None, 200) on success or (None, error_message,
    status_code) on failure, per the endpoint's spec error table."""
    targets = _match_targets_for_adom(req["adom"])
    if not targets:
        return None, f"No FortiAnalyzer target configured for ADOM '{req['adom']}'", 404

    now = datetime.datetime.now(datetime.timezone.utc)
    start_iso = (now - datetime.timedelta(days=req["days"])).strftime("%Y-%m-%dT%H:%M:%S")
    end_iso = now.strftime("%Y-%m-%dT%H:%M:%S")

    remaining = set(req["devices"])
    devices_queried: list[str] = []
    device_errors: dict[str, str] = {}
    srcips: set = set()
    dstips: set = set()
    dstports: set = set()
    log_count = 0
    truncated = False
    time_range = {"start": None, "end": None}

    for target in targets:
        if not remaining:
            break
        client = faz_client_factory(target)
        with client:
            resolved, _not_found_here = _resolve_devices_for_target(client, sorted(remaining))
            for name, devid in resolved.items():
                remaining.discard(name)
                try:
                    contribution = _search_one_device(
                        client, devid, req["policyid"], start_iso, end_iso, req["days"]
                    )
                except FAZError as exc:
                    device_errors[name] = str(exc)
                    continue
                devices_queried.append(name)
                srcips |= contribution["srcips"]
                dstips |= contribution["dstips"]
                dstports |= contribution["dstports"]
                log_count += contribution["log_count"]
                if contribution["truncated"]:
                    truncated = True
                time_range = {
                    "start": contribution["local_start"],
                    "end": contribution["local_end"],
                }

    devices_not_found = sorted(remaining)

    if not devices_queried and device_errors:
        return None, "; ".join(f"{name}: {msg}" for name, msg in device_errors.items()), 502

    response = {
        "policyid": req["policyid"],
        "days": req["days"],
        "time_range": time_range,
        "srcips": sorted(srcips),
        "dstips": sorted(dstips),
        "dstports": sorted(dstports),
        "log_count": log_count,
        "truncated": truncated,
        "devices_queried": sorted(devices_queried),
        "devices_not_found": devices_not_found,
        "device_errors": device_errors,
    }
    return response, None, 200
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_log_usage_orchestration.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_log_usage_orchestration.py
git commit -m "$(cat <<'EOF'
feat: add multi-target/multi-device orchestration for log-usage endpoint

_run_log_usage_search ties target matching, device resolution, and
per-device search/aggregation together: a device found on any matched
target counts as queried, a FAZError on one device doesn't block
others, and the request only 502s if every device errored.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Task 5: Flask route wiring

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Test: `tests/test_external_api_log_usage_route.py`

**Interfaces:**
- Consumes: `_gate()` (existing, feature-flag + auth), `_validate_log_usage_request`, `_run_log_usage_search` (Tasks 1/4), `app.faz_client.FAZClient` (existing, real constructor), `app.config.Config` (existing, `FAZ_VERIFY_SSL`/`FAZ_REQUEST_TIMEOUT`).
- Produces: `POST /external/api/log-usage` route.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_external_api_log_usage_route.py
import json

import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api_tokens._TOKENS_PATH", tmp_path / "api_tokens.json")
    monkeypatch.setattr("app.app_settings._SETTINGS_PATH", tmp_path / "app_settings.json")
    monkeypatch.setattr("app.faz_targets.FAZ_TARGETS_FILE", tmp_path / "faz_targets.json")
    import app.log_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", tmp_path / "logstats.db")
    history_mod.init_db()

    from app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def _enable_and_token():
    from app.api_tokens import create_token
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    raw, _ = create_token("test")
    return raw


def _post(client, token, payload):
    return client.post(
        "/external/api/log-usage",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"Authorization": f"Bearer {token}"} if token else {},
    )


def test_returns_503_when_disabled(client):
    resp = _post(client, "no-token", {"adom": "A", "devices": ["FW1"], "policyid": 1, "days": 1})
    assert resp.status_code == 503


def test_returns_401_when_no_token(client):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    resp = client.post(
        "/external/api/log-usage",
        data=json.dumps({"adom": "A", "devices": ["FW1"], "policyid": 1, "days": 1}),
        content_type="application/json",
    )
    assert resp.status_code == 401


def test_returns_400_on_invalid_body(client):
    token = _enable_and_token()
    resp = _post(client, token, {"adom": "A"})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_returns_404_when_no_faz_target(client):
    token = _enable_and_token()
    resp = _post(client, token, {"adom": "Nonexistent", "devices": ["FW1"], "policyid": 1, "days": 1})
    assert resp.status_code == 404


def test_happy_path_end_to_end(client, monkeypatch):
    from app.faz_targets import create_target

    token = _enable_and_token()
    create_target(label="Primary", host="1.2.3.4", adom="Enterprise Services", token="faztoken")

    import app.routes.external_api_routes as route_mod

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get_devices(self):
            return [{"devid": "SN001", "name": "FW-DC-01", "platform": "x"}]

        def local_time_range(self, start, end):
            return start, end

        def search_logs(self, **kwargs):
            return {
                "rows": [{"srcip": "10.1.1.5", "dstip": "10.2.2.10", "dstport": 443}],
                "fields": [],
                "truncated": False,
            }

    monkeypatch.setattr(route_mod, "FAZClient", lambda **kwargs: FakeClient())

    resp = _post(client, token, {
        "adom": "Enterprise Services", "devices": ["FW-DC-01"], "policyid": 123, "days": 30,
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["srcips"] == ["10.1.1.5"]
    assert data["dstips"] == ["10.2.2.10"]
    assert data["dstports"] == [443]
    assert data["devices_queried"] == ["FW-DC-01"]
    assert data["policyid"] == 123
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_log_usage_route.py -v`
Expected: FAIL (route doesn't exist, 404 on every request)

- [ ] **Step 3: Implement the route in `app/routes/external_api_routes.py`**

Add the `FAZClient` import near the top of the file if not already present from Task 3:

```python
from app.faz_client import FAZClient, FAZError
```

Add the route at the end of the file, after `executive_summary()`:

```python
@bp.route("/log-usage", methods=["POST"])
def log_usage():
    gate_error = _gate()
    if gate_error is not None:
        return gate_error

    data = request.get_json(silent=True) or {}
    req, err = _validate_log_usage_request(data)
    if err is not None:
        return jsonify({"error": err}), 400

    def _factory(target: dict) -> FAZClient:
        return FAZClient(
            host=target["host"],
            token=target.get("token", ""),
            adom=target.get("adom", "root"),
            verify_ssl=Config.FAZ_VERIFY_SSL,
            timeout=Config.FAZ_REQUEST_TIMEOUT,
        )

    response, error, status = _run_log_usage_search(req, faz_client_factory=_factory)
    if error is not None:
        app_log(
            "WARN",
            "external_api",
            "log-usage request failed",
            adom=req["adom"],
            error=error,
            status=status,
        )
        return jsonify({"error": error}), status

    return jsonify(response)
```

Update the module docstring at the top of the file to add the new endpoint to its list:

```
  POST /external/api/log-usage          Aggregated per-policy traffic observed in FAZ logs
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_log_usage_route.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Run the full new-test suite together plus the pre-existing external API tests**

Run: `uv run pytest tests/test_external_api_log_usage_validation.py tests/test_external_api_log_usage_resolution.py tests/test_external_api_log_usage_search.py tests/test_external_api_log_usage_orchestration.py tests/test_external_api_log_usage_route.py tests/test_external_api_routes.py -v`
Expected: PASS (all tests, no regressions in the pre-existing `executive/summary` tests)

- [ ] **Step 6: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_log_usage_route.py
git commit -m "$(cat <<'EOF'
feat: wire POST /external/api/log-usage into the external API blueprint

Same auth/feature-gate as executive/summary. Validates the request,
runs the multi-target/multi-device search via _run_log_usage_search,
and maps its (response, error, status) result straight onto the HTTP
response -- 400/404/502 on failure, 200 with the aggregated result on
success.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_015fFwXrvTShoJZwHZKVybEo
EOF
)"
```

---

## Follow-up (explicitly not part of this plan)

Before this endpoint is relied upon in production by 4thealth-plus's Log-Based Rule Review feature, confirm the `srcip`/`dstip`/`dstport` FortiAnalyzer traffic-log field names against a real FortiAnalyzer instance (e.g. a manual `/api/log-search` call inspecting the raw `fields`/`rows` this endpoint's aggregation logic assumes). Update `app/routes/external_api_routes.py`'s row-parsing in `_search_one_device` and this plan's spec document if they differ. This is the same category of live-hardware confirmation this codebase already requires before enabling other unconfirmed FAZ integrations (see `get_sys_status()`'s docstring for precedent).
