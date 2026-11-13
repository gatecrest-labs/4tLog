import pytest

from app.faz_client import FAZError, parse_faz_version


class FakeClient:
    adom = "root"
    version = parse_faz_version("v8.0.2-build0198 261006 (GA.F)")

    def __init__(self, fail=None, devices=None):
        self.fail = fail or {}  # name -> exception
        self._devices = (
            [{"devid": "FGT1", "name": "fw1", "platform": "FGT"}] if devices is None else devices
        )
        self.calls = []

    def _maybe(self, name):
        self.calls.append(name)
        if name in self.fail:
            raise self.fail[name]

    def get_sys_status(self):
        self._maybe("sys_status")
        return {"Version": "v8.0.2-build0198 261006 (GA.F)", "TZ": "US/Pacific"}

    def preflight(self):
        self._maybe("preflight")
        return True

    def get_log_fields(self, *a, **k):
        self._maybe("log_fields")
        return [{"name": "srcip"}]

    def get_devices(self):
        self._maybe("devices")
        return self._devices

    def get_log_stats(self, adom=None):
        self._maybe("log_stats")
        return [{"devid": "FGT1"}]

    def get_alert_counts(self, adom, filter):
        self._maybe("alerts")
        return 3

    def local_time_range(self, a, b):
        return a, b

    def run_fortiview(self, adom, view, time_range, limit=1000, filter=None, **_kw):
        self._maybe("fortiview:" + view)
        return []

    def search_logs(self, logtype, device, filter_expression, start, end, limit=1000, **_kw):
        self._maybe("search_logs")
        return {"rows": [], "fields": [], "truncated": False}


def _by_id(report):
    return {c["id"]: c for c in report["checks"]}


def test_all_ok_report_shape():
    from app.faz_selftest import run_selftest

    report = run_selftest(FakeClient())
    assert report["faz_version"] == "8.0.2"
    assert report["train"] == "8.0"
    assert report["sample"]["adom"] == "root"
    assert report["sample"]["device"] == "FGT1"
    assert report["summary"]["error"] == 0
    assert report["summary"]["denied"] == 0
    assert report["summary"]["ok"] == len(report["checks"])
    ids = _by_id(report)
    for expected in (
        "system_status",
        "preflight",
        "log_fields",
        "devices",
        "log_stats",
        "alert_counts",
        "fortiview_top_type",
        "fortiview_admin_logins",
        "log_search",
    ):
        assert expected in ids, expected
    for c in report["checks"]:
        assert c["feature"] and c["label"]


def test_permission_error_is_denied_not_error():
    from app.faz_selftest import run_selftest

    report = run_selftest(FakeClient(fail={"alerts": FAZError("No permission", code=-11)}))
    c = _by_id(report)["alert_counts"]
    assert c["status"] == "denied"
    assert c["code"] == -11


def test_unsupported_filter_is_an_error_naming_the_appliance_message():
    from app.faz_selftest import run_selftest

    err = FAZError("Invalid params: filter 'type' not supported.", code=-32002)
    report = run_selftest(FakeClient(fail={"fortiview:top-threats": err}))
    c = _by_id(report)["fortiview_top_threats"]
    assert c["status"] == "error"
    assert "not supported" in c["message"]
    assert c["code"] == -32002


def test_unscoped_fortiview_error_is_visible():
    from app.faz_selftest import run_selftest

    err = FAZError("Server error: No eligible device(s).", code=-32005)
    report = run_selftest(FakeClient(fail={"fortiview:top-type": err}))
    assert _by_id(report)["fortiview_top_type"]["status"] == "error"


def test_log_search_is_skipped_when_there_is_no_device():
    from app.faz_selftest import run_selftest

    report = run_selftest(FakeClient(devices=[]))
    c = _by_id(report)["log_search"]
    assert c["status"] == "skipped"
    assert "device" in c["message"]


def test_one_failing_check_does_not_stop_the_rest():
    from app.faz_selftest import run_selftest

    report = run_selftest(FakeClient(fail={"log_fields": RuntimeError("boom")}))
    assert _by_id(report)["log_fields"]["status"] == "error"
    assert _by_id(report)["fortiview_ssl_dialup_ipsec"]["status"] == "ok"


def test_report_is_json_serialisable():
    import json

    from app.faz_selftest import run_selftest

    json.dumps(run_selftest(FakeClient()))


def test_unknown_version_still_reports():
    from app.faz_selftest import run_selftest

    c = FakeClient()
    c.version = None
    report = run_selftest(c)
    assert report["faz_version"] is None and report["train"] is None


@pytest.mark.parametrize("name", ["system_status", "preflight"])
def test_core_check_failures_are_reported_as_errors(name):
    from app.faz_selftest import run_selftest

    key = {"system_status": "sys_status"}.get(name, name)
    report = run_selftest(FakeClient(fail={key: FAZError("down")}))
    assert _by_id(report)[name]["status"] == "error"


SDWAN_CHECK_IDS = {
    "sdwan_dev_stats": "sdwan-dev-stats",
    "sdwan_intf_sla_status_line": "sdwan-intf-sla-status-line",
    "sdwan_perf_stats_line": "sdwan-perf-stats-line",
    "sdwan_intf_bandwidth_line": "sdwan-intf-bandwidth-line",
}


def test_selftest_includes_the_four_sdwan_view_checks():
    from app.faz_selftest import run_selftest

    client = FakeClient()
    checks = _by_id(run_selftest(client))

    for check_id, view in SDWAN_CHECK_IDS.items():
        assert checks[check_id]["status"] == "ok", check_id
        assert checks[check_id]["feature"].startswith("SD-WAN tab")
        assert f"fortiview:{view}" in client.calls


def test_selftest_reports_a_missing_sdwan_view_as_error_without_hiding_the_rest():
    from app.faz_selftest import run_selftest

    client = FakeClient(
        fail={
            "fortiview:sdwan-perf-stats-line": FAZError(
                "Cannot find FortiView 'sdwan-perf-stats-line'", code=-32005
            )
        }
    )

    checks = _by_id(run_selftest(client))

    assert checks["sdwan_perf_stats_line"]["status"] == "error"
    assert checks["sdwan_perf_stats_line"]["code"] == -32005
    for check_id in SDWAN_CHECK_IDS.keys() - {"sdwan_perf_stats_line"}:
        assert checks[check_id]["status"] == "ok", check_id
