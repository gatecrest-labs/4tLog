import pytest


class FakeResponse:
    def __init__(self, json_body, status_code=200):
        self._json = json_body
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._json


def _client(monkeypatch, responses):
    """responses: list of dicts returned by successive _post() calls."""
    from app.faz_client import FAZClient

    client = FAZClient(host="192.168.64.4", token="test-token", adom="root")
    calls = []

    def fake_post(url, json=None, headers=None, verify=None, timeout=None):
        calls.append({"url": url, "json": json, "headers": headers})
        return FakeResponse(responses[len(calls) - 1])

    monkeypatch.setattr(client._http, "post", fake_post)
    return client, calls


def test_preflight_success(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": [{"status": {"code": 0, "message": "OK"}}]}],
    )
    assert client.preflight() is True
    assert calls[0]["headers"]["Authorization"] == "Bearer test-token"
    assert calls[0]["json"]["params"][0]["url"] == "/logview/adom/root/logfields"


def test_preflight_success_with_bare_result_and_no_status_field(monkeypatch):
    # Confirmed live against 192.168.64.4: /logview/adom/<adom>/logfields
    # returns result as a bare dict ({"data": [...]}) with no "status" key
    # at all — absence of "status" means success, not an implicit error.
    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": {"data": [{"index": 10, "field": []}]}}],
    )
    assert client.preflight() is True


def test_preflight_permission_denied_raises(monkeypatch):
    from app.faz_client import FAZError

    client, _ = _client(
        monkeypatch,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": [{"status": {"code": -11, "message": "No permission for the resource"}}],
            }
        ],
    )
    with pytest.raises(FAZError, match="No permission for the resource"):
        client.preflight()


def test_preflight_jsonrpc_error_raises(monkeypatch):
    from app.faz_client import FAZError

    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Invalid Request"}}],
    )
    with pytest.raises(FAZError, match="Invalid Request"):
        client.preflight()


def test_get_sys_status_returns_data(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": [
                    {
                        "status": {"code": 0, "message": "OK"},
                        "data": {
                            "hostname": "FAZ-TEST",
                            "version": "v7.6.7",
                            "serial": "FAZ-VM0000000001",
                            "ha-mode": "standalone",
                        },
                    }
                ],
            }
        ],
    )
    data = client.get_sys_status()
    assert data["hostname"] == "FAZ-TEST"
    assert calls[0]["json"]["params"][0]["url"] == "/sys/status"


def test_context_manager_closes_session(monkeypatch):
    from app.faz_client import FAZClient

    client = FAZClient(host="192.168.64.4", token="t", adom="root")
    closed = {"value": False}
    monkeypatch.setattr(client._http, "close", lambda: closed.__setitem__("value", True))
    with client as c:
        assert c is client
    assert closed["value"] is True


def test_build_filter_expression_ors_within_group_ands_across_groups():
    from app.faz_client import FAZClient

    expr = FAZClient.build_filter_expression(
        source_clauses=["srcip==10.1.1.5", "srcip==10.1.2.0/24"],
        destination_clauses=["dstip==8.8.8.8"],
        port_clauses=["dstport==443"],
    )
    assert expr == "(srcip==10.1.1.5 or srcip==10.1.2.0/24) and (dstip==8.8.8.8) and (dstport==443)"


def test_build_filter_expression_skips_empty_groups():
    from app.faz_client import FAZClient

    expr = FAZClient.build_filter_expression(
        source_clauses=["srcip==10.1.1.5"],
        destination_clauses=[],
        port_clauses=[],
    )
    assert expr == "(srcip==10.1.1.5)"


def test_build_filter_expression_extra_filters_numeric_unquoted_string_quoted():
    from app.faz_client import FAZClient

    expr = FAZClient.build_filter_expression(
        source_clauses=["srcip==10.1.1.5"],
        destination_clauses=[],
        port_clauses=[],
        extra_filters=[
            {"field": "action", "op": "==", "value": "deny"},
            {"field": "policyid", "op": "==", "value": "5"},
        ],
    )
    assert expr == '(srcip==10.1.1.5) and (action=="deny") and (policyid==5)'


def test_build_filter_expression_rejects_disallowed_op():
    from app.faz_client import FAZClient
    from app.log_search_filters import FilterValidationError

    with pytest.raises(FilterValidationError, match="operator"):
        FAZClient.build_filter_expression(
            source_clauses=["srcip==10.1.1.5"],
            destination_clauses=[],
            port_clauses=[],
            extra_filters=[{"field": "srcip", "op": ">=", "value": "0.0.0.0"}],
        )


def test_build_filter_expression_rejects_invalid_field_chars():
    from app.faz_client import FAZClient
    from app.log_search_filters import FilterValidationError

    with pytest.raises(FilterValidationError, match="field"):
        FAZClient.build_filter_expression(
            source_clauses=["srcip==10.1.1.5"],
            destination_clauses=[],
            port_clauses=[],
            extra_filters=[{"field": "srcip or dstip", "op": "==", "value": "1.2.3.4"}],
        )


def test_build_filter_expression_rejects_quote_injection_in_value():
    from app.faz_client import FAZClient
    from app.log_search_filters import FilterValidationError

    with pytest.raises(FilterValidationError, match="quote"):
        FAZClient.build_filter_expression(
            source_clauses=["srcip==10.1.1.5"],
            destination_clauses=[],
            port_clauses=[],
            extra_filters=[
                {"field": "srcip", "op": "==", "value": '0.0.0.0" or dstip>="0.0.0.0'}
            ],
        )


def test_get_log_fields_returns_field_list(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "data": [
                        {
                            "index": 10,
                            "logtype": "traffic",
                            "field": [
                                {"name": "srcip", "desc": "srcip"},
                                {"name": "action", "desc": "action"},
                            ],
                        }
                    ]
                },
            }
        ],
    )
    fields = client.get_log_fields("traffic")
    assert fields == [{"name": "srcip", "desc": "srcip"}, {"name": "action", "desc": "action"}]
    assert calls[0]["json"]["params"][0]["logtype"] == "traffic"


def test_get_devices_returns_serial_name_platform(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "data": [
                        {
                            "sn": "FWF71GTK25000691",
                            "name": "FortiWiFi-71G",
                            "platform_str": "FortiWiFi-71G",
                            "adm_pass": ["ENC", "should-not-leak"],
                        },
                        {"sn": "", "name": "no-serial-device"},
                    ]
                },
            }
        ],
    )
    devices = client.get_devices()
    assert devices == [
        {"devid": "FWF71GTK25000691", "name": "FortiWiFi-71G", "platform": "FortiWiFi-71G"}
    ]
    assert calls[0]["json"]["params"][0]["url"] == "/dvmdb/adom/root/device"
    assert "adm_pass" not in str(devices)


def test_get_devices_empty_list(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": {"data": []}}],
    )
    assert client.get_devices() == []


def test_search_logs_happy_path(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [
            {"jsonrpc": "2.0", "id": 1, "result": {"tid": 42}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"tid": 42, "percentage": 50, "data": []},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "tid": 42,
                    "percentage": 100,
                    "return-lines": 2,
                    "data": [
                        {"srcip": "10.1.1.5", "dstip": "8.8.8.8"},
                        {"srcip": "10.1.1.6", "dstip": "8.8.4.4"},
                    ],
                },
            },
        ],
    )
    monkeypatch.setattr("time.sleep", lambda _s: None)
    result = client.search_logs(
        logtype="traffic",
        device="All_FortiGate",
        filter_expression="(srcip==10.1.1.0/24)",
        start_time="2026-07-25T00:00:00",
        end_time="2026-07-25T23:59:59",
        limit=1000,
        poll_interval=0.01,
        timeout=5,
    )
    assert result["rows"] == [
        {"srcip": "10.1.1.5", "dstip": "8.8.8.8"},
        {"srcip": "10.1.1.6", "dstip": "8.8.4.4"},
    ]
    assert set(result["fields"]) == {"srcip", "dstip"}
    assert result["truncated"] is False
    assert calls[0]["json"]["method"] == "add"
    assert calls[0]["json"]["params"][0]["url"] == "/logview/adom/root/logsearch"
    assert calls[0]["json"]["params"][0]["filter"] == "(srcip==10.1.1.0/24)"
    assert calls[1]["json"]["params"][0]["url"] == "/logview/adom/root/logsearch/42"


def test_search_logs_marks_truncated_when_limit_reached(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [
            {"jsonrpc": "2.0", "id": 1, "result": {"tid": 7}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"tid": 7, "percentage": 100, "return-lines": 2, "data": [{}, {}]},
            },
        ],
    )
    result = client.search_logs(
        logtype="traffic", device="All_FortiGate", filter_expression="",
        start_time="2026-07-25T00:00:00", end_time="2026-07-25T23:59:59",
        limit=2, poll_interval=0.01, timeout=5,
    )
    assert result["truncated"] is True


def test_search_logs_raises_faz_error_on_submit_failure(monkeypatch):
    from app.faz_client import FAZError

    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "Bad filter"}}],
    )
    with pytest.raises(FAZError, match="Bad filter"):
        client.search_logs(
            logtype="traffic", device="All_FortiGate", filter_expression="garbage(",
            start_time="2026-07-25T00:00:00", end_time="2026-07-25T23:59:59",
        )


def test_search_logs_raises_timeout_when_never_reaches_100(monkeypatch):
    from app.faz_client import FAZSearchTimeout

    client, _ = _client(
        monkeypatch,
        [
            {"jsonrpc": "2.0", "id": 1, "result": {"tid": 1}},
            {"jsonrpc": "2.0", "id": 2, "result": {"tid": 1, "percentage": 10, "data": []}},
            {"jsonrpc": "2.0", "id": 3, "result": {"tid": 1, "percentage": 20, "data": []}},
        ],
    )
    monkeypatch.setattr("time.sleep", lambda _s: None)
    times = iter([0, 1, 2, 100])  # forces deadline exceeded on the 3rd poll
    monkeypatch.setattr("time.monotonic", lambda: next(times))
    with pytest.raises(FAZSearchTimeout):
        client.search_logs(
            logtype="traffic", device="All_FortiGate", filter_expression="",
            start_time="2026-07-25T00:00:00", end_time="2026-07-25T23:59:59",
            poll_interval=0.01, timeout=5,
        )


def test_local_time_range_converts_utc_to_appliance_timezone(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": [{"status": {"code": 0, "message": "OK"}, "data": {"TZ": "US/Pacific"}}],
            }
        ],
    )
    start, end = client.local_time_range("2026-07-25T21:00:00Z", "2026-07-25T22:00:00.000Z")
    assert start == "2026-07-25T14:00:00"
    assert end == "2026-07-25T15:00:00"


def test_local_time_range_falls_back_when_tz_missing(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": [{"status": {"code": 0}, "data": {}}]}],
    )
    start, end = client.local_time_range("2026-07-25T21:00:00Z", "2026-07-25T22:00:00Z")
    assert (start, end) == ("2026-07-25T21:00:00Z", "2026-07-25T22:00:00Z")


def test_local_time_range_falls_back_on_faz_error(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "error": {"code": -11, "message": "No permission"}}],
    )
    start, end = client.local_time_range("2026-07-25T21:00:00Z", "2026-07-25T22:00:00Z")
    assert (start, end) == ("2026-07-25T21:00:00Z", "2026-07-25T22:00:00Z")


def test_summarize_connection_error_connection_refused():
    import requests

    from app.faz_client import summarize_connection_error

    exc = requests.exceptions.ConnectionError("... Connection refused ...")
    assert summarize_connection_error(exc) == "Connection refused"


def test_get_log_stats_folds_vdoms_to_one_record_per_device(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "data": {
                        "devs": [
                            {
                                "devid": "FGT001",
                                "devname": "FGT-branch1",
                                "vdoms": [
                                    {"vdom": "root", "last-log-timestamp": 1000, "lograte": 5.0},
                                    {"vdom": "traffic", "last-log-timestamp": 1200, "lograte": 3.5},
                                ],
                            },
                            {
                                "devid": "FGT002",
                                "devname": "FGT-branch2",
                                "vdoms": [
                                    {"vdom": "root", "last-log-timestamp": 900, "lograte": 0.0},
                                ],
                            },
                        ]
                    }
                },
            }
        ],
    )
    stats = client.get_log_stats()
    assert stats == [
        {"devid": "FGT001", "devname": "FGT-branch1", "last_log_timestamp": 1200, "lograte": 8.5},
        {"devid": "FGT002", "devname": "FGT-branch2", "last_log_timestamp": 900, "lograte": 0.0},
    ]
    assert calls[0]["json"]["params"][0]["url"] == "/logview/adom/root/logstats"


def test_get_log_stats_empty_vdoms_yields_none_timestamp(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "data": {"devs": [{"devid": "FGT003", "devname": "FGT-branch3", "vdoms": []}]}
                },
            }
        ],
    )
    stats = client.get_log_stats()
    assert stats == [
        {"devid": "FGT003", "devname": "FGT-branch3", "last_log_timestamp": None, "lograte": 0.0}
    ]


def test_get_log_stats_uses_explicit_adom_override(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": {"data": {"devs": []}}}],
    )
    client.get_log_stats(adom="corp")
    assert calls[0]["json"]["params"][0]["url"] == "/logview/adom/corp/logstats"


def test_get_log_stats_empty_devs_list(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": {"data": {"devs": []}}}],
    )
    assert client.get_log_stats() == []
