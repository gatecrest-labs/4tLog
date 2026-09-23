from unittest.mock import MagicMock

import requests

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
            "rows": [],
            "fields": [],
            "truncated": False,
        }
    return client


def test_no_matching_target_returns_404(monkeypatch):
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [])
    response, error, status = _run_log_usage_search(_REQ, faz_client_factory=lambda t: None)
    assert response is None
    assert status == 404
    assert "Enterprise Services" in error


def test_happy_path_single_target_single_device(monkeypatch):
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [_target()])
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
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [_target()])
    client = _fake_client(devices=[])
    response, error, status = _run_log_usage_search(_REQ, faz_client_factory=lambda t: client)
    assert error is None
    assert status == 200
    assert response["devices_queried"] == []
    assert response["devices_not_found"] == ["FW-DC-01"]
    assert response["srcips"] == []


def test_device_found_on_second_target_not_first(monkeypatch):
    targets = [_target(host="1.1.1.1"), _target(host="2.2.2.2")]
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: targets)
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
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [_target()])
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
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [_target()])
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


def test_device_search_connection_error_does_not_crash_request(monkeypatch):
    """search_logs() raising a raw requests exception (not FAZError) must
    not propagate -- it should land in device_errors like a FAZError does."""
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [_target()])
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
            raise requests.ConnectionError("connection refused")
        return {"rows": [{"srcip": "10.1.1.6"}], "fields": [], "truncated": False}

    client.search_logs.side_effect = fake_search_logs
    response, error, status = _run_log_usage_search(req, faz_client_factory=lambda t: client)
    assert error is None
    assert status == 200
    assert response["devices_queried"] == ["FW-DC-02"]
    assert "FW-DC-01" in response["device_errors"]
    assert response["srcips"] == ["10.1.1.6"]


def test_device_search_malformed_json_does_not_crash_request(monkeypatch):
    """A JSONDecodeError from search_logs() (FAZ returned malformed JSON)
    is a requests.RequestException subclass and must be caught the same
    way as a connection error."""
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [_target()])
    client = _fake_client(
        devices=[{"devid": "SN001", "name": "FW-DC-01", "platform": "x"}],
        search_error=requests.exceptions.JSONDecodeError("Expecting value", "", 0),
    )
    response, error, status = _run_log_usage_search(_REQ, faz_client_factory=lambda t: client)
    assert status == 502
    assert response is None
    assert "FW-DC-01" in error


def test_get_devices_error_on_one_target_lets_another_target_resolve(monkeypatch):
    """get_devices() failing on one target must not crash the request --
    remaining device names stay eligible for the next target."""
    targets = [_target(host="1.1.1.1"), _target(host="2.2.2.2")]
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: targets)
    client_fail = MagicMock()
    client_fail.__enter__.return_value = client_fail
    client_fail.__exit__.return_value = False
    client_fail.get_devices.side_effect = requests.ConnectionError("refused")

    client_hit = _fake_client(
        devices=[{"devid": "SN001", "name": "FW-DC-01", "platform": "x"}],
        search_result={"rows": [{"srcip": "10.1.1.5"}], "fields": [], "truncated": False},
    )
    factory_calls = {"1.1.1.1": client_fail, "2.2.2.2": client_hit}
    response, error, status = _run_log_usage_search(
        _REQ, faz_client_factory=lambda t: factory_calls[t["host"]]
    )
    assert error is None
    assert status == 200
    assert response["devices_queried"] == ["FW-DC-01"]
    assert response["devices_not_found"] == []
    assert response["srcips"] == ["10.1.1.5"]


def test_get_devices_error_on_only_target_ends_in_devices_not_found(monkeypatch):
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [_target()])
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.get_devices.side_effect = FAZError("No permission for the resource")
    response, error, status = _run_log_usage_search(_REQ, faz_client_factory=lambda t: client)
    # No device was ever queried -- this is the all-devices-errored 502 case.
    assert response is None
    assert status == 502
    assert "FW-DC-01" in error


def test_deadline_exceeded_skips_remaining_devices(monkeypatch):
    """When the whole-request deadline is hit partway through, devices not
    yet attempted must show up in device_errors as 'skipped', not crash,
    and not be misreported as devices_not_found."""
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [_target()])
    req = {**_REQ, "devices": ["FW-DC-01", "FW-DC-02"]}
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.get_devices.return_value = [
        {"devid": "SN001", "name": "FW-DC-01", "platform": "x"},
        {"devid": "SN002", "name": "FW-DC-02", "platform": "x"},
    ]
    client.local_time_range.return_value = ("a", "b")
    client.search_logs.return_value = {
        "rows": [{"srcip": "10.1.1.5"}],
        "fields": [],
        "truncated": False,
    }

    # Call sequence inside _run_log_usage_search: 1) compute the deadline,
    # 2) check before device 1 (let it through), 3) check before device 2
    # (report the deadline as blown). Devices are processed in sorted order
    # (FW-DC-01, then FW-DC-02).
    real_monotonic = __import__("time").monotonic
    call_count = {"n": 0}

    def fake_monotonic():
        call_count["n"] += 1
        base = real_monotonic()
        if call_count["n"] <= 2:
            return base
        return base + 1000  # far past any deadline computed from call 1

    monkeypatch.setattr("app.routes.external_api_routes.time.monotonic", fake_monotonic)

    response, error, status = _run_log_usage_search(req, faz_client_factory=lambda t: client)
    assert error is None
    assert status == 200
    assert response["devices_queried"] == ["FW-DC-01"]
    assert response["devices_not_found"] == []
    assert response["device_errors"] == {"FW-DC-02": "skipped: request deadline exceeded"}


def test_truncated_true_if_any_device_truncated(monkeypatch):
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: [_target()])
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
