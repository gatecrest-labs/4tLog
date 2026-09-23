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
