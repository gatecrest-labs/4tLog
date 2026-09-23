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
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: targets)
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
    monkeypatch.setattr("app.routes.external_api_routes.list_targets", lambda: targets)
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
