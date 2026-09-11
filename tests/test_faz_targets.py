import pytest


@pytest.fixture
def targets_file(tmp_path, monkeypatch):
    path = tmp_path / "faz_targets.json"
    import app.faz_targets as faz_targets_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", path)
    yield path


def test_list_empty_when_no_file(targets_file):
    from app.faz_targets import list_targets

    assert list_targets() == []


def test_create_list_get(targets_file):
    from app.faz_targets import create_target, get_target, list_targets

    assert create_target("Primary", host="192.168.64.4", adom="root", token="abc123") is True
    assert [t["label"] for t in list_targets()] == ["Primary"]
    t = get_target("Primary")
    assert t["host"] == "192.168.64.4"
    assert t["adom"] == "root"
    assert t["token"] == "abc123"


def test_create_duplicate_label_fails(targets_file):
    from app.faz_targets import create_target

    assert create_target("Primary", host="192.168.64.4") is True
    assert create_target("Primary", host="10.0.0.9") is False


def test_create_with_snmp_overrides(targets_file):
    from app.faz_targets import create_target, get_target

    create_target(
        "Primary",
        host="192.168.64.4",
        snmp_overrides={"snmp_user": "monitor2", "snmp_auth_key": "k1"},
    )
    t = get_target("Primary")
    assert t["snmp_user"] == "monitor2"
    assert t["snmp_auth_key"] == "k1"


def test_update_target(targets_file):
    from app.faz_targets import create_target, get_target, update_target

    create_target("Primary", host="192.168.64.4", adom="root", token="abc123")
    ok = update_target("Primary", host="10.0.0.9", adom="lab", token="xyz789")
    assert ok is True
    t = get_target("Primary")
    assert t["host"] == "10.0.0.9"
    assert t["adom"] == "lab"
    assert t["token"] == "xyz789"


def test_update_target_preserves_snmp_overrides_when_omitted(targets_file):
    from app.faz_targets import create_target, get_target, update_target

    create_target(
        "Primary",
        host="192.168.64.4",
        adom="root",
        token="abc123",
        snmp_overrides={"snmp_user": "monitor2", "snmp_auth_key": "k1"},
    )

    # Editing only host/adom/token (as the Admin UI's edit modal does, since
    # it has no SNMP fields) must not wipe the previously-set SNMP overrides.
    ok = update_target("Primary", host="10.0.0.9", adom="lab", token="xyz789", snmp_overrides=None)
    assert ok is True
    t = get_target("Primary")
    assert t["host"] == "10.0.0.9"
    assert t["snmp_user"] == "monitor2"
    assert t["snmp_auth_key"] == "k1"


def test_update_target_explicit_snmp_overrides_still_apply(targets_file):
    from app.faz_targets import create_target, get_target, update_target

    create_target(
        "Primary",
        host="192.168.64.4",
        snmp_overrides={"snmp_user": "monitor2", "snmp_auth_key": "k1"},
    )

    ok = update_target(
        "Primary",
        host="192.168.64.4",
        adom="root",
        token="abc123",
        snmp_overrides={"snmp_user": "monitor3"},
    )
    assert ok is True
    t = get_target("Primary")
    assert t["snmp_user"] == "monitor3"
    # snmp_auth_key wasn't part of the explicit override, so it's preserved.
    assert t["snmp_auth_key"] == "k1"


def test_update_target_blank_token_preserves_existing_token(targets_file):
    from app.faz_targets import create_target, get_target, update_target

    create_target("Primary", host="192.168.64.4", adom="root", token="abc123")

    ok = update_target("Primary", host="10.0.0.9", adom="root", token="")
    assert ok is True
    t = get_target("Primary")
    assert t["token"] == "abc123"
    assert t["host"] == "10.0.0.9"


def test_update_missing_target_fails(targets_file):
    from app.faz_targets import update_target

    assert update_target("Ghost", host="10.0.0.9", adom="root", token="x") is False


def test_list_returns_empty_on_corrupt_json(targets_file):
    from app.faz_targets import list_targets

    targets_file.write_text("{not valid json")
    assert list_targets() == []


def test_delete_target(targets_file):
    from app.faz_targets import create_target, delete_target, list_targets

    create_target("Primary", host="192.168.64.4")
    assert delete_target("Primary") is True
    assert list_targets() == []
    assert delete_target("Primary") is False


def test_create_target_defaults_threat_poll_enabled_true(targets_file):
    from app.faz_targets import create_target, get_target

    create_target("Primary", host="192.168.64.4")
    assert get_target("Primary")["threat_poll_enabled"] is True


def test_create_target_threat_poll_enabled_false(targets_file):
    from app.faz_targets import create_target, get_target

    create_target("Primary", host="192.168.64.4", threat_poll_enabled=False)
    assert get_target("Primary")["threat_poll_enabled"] is False


def test_update_target_changes_threat_poll_enabled(targets_file):
    from app.faz_targets import create_target, get_target, update_target

    create_target("Primary", host="192.168.64.4")
    update_target("Primary", host="192.168.64.4", adom="root", token="", threat_poll_enabled=False)
    assert get_target("Primary")["threat_poll_enabled"] is False
