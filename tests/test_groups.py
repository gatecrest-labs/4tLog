import pytest


@pytest.fixture
def groups_file(tmp_path, monkeypatch):
    path = tmp_path / "groups.json"
    import app.groups as groups_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", path)
    groups_mod.KNOWN_TABS = {"dashboard": "Dashboard", "log_search": "Log Search", "admin": "Admin"}
    yield path
    groups_mod.KNOWN_TABS = {}


@pytest.fixture
def no_users(monkeypatch):
    import app.auth as auth_mod

    monkeypatch.setattr(auth_mod, "_load_users", lambda: {})


def test_create_list_get_group(groups_file, no_users):
    from app.groups import create_group, get_group, list_groups

    assert create_group("noc", members=["alice"], allowed_tabs=["dashboard"]) is True
    assert create_group("noc", allowed_tabs=["dashboard"]) is False  # duplicate
    assert [g["name"] for g in list_groups()] == ["noc"]
    g = get_group("noc")
    assert g["members"] == ["alice"]
    assert g["allowed_tabs"] == ["dashboard"]
    assert g["adom_restrict"] is False


def test_update_group_filters_unknown_tabs(groups_file, no_users):
    from app.groups import create_group, get_group, update_group

    create_group("noc", allowed_tabs=["dashboard"])
    ok = update_group("noc", members=["bob"], allowed_tabs=["dashboard", "bogus_tab"])
    assert ok is True
    g = get_group("noc")
    assert g["allowed_tabs"] == ["dashboard"]  # bogus_tab filtered out
    assert g["members"] == ["bob"]


def test_update_group_missing_returns_false(groups_file, no_users):
    from app.groups import update_group

    assert update_group("ghost", members=[], allowed_tabs=[]) is False


def test_delete_group(groups_file, no_users):
    from app.groups import create_group, delete_group

    create_group("noc", allowed_tabs=["dashboard"])
    assert delete_group("noc") is True
    assert delete_group("noc") is False


def test_get_allowed_tabs_union_across_groups(groups_file, no_users):
    from app.groups import create_group, get_allowed_tabs

    create_group("g1", members=["alice"], allowed_tabs=["dashboard"])
    create_group("g2", members=["alice"], allowed_tabs=["log_search"])
    assert get_allowed_tabs("alice") == {"dashboard", "log_search"}


def test_get_allowed_tabs_admin_role_gets_everything(groups_file, no_users):
    from app.groups import get_allowed_tabs

    assert get_allowed_tabs("whoever", role="admin") == {"dashboard", "log_search", "admin"}


def test_get_allowed_tabs_no_membership_is_empty(groups_file, no_users):
    from app.groups import get_allowed_tabs

    assert get_allowed_tabs("nobody") == set()


def test_user_can_access_tab(groups_file, no_users):
    from app.groups import create_group, user_can_access_tab

    create_group("g1", members=["alice"], allowed_tabs=["dashboard"])
    assert user_can_access_tab("alice", "dashboard") is True
    assert user_can_access_tab("alice", "admin") is False
