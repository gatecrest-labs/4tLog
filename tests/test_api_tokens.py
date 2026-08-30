import pytest


@pytest.fixture
def tokens_file(tmp_path, monkeypatch):
    path = tmp_path / "api_tokens.json"
    import app.api_tokens as tokens_mod

    monkeypatch.setattr(tokens_mod, "_TOKENS_PATH", path)
    yield path


def test_list_tokens_empty_when_no_file(tokens_file):
    from app.api_tokens import list_tokens

    assert list_tokens() == []


def test_create_returns_plaintext_once_and_never_stores_it(tokens_file):
    from app.api_tokens import create_token, list_tokens

    raw, record = create_token("4tExecutive poller")
    assert raw.startswith("4tl_")
    assert record["name"] == "4tExecutive poller"
    assert "token_hash" not in record

    listed = list_tokens()
    assert len(listed) == 1
    assert "token_hash" not in listed[0]
    assert raw not in str(listed)


def test_validate_token_roundtrip(tokens_file):
    from app.api_tokens import create_token, validate_token

    raw, record = create_token("test")
    validated = validate_token(raw)
    assert validated["id"] == record["id"]


def test_validate_token_rejects_wrong_value(tokens_file):
    from app.api_tokens import create_token, validate_token

    create_token("test")
    assert validate_token("wrong-token") is None


def test_validate_token_rejects_revoked(tokens_file):
    from app.api_tokens import create_token, revoke_token, validate_token

    raw, record = create_token("test")
    assert revoke_token(record["id"]) is True
    assert validate_token(raw) is None


def test_revoke_unknown_id_returns_false(tokens_file):
    from app.api_tokens import revoke_token

    assert revoke_token("does-not-exist") is False


def test_app_settings_defaults_to_disabled(tmp_path, monkeypatch):
    import app.app_settings as settings_mod

    monkeypatch.setattr(settings_mod, "_SETTINGS_PATH", tmp_path / "app_settings.json")
    from app.app_settings import get_setting

    assert get_setting("external_api_enabled", False) is False


def test_app_settings_set_and_get(tmp_path, monkeypatch):
    import app.app_settings as settings_mod

    monkeypatch.setattr(settings_mod, "_SETTINGS_PATH", tmp_path / "app_settings.json")
    from app.app_settings import get_setting, set_setting

    set_setting("external_api_enabled", True)
    assert get_setting("external_api_enabled", False) is True
