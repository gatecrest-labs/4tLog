from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "manage_api_tokens.py"


@pytest.fixture
def isolated_files(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api_tokens._TOKENS_PATH", tmp_path / "api_tokens.json")
    monkeypatch.setattr("app.app_settings._SETTINGS_PATH", tmp_path / "app_settings.json")
    yield tmp_path


def test_create_and_list(isolated_files):
    import manage_api_tokens
    from app.api_tokens import list_tokens

    manage_api_tokens.cmd_create(_Args(name="test-token"))
    tokens = list_tokens()
    assert len(tokens) == 1
    assert tokens[0]["name"] == "test-token"


def test_revoke(isolated_files):
    import manage_api_tokens
    from app.api_tokens import create_token, list_tokens

    _, record = create_token("to-revoke")
    manage_api_tokens.cmd_revoke(_Args(token_id=record["id"]))
    assert list_tokens() == []


def test_enable_disable(isolated_files):
    import manage_api_tokens
    from app.app_settings import get_setting

    manage_api_tokens.cmd_enable(_Args())
    assert get_setting("external_api_enabled") is True
    manage_api_tokens.cmd_disable(_Args())
    assert get_setting("external_api_enabled") is False


class _Args:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
