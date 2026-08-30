import json

import pytest


@pytest.fixture
def users_file(tmp_path, monkeypatch):
    path = tmp_path / "users.json"
    import app.auth as auth_mod

    monkeypatch.setattr(auth_mod, "USERS_FILE", path)
    return path


def test_add_user_hashes_password(users_file):
    from app.auth import add_user, list_users

    add_user("alice", "Str0ng!Passw0rd", role="admin")
    users = list_users()
    assert users == [{"username": "alice", "role": "admin"}]
    data = json.loads(users_file.read_text())
    assert data["alice"]["password_hash"] != "Str0ng!Passw0rd"


def test_authenticate_success_and_failure(users_file):
    from app.auth import add_user, authenticate

    add_user("bob", "Str0ng!Passw0rd", role="viewer")
    assert authenticate("bob", "Str0ng!Passw0rd") == ("viewer", [])
    assert authenticate("bob", "wrong-password") is None
    assert authenticate("nobody", "whatever") is None


def test_authenticate_with_malformed_hash_returns_none(users_file):
    # Mirrors users.example.json's placeholder password_hash, which is not
    # a valid bcrypt hash — bcrypt.checkpw raises ValueError('Invalid salt')
    # for it. authenticate() must treat this as auth failure, not crash.
    from app.auth import authenticate

    users_file.write_text(
        json.dumps({"placeholder": {"password_hash": "not-a-real-bcrypt-hash", "role": "viewer"}})
    )
    assert authenticate("placeholder", "whatever") is None


def test_delete_user(users_file):
    from app.auth import add_user, delete_user, list_users

    add_user("carol", "Str0ng!Passw0rd")
    assert delete_user("carol") is True
    assert delete_user("carol") is False
    assert list_users() == []


def test_validate_password_policy_rejects_weak_passwords():
    from app.auth import validate_password_policy

    with pytest.raises(ValueError):
        validate_password_policy("short")
    with pytest.raises(ValueError):
        validate_password_policy("alllowercase123!")
    validate_password_policy("Str0ng!Passw0rd")  # should not raise


def test_generate_secret_key_is_64_hex_chars():
    from app.auth import generate_secret_key

    key = generate_secret_key()
    assert len(key) == 64
    int(key, 16)  # raises if not valid hex
