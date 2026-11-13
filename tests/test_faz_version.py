from unittest.mock import MagicMock

import pytest


@pytest.mark.parametrize(
    "raw, expected",
    [
        # 8.0.2 captured from the lab FAZVM64-KVM; 7.6.7 per app/faz_health_cache.py notes.
        ("v8.0.2-build0198 261006 (GA.F)", (8, 0, 2, 198)),
        ("v7.6.7-build3737 260101 (GA)", (7, 6, 7, 3737)),
        ("v7.4.5,build2360,240702 (GA)", (7, 4, 5, 2360)),
        ("v7.6.7", (7, 6, 7, None)),
    ],
)
def test_parse_faz_version(raw, expected):
    from app.faz_client import parse_faz_version

    v = parse_faz_version(raw)
    assert (v.major, v.minor, v.patch, v.build) == expected


@pytest.mark.parametrize("raw", ["", None, "garbage", "v8", 42])
def test_parse_faz_version_unparseable_returns_none(raw):
    from app.faz_client import parse_faz_version

    assert parse_faz_version(raw) is None


def test_faz_version_train_and_ordering():
    from app.faz_client import parse_faz_version

    v = parse_faz_version("v8.0.2-build0198 261006 (GA.F)")
    assert v.train == "8.0"
    assert v >= (7, 6)
    assert not (v < (8, 0, 2))
    assert parse_faz_version("v7.4.5,build2360") < parse_faz_version("v7.6.0")


def test_client_version_is_fetched_once_and_cached():
    from app.faz_client import FAZClient

    c = FAZClient(host="faz.example.com", token="t")
    c.get_sys_status = MagicMock(return_value={"Version": "v8.0.2-build0198 261006 (GA.F)"})
    assert c.version.train == "8.0"
    assert c.version.patch == 2
    c.get_sys_status.assert_called_once()


def test_client_version_unknown_when_status_unavailable():
    from app.faz_client import FAZClient, FAZError

    c = FAZClient(host="faz.example.com", token="t")
    c.get_sys_status = MagicMock(side_effect=FAZError("boom"))
    assert c.version is None
    assert c.version is None  # never raises
