from unittest.mock import MagicMock

import pytest

from app.faz_client import FAZError
from app.routes.external_api_routes import _search_one_device


def _client(rows, truncated=False, local_range=("2026-08-24T00:00:00", "2026-09-23T00:00:00")):
    client = MagicMock()
    client.local_time_range.return_value = local_range
    client.search_logs.return_value = {"rows": rows, "fields": [], "truncated": truncated}
    return client


def test_search_one_device_aggregates_rows():
    client = _client([
        {"srcip": "10.1.1.5", "dstip": "10.2.2.10", "dstport": 443},
        {"srcip": "10.1.1.6", "dstip": "10.2.2.10", "dstport": 8443},
    ])
    result = _search_one_device(client, "SN001", 123, "2026-08-24T00:00:00", "2026-09-23T00:00:00", 30)
    assert result["srcips"] == {"10.1.1.5", "10.1.1.6"}
    assert result["dstips"] == {"10.2.2.10"}
    assert result["dstports"] == {443, 8443}
    assert result["log_count"] == 2
    assert result["truncated"] is False
    assert result["local_start"] == "2026-08-24T00:00:00"
    assert result["local_end"] == "2026-09-23T00:00:00"


def test_search_one_device_truncated_flag_passed_through():
    client = _client([{"srcip": "10.1.1.5"}], truncated=True)
    result = _search_one_device(client, "SN001", 123, "a", "b", 30)
    assert result["truncated"] is True


def test_search_one_device_skips_rows_missing_fields():
    client = _client([{"srcip": "10.1.1.5"}, {"dstip": "10.2.2.10"}, {}])
    result = _search_one_device(client, "SN001", 123, "a", "b", 30)
    assert result["srcips"] == {"10.1.1.5"}
    assert result["dstips"] == {"10.2.2.10"}
    assert result["dstports"] == set()
    assert result["log_count"] == 3


def test_search_one_device_builds_correct_filter_expression():
    client = _client([])
    _search_one_device(client, "SN001", 456, "a", "b", 30)
    call_kwargs = client.search_logs.call_args.kwargs
    assert call_kwargs["filter_expression"] == "policyid==456"
    assert call_kwargs["device"] == "SN001"
    assert call_kwargs["logtype"] == "traffic"


def test_search_one_device_propagates_faz_error():
    client = MagicMock()
    client.local_time_range.return_value = ("a", "b")
    client.search_logs.side_effect = FAZError("boom")
    with pytest.raises(FAZError, match="boom"):
        _search_one_device(client, "SN001", 123, "a", "b", 30)


def test_search_one_device_empty_dstport_not_added():
    """A row with dstport=0 is a legitimate value and must be kept;
    a row with no dstport key at all must not add None to the set."""
    client = _client([{"dstport": 0}, {}])
    result = _search_one_device(client, "SN001", 123, "a", "b", 30)
    assert result["dstports"] == {0}


def test_search_one_device_normalizes_mixed_type_dstports():
    """FAZ's JSON response shape for dstport is unconfirmed (int vs str) --
    mixed types across rows/devices must not crash sorted() downstream, so
    every coercible value is normalized to int."""
    client = _client([{"dstport": "443"}, {"dstport": 8443}])
    result = _search_one_device(client, "SN001", 123, "a", "b", 30)
    assert result["dstports"] == {443, 8443}
    assert all(isinstance(p, int) for p in result["dstports"])
    assert sorted(result["dstports"]) == [443, 8443]


def test_search_one_device_skips_non_numeric_dstport():
    client = _client([{"dstport": "not-a-port"}, {"dstport": 443}])
    result = _search_one_device(client, "SN001", 123, "a", "b", 30)
    assert result["dstports"] == {443}
