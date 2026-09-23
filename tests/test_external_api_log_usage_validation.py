from app.routes.external_api_routes import _validate_log_usage_request


def test_valid_request_normalizes():
    req, err = _validate_log_usage_request({
        "adom": " Enterprise Services ", "devices": ["FW-DC-01", " FW-DC-02 "],
        "policyid": 123, "days": 30,
    })
    assert err is None
    assert req == {
        "adom": "Enterprise Services", "devices": ["FW-DC-01", "FW-DC-02"],
        "policyid": 123, "days": 30,
    }


def test_missing_adom_rejected():
    req, err = _validate_log_usage_request({"devices": ["FW1"], "policyid": 1, "days": 1})
    assert req is None
    assert "adom" in err


def test_blank_adom_rejected():
    req, err = _validate_log_usage_request({
        "adom": "   ", "devices": ["FW1"], "policyid": 1, "days": 1,
    })
    assert req is None
    assert "adom" in err


def test_missing_devices_rejected():
    req, err = _validate_log_usage_request({"adom": "A", "policyid": 1, "days": 1})
    assert req is None
    assert "devices" in err


def test_empty_devices_list_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": [], "policyid": 1, "days": 1,
    })
    assert req is None
    assert "devices" in err


def test_non_string_device_entry_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1", 42], "policyid": 1, "days": 1,
    })
    assert req is None
    assert "devices" in err


def test_missing_policyid_rejected():
    req, err = _validate_log_usage_request({"adom": "A", "devices": ["FW1"], "days": 1})
    assert req is None
    assert "policyid" in err


def test_zero_policyid_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 0, "days": 1,
    })
    assert req is None
    assert "policyid" in err


def test_negative_policyid_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": -5, "days": 1,
    })
    assert req is None
    assert "policyid" in err


def test_boolean_policyid_rejected():
    """A JSON bool is a Python int subtype -- must not be silently accepted."""
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": True, "days": 1,
    })
    assert req is None
    assert "policyid" in err


def test_days_zero_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 0,
    })
    assert req is None
    assert "days" in err


def test_days_61_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 61,
    })
    assert req is None
    assert "days" in err


def test_days_float_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 30.5,
    })
    assert req is None
    assert "days" in err


def test_days_string_rejected():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": "30",
    })
    assert req is None
    assert "days" in err


def test_devices_deduped_case_insensitively_preserving_first_casing():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1", "fw1", "FW2"], "policyid": 1, "days": 1,
    })
    assert err is None
    assert req["devices"] == ["FW1", "FW2"]


def test_days_boundaries_accepted():
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 1,
    })
    assert err is None
    req, err = _validate_log_usage_request({
        "adom": "A", "devices": ["FW1"], "policyid": 1, "days": 60,
    })
    assert err is None
