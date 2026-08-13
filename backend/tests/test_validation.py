"""Unit tests for validation utilities (input hardening)."""

import pytest

from app.utils.errors import ValidationFailedError
from app.utils.validation import (
    is_loopback_or_private,
    resolve_hostname_to_ips,
    sanitize_filename,
    target_is_locally_authorized,
    validate_password,
    validate_port_range,
    validate_target_address,
    validate_username,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("127.0.0.1", ("127.0.0.1", "ip")),
        ("10.0.0.8", ("10.0.0.8", "ip")),
        ("192.168.1.1", ("192.168.1.1", "ip")),
        ("localhost", ("localhost", "hostname")),
        ("lab.local", ("lab.local", "hostname")),
        ("MY-LAB-01.internal", ("my-lab-01.internal", "hostname")),
    ],
)
def test_valid_target_addresses(value, expected):
    assert validate_target_address(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "127.0.0.1; rm -rf /",
        "a && b",
        "x | cat",
        "host`id`",
        "$(whoami)",
        'quote"here',
        "back\\slash",
        "1.2.3.999",
        "http://example.com",
        "https://example.com/x",
        "192.168.1.0/24",
        "a" * 254,
        "has space",
        "foo/bar",
        "<script>",
    ],
)
def test_invalid_target_addresses_rejected(value):
    with pytest.raises(ValidationFailedError):
        validate_target_address(value)


def test_local_authorization_checks():
    assert target_is_locally_authorized("127.0.0.1", "ip") is True
    assert target_is_locally_authorized("10.1.2.3", "ip") is True
    assert target_is_locally_authorized("192.168.0.1", "ip") is True
    assert target_is_locally_authorized("8.8.8.8", "ip") is False
    assert target_is_locally_authorized("localhost", "hostname") is True
    assert target_is_locally_authorized("example.com", "hostname") is False
    assert is_loopback_or_private("169.254.1.1") is True


def test_resolve_hostname_returns_loopback_for_localhost():
    ips = resolve_hostname_to_ips("localhost")
    assert "127.0.0.1" in ips


@pytest.mark.parametrize("value", ["top-100", "top-1000", "1", "1-1024", "22", "8000-9000"])
def test_valid_port_ranges(value):
    assert validate_port_range(value)


@pytest.mark.parametrize("value", ["top-500", "0-100", "1-2000", "70000", "5-2", "-1", "abc", "1-2-3", ""])
def test_invalid_port_ranges(value):
    with pytest.raises(ValidationFailedError):
        validate_port_range(value)


def test_username_and_password_validation():
    validate_username("good-name_1")
    with pytest.raises(ValidationFailedError):
        validate_username("x")
    with pytest.raises(ValidationFailedError):
        validate_username("bad name")
    validate_password("longenoughpassword")
    with pytest.raises(ValidationFailedError):
        validate_password("short")
    with pytest.raises(ValidationFailedError):
        validate_password("x" * 100)


def test_filename_sanitization_blocks_traversal():
    assert sanitize_filename("../../etc/passwd") == "etc_passwd"
    assert "\\" not in sanitize_filename("a\\b\\c")
    assert sanitize_filename("report.pdf") == "report.pdf"
    assert sanitize_filename("") == "file"
