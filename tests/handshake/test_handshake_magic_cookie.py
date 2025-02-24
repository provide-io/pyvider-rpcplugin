# pyvider/rpcplugin/tests/handshake/test_handshake_magic_cookie.py

import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.handshake import validate_magic_cookie

# Define valid configurations for testing
VALID_MAGIC_COOKIE_KEY = "PLUGIN_MAGIC_COOKIE"
VALID_MAGIC_COOKIE = "hello"

import pytest
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.handshake import validate_magic_cookie


def test_validate_magic_cookie_valid(monkeypatch):
    # Make sure config sees valid cookie scenario
    monkeypatch.setitem(
        rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE"
    )
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", "hello")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", "hello")
    validate_magic_cookie()  # no error expected


def test_validate_magic_cookie_invalid(monkeypatch):
    # mismatch scenario
    monkeypatch.setitem(
        rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE"
    )
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", "hello")
    monkeypatch.setitem(
        rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", "invalid_cookie"
    )

    with pytest.raises(
        HandshakeError, match="cookie_provided does not match required cookie_value"
    ):
        validate_magic_cookie()


@pytest.mark.parametrize(
    "magic_cookie_key, magic_cookie_value, expected_error",
    [
        (
            "PLUGIN_MAGIC_COOKIE",
            "invalid_cookie",
            "cookie_provided does not match required cookie_value",
        ),
        (None, None, ""),
        ("PLUGIN_MAGIC_COOKIE", None, "cookie not provided"),
        (None, "hello", "cookie_key not found"),
    ],
)
def test_validate_magic_cookie_failures(
    monkeypatch, magic_cookie_key, magic_cookie_value, expected_error
):
    monkeypatch.setitem(
        rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", magic_cookie_key
    )
    monkeypatch.setitem(
        rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", "hello"
    )  # default
    monkeypatch.setitem(
        rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", magic_cookie_value
    )

    with pytest.raises(HandshakeError, match=expected_error):
        validate_magic_cookie()


def test_validate_magic_cookie_missing_still_raises():
    with pytest.raises(HandshakeError, match="cookie_key not found"):
        validate_magic_cookie(magic_cookie_key=None, magic_cookie_value=None)


@pytest.mark.parametrize(
    "set_key, set_value, set_cookie, expect_error, error_regex",
    [
        # Valid scenario: everything matches
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            "PLUGIN_MAGIC_COOKIE_VALUE",
            "PLUGIN_MAGIC_COOKIE_VALUE",
            False,
            None,
        ),
        # Missing environment variables
        (None, None, None, True, "cookie_key not found"),
        # Invalid cookie
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            "some_expected",
            "different_cookie",
            True,
            "cookie_provided does not match required cookie_value",
        ),
    ],
)
def test_validate_magic_cookie(
    monkeypatch, set_key, set_value, set_cookie, expect_error, error_regex
):
    """
    Parametrized test that covers valid/invalid cookie scenarios.
    We monkeypatch rpcplugin_config so that validate_magic_cookie sees the right values.
    """
    # 1) Clear out existing config keys to avoid overshadowing
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", None)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", None)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", None)

    # 2) If we want to set them, do so now
    if set_key is not None:
        monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", set_key)
    if set_value is not None:
        monkeypatch.setitem(
            rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", set_value
        )
    if set_cookie is not None:
        monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", set_cookie)

    # 3) Now call validate_magic_cookie
    if expect_error:
        with pytest.raises(HandshakeError, match=error_regex):
            validate_magic_cookie()
    else:
        # Should not raise
        validate_magic_cookie()


def test_validate_magic_cookie_explicit_args(monkeypatch):
    """
    Example test providing explicit function arguments
    rather than reading from config.
    """
    # Even if config is set, we can override with function args
    # Suppose we pass an invalid cookie to demonstrate mismatch:
    with pytest.raises(
        HandshakeError, match="cookie_provided does not match required cookie_value"
    ):
        validate_magic_cookie(
            magic_cookie_key="KEY", magic_cookie_value="EXPECTED", magic_cookie="WRONG"
        )
