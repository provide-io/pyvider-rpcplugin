# tests/handshake/test_handshake_magic_cookie.py
import pytest
import re
from unittest.mock import patch

from pyvider.rpcplugin.handshake import validate_magic_cookie
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.handshake import _SENTINEL_INSTANCE


@pytest.mark.parametrize(
    "magic_cookie_key_config, magic_cookie_value_config, magic_cookie_env_var, expected_error_regex",
    [
        # Valid scenario
        ("PLUGIN_MAGIC_COOKIE_KEY", "expected_value", "expected_value", None),
        # Error: Key not configured (but value and cookie provided)
        (
            None,
            "expected_value",
            "expected_value",
            r"\[HandshakeError\] Magic cookie key is not configured.*Hint:.*",
        ),
        # Error: Expected value not configured
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            None,
            "some_cookie",
            r"\[HandshakeError\] Expected magic cookie value is not configured.*Hint:.*",
        ),
        # Error: Cookie not provided by client
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            "expected_value",
            None,
            r"\[HandshakeError\] Magic cookie not provided by the client\. Expected via environment variable 'PLUGIN_MAGIC_COOKIE_KEY'\..*Hint:.*",
        ),
        # Error: Cookie mismatch - THIS IS THE TARGETED CASE
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            "expected_value", # This is the 'set_value' or 'expected_value_config'
            "wrong_cookie",   # This is the 'set_cookie' or 'magic_cookie_env_var'
            # Applying the more flexible regex that worked for a similar case
            r"\[HandshakeError\] Magic cookie mismatch\. Expected: 'expected_value', Received: 'wrong_cookie'\. \(Hint: Verify that the environment variable 'PLUGIN_MAGIC_COOKIE_KEY' set by the client matches the server's expected 'PLUGIN_MAGIC_COO.*\)"
        ),
    ],
)
def test_validate_magic_cookie_config_scenarios(
    monkeypatch,
    magic_cookie_key_config,
    magic_cookie_value_config,
    magic_cookie_env_var,
    expected_error_regex,
):
    """Tests validate_magic_cookie by mocking rpcplugin_config values."""
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", magic_cookie_key_config)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", magic_cookie_value_config)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", magic_cookie_env_var)

    if expected_error_regex:
        with pytest.raises(HandshakeError, match=expected_error_regex):
            validate_magic_cookie()
    else:
        validate_magic_cookie()


@pytest.mark.parametrize(
    "magic_cookie_key, magic_cookie_value, expected_error",
    [
        (
            "PLUGIN_MAGIC_COOKIE",
            "invalid_cookie",
            r"\[HandshakeError\] Magic cookie mismatch\. Expected: 'hello', Received: 'invalid_cookie'\. \(Hint: Verify that the environment variable 'PLUGIN_MAGIC_COOKIE' set by the client matches the server's expected 'PLUGIN_MAGIC_COOKIE_.*\)"
        ),
        (
            None,
            None,
            r"\[HandshakeError\] Magic cookie key is not configured.*Hint:.*",
        ),
        (
            "PLUGIN_MAGIC_COOKIE",
            None,
            r"\[HandshakeError\] Magic cookie not provided by the client\. Expected via environment variable 'PLUGIN_MAGIC_COOKIE'\..*Hint:.*",
        ),
        (
            None,
            "hello",
            r"\[HandshakeError\] Magic cookie key is not configured.*Hint:.*",
        ),
    ],
)
def test_validate_magic_cookie_failures(
    monkeypatch, magic_cookie_key, magic_cookie_value, expected_error
) -> None:
    monkeypatch.setitem(
        rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", magic_cookie_key
    )
    monkeypatch.setitem(
        rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", "hello"
    )
    monkeypatch.setitem(
        rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", magic_cookie_value
    )

    if expected_error:
        with pytest.raises(HandshakeError, match=expected_error):
            validate_magic_cookie()
    else:
        validate_magic_cookie()
        pytest.fail("HandshakeError was expected but not raised.")


def test_validate_magic_cookie_missing_still_raises(monkeypatch) -> None:
    """Test that if cookie key/value are not passed as args AND not in config, it still raises."""
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", None)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", None)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", None)
    with pytest.raises(HandshakeError, match="Magic cookie key is not configured"):
        validate_magic_cookie(
            magic_cookie_key=_SENTINEL_INSTANCE,
            magic_cookie_value=_SENTINEL_INSTANCE,
            magic_cookie=_SENTINEL_INSTANCE,
        )


@pytest.mark.parametrize(
    "set_key, set_value, set_cookie, expect_error, error_regex",
    [
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            "PLUGIN_MAGIC_COOKIE_VALUE",
            "PLUGIN_MAGIC_COOKIE_VALUE",
            False,
            None,
        ),
        (None, None, None, True, r"\[HandshakeError\] Magic cookie key is not configured.*Hint:.*"),
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            "some_expected",
            "different_cookie",
            True,
            r"\[HandshakeError\] Magic cookie mismatch\. Expected: 'some_expected', Received: 'different_cookie'\. \(Hint: Verify that the environment variable 'PLUGIN_MAGIC_COOKIE_KEY' set by the client matches the server's expected 'PLUGIN_MAGIC_COO\.\.\..*\)",
        ),
    ],
)
def test_validate_magic_cookie(
    monkeypatch, set_key, set_value, set_cookie, expect_error, error_regex
) -> None:
    """
    Parametrized test that covers valid/invalid cookie scenarios by directly setting config.
    """
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", set_key)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", set_value)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", set_cookie)

    if expect_error:
        with pytest.raises(HandshakeError, match=error_regex):
            validate_magic_cookie()
    else:
        validate_magic_cookie()


def test_validate_magic_cookie_explicit_args(monkeypatch) -> None:
    """
    Test validate_magic_cookie providing explicit function arguments.
    """
    # Config can be anything, args should override
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", "CONFIG_KEY_SHOULD_BE_IGNORED")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", "CONFIG_VALUE_SHOULD_BE_IGNORED")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE", "CONFIG_ACTUAL_COOKIE_SHOULD_BE_IGNORED")

    # Valid case with explicit args
    validate_magic_cookie(
        magic_cookie_key="EXPLICIT_KEY",
        magic_cookie_value="EXPECTED",
        magic_cookie="EXPECTED",
    )

    # Invalid case with explicit args (mismatch)
    expected_mismatch_regex = (
        r"\[HandshakeError\] Magic cookie mismatch\. Expected: 'EXPECTED', Received: 'WRONG'\. "
        r"\(Hint: Verify that the environment variable 'EXPLICIT_KEY' set by the client "
        r"matches the server's expected 'PLUGIN_MAGIC_COOKIE_VALUE'\.\)"
    )
    with pytest.raises(HandshakeError, match=expected_mismatch_regex):
        validate_magic_cookie(
            magic_cookie_key="EXPLICIT_KEY",
            magic_cookie_value="EXPECTED",
            magic_cookie="WRONG",
        )

    # Key not configured (explicitly None)
    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] Magic cookie key is not configured.*"):
        validate_magic_cookie(magic_cookie_key=None, magic_cookie_value="V", magic_cookie="C")

    # Expected value not configured (explicitly None)
    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] Expected magic cookie value is not configured.*"):
        validate_magic_cookie(magic_cookie_key="K", magic_cookie_value=None, magic_cookie="C")

    # Actual cookie not provided (explicitly None)
    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] Magic cookie not provided by the client\. Expected via environment variable 'K'\..*"):
        validate_magic_cookie(magic_cookie_key="K", magic_cookie_value="V", magic_cookie=None)


def test_validate_magic_cookie_explicit_none_empty_key(monkeypatch) -> None:
    """Test that explicit None or empty string for key args raises error."""
    with pytest.raises(HandshakeError, match="Magic cookie key is not configured"):
        validate_magic_cookie(magic_cookie_key=None, magic_cookie_value="val", magic_cookie="cook")

    with pytest.raises(HandshakeError, match="Magic cookie key is not configured"):
        validate_magic_cookie(magic_cookie_key="", magic_cookie_value="val", magic_cookie="cook")

    with pytest.raises(HandshakeError, match="Expected magic cookie value is not configured"):
        validate_magic_cookie(magic_cookie_key="key", magic_cookie_value=None, magic_cookie="cook")

    with pytest.raises(HandshakeError, match="Expected magic cookie value is not configured"):
        validate_magic_cookie(magic_cookie_key="key", magic_cookie_value="", magic_cookie="cook")

    with pytest.raises(HandshakeError, match="Magic cookie not provided by the client"):
        validate_magic_cookie(magic_cookie_key="key", magic_cookie_value="val", magic_cookie=None)

    with pytest.raises(HandshakeError, match="Magic cookie not provided by the client"):
        validate_magic_cookie(magic_cookie_key="key", magic_cookie_value="val", magic_cookie="")
