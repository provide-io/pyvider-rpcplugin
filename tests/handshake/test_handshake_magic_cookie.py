#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


import pytest

from pyvider.rpcplugin.handshake import validate_magic_cookie
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.handshake import _SENTINEL_INSTANCE


@pytest.mark.parametrize(
    "magic_cookie_key_config, magic_cookie_value_config, magic_cookie_env_var, expected_error_regex",
    [
        # Valid scenario
        ("PLUGIN_MAGIC_COOKIE_KEY", "expected_value", "expected_value", None),
        # Error: Key not configured
        (
            None,
            "expected_value",
            "expected_value",
            r"Internal configuration error: cookie_key is missing for lookup",
        ),
        # Error: Expected value not configured
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            None,
            "some_cookie",
            r"Expected magic cookie value is not configured",
        ),
        # Error: Cookie not provided by client
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            "expected_value",
            None,
            r"Magic cookie not provided by the client.*PLUGIN_MAGIC_COOKIE_KEY",
        ),
        # Error: Cookie mismatch
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            "expected_value",
            "wrong_cookie",
            r"Magic cookie mismatch.*Expected: 'expected_value'.*Received: 'wrong_cookie'",
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
    monkeypatch.setattr(
        rpcplugin_config, "plugin_magic_cookie_key", magic_cookie_key_config
    )
    monkeypatch.setattr(
        rpcplugin_config, "plugin_magic_cookie_value", magic_cookie_value_config
    )
    if magic_cookie_key_config and magic_cookie_env_var is not None:
        monkeypatch.setenv(magic_cookie_key_config, magic_cookie_env_var)
    elif magic_cookie_key_config and magic_cookie_env_var is None:
        monkeypatch.delenv(magic_cookie_key_config, raising=False)

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
            r"Magic cookie mismatch.*Expected: 'hello'.*Received: 'invalid_cookie'",
        ),
        (
            None,
            None,
            r"Internal configuration error: cookie_key is missing for lookup",
        ),
        (
            "PLUGIN_MAGIC_COOKIE",
            None,
            r"Magic cookie not provided by the client.*PLUGIN_MAGIC_COOKIE",
        ),
        (
            None,
            "hello",
            r"Internal configuration error: cookie_key is missing for lookup",
        ),
    ],
)
def test_validate_magic_cookie_failures(
    monkeypatch, magic_cookie_key, magic_cookie_value, expected_error
) -> None:
    monkeypatch.setattr(
        rpcplugin_config, "plugin_magic_cookie_key", magic_cookie_key
    )
    monkeypatch.setattr(rpcplugin_config, "plugin_magic_cookie_value", "hello")

    if magic_cookie_key and magic_cookie_value is not None:
        monkeypatch.setenv(magic_cookie_key, magic_cookie_value)
    elif magic_cookie_key and magic_cookie_value is None:
        monkeypatch.delenv(magic_cookie_key, raising=False)

    if expected_error:
        with pytest.raises(HandshakeError, match=expected_error):
            validate_magic_cookie()
    else:
        validate_magic_cookie()
        pytest.fail("HandshakeError was expected but not raised.")


def test_validate_magic_cookie_missing_still_raises(monkeypatch) -> None:
    """Test that if cookie key/value are not passed as args AND not in config, it still raises."""
    monkeypatch.setattr(rpcplugin_config, "plugin_magic_cookie_key", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_magic_cookie_value", None)
    with pytest.raises(HandshakeError, match=r"Internal configuration error: cookie_key is missing for lookup") :
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
        (
            None,
            None,
            None,
            True,
            r"Internal configuration error: cookie_key is missing for lookup",
        ),
        (
            "PLUGIN_MAGIC_COOKIE_KEY",
            "some_expected",
            "different_cookie",
            True,
            r"Magic cookie mismatch.*Expected: 'some_expected'.*Received: 'different_cookie'",
        ),
    ],
)
def test_validate_magic_cookie(
    monkeypatch, set_key, set_value, set_cookie, expect_error, error_regex
) -> None:
    """
    Parametrized test that covers valid/invalid cookie scenarios by directly setting config.
    """
    monkeypatch.setattr(rpcplugin_config, "plugin_magic_cookie_key", set_key)
    monkeypatch.setattr(rpcplugin_config, "plugin_magic_cookie_value", set_value)

    if set_key and set_cookie is not None:
        monkeypatch.setenv(set_key, set_cookie)
    elif set_key and set_cookie is None:
        monkeypatch.delenv(set_key, raising=False)

    if expect_error:
        with pytest.raises(HandshakeError, match=error_regex):
            validate_magic_cookie()
    else:
        validate_magic_cookie()


def test_validate_magic_cookie_explicit_args(monkeypatch) -> None:
    """
    Test validate_magic_cookie providing explicit function arguments.
    """
    monkeypatch.setattr(
        rpcplugin_config,
        "plugin_magic_cookie_key",
        "CONFIG_KEY_SHOULD_BE_IGNORED",
    )
    monkeypatch.setattr(
        rpcplugin_config,
        "plugin_magic_cookie_value",
        "CONFIG_VALUE_SHOULD_BE_IGNORED",
    )

    validate_magic_cookie(
        magic_cookie_key="EXPLICIT_KEY",
        magic_cookie_value="EXPECTED",
        magic_cookie="EXPECTED",
    )

    expected_mismatch_regex = (
        r"Magic cookie mismatch.*Expected: 'EXPECTED'.*Received: 'WRONG'"
    )
    with pytest.raises(HandshakeError, match=expected_mismatch_regex):
        validate_magic_cookie(
            magic_cookie_key="EXPLICIT_KEY",
            magic_cookie_value="EXPECTED",
            magic_cookie="WRONG",
        )

    with pytest.raises(
        HandshakeError, match=r"Magic cookie key is not configured"
    ):
        validate_magic_cookie(
            magic_cookie_key=None, magic_cookie_value="V", magic_cookie="C"
        )

    with pytest.raises(
        HandshakeError,
        match=r"Expected magic cookie value is not configured",
    ):
        validate_magic_cookie(
            magic_cookie_key="K", magic_cookie_value=None, magic_cookie="C"
        )

    with pytest.raises(
        HandshakeError,
        match=r"Magic cookie not provided by the client.*K",
    ):
        validate_magic_cookie(
            magic_cookie_key="K", magic_cookie_value="V", magic_cookie=None
        )


def test_validate_magic_cookie_explicit_none_empty_key(monkeypatch) -> None:
    """Test that explicit None or empty string for key args raises error."""
    with pytest.raises(HandshakeError, match="Magic cookie key is not configured"):
        validate_magic_cookie(
            magic_cookie_key=None, magic_cookie_value="val", magic_cookie="cook"
        )

    with pytest.raises(HandshakeError, match="Magic cookie key is not configured"):
        validate_magic_cookie(
            magic_cookie_key="", magic_cookie_value="val", magic_cookie="cook"
        )

    with pytest.raises(
        HandshakeError, match="Expected magic cookie value is not configured"
    ):
        validate_magic_cookie(
            magic_cookie_key="key", magic_cookie_value=None, magic_cookie="cook"
        )

    with pytest.raises(
        HandshakeError, match="Expected magic cookie value is not configured"
    ):
        validate_magic_cookie(
            magic_cookie_key="key", magic_cookie_value="", magic_cookie="cook"
        )

    with pytest.raises(HandshakeError, match="Magic cookie not provided by the client"):
        validate_magic_cookie(
            magic_cookie_key="key", magic_cookie_value="val", magic_cookie=None
        )

    with pytest.raises(HandshakeError, match="Magic cookie not provided by the client"):
        validate_magic_cookie(
            magic_cookie_key="key", magic_cookie_value="val", magic_cookie=""
        )

# 🐍🔌📞🔚
