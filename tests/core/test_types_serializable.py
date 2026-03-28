#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for serializable type validation."""

import inspect

from provide.testkit.mocking import MagicMock, patch

from pyvider.rpcplugin import types as types_module_logger_ref
from pyvider.rpcplugin.types import is_valid_serializable


# Test for is_valid_serializable
def test_is_valid_serializable_true(mocker: object) -> None:
    """Test is_valid_serializable with an object that correctly implements the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    class ValidSerializable:  # Does NOT inherit SerializableT
        def to_dict(self) -> dict[str, object]:
            return {"data": "valid"}

        @classmethod
        def from_dict(cls, data: dict[str, object]) -> "ValidSerializable":
            instance = cls()
            return instance

    instance = ValidSerializable()
    assert is_valid_serializable(instance) is True
    expected_log_calls = [
        mocker.call("SerializableT: All structural and signature checks passed."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 1


# --- New tests for covering missed branches ---


# SerializableT Not Callable
def test_is_valid_serializable_false_to_dict_not_callable(mocker: object) -> None:
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug")

    class NotCallableDict:
        to_dict = 123  # Not callable

        @classmethod
        def from_dict(cls, data):
            return cls()

    assert is_valid_serializable(NotCallableDict()) is False
    mock_logger_debug.assert_any_call("SerializableT: Attribute to_dict is not callable.")


def test_is_valid_serializable_false_from_dict_not_callable(mocker: object) -> None:
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug")

    class NotCallableFromDict:
        def to_dict(self):
            return {}

        from_dict = 123  # Not callable

    assert is_valid_serializable(NotCallableFromDict()) is False
    mock_logger_debug.assert_any_call("SerializableT: Attribute from_dict is not callable.")


# SerializableT Inspect Signature Fails
def test_is_valid_serializable_inspect_signature_to_dict_fails(mocker: object) -> None:
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug")

    class TargetForInspectFail:
        def to_dict(self):
            return {}

        @classmethod
        def from_dict(cls, data):
            return cls()

    with patch(
        "inspect.signature", side_effect=TypeError("Inspect fail for to_dict!")
    ):  # Changed to TypeError
        assert is_valid_serializable(TargetForInspectFail()) is False
    mock_logger_debug.assert_any_call("SerializableT: Could not inspect to_dict signature.")


def test_is_valid_serializable_inspect_signature_from_dict_fails(mocker: object) -> None:
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug")

    class TargetForInspectFail:
        def to_dict(self):
            return {}

        @classmethod
        def from_dict(cls, data):
            return cls()

    original_inspect_signature = inspect.signature

    def inspect_side_effect_selective(obj_to_inspect):
        # Check if it's the 'from_dict' method of our target class
        if (
            hasattr(obj_to_inspect, "__qualname__")
            and "TargetForInspectFail.from_dict" in obj_to_inspect.__qualname__
        ):
            raise ValueError("Inspect fail for from_dict!")
        return original_inspect_signature(obj_to_inspect)

    with patch("inspect.signature", side_effect=inspect_side_effect_selective):
        assert is_valid_serializable(TargetForInspectFail()) is False
    mock_logger_debug.assert_any_call("SerializableT: Could not inspect from_dict signature.")


def test_is_valid_serializable_false_missing_methods(mocker: object) -> None:
    """Test is_valid_serializable with an object missing required methods."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    class InvalidSerializableMissing:
        # Missing to_dict and from_dict
        pass

    instance = InvalidSerializableMissing()
    assert is_valid_serializable(instance) is False
    expected_log_calls = [
        mocker.call("SerializableT: Method to_dict is missing."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 1


def test_is_valid_serializable_false_incorrect_signature(mocker: object) -> None:
    """Test is_valid_serializable with an object having methods with incorrect signatures."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    class InvalidSerializableSignature:  # Does NOT inherit SerializableT
        def to_dict(self, extra_arg: int) -> dict[str, object]:
            return {"key": extra_arg}

        @classmethod
        def from_dict(cls, data: dict[str, object], extra_arg: int) -> "InvalidSerializableSignature":
            return cls()

    instance = InvalidSerializableSignature()
    assert is_valid_serializable(instance) is False
    expected_log_calls = [
        mocker.call("SerializableT: to_dict signature incorrect. Expected 0 params, got 1."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 1

# 🐍🔌📞🔚
