# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


import pytest
from provide.testkit.mocking import MagicMock

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol


def test_abstract_methods_must_be_implemented() -> None:
    """Test that both abstract methods must be implemented."""

    # Trying to create a class with neither method implemented
    class EmptyProtocol(RPCPluginProtocol):
        pass

    with pytest.raises(TypeError) as excinfo:
        EmptyProtocol()  # type: ignore[abstract]

    error_message = str(excinfo.value)
    assert "Can't instantiate abstract class" in error_message
    assert "get_grpc_descriptors" in error_message
    assert "add_to_server" in error_message

    # Implementing just one method is still not enough
    class PartialProtocol(RPCPluginProtocol):
        def get_grpc_descriptors(self):
            return MagicMock(), "TestService" # type: ignore[override] # Intentionally non-async for test

    with pytest.raises(TypeError) as excinfo:
        PartialProtocol()  # type: ignore[abstract]

    error_message = str(excinfo.value)
    assert "Can't instantiate abstract class" in error_message
    assert "add_to_server" in error_message
    assert "get_grpc_descriptors" not in error_message

# 🐍🔌📞🔚
