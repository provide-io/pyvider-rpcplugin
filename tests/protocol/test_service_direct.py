
# tests/protocol/test_service_direct.py

import asyncio
import signal
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo

# MockIterator removed as its only user (test_broker_start_stream_exception_line95) is removed.

# test_controller_delayed_shutdown_unix_path removed, covered by test_service.py::test_controller_delayed_shutdown_signal_handlers
# test_controller_delayed_shutdown_windows_path removed, covered by test_service.py::test_controller_delayed_shutdown_signal_handlers

### 🐍🏗🧪️
