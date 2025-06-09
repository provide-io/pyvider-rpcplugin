
# tests/protocol/test_service_improvements.py

import asyncio
import pytest
import signal
from unittest.mock import MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo

# test_stdio_put_line_exception_handling removed as it's covered by test_service.py::test_stdio_put_line_error
# test_broker_service_start_stream_error_handling removed as it's covered by tests in test_service.py

# test_controller_delayed_shutdown_unix removed, covered by test_service.py::test_controller_delayed_shutdown_signal_handlers
# test_controller_delayed_shutdown_windows removed, covered by test_service.py::test_controller_delayed_shutdown_signal_handlers

### 🐍🏗🧪️
