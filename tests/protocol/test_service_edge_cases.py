
# tests/protocol/test_service_edge_cases.py

import asyncio
import pytest
from unittest.mock import MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCStdioService,
    GRPCBrokerService,
    SubchannelConnection,
    BrokerError,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from google.protobuf.empty_pb2 import Empty

# test_stdio_service_timeouts moved to test_service.py
# test_stdio_service_backpressure moved to test_service.py

from unittest.mock import AsyncMock # Ensure this is imported

### 🐍🏗🧪️
