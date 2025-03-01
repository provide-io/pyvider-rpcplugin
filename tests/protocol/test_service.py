
# tests/protocol/test_service.py

import asyncio
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import grpc

from pyvider.rpcplugin.protocol.service import (
    BrokerError,
    SubchannelConnection, 
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from google.protobuf.empty_pb2 import Empty

@pytest.fixture
def subchannel():
    """Fixture providing a SubchannelConnection instance."""
    return SubchannelConnection(conn_id=1, address="localhost:12345")

@pytest.mark.asyncio
async def test_subchannel_open(subchannel):
    """Test opening a subchannel connection."""
    assert not subchannel.is_open
    await subchannel.open()
    assert subchannel.is_open

@pytest.mark.asyncio
async def test_subchannel_close(subchannel):
    """Test closing a subchannel connection."""
    await subchannel.open()
    assert subchannel.is_open
    await subchannel.close()
    assert not subchannel.is_open
