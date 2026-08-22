#
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""The server must carry messages as large as its client will send.

gRPC defaults both message limits to 4 MB. Terraform's limit is 256 MB
(`grpcMaxMessageSize` in `internal/plugin6`) and it will send more than 4 MB in
ordinary use: a resource whose configuration holds a large attribute, or a
state-store write chunk, which it sizes from the 8 MB default it proposes
during chunk-size negotiation.

Leaving the gRPC default in place makes the server refuse those before a
handler is reached, and the caller sees only:

    rpc error: code = ResourceExhausted
    SERVER: Received message larger than max (6291555 vs. 4194304)
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from pyvider.rpcplugin.server.network import GRPC_MAX_MESSAGE_SIZE

#: `grpcMaxMessageSize` in terraform/internal/plugin6/grpc_provider.go.
TERRAFORM_MAX_MESSAGE_SIZE = 256 << 20

#: What gRPC uses when nothing is passed, and what this exists to displace.
GRPC_DEFAULT_MAX_MESSAGE_SIZE = 4 << 20

#: `chunks.DefaultStateStoreChunkSize` -- the size Terraform proposes, and so
#: the size of a write chunk the server has to be able to receive.
STATE_STORE_DEFAULT_CHUNK_SIZE = 8 << 20


class TestMessageSizeConstant:
    def test_it_matches_terraforms_limit(self) -> None:
        assert GRPC_MAX_MESSAGE_SIZE == TERRAFORM_MAX_MESSAGE_SIZE

    def test_it_clears_a_default_state_store_chunk(self) -> None:
        """A single write chunk must fit, with room for the envelope around it."""
        assert GRPC_MAX_MESSAGE_SIZE > STATE_STORE_DEFAULT_CHUNK_SIZE

    def test_it_is_not_the_grpc_default(self) -> None:
        assert GRPC_MAX_MESSAGE_SIZE > GRPC_DEFAULT_MAX_MESSAGE_SIZE


class TestServerConstruction:
    @pytest.mark.asyncio
    async def test_both_limits_are_passed_to_the_server(self) -> None:
        """Send matters as much as receive: ReadStateBytes streams outbound."""
        from pyvider.rpcplugin.server import network

        captured: dict[str, object] = {}

        def _capture(*args: object, **kwargs: object) -> object:
            captured.update(kwargs)
            raise _Stop

        class _Stop(Exception):
            pass

        with patch.object(network, "GRPCServer", _capture):
            server = network.ServerNetworkMixin.__new__(network.ServerNetworkMixin)
            server._rate_limiter = None
            with pytest.raises(_Stop):
                await server._initialize_server_with_services()

        options = dict(captured.get("options") or [])
        assert options.get("grpc.max_receive_message_length") == GRPC_MAX_MESSAGE_SIZE
        assert options.get("grpc.max_send_message_length") == GRPC_MAX_MESSAGE_SIZE


# 🐍📡🔚
