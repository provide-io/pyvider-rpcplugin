#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""go-plugin's Ping() checks the health service named exactly "plugin".

`go-plugin/grpc_server.go:26` declares `GRPCServiceName = "plugin"` and marks
that name SERVING (`grpc_server.go:78-83`); `go-plugin/grpc_client.go:127-134`
is the only caller, and it asks for that name and nothing else. A health
service registered under any other name answers NOT_FOUND.
"""

from __future__ import annotations

import sys

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
import pytest

from tests.goplugin import harness

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the harness serves over a Unix socket",
)

#: go-plugin/grpc_server.go:26
GO_PLUGIN_HEALTH_SERVICE = "plugin"


def _check(target: str, service: str) -> str:
    with grpc.insecure_channel(target) as channel:
        stub = health_pb2_grpc.HealthStub(channel)
        try:
            reply = stub.Check(health_pb2.HealthCheckRequest(service=service), timeout=10)
        except grpc.RpcError as exc:
            return exc.code().name
        return health_pb2.HealthCheckResponse.ServingStatus.Name(reply.status)


def test_health_service_answers_to_plugin() -> None:
    """What go-plugin's Ping() asks for must be what the plugin serves."""
    with harness.spawn() as plugin:
        target = f"unix:{plugin.read_handshake().split('|')[3]}"

        assert _check(target, GO_PLUGIN_HEALTH_SERVICE) == "SERVING"


def test_health_service_still_answers_the_plugins_own_service() -> None:
    """The registered service name keeps working alongside it."""
    with harness.spawn(args=["--service-name", "tfplugin6.Provider"]) as plugin:
        target = f"unix:{plugin.read_handshake().split('|')[3]}"

        assert _check(target, "tfplugin6.Provider") == "SERVING"
        assert _check(target, "") == "SERVING"
