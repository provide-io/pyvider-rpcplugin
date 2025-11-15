#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""gRPC Health Checking Servicer Implementation.

This module provides a `HealthServicer` class that implements the standard
gRPC Health Checking Protocol, allowing clients to query the health status
of the plugin server or specific services within it."""

from collections.abc import AsyncIterator, Callable

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
from provide.foundation.logger import get_logger

logger = get_logger(__name__)


class HealthServicer(health_pb2_grpc.HealthServicer):
    """
    gRPC Health Checking Protocol implementation for plugin servers.

    This servicer implements the standard gRPC Health Checking Protocol
    (https://github.com/grpc/grpc/blob/master/doc/health-checking.md),
    allowing clients to query the health status of the plugin server and
    its services.

    The health checker supports:
    - Overall server health status (when service name is empty)
    - Service-specific health checks
    - Customizable health determination via callable
    - Standard gRPC health status responses (SERVING, NOT_SERVING, SERVICE_UNKNOWN)

    Example:
        ```python
        from pyvider.rpcplugin.health_servicer import HealthServicer

        class MyServer:
            def __init__(self):
                self.is_healthy = True

            def check_health(self) -> bool:
                # Custom health check logic
                return self.is_healthy and self.database_connected()

        server = MyServer()
        health_servicer = HealthServicer(
            app_is_healthy_callable=server.check_health,
            service_name="my.plugin.Service"
        )

        # Add to gRPC server
        grpc_health.v1.health_pb2_grpc.add_HealthServicer_to_server(
            health_servicer, grpc_server
        )
        ```

    Note:
        The Watch method for streaming health updates is not currently
        implemented. Clients should use periodic Check calls instead.
    """

    def __init__(self, app_is_healthy_callable: Callable[[], bool], service_name: str = "") -> None:
        """
        Initialize the health servicer with health check logic.

        Args:
            app_is_healthy_callable: A callable that returns True if the
                                   application/service is healthy, False otherwise.
                                   This callable is invoked on each health check
                                   request, allowing dynamic health determination.
            service_name: The name of the service this health checker monitors.
                         An empty string (default) indicates overall server health.
                         Use fully qualified service names for clarity
                         (e.g., "myapp.v1.DataService").

        Example:
            ```python
            # Simple health check
            health_servicer = HealthServicer(
                app_is_healthy_callable=lambda: True,
                service_name=""  # Overall server health
            )

            # Complex health check
            def check_dependencies():
                return (
                    database.is_connected() and
                    cache.is_available() and
                    not rate_limiter.is_overloaded()
                )

            health_servicer = HealthServicer(
                app_is_healthy_callable=check_dependencies,
                service_name="api.v1.UserService"
            )
            ```
        """
        self._app_is_healthy_callable = app_is_healthy_callable
        self._service_name = service_name
        logger.debug(
            f"❤️⚕️ HealthServicer initialized for service '{service_name}'. "
            f"Main app health check: {app_is_healthy_callable()}"
        )

    async def Check(  # type: ignore[override]  # pyre-ignore[14]
        self,
        request: health_pb2.HealthCheckRequest,
        context: grpc.aio.ServicerContext[health_pb2.HealthCheckRequest, health_pb2.HealthCheckResponse],
    ) -> health_pb2.HealthCheckResponse:
        """
        Checks the health of the server or a specific service.
        """
        requested_service = request.service
        logger.debug(
            f"❤️⚕️ Health Check requested for service: '{requested_service}'. "
            f"Monitored service: '{self._service_name}'"
        )

        if not requested_service or requested_service == self._service_name:
            if self._app_is_healthy_callable():
                logger.debug(f"❤️⚕️ Reporting SERVING for '{requested_service or 'overall server'}'")
                return health_pb2.HealthCheckResponse(status=health_pb2.HealthCheckResponse.SERVING)
            else:
                logger.warning(
                    f"❤️⚕️ Reporting NOT_SERVING for "
                    f"'{requested_service or 'overall server'}' as app is unhealthy."
                )
                return health_pb2.HealthCheckResponse(status=health_pb2.HealthCheckResponse.NOT_SERVING)
        else:
            logger.info(
                f"❤️⚕️ Service '{requested_service}' not found by this health checker. "
                f"Monitored: '{self._service_name}'."
            )
            await context.abort(grpc.StatusCode.NOT_FOUND, f"Service '{requested_service}' not found.")
            # This line is technically unreachable due to abort, but linters/type
            # checkers might expect a return.
            return health_pb2.HealthCheckResponse(status=health_pb2.HealthCheckResponse.SERVICE_UNKNOWN)

    async def Watch(  # type: ignore[override]  # pyre-ignore[14]
        self,
        request: health_pb2.HealthCheckRequest,
        context: grpc.aio.ServicerContext[health_pb2.HealthCheckRequest, health_pb2.HealthCheckResponse],
    ) -> AsyncIterator[health_pb2.HealthCheckResponse]:
        """
        Streams health status updates. This is not implemented in this basic version.
        """
        requested_service = request.service
        logger.info(
            f"❤️⚕️ Watch requested for service: '{requested_service}'. Monitored: "
            f"'{self._service_name}'. Watch is not implemented."
        )
        await context.abort(grpc.StatusCode.UNIMPLEMENTED, "Watch streaming is not implemented.")
        # This part is unreachable due to abort but makes type checkers happy
        # if they expect a yield for an AsyncIterator.
        if False:  # pylint: disable=using-constant-test
            yield health_pb2.HealthCheckResponse()


# 🐍🔌📞🔚
