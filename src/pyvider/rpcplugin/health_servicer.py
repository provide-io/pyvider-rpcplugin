#
# src/pyvider/rpcplugin/health_servicer.py
#

"""
gRPC Health Checking Servicer Implementation.

This module provides a `HealthServicer` class that implements the standard
gRPC Health Checking Protocol, allowing clients to query the health status
of the plugin server or specific services within it.
"""

from collections.abc import AsyncIterator, Callable

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

from pyvider.telemetry import logger


class HealthServicer(health_pb2_grpc.HealthServicer):
    """
    Implements the standard gRPC Health Checking Protocol.
    """

    def __init__(
        self, app_is_healthy_callable: Callable[[], bool], service_name: str = ""
    ) -> None:
        """
        Args:
            app_is_healthy_callable: A callable that returns True if the main
                                     application is healthy, False otherwise.
            service_name: The name of the primary service this health checker
                          monitors. An empty string means it reports the
                          overall server status.
        """
        self._app_is_healthy_callable = app_is_healthy_callable
        self._service_name = service_name
        logger.debug(
            f"❤️⚕️ HealthServicer initialized for service '{service_name}'. "
            f"Main app health check: {app_is_healthy_callable()}"
        )

    async def Check(
        self, request: health_pb2.HealthCheckRequest, context: grpc.aio.ServicerContext
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
                logger.debug(
                    f"❤️⚕️ Reporting SERVING for "
                    f"'{requested_service or 'overall server'}'"
                )
                return health_pb2.HealthCheckResponse(
                    status=health_pb2.HealthCheckResponse.SERVING
                )
            else:
                logger.warning(
                    f"❤️⚕️ Reporting NOT_SERVING for "
                    f"'{requested_service or 'overall server'}' as app is unhealthy."
                )
                return health_pb2.HealthCheckResponse(
                    status=health_pb2.HealthCheckResponse.NOT_SERVING
                )
        else:
            logger.info(
                f"❤️⚕️ Service '{requested_service}' not found by this health checker. "
                f"Monitored: '{self._service_name}'."
            )
            await context.abort(
                grpc.StatusCode.NOT_FOUND, f"Service '{requested_service}' not found."
            )
            # This line is technically unreachable due to abort, but linters/type
            # checkers might expect a return.
            return health_pb2.HealthCheckResponse(
                status=health_pb2.HealthCheckResponse.SERVICE_UNKNOWN
            )

    async def Watch(
        self, request: health_pb2.HealthCheckRequest, context: grpc.aio.ServicerContext
    ) -> AsyncIterator[health_pb2.HealthCheckResponse]:
        """
        Streams health status updates. This is not implemented in this basic version.
        """
        requested_service = request.service
        logger.info(
            f"❤️⚕️ Watch requested for service: '{requested_service}'. Monitored: "
            f"'{self._service_name}'. Watch is not implemented."
        )
        await context.abort(
            grpc.StatusCode.UNIMPLEMENTED, "Watch streaming is not implemented."
        )
        # This part is unreachable due to abort but makes type checkers happy
        # if they expect a yield for an AsyncIterator.
        if False:  # pylint: disable=using-constant-test
            yield health_pb2.HealthCheckResponse()  # type: ignore[misc]


# 🐍🏗️🔌
