import asyncio
import grpc
import logging

from . import service_a_pb2, service_a_pb2_grpc
from . import service_b_pb2, service_b_pb2_grpc
from . import service_c_pb2, service_c_pb2_grpc
from . import external_mock_service_pb2, external_mock_service_pb2_grpc

from .fault_injector import inject_fault_async, FaultType, fault_configs # Allow direct access for modification

from pyvider.rpcplugin.client import SecureRpcClient # For broker
from pyvider.rpcplugin.broker import GRPCBroker # For broker
from pyvider.rpcplugin.server import PluginServer # For getting broker

logger = logging.getLogger(__name__)

# --- Retry Configuration ---
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 0.5

# --- Servicer Implementations ---

class ServiceCImpl(service_c_pb2_grpc.ServiceCServicer):
    async def ProcessDataC(self, request: service_c_pb2.RequestC, context: grpc.aio.ServicerContext) -> service_c_pb2.ResponseC:
        logger.info(f"[ServiceC] Received ProcessDataC request with: {request.input_data_from_B}")
        await inject_fault_async("ServiceC_Processing") # Fault point within C's processing

        processed_data = f"ServiceC processed ({request.input_data_from_B})"
        logger.info(f"[ServiceC] Sending response: {processed_data}")
        return service_c_pb2.ResponseC(processed_data_C=processed_data)

class ServiceBImpl(service_b_pb2_grpc.ServiceBServicer):
    def __init__(self, plugin_server: PluginServer):
        self.plugin_server = plugin_server
        # Internal client for ServiceC (assuming ServiceC is hosted on the same server)
        # This requires the server to be running and ServiceC registered.
        # A common pattern is to pass the channel or create it on first use.
        # For simplicity, we'll assume direct servicer calls if on same server,
        # or use the server's own channel if they were separate sub-plugins.
        # For this example, let's use the server's internal gRPC machinery if possible,
        # or make a new channel to itself if needed.

        # To make an internal call to ServiceC, we need a stub.
        # This stub would typically connect to where ServiceC is hosted.
        # If ServiceC is on the same gRPC server instance:
        # One way is to get the server's address from config and create a client channel to itself.
        # This simulates how microservices might call each other even if co-hosted.

        # Placeholder for ServiceC stub - will be initialized properly
        self._service_c_stub: Optional[service_c_pb2_grpc.ServiceCStub] = None

    async def _get_service_c_stub(self) -> service_c_pb2_grpc.ServiceCStub:
        if self._service_c_stub is None:
            # Assuming Service C is running on the same server instance.
            # We need the server's address. This is a bit circular if not careful.
            # For this example, let's assume the PluginServer has a way to give its own secure channel
            # or we use the configured host address.
            # For now, this is a simplified approach. A real plugin might get this from config
            # or a service discovery mechanism.
            # This example will rely on the main plugin_main.py to provide the channel.
            if hasattr(self.plugin_server, "_internal_channel_for_services"):
                channel = self.plugin_server._internal_channel_for_services
                if channel:
                    self._service_c_stub = service_c_pb2_grpc.ServiceCStub(channel)
                else:
                    # Fallback: create a new channel to self if not provided.
                    # This requires server to be fully up and listening.
                    # This is less ideal for internal calls usually.
                    server_address = self.plugin_server.config.plugin_host_address()
                    # TODO: Need proper credentials for internal mTLS call if server is mTLS
                    # For now, assuming insecure for this specific internal call path if not handled by PluginServer
                    # This part is complex for a generic example.
                    logger.warning("[ServiceB] Creating a new channel to self for ServiceC. This might be insecure or misconfigured for mTLS.")
                    # This is a simplification. In mTLS, this channel would need client certs trusted by the server.
                    # A better approach is for PluginServer to provide a pre-configured internal channel.
                    # For now, this will likely fail if the main server is mTLS and these certs aren't set.
                    # We will assume plugin_main.py sets up `_internal_channel_for_services` correctly.
                    if not server_address:
                         raise RuntimeError("Server address not configured, cannot create internal C stub.")
                    temp_channel = grpc.aio.secure_channel(server_address, grpc.local_channel_credentials()) # type: ignore
                    self._service_c_stub = service_c_pb2_grpc.ServiceCStub(temp_channel)

            if not self._service_c_stub:
                 raise RuntimeError("ServiceC stub not available in ServiceB. _internal_channel_for_services not set up in PluginServer.")

        return self._service_c_stub


    async def ProcessDataB(self, request: service_b_pb2.RequestB, context: grpc.aio.ServicerContext) -> service_b_pb2.ResponseB:
        logger.info(f"[ServiceB] Received ProcessDataB request with: {request.input_data_from_A}")
        await inject_fault_async("ServiceB_Processing") # Fault point within B

        response_c_data = None
        if request.trigger_internal_call_to_c:
            logger.info("[ServiceB] Triggering internal call to ServiceC...")
            service_c_stub = await self._get_service_c_stub()

            for attempt in range(MAX_RETRIES + 1):
                try:
                    await inject_fault_async("ServiceB_to_ServiceC") # Fault point before calling C
                    c_request = service_c_pb2.RequestC(input_data_from_B=request.input_data_from_A)
                    response_c_data = await service_c_stub.ProcessDataC(c_request, timeout=5.0) # Added timeout
                    logger.info(f"[ServiceB] Received from ServiceC: {response_c_data.processed_data_C}")
                    break # Success
                except grpc.aio.AioRpcError as e:
                    logger.error(f"[ServiceB] RPC error calling ServiceC (attempt {attempt+1}/{MAX_RETRIES+1}): {e.details()} (Code: {e.code()})")
                    if attempt == MAX_RETRIES or e.code() not in [grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED]:
                        # Non-retryable error or max retries reached
                        # Propagate error or handle gracefully
                        # For simplicity, we'll let the error propagate to ServiceA if all retries fail
                        # Or, return a partial success from B. Here, we'll just log and data_from_C will be None.
                        response_c_data = service_c_pb2.ResponseC(processed_data_C=f"Error calling ServiceC: {e.details()}")
                        break
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                except Exception as e: # Catch other errors like fault injection
                    logger.error(f"[ServiceB] Non-RPC error during ServiceC call (attempt {attempt+1}): {e}")
                    if attempt == MAX_RETRIES:
                        response_c_data = service_c_pb2.ResponseC(processed_data_C=f"Internal error calling ServiceC: {e}")
                        break
                    await asyncio.sleep(RETRY_DELAY_SECONDS)

        processed_data = f"ServiceB processed ({request.input_data_from_A})"
        logger.info(f"[ServiceB] Sending response: {processed_data}")

        # Ensure response_c_data is not None if the call was attempted
        if request.trigger_internal_call_to_c and response_c_data is None:
            response_c_data = service_c_pb2.ResponseC(processed_data_C="ServiceC call was triggered but resulted in no data (possibly max retries exceeded).")

        return service_b_pb2.ResponseB(
            processed_data_B=processed_data,
            data_from_C=response_c_data if response_c_data else None # Ensure it's None if not set
        )


class ServiceAImpl(service_a_pb2_grpc.ServiceAServicer):
    def __init__(self, plugin_server: PluginServer):
        self.plugin_server = plugin_server
        # Internal client for ServiceB
        self._service_b_stub: Optional[service_b_pb2_grpc.ServiceBStub] = None
        # Broker client for ExternalMockService
        self._external_service_stub: Optional[external_mock_service_pb2_grpc.ExternalMockServiceStub] = None

    async def _get_service_b_stub(self) -> service_b_pb2_grpc.ServiceBStub:
        if self._service_b_stub is None:
            # Similar to ServiceB's C stub, this needs proper channel setup.
            # Relying on plugin_main.py to set up `_internal_channel_for_services`.
            if hasattr(self.plugin_server, "_internal_channel_for_services"):
                channel = self.plugin_server._internal_channel_for_services
                if channel:
                    self._service_b_stub = service_b_pb2_grpc.ServiceBStub(channel)
                else:
                    raise RuntimeError("ServiceB stub not available in ServiceA. _internal_channel_for_services not set up in PluginServer or is None.")
            else:
                 raise RuntimeError("ServiceB stub not available in ServiceA. _internal_channel_for_services not set up in PluginServer.")
        return self._service_b_stub

    async def _get_external_service_stub(self) -> external_mock_service_pb2_grpc.ExternalMockServiceStub:
        if self._external_service_stub is None:
            broker: Optional[GRPCBroker] = self.plugin_server.broker_singleton
            if not broker:
                raise RuntimeError("GRPCBroker not available in PluginServer.")

            # The subchannel_name must match what the other side (client_app.py in this example)
            # uses when it calls `broker.start_serving_subchannel`.
            subchannel_name = "ExternalMockServiceChannel"
            logger.info(f"[ServiceA] Opening broker subchannel: {subchannel_name}")

            try:
                # Note: open_subchannel is synchronous in the current rpcplugin,
                # but it returns a gRPC channel that can be used with an async stub.
                # If open_subchannel becomes async, this would need 'await'.
                # The channel returned by broker is an aio.Channel
                external_channel = broker.open_subchannel(
                    stub_class=external_mock_service_pb2_grpc.ExternalMockServiceStub,
                    subchannel_name=subchannel_name,
                    # Assuming client_app.py will serve this.
                    # No specific client_cert or server_ca needed here if broker handles mTLS at plugin boundary.
                )
                if not external_channel:
                    raise RuntimeError(f"Failed to open broker subchannel '{subchannel_name}'.")
                self._external_service_stub = external_mock_service_pb2_grpc.ExternalMockServiceStub(external_channel)
                logger.info(f"[ServiceA] Successfully opened broker subchannel '{subchannel_name}' and created ExternalMockServiceStub.")
            except Exception as e:
                logger.error(f"[ServiceA] Error opening broker subchannel '{subchannel_name}': {e}")
                raise RuntimeError(f"Failed to get external service stub via broker: {e}") from e

        return self._external_service_stub

    async def ProcessDataA(self, request: service_a_pb2.RequestA, context: grpc.aio.ServicerContext) -> service_a_pb2.ResponseA:
        logger.info(f"[ServiceA] Received ProcessDataA request with: {request.input_data}")
        await inject_fault_async("ServiceA_Processing")

        response_from_b_str = "N/A"
        response_from_external_str = "N/A"

        # Call ServiceB
        if request.trigger_internal_call_to_b:
            logger.info("[ServiceA] Triggering internal call to ServiceB...")
            service_b_stub = await self._get_service_b_stub()
            b_response_data = None
            for attempt in range(MAX_RETRIES + 1):
                try:
                    await inject_fault_async("ServiceA_to_ServiceB")
                    b_request = service_b_pb2.RequestB(
                        input_data_from_A=request.input_data,
                        trigger_internal_call_to_c=True # Example: always try to call C from B
                    )
                    b_response = await service_b_stub.ProcessDataB(b_request, timeout=10.0) # Increased timeout for B->C chain
                    logger.info(f"[ServiceA] Received from ServiceB: {b_response.processed_data_B}, From C (via B): {b_response.data_from_C.processed_data_C if b_response.data_from_C else 'N/A'}")
                    response_from_b_str = f"{b_response.processed_data_B} (and from C: {b_response.data_from_C.processed_data_C if b_response.data_from_C else 'N/A'})"
                    break # Success
                except grpc.aio.AioRpcError as e:
                    logger.error(f"[ServiceA] RPC error calling ServiceB (attempt {attempt+1}): {e.details()} (Code: {e.code()})")
                    if attempt == MAX_RETRIES or e.code() not in [grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED]:
                        response_from_b_str = f"Error calling ServiceB: {e.details()}"
                        break
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                except Exception as e: # Catch other errors
                    logger.error(f"[ServiceA] Non-RPC error during ServiceB call (attempt {attempt+1}): {e}")
                    if attempt == MAX_RETRIES:
                        response_from_b_str = f"Internal error calling ServiceB: {e}"
                        break
                    await asyncio.sleep(RETRY_DELAY_SECONDS)

        # Call ExternalMockService via Broker
        if request.trigger_broker_call_to_external:
            logger.info("[ServiceA] Triggering broker call to ExternalMockService...")
            try:
                external_stub = await self._get_external_service_stub()

                for attempt in range(MAX_RETRIES + 1):
                    try:
                        await inject_fault_async("ServiceA_to_ExternalBroker")
                        ext_request = external_mock_service_pb2.ExternalRequest(data_from_A_via_broker=request.input_data)
                        # Simple unary call for now
                        ext_response = await external_stub.ProcessExternalData(ext_request, timeout=5.0)
                        logger.info(f"[ServiceA] Received from ExternalMockService (via broker): {ext_response.processed_external_data}")
                        response_from_external_str = ext_response.processed_external_data
                        break # Success
                    except grpc.aio.AioRpcError as e:
                        logger.error(f"[ServiceA] RPC error calling ExternalService via broker (attempt {attempt+1}): {e.details()} (Code: {e.code()})")
                        if attempt == MAX_RETRIES or e.code() not in [grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED]:
                            response_from_external_str = f"Error calling ExternalService: {e.details()}"
                            break
                        # Important: If subchannel is broken, may need to re-open it.
                        # Current broker logic might handle this, or stub becomes invalid.
                        # For simplicity, just retrying the call. A robust client might reset _external_service_stub = None here.
                        if e.code() == grpc.StatusCode.UNAVAILABLE: # Example: subchannel might be dead
                            logger.warning("[ServiceA] External service unavailable, broker subchannel might need reset.")
                            self._external_service_stub = None # Force re-creation on next attempt/call
                        await asyncio.sleep(RETRY_DELAY_SECONDS)
                    except Exception as e:
                        logger.error(f"[ServiceA] Non-RPC error during ExternalService call via broker (attempt {attempt+1}): {e}")
                        if attempt == MAX_RETRIES:
                            response_from_external_str = f"Internal error calling ExternalService: {e}"
                            break
                        await asyncio.sleep(RETRY_DELAY_SECONDS)
            except RuntimeError as e: # Catch errors from _get_external_service_stub
                logger.error(f"[ServiceA] Failed to get external service stub: {e}")
                response_from_external_str = f"Failed to connect to ExternalService: {e}"


        processed_data_A = f"ServiceA processed ({request.input_data})"
        logger.info(f"[ServiceA] Sending final response for input: {request.input_data}")
        return service_a_pb2.ResponseA(
            processed_data_A=processed_data_A,
            data_from_B=response_from_b_str,
            data_from_external=response_from_external_str
        )

# Helper function to add servicers to a gRPC server
def add_all_servicers(server: grpc.aio.Server, plugin_server_instance: PluginServer):
    """
    Adds all defined servicers to the gRPC server.
    plugin_server_instance is the main PluginServer, used here to pass to servicers
    if they need access to broker or config.
    """
    service_a_pb2_grpc.add_ServiceAServicer_to_server(ServiceAImpl(plugin_server_instance), server)
    service_b_pb2_grpc.add_ServiceBServicer_to_server(ServiceBImpl(plugin_server_instance), server)
    service_c_pb2_grpc.add_ServiceCServicer_to_server(ServiceCImpl(), server) # ServiceC is simple
    logger.info("ServiceA, ServiceB, and ServiceC servicers added to gRPC server.")

def configure_example_faults():
    """ Pre-configure some fault scenarios for demonstration. """
    logger.info("Configuring example fault injection scenarios...")
    # Make calls to ServiceB sometimes slow
    fault_injector.configure_fault("ServiceA_to_ServiceB", FaultType.DELAY, probability=0.3, delay_seconds=1.0)
    # Make calls to ServiceC sometimes fail with RPC error
    fault_injector.configure_fault("ServiceB_to_ServiceC", FaultType.ERROR_RPC, probability=0.2, error_message="Simulated network issue calling ServiceC")
    # Make calls to ExternalBroker sometimes fail internally before even trying
    fault_injector.configure_fault("ServiceA_to_ExternalBroker", FaultType.ERROR_INTERNAL, probability=0.1, error_message="Broker client internal error")
    # Make ExternalService processing itself sometimes slow
    fault_injector.configure_fault("ExternalService_Processing", FaultType.DELAY, probability=0.2, delay_seconds=0.7)
    logger.info("Example fault scenarios configured.")

if __name__ == '__main__':
    # This part is for basic testing of servicers if run directly, not via plugin_main.
    # It won't have full broker/plugin context.
    logging.basicConfig(level=logging.INFO)
    logger.info("services_impl.py run directly - this is for basic checks only.")

    # To do a meaningful test, you'd need to mock PluginServer and channels.
    # For example:
    # class MockPluginServer:
    #     def __init__(self):
    #         self.broker_singleton = None # Mock broker if needed
    #         self.config = lambda: None # Mock config
    #         # ... other attributes servicers might expect

    # mock_plugin_server = MockPluginServer()
    # service_a = ServiceAImpl(mock_plugin_server)
    # service_b = ServiceBImpl(mock_plugin_server)
    # service_c = ServiceCImpl()

    # loop = asyncio.get_event_loop()
    # async def test_call():
    #    req_a = service_a_pb2.RequestA(input_data="direct_test", trigger_internal_call_to_b=False, trigger_broker_call_to_external=False)
    #    # res_a = await service_a.ProcessDataA(req_a, None) # Context would be None
    #    # print(res_a)
    # loop.run_until_complete(test_call())
    print("Run plugin_main.py to test the full multi-service plugin.")
