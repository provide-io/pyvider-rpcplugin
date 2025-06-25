import random
import asyncio
import logging
from enum import Enum, auto

logger = logging.getLogger(__name__)

class FaultType(Enum):
    NONE = auto()
    DELAY = auto()
    ERROR_RPC = auto()
    ERROR_INTERNAL = auto()

class FaultConfig:
    def __init__(self, fault_type: FaultType = FaultType.NONE, probability: float = 0.0, delay_seconds: float = 0.0, error_message: str = "Simulated fault"):
        self.fault_type = fault_type
        self.probability = probability # 0.0 to 1.0
        self.delay_seconds = delay_seconds
        self.error_message = error_message

    def should_inject(self) -> bool:
        return random.random() < self.probability

# Global fault configurations for different services/points
fault_configs = {
    "ServiceA_to_ServiceB": FaultConfig(),
    "ServiceB_to_ServiceC": FaultConfig(),
    "ServiceA_to_ExternalBroker": FaultConfig(),
    "ExternalService_Processing": FaultConfig(fault_type=FaultType.DELAY, probability=0.1, delay_seconds=0.5), # Example default
}

def configure_fault(point_name: str, fault_type: FaultType, probability: float, delay_seconds: float = 0, error_message: str = "Simulated fault"):
    if point_name not in fault_configs:
        logger.warning(f"Fault point '{point_name}' not recognized. Adding new config.")
    fault_configs[point_name] = FaultConfig(fault_type, probability, delay_seconds, error_message)
    logger.info(f"Fault configured for '{point_name}': Type={fault_type.name}, Prob={probability}, Delay={delay_seconds}s")

async def inject_fault_async(point_name: str):
    """
    Injects a fault if configured for the given point.
    Raises an exception for ERROR types, or introduces delay.
    To be used with `await inject_fault_async(...)` in async functions.
    """
    if point_name in fault_configs:
        config = fault_configs[point_name]
        if config.should_inject():
            logger.warning(f"Injecting fault at '{point_name}': Type={config.fault_type.name}")
            if config.fault_type == FaultType.DELAY:
                await asyncio.sleep(config.delay_seconds)
                logger.info(f"Injected delay of {config.delay_seconds}s at '{point_name}' completed.")
            elif config.fault_type == FaultType.ERROR_RPC:
                # This would typically be converted to a grpc.RpcError by the calling service
                raise RuntimeError(f"Simulated RPC Fault: {config.error_message} at {point_name}")
            elif config.fault_type == FaultType.ERROR_INTERNAL:
                raise Exception(f"Simulated Internal Fault: {config.error_message} at {point_name}")
            # FaultType.NONE or unrecognized type will do nothing after logging.
    # No fault injected or point not configured
    pass

def inject_fault_sync(point_name: str):
    """
    Synchronous version of fault injection.
    Raises an exception for ERROR types, or introduces delay.
    """
    if point_name in fault_configs:
        config = fault_configs[point_name]
        if config.should_inject():
            logger.warning(f"Injecting fault at '{point_name}': Type={config.fault_type.name}")
            if config.fault_type == FaultType.DELAY:
                import time
                time.sleep(config.delay_seconds)
                logger.info(f"Injected delay of {config.delay_seconds}s at '{point_name}' completed.")
            elif config.fault_type == FaultType.ERROR_RPC:
                raise RuntimeError(f"Simulated RPC Fault: {config.error_message} at {point_name}")
            elif config.fault_type == FaultType.ERROR_INTERNAL:
                raise Exception(f"Simulated Internal Fault: {config.error_message} at {point_name}")
    pass

# Example of how to use it:
#
# In an async service method:
#   await inject_fault_async("ServiceA_to_ServiceB")
#   # proceed with call to ServiceB
#
# In a sync method (less common in async gRPC services but possible):
#   inject_fault_sync("Some_Sync_Point")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    # Example configuration
    configure_fault("ServiceA_to_ServiceB", FaultType.DELAY, 0.5, delay_seconds=1.5)
    configure_fault("ServiceB_to_ServiceC", FaultType.ERROR_RPC, 0.3, error_message="Failed to call ServiceC")

    async def test_async_faults():
        print("\nTesting async faults:")
        for i in range(5):
            print(f"Attempt {i+1}:")
            try:
                await inject_fault_async("ServiceA_to_ServiceB")
                print("  ServiceA_to_ServiceB: No fault or non-blocking fault.")
            except Exception as e:
                print(f"  ServiceA_to_ServiceB: Caught error: {e}")

            try:
                await inject_fault_async("ServiceB_to_ServiceC")
                print("  ServiceB_to_ServiceC: No fault or non-blocking fault.")
            except Exception as e:
                print(f"  ServiceB_to_ServiceC: Caught error: {e}")
            print("-" * 20)

    asyncio.run(test_async_faults())

    # Synchronous test (conceptual)
    print("\nTesting sync faults (conceptual):")
    # configure_fault("MySyncOperation", FaultType.ERROR_INTERNAL, 1.0) # Guaranteed error
    # try:
    #     inject_fault_sync("MySyncOperation")
    # except Exception as e:
    #     print(f"Caught sync error: {e}")
    print("Fault injector demonstration complete.")
