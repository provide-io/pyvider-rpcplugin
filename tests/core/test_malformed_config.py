from pyvider.rpcplugin import configure, RPCPluginConfig
from pyvider.rpcplugin.config import load_config_from_file # rpcplugin_config is already an instance
from pyvider.telemetry import logger # Assuming logger is accessible for checking logs if needed
import os

# Get the global singleton instance for direct use if needed, or rely on RPCPluginConfig.instance()
# For consistency with how it's used in config.py, direct import might be less representative
# than RPCPluginConfig.instance() or the configure() which manipulates the global one.
# Let's use RPCPluginConfig.instance() for getting values to be sure.

def print_current_config_state(message):
    # Re-fetch the global config instance to ensure it's the latest state
    current_config_instance = RPCPluginConfig.instance()
    # Using logger.info for test output as per the prompt's style
    logger.info(f"--- {message} ---")
    logger.info(f"Magic Cookie: {current_config_instance.magic_cookie_value()}")
    logger.info(f"Auto mTLS: {current_config_instance.auto_mtls_enabled()}")
    logger.info(f"Handshake Timeout: {current_config_instance.handshake_timeout()}")
    logger.info("--------------------")

# Setup initial config (defaults)
configure() # Resets to defaults and reloads from any existing (parent) env vars
print_current_config_state("Initial default configuration")

# Store initial default values to check against later
initial_config_snapshot = {
    "magic_cookie": RPCPluginConfig.instance().magic_cookie_value(),
    "auto_mtls": RPCPluginConfig.instance().auto_mtls_enabled(),
    "handshake_timeout": RPCPluginConfig.instance().handshake_timeout()
}

# Test malformed JSON
logger.info("Attempting to load malformed_config.json...")
try:
    load_config_from_file("malformed_config.json")
    logger.error("Malformed JSON did not raise an error!", extra={"test_status": "failed"})
except ValueError as e:
    logger.info(f"Successfully caught expected ValueError for malformed JSON.", extra={"error_message": str(e), "test_status": "passed"})
except Exception as e:
    logger.error(f"Caught unexpected exception for malformed JSON: {type(e).__name__}", extra={"error_message": str(e), "test_status": "failed"})
print_current_config_state("Configuration after attempting malformed JSON")

# Test malformed YAML
logger.info("Attempting to load malformed_config.yaml...")
try:
    load_config_from_file("malformed_config.yaml")
    logger.error("Malformed YAML did not raise an error!", extra={"test_status": "failed"})
except ValueError as e:
    logger.info(f"Successfully caught expected ValueError for malformed YAML.", extra={"error_message": str(e), "test_status": "passed"})
except Exception as e:
    logger.error(f"Caught unexpected exception for malformed YAML: {type(e).__name__}", extra={"error_message": str(e), "test_status": "failed"})
print_current_config_state("Configuration after attempting malformed YAML")

# Test malformed .env
logger.info("Attempting to load malformed_config.env...")
try:
    load_config_from_file("malformed_config.env")
    # The .env loader in config.py might log errors per line but not raise a single ValueError for the whole file
    # if it can process some lines or if it's designed to be lenient.
    # Let's check if the log indicates errors during loading.
    # For this test, we expect a ValueError as per the prompt if *any* line is malformed to the point of parsing failure.
    # The current _load_dotenv_file will raise ValueError on line.split("=", 1) if no "=" is present.
    logger.error("Malformed .env did not raise an error as expected by this test design!", extra={"test_status": "failed"})
except ValueError as e:
    logger.info(f"Successfully caught expected ValueError for malformed .env.", extra={"error_message": str(e), "test_status": "passed"})
except Exception as e:
    logger.error(f"Caught unexpected exception for malformed .env: {type(e).__name__}", extra={"error_message": str(e), "test_status": "failed"})
print_current_config_state("Configuration after attempting malformed .env")

# Verify that after failed loads, the config is still the same as the initial snapshot
final_config_instance = RPCPluginConfig.instance()
if (final_config_instance.magic_cookie_value() == initial_config_snapshot["magic_cookie"] and
    final_config_instance.auto_mtls_enabled() == initial_config_snapshot["auto_mtls"] and
    final_config_instance.handshake_timeout() == initial_config_snapshot["handshake_timeout"]):
    logger.info("Config correctly remained at initial state after failed loads.", extra={"test_status": "passed"})
else:
    logger.error("Config changed from initial state after failed loads!",
                 extra={
                     "final_cookie": final_config_instance.magic_cookie_value(),
                     "initial_cookie": initial_config_snapshot["magic_cookie"],
                     "test_status": "failed"
                 })

logger.info("Finished malformed config loading tests.")
