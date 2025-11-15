# tests/conftest.py
import sys
import os
import pytest
from pyvider.rpcplugin.config import RPCPluginConfig, CONFIG_SCHEMA
from tests.fixtures import *

@pytest.fixture(autouse=True, scope="function")
def reset_rpcplugin_config_singleton():
    """
    Fixture to reset the RPCPluginConfig singleton and relevant env vars before each test.
    This ensures complete test isolation with respect to configuration.
    """
    # Force the singleton to be cleared
    RPCPluginConfig._instance = None

    # Backup and clear all environment variables defined in the schema
    env_keys_to_clear = list(CONFIG_SCHEMA.keys())
    original_env_values = {key: os.environ.get(key) for key in env_keys_to_clear}

    for key in env_keys_to_clear:
        if key in os.environ:
            del os.environ[key]

    # The test runs now in a pristine environment. The first call to
    # RPCPluginConfig.instance() in the test will create a fresh instance.
    yield

    # Teardown: Restore original environment variables
    for key, value in original_env_values.items():
        if value is not None:
            os.environ[key] = value
        elif key in os.environ:
            del os.environ[key]
    
    # Final reset to ensure no state leaks to subsequent test modules
    RPCPluginConfig._instance = None
