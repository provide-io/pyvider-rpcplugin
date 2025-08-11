# tests/conftest.py
import sys
import os
import asyncio
import pytest
from pyvider.rpcplugin.config import RPCPluginConfig, CONFIG_SCHEMA
from tests.fixtures import *


@pytest.fixture
def _function_event_loop():
    """Provide the event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    # Cleanup pending tasks
    try:
        pending = asyncio.all_tasks(loop)
    except AttributeError:
        # Python 3.9+ uses asyncio.all_tasks without loop parameter
        pending = asyncio.all_tasks()
        pending = {task for task in pending if task.get_loop() == loop}
    
    for task in pending:
        task.cancel()
    
    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    loop.close()

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


# 🐍🔌🧪🪄
