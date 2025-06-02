
# tests/conftest.py

import pytest
import os
from pyvider.rpcplugin.config import RPCPluginConfig, CONFIG_SCHEMA

from tests.fixtures import *

@pytest.fixture(autouse=True, scope="function")
def reset_rpcplugin_config_singleton():
    '''Fixture to reset the RPCPluginConfig singleton and relevant env vars before each test.'''
    RPCPluginConfig._instance = None # Reset singleton

    # Clear relevant environment variables to ensure a clean slate for each test
    env_keys_to_clear = list(CONFIG_SCHEMA.keys())
    original_env_values = {key: os.environ.get(key) for key in env_keys_to_clear}

    for key in env_keys_to_clear:
        if key in os.environ:
            del os.environ[key]

    yield # Test runs

    # Restore original environment variables
    for key, value in original_env_values.items():
        if value is not None:
            os.environ[key] = value
        elif key in os.environ: # If it was set during test but originally None
            del os.environ[key]

################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#

### 🐍🏗🧪️
