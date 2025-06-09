import sys # Added sys
import os # os was already here, ensure it's at the top with sys

# Add the project root to sys.path to allow 'from tests.fixtures import *'
# This ensures that 'tests' package can be found from the project root.
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# tests/conftest.py

import pytest
# import os # Moved to top
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
