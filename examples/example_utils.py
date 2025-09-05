#!/usr/bin/env python3
"""
Utility functions for pyvider-rpcplugin examples.
Provides consistent path resolution and environment setup.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, cast  # For DummyHandler type hint

import grpc  # For DummyHandler type hint

from pyvider.rpcplugin import configure as pyvider_configure
from pyvider.rpcplugin.config import CONFIG_SCHEMA, rpcplugin_config
from provide.foundation import logger as dummy_handler_logger


def setup_example_environment() -> Path:
    """
    Configure Python path for examples to find pyvider modules.
    Returns the project root path.
    """
    # Get project root (examples/../)
    examples_dir = Path(__file__).resolve().parent
    project_root = examples_dir.parent
    src_dir = project_root / "src"

    # Add src to Python path if it exists
    if src_dir.exists() and str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    # Also add project root for examples imports
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    # Add examples/proto to sys.path for generated protobuf files
    examples_proto_path = examples_dir / "proto"
    if examples_proto_path.is_dir() and str(examples_proto_path) not in sys.path:
        sys.path.insert(0, str(examples_proto_path))

    return project_root


def clear_plugin_env_vars() -> None:
    """
    Clear any existing plugin environment variables that might interfere with
    examples.
    """
    plugin_vars = [k for k in os.environ.keys() if k.startswith("PLUGIN_")]
    for var in plugin_vars:
        if var in os.environ:  # Check if var actually exists before deleting
            del os.environ[var]


def configure_for_example(clear_env: bool = False) -> None:
    """
    Configure environment for example execution.

    Args:
        clear_env: If True, clears existing PLUGIN_* environment variables.
                   Should typically be True for client examples that launch servers,
                   and False for server examples that expect env vars from a client.
    """
    if clear_env:
        # Clear any existing PLUGIN_* env vars to ensure examples run in a clean state
        clear_plugin_env_vars()

    setup_example_environment()

    # Configure basic logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)-7s] %(name)s: 🐍 %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        example_defaults = {
            "PLUGIN_AUTO_MTLS": False,
            "PLUGIN_MAGIC_COOKIE_KEY": "PYVIDER_PLUGIN_MAGIC_COOKIE",
            "PLUGIN_MAGIC_COOKIE_VALUE": "pyvider-example-cookie",
            "PLUGIN_LOG_LEVEL": "INFO",
            "PLUGIN_HANDSHAKE_TIMEOUT": 5.0,
            "PLUGIN_CONNECTION_TIMEOUT": 5.0,
        }

        config_to_apply_programmatically = {}
        for key, example_value in example_defaults.items():
            current_val = rpcplugin_config.get(key)
            schema_default = CONFIG_SCHEMA.get(key, {}).get("default")

            if key == "PLUGIN_AUTO_MTLS":
                if current_val is True:
                    config_to_apply_programmatically[key] = example_value
                elif current_val is None:
                    config_to_apply_programmatically[key] = example_value
            elif current_val == schema_default or key == "PLUGIN_LOG_LEVEL":
                config_to_apply_programmatically[key] = example_value

        if config_to_apply_programmatically:
            mapped_args = {}
            other_kwargs = {}

            for key, value in config_to_apply_programmatically.items():
                if key == "PLUGIN_AUTO_MTLS":
                    mapped_args["auto_mtls"] = value
                elif key == "PLUGIN_MAGIC_COOKIE_VALUE":
                    mapped_args["magic_cookie"] = value
                elif key == "PLUGIN_HANDSHAKE_TIMEOUT":
                    mapped_args["handshake_timeout"] = value
                elif key == "PLUGIN_CONNECTION_TIMEOUT":
                    mapped_args["connection_timeout"] = value
                else:
                    other_kwargs[key] = value

            if mapped_args or other_kwargs:
                mc_val = mapped_args.get("magic_cookie")
                am_val = mapped_args.get("auto_mtls")
                ht_val = cast(float | None, mapped_args.get("handshake_timeout"))
                ct_val = cast(float | None, mapped_args.get("connection_timeout"))

                explicitly_handled_plugin_keys = [
                    "PLUGIN_AUTO_MTLS",
                    "PLUGIN_MAGIC_COOKIE_VALUE",
                    "PLUGIN_HANDSHAKE_TIMEOUT",
                    "PLUGIN_CONNECTION_TIMEOUT",
                ]
                final_other_kwargs = {
                    k: v
                    for k, v in other_kwargs.items()
                    if k not in explicitly_handled_plugin_keys
                    and k.startswith("PLUGIN_")
                }

                pyvider_configure(
                    magic_cookie=str(mc_val) if mc_val is not None else None,
                    auto_mtls=bool(am_val) if am_val is not None else None,
                    handshake_timeout=ht_val,
                    connection_timeout=ct_val,
                    **final_other_kwargs,  # type: ignore[arg-type]
                )
    except ImportError:
        logging.error(
            "Failed to import pyvider.rpcplugin.configure. "
            "Ensure pyvider-rpcplugin is installed and accessible."
        )
    except Exception as e:
        logging.error(f"Error applying example default configurations: {e}")


def get_example_port(base_port: int = 50051) -> int:
    """Get an available port for examples."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", base_port))
        return s.getsockname()[1]


class DummyHandler:
    """
    A basic handler for dummy servers in examples.
    It typically doesn't implement any custom RPC methods that are called by clients,
    primarily serving to allow the server to complete its handshake and start.
    """

    async def NoOp(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        dummy_handler_logger.info(
            "DummyHandler: NoOp called (generally not expected in basic examples)"
        )
        return {}


# 🐍🛠️

# 🐍🔌📄🪄
