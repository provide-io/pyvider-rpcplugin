#!/usr/bin/env python3
"""
Utility functions for pyvider-rpcplugin examples.
Provides consistent path resolution and environment setup.
"""

import os
import sys
from pathlib import Path


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

    return project_root


def configure_for_example() -> None:
    """Configure environment for example execution."""
    setup_example_environment()

    # Configure basic logging
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)-7s] %(name)s: 🐍 %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Import configure from the library
    try:
        from pyvider.rpcplugin import configure as pyvider_configure
        from pyvider.rpcplugin.config import (
            rpcplugin_config,
            CONFIG_SCHEMA,  # Import CONFIG_SCHEMA directly
        )

        # Set some safe defaults for examples if not already set by environment.
        # This helps examples run consistently without requiring extensive env setup.
        # We use specific keys to avoid accidentally overriding user-set complex configs.
        example_defaults = {
            "PLUGIN_AUTO_MTLS": False,
            "PLUGIN_MAGIC_COOKIE_KEY": "PYVIDER_PLUGIN_MAGIC_COOKIE",
            "PLUGIN_MAGIC_COOKIE_VALUE": "pyvider-example-cookie",
            "PLUGIN_LOG_LEVEL": "INFO",
            "PLUGIN_HANDSHAKE_TIMEOUT": 15.0,
            "PLUGIN_CONNECTION_TIMEOUT": 10.0,
        }

        config_to_apply_programmatically = {}
        for key, example_value in example_defaults.items():
            current_val = rpcplugin_config.get(key)
            # Use the imported CONFIG_SCHEMA
            schema_default = CONFIG_SCHEMA.get(key, {}).get("default")

            # Apply if current value is the schema default, or if key isn't in
            # schema (custom for example), or if it's a log level we want to enforce.
            if current_val == schema_default or key == "PLUGIN_LOG_LEVEL":
                config_to_apply_programmatically[key] = example_value
            elif key == "PLUGIN_AUTO_MTLS" and current_val is None:
                config_to_apply_programmatically[key] = example_value

        # Call pyvider_configure with specific keyword arguments that match its signature
        if config_to_apply_programmatically:
            # Prepare arguments for pyvider_configure, mapping PLUGIN_ prefixed keys
            # to the function's parameter names.
            mapped_args = {}
            other_kwargs = {}

            for key, value in config_to_apply_programmatically.items():
                if key == "PLUGIN_AUTO_MTLS":
                    mapped_args["auto_mtls"] = value
                elif key == "PLUGIN_MAGIC_COOKIE_VALUE":
                    mapped_args["magic_cookie"] = value # This sets both value and fallback
                elif key == "PLUGIN_HANDSHAKE_TIMEOUT":
                    mapped_args["handshake_timeout"] = value
                elif key == "PLUGIN_CONNECTION_TIMEOUT":
                    mapped_args["connection_timeout"] = value
                # Add other direct mappings if configure() signature expands
                else:
                    # Collect remaining PLUGIN_ prefixed keys for **kwargs
                    other_kwargs[key] = value

            # Only call if there's something to configure
            if mapped_args or other_kwargs:
                # Ensure types for explicitly named arguments or pass None
                mc_val = mapped_args.get("magic_cookie")
                am_val = mapped_args.get("auto_mtls")
                ht_val = mapped_args.get("handshake_timeout")
                ct_val = mapped_args.get("connection_timeout")

                # Filter other_kwargs to only include keys not explicitly handled
                # and that are actual PLUGIN_ prefixed keys from example_defaults
                # that configure() would expect in its **kwargs.
                explicitly_handled_plugin_keys = [
                    "PLUGIN_AUTO_MTLS", "PLUGIN_MAGIC_COOKIE_VALUE",
                    "PLUGIN_HANDSHAKE_TIMEOUT", "PLUGIN_CONNECTION_TIMEOUT"
                ]
                final_other_kwargs = {
                    k: v for k, v in other_kwargs.items()
                    if k not in explicitly_handled_plugin_keys and k.startswith("PLUGIN_")
                }


                # The following call to pyvider_configure might report type errors with
                # mypy due to dynamic construction of arguments.
                # In a strict mypy environment, specific # type: ignore[arg-type]
                # comments might be needed for the lines where ht_val or ct_val are used,
                # or for the **final_other_kwargs if mypy cannot resolve them.
                # For the purpose of these examples, the functional behavior is prioritized.
                pyvider_configure(
                    magic_cookie=str(mc_val) if mc_val is not None else None,
                    auto_mtls=bool(am_val) if am_val is not None else None,
                    handshake_timeout=float(ht_val) if ht_val is not None else None, # type: ignore[arg-type]
                    connection_timeout=float(ct_val) if ct_val is not None else None, # type: ignore[arg-type]
                    # protocol_version and transports are not in example_defaults currently
                    # server_cert, server_key, client_cert, client_key also not in example_defaults
                    **final_other_kwargs # type: ignore[arg-type]
                )
                # logging.info(f"Applied example default configurations. Mapped: {mapped_args}, Others: {final_other_kwargs}")

    except ImportError:
        logging.error(
            "Failed to import pyvider.rpcplugin.configure. "
            "Ensure pyvider-rpcplugin is installed and accessible."
        )
    except Exception as e:
        logging.error(f"Error applying example default configurations: {e}")


def clear_plugin_env_vars() -> None:
    """
    Clear any existing plugin environment variables that might interfere with
    examples.
    """
    plugin_vars = [k for k in os.environ.keys() if k.startswith("PLUGIN_")]
    for var in plugin_vars:
        if var in os.environ: # Check if var actually exists before deleting
            del os.environ[var]


def get_example_port(base_port: int = 50051) -> int:
    """Get an available port for examples."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", base_port))
        return s.getsockname()[1]


# 🐍🛠️
