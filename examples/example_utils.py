#!/usr/bin/env python3
"""
Utility functions for pyvider-rpcplugin examples.
Provides consistent path resolution and environment setup.
"""

import os
import sys
from pathlib import Path
from typing import Any

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

def clear_plugin_env_vars() -> None:
    """Clear any existing plugin environment variables."""
    plugin_vars = [k for k in os.environ.keys() if k.startswith('PLUGIN_')]
    for var in plugin_vars:
        del os.environ[var]

def get_example_port(base_port: int = 50051) -> int:
    """Get an available port for examples."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', base_port))
        return s.getsockname()[1]

# 🐍🛠️
