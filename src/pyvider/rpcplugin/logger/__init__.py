
# pyvider/rpcplugin/logger/__init__.py

import importlib
import logging

try:
    logger = importlib.import_module("pyvider").logger

except ModuleNotFoundError:
    logger = logging.getLogger("rpcplugin")
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)  # Default level

# Usage
logger.info("RPCPlugin logger initialized")

from pyvider.rpcplugin.logger.emoji_matrix import show_emoji_matrix
show_emoji_matrix()

__all__ = [
    'logger',
]
