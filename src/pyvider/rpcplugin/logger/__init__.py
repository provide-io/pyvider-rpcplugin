
# pyvider/rpcplugin/logger/__init__.py

import importlib
import logging

try:
    logger = importlib.import_module("pyvider").logger

except (ModuleNotFoundError, AttributeError):
    logger = logging.getLogger("rpcplugin")
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)  # Default level

# Usage
logger.info("RPCPlugin logger initialized")

# Add a trace function if one is not already defined.
if not hasattr(logger, "trace"):
    _trace_counter = 0

    def trace(msg, *args, **kwargs):
        global _trace_counter
        _trace_counter += 1
        # Prefix the message with a zero-padded counter
        prefix = f"{_trace_counter:03d}: "
        return logger.debug(prefix + str(msg), *args, **kwargs)

    logger.trace = trace

from pyvider.rpcplugin.logger.emoji_matrix import show_emoji_matrix
show_emoji_matrix()

# if logger is missing trace then it freezes... and never exits. which seems suss.
__all__ = [
    "logger",
]
