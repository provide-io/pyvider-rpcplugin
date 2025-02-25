# slogger.py

import logging
import structlog

# Base TRACE level
BASE_TRACE_LEVEL = 33  # Start at 33 as required

def _trace(self, level=None, message=None, *args, **kwargs):
    """
    Custom trace method for logging.
    Usage:
      logger.trace(57, "Message")  # Logs at TRACE57 level
      logger.trace("Message")      # Logs at base TRACE level
    """
    # Handle case where only a message is provided
    if message is None and isinstance(level, str):
        message = level
        level = None
    
    # Determine the actual trace level
    if level is not None:
        trace_level_name = f"TRACE{level}"
        trace_level_value = BASE_TRACE_LEVEL + level
        # Add the level name if it doesn't exist
        if not hasattr(logging, trace_level_name):
            logging.addLevelName(trace_level_value, trace_level_name)
    else:
        trace_level_value = BASE_TRACE_LEVEL
        trace_level_name = "TRACE"
    
    # Log the message at the appropriate level
    if self.isEnabledFor(trace_level_value):
        self._log(trace_level_value, message, args, **kwargs)

# Add the trace method to the Logger class
logging.Logger.trace = _trace

# Add the base TRACE level
logging.addLevelName(BASE_TRACE_LEVEL, "TRACE")

# Configure structlog to recognize our custom levels
def get_level_name(level_no):
    """Get level name, handling TRACE levels."""
    name = logging.getLevelName(level_no)
    if name.startswith('Level '):  # This indicates logging doesn't recognize the level
        if level_no >= BASE_TRACE_LEVEL:
            # Compute the trace level from the numeric value
            trace_num = level_no - BASE_TRACE_LEVEL
            if trace_num == 0:
                return "TRACE"
            else:
                return f"TRACE{trace_num}"
    return name

# Configure structlog
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(BASE_TRACE_LEVEL),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        # Add a processor to properly format level names
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

# Get a structlog logger
logger = structlog.get_logger()

# Example usage
logger.trace("This is a base trace log")  # Uses TRACE (level 33)
logger.trace(57, "This is a TRACE57 log")  # Uses TRACE57 (level 90)
logger.debug("This is a debug log")
logger.info("This is an info log")
