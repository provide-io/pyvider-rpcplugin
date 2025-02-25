import logging
import structlog

# Default trace level (lowest possible)
DEFAULT_TRACE_LEVEL = 33

# Configure structlog with NOTSET to allow custom levels
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.NOTSET),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

# Extend logger to support `trace` method
def trace(self, level, message, *args, **kwargs):
    """
    Custom trace method that accepts a level and logs with a dynamic log level name.
    Example: trace(432, "Custom trace message") -> Log level "TRACE432"
    """
    if not isinstance(level, int):
        raise ValueError("Trace level must be an integer.")

    log_level_name = f"TRACE{level}"  # Example: TRACE432
    logging.addLevelName(level, log_level_name)  # Dynamically register level

    if self.isEnabledFor(level):
        self._log(level, message, args, **kwargs)

# Attach custom trace method to Logger class
logging.Logger.trace = trace

# Get a structlog logger
logger = structlog.get_logger()

# Example usage
logger.trace(432, "This is a trace log with level 432")  # Logs as "TRACE432"
logger.trace(100, "This is a trace log with level 100")  # Logs as "TRACE100"
logger.debug("This is a debug log")  # Logs as "DEBUG"
logger.info("This is an info log")  # Logs as "INFO"
