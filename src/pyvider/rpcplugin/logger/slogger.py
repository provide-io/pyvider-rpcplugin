import logging
import structlog

# slogger.py

# Configure default TRACE level (should be lower than DEBUG)
DEFAULT_TRACE_LEVEL = 5  

# Extend logger to support `trace` method
def trace(self, level, message, *args, **kwargs):
    """
    Custom trace method that allows dynamic log levels.
    Example: logger.trace(432, "Message") -> Logs with level TRACE432.
    """
    if not isinstance(level, int):
        raise ValueError("Trace level must be an integer.")

    log_level_name = f"TRACE{level}"  # Example: TRACE432
    logging.addLevelName(level, log_level_name)  # Dynamically register level

    if self.isEnabledFor(level):
        self._log(level, message, args, **kwargs)

# Attach the method to `logging.Logger`
logging.Logger.trace = trace

# Configure structlog to use standard logging with filtering
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

# Create a standard Python logger and wrap it with structlog
std_logger = logging.getLogger("slogger")
std_logger.setLevel(logging.NOTSET)  # Allow all levels
struct_logger = structlog.wrap_logger(std_logger)

# Example usage
struct_logger.trace(432, "This is a trace log with level 432")  # Logs as "TRACE432"
struct_logger.trace(100, "This is a trace log with level 100")  # Logs as "TRACE100"
struct_logger.debug("This is a debug log")  # Logs as "DEBUG"
struct_logger.info("This is an info log")  # Logs as "INFO"
