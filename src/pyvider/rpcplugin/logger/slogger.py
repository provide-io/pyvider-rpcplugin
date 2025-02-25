import logging
import structlog

# Define a custom TRACE level (lower than DEBUG)
TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")

# Extend logger to support `trace` method
def trace(self, level, message = None, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL):
        self._log(TRACE_LEVEL, message, args, **kwargs)

logging.Logger.trace = trace

# Configure structlog with the new TRACE level
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(TRACE_LEVEL),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

# Get a structlog logger
logger = structlog.get_logger()

# Log messages with the new TRACE level
logger.trace("This is a trace log")
logger.debug("This is a debug log")
logger.info("This is an info log")
