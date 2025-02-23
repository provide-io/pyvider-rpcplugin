import inspect
import logging
import os
import sys
from typing import Optional

from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource

from .formatters import AlignedFormatter


def initialize_logger_provider():
    current_provider = logging.getLogger()
    if not isinstance(current_provider, LoggerProvider):
        provider = LoggerProvider()
        set_logger_provider(provider)
        logger.debug("Initializing LoggerProvider.")
        return provider
    else:
        logger.debug("LoggerProvider already initialized.")
        return current_provider

class SuppressKqueueFilter(logging.Filter):
    def filter(self, record):
        return "KqueueSelector" not in record.getMessage()

class UTF8StreamHandler(logging.StreamHandler):
    def __init__(self, stream=None):
        # Force UTF-8 encoding for the stream
        if stream is None:
            stream = sys.stderr
        super().__init__(codecs.getwriter("utf-8")(stream))

class PyviderLoggerBase(logging.Logger):
    """Custom logger class with OTEL integration and dynamic caller detection."""

    def __init__(self, name: str = "default", level=logging.NOTSET):
        super().__init__(name, level)
        self._otel_handler = None

    def _determine_caller(self) -> str:
        frame = inspect.currentframe()
        while frame:
            frame = frame.f_back
            if frame:
                module = frame.f_globals.get("__name__", "unknown")
                if module != __name__ and not module.startswith("logging"):
                    return module
        return "unknown"

    def _inject_caller(self, record: logging.LogRecord) -> None:
        record.name = self._determine_caller() or "unknown_function"

    def _log(self, level, msg, args, exc_info=None, extra=None, stack_info=False, stacklevel=1):
        # Inject the correct caller module into the record
        record = logging.LogRecord(
            name=self._determine_caller(),  # Dynamically resolve the caller module
            level=level,
            pathname="",
            lineno=0,
            msg=msg,
            args=args,
            exc_info=exc_info,
        )
        self.handle(record)  # Directly handle the modified record


    def trace(self, *args, **kwargs):
        """
        A custom trace method for logging.
        """
        if len(args) == 1 and isinstance(args[0], str):
            # Handle case where only a message is passed
            trace_level_value = 15
            if not hasattr(logging, 'TRACE'):
                logging.addLevelName(trace_level_value, 'TRACE')
            self.log(trace_level_value, args[0], **kwargs)
        elif len(args) == 2 and isinstance(args[0], int):
            # Handle case where trace level and message are both passed
            trace_depth = args[0]
            message = args[1]
            trace_level_name = f'TRACE{trace_depth}'
            trace_level_value = 15 + trace_depth  # Setting TRACE levels above standard levels to avoid conflicts
            if not hasattr(logging, trace_level_name):
                logging.addLevelName(trace_level_value, trace_level_name)
            self.log(trace_level_value, message, **kwargs)
        elif len(args) > 1 and isinstance(args[0], str):
            # Handle message with formatting arguments
            trace_level_value = 15
            if not hasattr(logging, 'TRACE'):
                logging.addLevelName(trace_level_value, 'TRACE')
            formatted_message = args[0] % args[1:]
            self.log(trace_level_value, formatted_message, **kwargs)
        else:
            # Handle invalid usage
            raise ValueError("Invalid arguments for trace method. Use either trace(message), trace(level, message), or trace(message, *args)")

    def configure_otel_handler(self, service_name: str, endpoint: str, insecure: bool = True):
        if self._otel_handler is None:
            resource = Resource.create({"service.name": service_name})
            provider = LoggerProvider(resource=resource)

            uptrace_dsn = os.getenv("UPTRACE_DSN", "http://PyviderSecret-456@localhost:14318?grpc=14317")
            exporter = OTLPLogExporter(
                endpoint=endpoint,
                headers={'uptrace-dsn': uptrace_dsn},
                insecure=insecure
            )
            provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
            set_logger_provider(provider)

            self._otel_handler = LoggingHandler(logger_provider=provider)
            self.addHandler(self._otel_handler)


# Step 2: Set PyviderLoggerBase as the default logger class
logging.setLoggerClass(PyviderLoggerBase)


class PyviderLogger:
    def __init__(
        self,
        default_level: int = logging.DEBUG,
        otlp_enabled: bool = True,
        otlp_endpoint: Optional[str] = None,
        insecure: bool = True,
        service_name: str = "pyvider-service",
        instance_id: str = "default-instance",
    ):
        self.default_level: int = default_level
        self.loggers: dict[str, PyviderLoggerBase] = {}
        self.console = sys.stderr

        self.service_name = service_name
        self.instance_id = instance_id
        self.otlp_endpoint = otlp_endpoint
        self.insecure = insecure

        # Initialize OpenTelemetry logging and tracing
        self._otel_initialized = False  # Class-level flag to prevent reinitialization
        self._setup_opentelemetry()

    def get_logger(self, name: str = "default") -> PyviderLoggerBase:

        if name not in self.loggers:
            logger = PyviderLoggerBase(name=name)
            logger.setLevel(self.default_level)

            if not logger.hasHandlers():
                formatter = logging.Formatter(
                    fmt="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )

                stream_handler = logging.StreamHandler(sys.stderr)
                #stream_handler = UTF8StreamHandler(sys.stderr)
                stream_formatter = AlignedFormatter(fmt="%(asctime)s", datefmt="%Y-%m-%d %H:%M:%S")
                stream_handler.setFormatter(stream_formatter)
                logger.addHandler(stream_handler)


            if self.otlp_endpoint:
                logger.configure_otel_handler(self.service_name, self.otlp_endpoint, self.insecure)

            self.loggers[name] = logger
        return self.loggers[name]

    def _determine_caller(self) -> str:
        """Dynamically get the caller's module/class name."""
        frame = inspect.currentframe()
        while frame:
            frame = frame.f_back
            if frame:
                module = frame.f_globals.get("__name__", "unknown")
                function = frame.f_code.co_name
                if function == "<module>":
                    return module
                return f"{module}.{function}"
        return "unknown"

    def __getattr__(self, name):
        # Pass any attributes not explicitly defined here to a default logger
        if "_default_logger" in self.__dict__:
            return getattr(self._default_logger, name)
        raise AttributeError(f"module 'logger' has no attribute '{name}'")

    def _trace(self, logger_self, *args, **kwargs):
        """
        A custom trace method for logging.
        """
        if len(args) == 1 and isinstance(args[0], str):
            # Handle case where only a message is passed
            trace_level_value = 15
            if not hasattr(logging, 'TRACE'):
                logging.addLevelName(trace_level_value, 'TRACE')
            logger_self.log(trace_level_value, args[0], **kwargs)
        elif len(args) == 2 and isinstance(args[0], int):
            # Handle case where trace level and message are both passed
            trace_depth = args[0]
            message = args[1]
            trace_level_name = f'TRACE{trace_depth}'
            trace_level_value = 15 + trace_depth  # Setting TRACE levels above standard levels to avoid conflicts
            if not hasattr(logging, trace_level_name):
                logging.addLevelName(trace_level_value, trace_level_name)
            logger_self.log(trace_level_value, message, **kwargs)
        elif len(args) > 1 and isinstance(args[0], str):
            # Handle message with formatting arguments
            trace_level_value = 15
            if not hasattr(logging, 'TRACE'):
                logging.addLevelName(trace_level_value, 'TRACE')
            formatted_message = args[0] % args[1:]
            logger_self.log(trace_level_value, formatted_message, **kwargs)
        else:
            # Handle invalid usage
            raise ValueError("Invalid arguments for trace method. Use either trace(message), trace(level, message), or trace(message, *args)")

    def _setup_opentelemetry(self):
        """Configure OpenTelemetry tracing and logging with resources."""
        if self._otel_initialized:
            return  # Skip reinitialization

        try:
            # Validate essential attributes
            if not self.service_name or not self.instance_id:
                raise ValueError("service_name and instance_id must be provided.")

            # Configure resources
            resource = Resource.create(
                {
                    "service.name": self.service_name,
                    "service.instance.id": self.instance_id,
                }
            )

            # Set up logging
            logger_provider = LoggerProvider(resource=resource)
            if self.otlp_endpoint:
                exporter = OTLPLogExporter(endpoint=self.otlp_endpoint, insecure=self.insecure)
                logger_provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
            set_logger_provider(logger_provider)

            self._otel_initialized = True  # Mark as initialized
            logging.getLogger(__name__).debug("OpenTelemetry successfully configured.")

        except Exception as e:
            logging.getLogger(__name__).error(f"Error during OpenTelemetry setup: {e}")
            raise

    def set_logger_level(self, logger: logging.Logger, level_name: str) -> None:
        """
        Set the logging level for a given logger.
        :param logger: The logger instance.
        :param level_name: The desired logging level (e.g., 'DEBUG', 'TRACE10').
        """
        level_name = level_name.upper()
        if level_name.startswith('TRACE') and level_name != 'TRACE':
            try:
                trace_depth = int(level_name.replace('TRACE', ''))
                level_value = 15 + trace_depth
                logging.addLevelName(level_value, level_name)
                logger.setLevel(level_value)
            except ValueError:
                raise ValueError(f"Invalid TRACE level: {level_name}")
        elif hasattr(logging, level_name):
            # Standard logging levels
            level_value = getattr(logging, level_name)
            logger.setLevel(level_value)
        else:
            raise ValueError(f"Invalid level name: {level_name}")

    def set_level(self, name: str, level_name: str) -> None:
        """
        Set the logging level for a given logger by name.
        :param name: The name of the logger.
        :param level_name: The desired logging level (e.g., 'DEBUG', 'TRACE10').
        """
        if name in self.loggers:
            logger = self.loggers[name]
            self.set_logger_level(logger, level_name)
        else:
            raise ValueError(f"Logger '{name}' does not exist.")

    def set_global_level(self, level_name: str) -> None:
        """
        Set the logging level for all loggers managed by PyviderLogger.
        :param level_name: The desired logging level (e.g., 'DEBUG', 'TRACE10').
        """
        level_name = level_name.upper()
        if level_name.startswith('TRACE') and level_name != 'TRACE':
            try:
                trace_depth = int(level_name.replace('TRACE', ''))
                level_value = 15 + trace_depth
                logging.addLevelName(level_value, level_name)
                for logger in self.loggers.values():
                    logger.setLevel(level_value)
            except ValueError:
                raise ValueError(f"Invalid TRACE level: {level_name}")
        elif hasattr(logging, level_name):
            # Standard logging levels
            level_value = getattr(logging, level_name)
            for logger in self.loggers.values():
                logger.setLevel(level_value)
        else:
            raise ValueError(f"Invalid level name: {level_name}")

    def set_trace_level_range(self, name: str, min_trace: int, max_trace: int) -> None:
        """
        Set the logging level for a given logger to show TRACE levels within a given range.
        :param name: The name of the logger.
        :param min_trace: The minimum TRACE level to show.
        :param max_trace: The maximum TRACE level to show.
        """
        if name in self.loggers:
            logger = self.loggers[name]
            min_level = 15 + min_trace
            max_level = 15 + max_trace

            def trace_filter(record: logging.LogRecord) -> bool:
                if record.levelname.startswith('TRACE'):
                    return min_level <= record.levelno <= max_level
                return True  # Allow standard logging levels to pass through

            # Clear existing filters and add the new trace range filter
            logger.filters.clear()
            logger.addFilter(trace_filter)
            handler.addFilter(SuppressKqueueFilter())
        else:
            raise ValueError(f"Logger '{name}' does not exist.")

# Create an instance of PyviderLogger
pyvider_logger = PyviderLogger()

# Use the instance to get a logger
logger = pyvider_logger.get_logger(__name__)
