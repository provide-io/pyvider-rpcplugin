import inspect
import logging
import sys

from .formatters import AlignedFormatter
from types import TracebackType
from typing import Mapping, Optional, Tuple, Type, Union


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
    def filter(self, record: logging.LogRecord):
        return "KqueueSelector" not in record.getMessage()


class UTF8StreamHandler(logging.StreamHandler):
    def __init__(self, stream=None) -> None:
        # Force UTF-8 encoding for the stream
        if stream is None:
            stream = sys.stderr
        super().__init__(codecs.getwriter("utf-8")(stream))


class PyviderLoggerBase(logging.Logger):
    """Custom logger class with OTEL integration and dynamic caller detection."""

    def __init__(self, name: str = "default", level: Union[int, str]=logging.NOTSET) -> None:
        super().__init__(name, level)

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

    def _log(
        self,
        level: int,
        msg: object,
        args: Union[Mapping[str, object], Tuple[object, ...]],
        exc_info: Union[None, BaseException, bool, Tuple[Type[BaseException], BaseException, Optional[TracebackType]], Tuple[None, ...]]=None,
        extra: Optional[Mapping[str, object]]=None,
        stack_info: bool=False,
        stacklevel: int=1,
    ) -> None:
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

    def trace(self, *args, **kwargs) -> None:
        """
        A custom trace method for logging.
        """
        if len(args) == 1 and isinstance(args[0], str):
            # Handle case where only a message is passed
            trace_level_value = 15
            if not hasattr(logging, "TRACE"):
                logging.addLevelName(trace_level_value, "TRACE")
            self.log(trace_level_value, args[0], **kwargs)
        elif len(args) == 2 and isinstance(args[0], int):
            # Handle case where trace level and message are both passed
            trace_depth = args[0]
            message = args[1]
            trace_level_name = f"TRACE{trace_depth}"
            trace_level_value = (
                15 + trace_depth
            )  # Setting TRACE levels above standard levels to avoid conflicts
            if not hasattr(logging, trace_level_name):
                logging.addLevelName(trace_level_value, trace_level_name)
            self.log(trace_level_value, message, **kwargs)
        elif len(args) > 1 and isinstance(args[0], str):
            # Handle message with formatting arguments
            trace_level_value = 15
            if not hasattr(logging, "TRACE"):
                logging.addLevelName(trace_level_value, "TRACE")
            formatted_message = args[0] % args[1:]
            self.log(trace_level_value, formatted_message, **kwargs)
        else:
            # Handle invalid usage
            raise ValueError(
                "Invalid arguments for trace method. Use either trace(message), trace(level, message), or trace(message, *args)"
            )


# Step 2: Set PyviderLoggerBase as the default logger class
logging.setLoggerClass(PyviderLoggerBase)


class PyviderLogger:
    def __init__(
        self,
        default_level: int = logging.DEBUG,
        insecure: bool = True,
        service_name: str = "pyvider-service",
        instance_id: str = "default-instance",
    ) -> None:
        self.default_level: int = default_level
        self.loggers: dict[str, PyviderLoggerBase] = {}
        self.console = sys.stderr

        self.service_name = service_name
        self.instance_id = instance_id
        self.insecure = insecure

    def get_logger(self, name: str = "default") -> PyviderLoggerBase:
        if name not in self.loggers:
            logger = PyviderLoggerBase(name=name)
            logger.setLevel(self.default_level)

            if not logger.hasHandlers():
                logging.Formatter(
                    fmt="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )

                stream_handler = logging.StreamHandler(sys.stderr)
                # stream_handler = UTF8StreamHandler(sys.stderr)
                stream_formatter = AlignedFormatter(
                    fmt="%(asctime)s", datefmt="%Y-%m-%d %H:%M:%S"
                )
                stream_handler.setFormatter(stream_formatter)
                logger.addHandler(stream_handler)

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

    def _trace(self, logger_self, *args, **kwargs) -> None:
        """
        A custom trace method for logging.
        """
        if len(args) == 1 and isinstance(args[0], str):
            # Handle case where only a message is passed
            trace_level_value = 15
            if not hasattr(logging, "TRACE"):
                logging.addLevelName(trace_level_value, "TRACE")
            logger_self.log(trace_level_value, args[0], **kwargs)
        elif len(args) == 2 and isinstance(args[0], int):
            # Handle case where trace level and message are both passed
            trace_depth = args[0]
            message = args[1]
            trace_level_name = f"TRACE{trace_depth}"
            trace_level_value = (
                15 + trace_depth
            )  # Setting TRACE levels above standard levels to avoid conflicts
            if not hasattr(logging, trace_level_name):
                logging.addLevelName(trace_level_value, trace_level_name)
            logger_self.log(trace_level_value, message, **kwargs)
        elif len(args) > 1 and isinstance(args[0], str):
            # Handle message with formatting arguments
            trace_level_value = 15
            if not hasattr(logging, "TRACE"):
                logging.addLevelName(trace_level_value, "TRACE")
            formatted_message = args[0] % args[1:]
            logger_self.log(trace_level_value, formatted_message, **kwargs)
        else:
            # Handle invalid usage
            raise ValueError(
                "Invalid arguments for trace method. Use either trace(message), trace(level, message), or trace(message, *args)"
            )

    def set_logger_level(self, logger: logging.Logger, level_name: str) -> None:
        """
        Set the logging level for a given logger.
        :param logger: The logger instance.
        :param level_name: The desired logging level (e.g., 'DEBUG', 'TRACE10').
        """
        level_name = level_name.upper()
        if level_name.startswith("TRACE") and level_name != "TRACE":
            try:
                trace_depth = int(level_name.replace("TRACE", ""))
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
        if level_name.startswith("TRACE") and level_name != "TRACE":
            try:
                trace_depth = int(level_name.replace("TRACE", ""))
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
                if record.levelname.startswith("TRACE"):
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
logger: PyviderLoggerBase = pyvider_logger.get_logger(__name__)
