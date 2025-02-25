"""
Structured logging with custom trace levels for Python 3.12+.

This module provides a structlog-based logger with support for custom trace levels.
It allows logging at arbitrary TRACE levels by calling logger.trace(level, message).
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict, List, Optional, Union, cast, TypeVar, Protocol, Callable

import attrs
import structlog
from structlog.types import EventDict, Processor, WrappedLogger

# Base TRACE level - 33 is between DEBUG (10) and WARNING (30)
BASE_TRACE_LEVEL = 33

# Type definitions
Message = str
LogLevel = int
LevelName = str

@attrs.define(frozen=True, slots=True)
class TraceLevel:
    """
    Represents a custom trace level.
    
    Attributes:
        value: The numeric value of the trace level
        name: The name of the trace level (e.g., "TRACE57")
    """
    value: int
    name: str

    @classmethod
    def create(cls, level: Optional[int] = None) -> TraceLevel:
        """
        Create a TraceLevel from an optional level number.
        
        Args:
            level: The trace level, None for base TRACE level
            
        Returns:
            A TraceLevel instance with appropriate name and value
        """
        if level is None:
            return cls(BASE_TRACE_LEVEL, "TRACE")
        
        level_value = BASE_TRACE_LEVEL + level
        level_name = f"TRACE{level}"
        return cls(level_value, level_name)

@attrs.define
class TraceLevelRegistry:
    """Registry for managing trace levels."""
    
    _registered_levels: Dict[int, str] = attrs.field(factory=dict)
    
    def register_level(self, level: TraceLevel) -> None:
        """
        Register a trace level with the logging system.
        
        Args:
            level: The TraceLevel to register
        """
        if level.value not in self._registered_levels:
            logging.addLevelName(level.value, level.name)
            self._registered_levels[level.value] = level.name
    
    def get_level_name(self, level_value: int) -> str:
        """
        Get the name for a numeric log level, handling TRACE levels.
        
        Args:
            level_value: The numeric log level
            
        Returns:
            The name of the log level
        """
        # First check if it's a registered level
        if level_value in self._registered_levels:
            return self._registered_levels[level_value]
        
        # Check if it's a standard level
        name = logging.getLevelName(level_value)
        if isinstance(name, str) and not name.startswith('Level '):
            return name
            
        # Handle unknown TRACE levels
        if level_value >= BASE_TRACE_LEVEL:
            trace_num = level_value - BASE_TRACE_LEVEL
            level_name = "TRACE" if trace_num == 0 else f"TRACE{trace_num}"
            # Register this level for future use
            self.register_level(TraceLevel(level_value, level_name))
            return level_name
            
        # Fall back to the standard level name or a generic name
        return name

# Singleton instance of the registry
trace_registry = TraceLevelRegistry()

# Register the base TRACE level
trace_registry.register_level(TraceLevel.create())

# Add trace method to standard Logger class
def trace_method(self, level_or_message: Union[int, str], message: Optional[str] = None, *args, **kwargs):
    """
    Log a message at a custom TRACE level.
    
    Args:
        level_or_message: Either the trace level (int) or the message if no level is provided
        message: The message to log (if level is provided)
        *args: Format string arguments
        **kwargs: Additional context variables for the log
    """
    if message is None and isinstance(level_or_message, str):
        # Case: logger.trace("message")
        trace_level = TraceLevel.create()
        message = level_or_message
    else:
        # Case: logger.trace(42, "message")
        level = cast(int, level_or_message)
        trace_level = TraceLevel.create(level)
        message = cast(str, message)
    
    # Register the level
    trace_registry.register_level(trace_level)
    
    # Log at the trace level
    if self.isEnabledFor(trace_level.value):
        self._log(trace_level.value, message, args, **kwargs)

# Attach trace method to Logger class
logging.Logger.trace = trace_method  # type: ignore

def trace_level_name_processor(
    _: WrappedLogger, __: str, event_dict: EventDict
) -> EventDict:
    """
    Structlog processor that formats log level names correctly for TRACE levels.
    
    Args:
        _: The wrapped logger (unused)
        __: The method name (unused)
        event_dict: The event dictionary
        
    Returns:
        The modified event dictionary
    """
    # Get the level number from the event dictionary
    level_number = event_dict.get("level_number")
    if level_number is not None:
        # Use our registry to get the correct level name
        level_name = trace_registry.get_level_name(level_number)
        event_dict["level"] = level_name
    return event_dict

@attrs.define
class SLogger:
    """
    Structured logger with trace level support.
    
    This class provides a wrapper around structlog that adds support for
    custom trace levels through the trace() method.
    """
    
    name: str = attrs.field()
    _logger: logging.Logger = attrs.field()
    _structlog: Any = attrs.field()
    _processors: List[Processor] = attrs.field(factory=list)
    
    @classmethod
    def configure(
        cls,
        min_level: int = logging.INFO,
        console: bool = True,
        json_format: bool = False,
        log_file: Optional[str] = None,
        extra_processors: Optional[List[Processor]] = None,
    ) -> None:
        """
        Configure logging with appropriate settings for trace levels.
        
        Args:
            min_level: Minimum log level to record
            console: Whether to log to console
            json_format: Whether to format logs as JSON
            log_file: Path to log file (if any)
            extra_processors: Additional structlog processors to use
        """
        # Configure basic logging first
        logging.basicConfig(
            level=min_level,
            format="%(message)s",
            handlers=[],  # We'll add handlers manually
        )
        
        # Set up handlers
        handlers: List[logging.Handler] = []
        
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(min_level)
            handlers.append(console_handler)
            
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(min_level)
            handlers.append(file_handler)
        
        # Set up root logger
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            root_logger.removeHandler(handler)
        
        for handler in handlers:
            root_logger.addHandler(handler)
        
        # Configure structlog processors
        processors: List[Processor] = [
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            trace_level_name_processor,
        ]
        
        if extra_processors:
            processors.extend(extra_processors)
            
        # Add formatters based on configuration
        if json_format:
            processors.append(structlog.processors.format_exc_info)
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())
        
        # Configure structlog
        structlog.configure(
            processors=processors,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        # Store processors for later use
        cls._common_processors = processors
    
    @classmethod
    def get_logger(cls, name: str = "") -> "SLogger":
        """
        Get a structured logger with trace capabilities.
        
        Args:
            name: Name of the logger
            
        Returns:
            An SLogger instance
        """
        # Get the standard library logger with trace capability
        logger = logging.getLogger(name)
        
        # Get structlog logger
        structlog_logger = structlog.get_logger(name)
        
        # Return our logger instance
        try:
            processors = cls._common_processors  # type: ignore
        except AttributeError:
            # No configuration was done, use default processors
            processors = []
            
        return cls(name=name, logger=logger, structlog=structlog_logger, processors=processors)
        
    def trace(self, level_or_message: Union[int, str], message: Optional[str] = None, **kwargs: Any) -> None:
        """
        Log a message at a custom TRACE level with structured context.
        
        Args:
            level_or_message: Either the trace level (int) or the message if no level is provided
            message: The message to log (if level is provided)
            **kwargs: Additional context variables for the log
        """
        # Create a bound logger with the kwargs
        bound_logger = self._structlog.bind(**kwargs) if kwargs else self._structlog
        
        # Use the trace method we added to the standard Logger
        if message is None and isinstance(level_or_message, str):
            # Case: logger.trace("message")
            self.logger.trace(level_or_message)  # type: ignore
        else:
            # Case: logger.trace(42, "message")
            level = cast(int, level_or_message)
            msg = cast(str, message)
            self._logger.trace(level, msg)  # type: ignore
    
    # Forward standard logging methods to the structlog logger
    def debug(self, message: str, **kwargs: Any) -> None:
        """Log a message at DEBUG level."""
        self._structlog.debug(message, **kwargs)
        
    def info(self, message: str, **kwargs: Any) -> None:
        """Log a message at INFO level."""
        self._structlog.info(message, **kwargs)
        
    def warning(self, message: str, **kwargs: Any) -> None:
        """Log a message at WARNING level."""
        self._structlog.warning(message, **kwargs)
        
    def error(self, message: str, **kwargs: Any) -> None:
        """Log a message at ERROR level."""
        self._structlog.error(message, **kwargs)
        
    def critical(self, message: str, **kwargs: Any) -> None:
        """Log a message at CRITICAL level."""
        self._structlog.critical(message, **kwargs)
        
    def exception(self, message: str, **kwargs: Any) -> None:
        """Log a message at ERROR level with exception information."""
        self._structlog.exception(message, **kwargs)
        
    def log(self, level: int, message: str, **kwargs: Any) -> None:
        """Log a message at the specified level."""
        # Register level if it's a custom level
        if level >= BASE_TRACE_LEVEL:
            trace_level = TraceLevel(level, logging.getLevelName(level))
            trace_registry.register_level(trace_level)
        
        # Use structlog's log method
        self._structlog.log(level, message, **kwargs)
        
    def bind(self, **kwargs: Any) -> "SLogger":
        """
        Bind context variables to the logger.
        
        Args:
            **kwargs: Context variables to bind
            
        Returns:
            A new SLogger with bound context
        """
        return SLogger(
            name=self.name,
            _logger=self._logger,
            _structlog=self._structlog.bind(**kwargs),
            _processors=self._processors
        )

# Initialize trace level registry
trace_registry.register_level(TraceLevel.create())

# Storage for common processors
SLogger._common_processors = []  # type: ignore

# Create a default logger for convenience
logger = SLogger.get_logger()

# Example usage
if __name__ == "__main__":
    # Configure logging
    SLogger.configure(
        min_level=logging.DEBUG,  # Set to DEBUG or lower to capture trace messages
        console=True,
        json_format=False,
    )
    
    # Get a logger
    example_logger = SLogger.get_logger("example")
    
    # Log at various levels
    example_logger.trace("This is a base trace log")
    example_logger.trace(57, "This is a TRACE57 log") 
    example_logger.debug("This is a debug log")
    example_logger.info("This is an info log", extra_field="test")
    
    # Bind some context
    ctx_logger = example_logger.bind(user_id=123)
    ctx_logger.warning("This is a warning with context")
    
    # Log at a high trace level
    example_logger.trace(432, "This is a high-detail trace log with context", operation="query_db")
