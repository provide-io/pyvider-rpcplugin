# pyvider/observability/logging/proxy.py
from typing import Any

from opentelemetry import trace


class LoggerProxy:
    def __init__(self, logger):
        self._logger = logger
        self._otel_handler = None

    def _log(self, level: str, message: str, **kwargs: Any) -> None:
        current_span = trace.get_current_span()
        span_context = current_span.get_span_context()

        context = {
            "trace_id": span_context.trace_id,
            "span_id": span_context.span_id,
            **kwargs,
        }

        self._logger.log(level, message, extra=context)

    def debug(self, message: str, **kwargs: Any) -> None:
        self._log("DEBUG", message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        self._log("INFO", message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._log("WARNING", message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self._log("ERROR", message, **kwargs)
