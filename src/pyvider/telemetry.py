import logging

# Create a basic logger
logger = logging.getLogger("pyvider.dummy_telemetry")
logger.addHandler(logging.NullHandler()) # Avoid "No handler found" warnings

# You can add more sophisticated mock logging features if needed by tests
# For example, a list to capture log messages:
# captured_logs = []
# class CaptureHandler(logging.Handler):
#     def emit(self, record):
#         captured_logs.append(self.format(record))
# logger.addHandler(CaptureHandler())
