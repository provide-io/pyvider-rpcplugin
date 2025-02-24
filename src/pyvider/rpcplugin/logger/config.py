# pyvider/observability/logging/config.py
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource


def configure_logging(
    service_name: str,
    otlp_endpoint: Optional[str] = None,
    insecure: bool = False
) -> None:
    resource = Resource.create({SERVICE_NAME: service_name})
    provider = LoggerProvider(resource=resource)

    if otlp_endpoint:
        exporter = OTLPLogExporter(
            endpoint=otlp_endpoint,
            insecure=insecure
        )
        provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
