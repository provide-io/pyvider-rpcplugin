"""Security and mTLS configuration."""

from attrs import define, field
from provide.foundation.config import validate_positive


@define(slots=True)
class SecurityConfig:
    """Security and mTLS configuration."""

    # =====================================================
    # mTLS Settings
    # =====================================================

    plugin_auto_mtls: bool = field(
        default=True,
        description="Enable automatic mutual TLS certificate generation",
        env_var="PLUGIN_AUTO_MTLS",
    )

    plugin_insecure: bool = field(
        default=False,
        description="Allow insecure connections (disable TLS)",
        env_var="PLUGIN_INSECURE",
    )

    plugin_cert_validity_days: int = field(
        default=365,
        validator=validate_positive,
        description="Certificate validity period in days",
        env_var="PLUGIN_CERT_VALIDITY_DAYS",
    )

    # =====================================================
    # Server Certificates
    # =====================================================

    plugin_server_cert: str | None = field(
        default=None,
        description="Server certificate (PEM format or file:// path)",
        env_var="PLUGIN_SERVER_CERT",
        sensitive=True,
    )

    plugin_server_key: str | None = field(
        default=None,
        description="Server private key (PEM format or file:// path)",
        env_var="PLUGIN_SERVER_KEY",
        sensitive=True,
    )

    plugin_server_root_certs: str | None = field(
        default=None,
        description="Server root certificates (PEM format or file:// path)",
        env_var="PLUGIN_SERVER_ROOT_CERTS",
        sensitive=True,
    )

    # =====================================================
    # Client Certificates
    # =====================================================

    plugin_client_cert: str | None = field(
        default=None,
        description="Client certificate (PEM format or file:// path)",
        env_var="PLUGIN_CLIENT_CERT",
        sensitive=True,
    )

    plugin_client_key: str | None = field(
        default=None,
        description="Client private key (PEM format or file:// path)",
        env_var="PLUGIN_CLIENT_KEY",
        sensitive=True,
    )

    plugin_client_root_certs: str | None = field(
        default=None,
        description="Client root certificates for mTLS validation",
        env_var="PLUGIN_CLIENT_ROOT_CERTS",
        sensitive=True,
    )

    # =====================================================
    # Certificate Authority
    # =====================================================

    plugin_ca_cert: str | None = field(
        default=None,
        description="Certificate Authority certificate (PEM format or file:// path)",
        env_var="PLUGIN_CA_CERT",
        sensitive=True,
    )