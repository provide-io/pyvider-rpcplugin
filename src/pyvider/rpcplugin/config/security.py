"""Security configuration for Pyvider RPC Plugin.

Contains security-related settings like mTLS configuration,
certificate management, and authentication settings.
"""

from provide.foundation.config import field, validate_positive


class SecurityConfigMixin:
    """Security configuration settings."""

    # mTLS configuration
    plugin_auto_mtls: bool = field(
        default=False,
        description="Enable automatic mTLS certificate generation",
        env_var="PLUGIN_AUTO_MTLS",
    )

    plugin_client_cert: str | None = field(
        default=None,
        description="Path to client certificate file for mTLS",
        env_var="PLUGIN_CLIENT_CERT",
    )

    plugin_client_key: str | None = field(
        default=None,
        description="Path to client private key file for mTLS",
        env_var="PLUGIN_CLIENT_KEY",
    )

    plugin_server_cert: str | None = field(
        default=None,
        description="Path to server certificate file",
        env_var="PLUGIN_SERVER_CERT",
    )

    plugin_server_key: str | None = field(
        default=None,
        description="Path to server private key file",
        env_var="PLUGIN_SERVER_KEY",
    )

    plugin_ca_cert: str | None = field(
        default=None,
        description="Path to certificate authority file",
        env_var="PLUGIN_CA_CERT",
    )

    plugin_insecure: bool = field(
        default=False,
        description="Disable TLS for development (insecure)",
        env_var="PLUGIN_INSECURE",
    )

    # Certificate configuration
    plugin_cert_validity_days: int = field(
        default=365,
        validator=validate_positive,
        description="Certificate validity period in days",
        env_var="PLUGIN_CERT_VALIDITY_DAYS",
    )

    # Helper methods
    def auto_mtls_enabled(self) -> bool:
        """Get auto mTLS enabled flag."""
        return self.plugin_auto_mtls

    def cert_validity_days(self) -> int:
        """Get certificate validity period in days."""
        return self.plugin_cert_validity_days