"""Core configuration for Pyvider RPC Plugin.

Contains fundamental settings like protocol versions, magic cookies,
and core version information.
"""

from provide.foundation.config import field, validate_choice, validate_non_negative
from ..defaults import DEFAULT_PLUGIN_PROTOCOL_VERSIONS, DEFAULT_SUPPORTED_PROTOCOL_VERSIONS


class CoreConfigMixin:
    """Core configuration settings."""

    # Core version and protocol settings
    plugin_core_version: int = field(
        default=1,
        validator=validate_choice(DEFAULT_SUPPORTED_PROTOCOL_VERSIONS),
        description="Core protocol version supported by this plugin",
        env_var="PLUGIN_CORE_VERSION",
    )

    plugin_protocol_versions: list[int] = field(
        default_factory=lambda: DEFAULT_PLUGIN_PROTOCOL_VERSIONS.copy(),
        description="List of protocol versions this plugin supports",
        env_var="PLUGIN_PROTOCOL_VERSIONS",
    )

    plugin_protocol_version: int = field(
        default=1,
        validator=validate_choice(DEFAULT_SUPPORTED_PROTOCOL_VERSIONS),
        description="Preferred protocol version for communication",
        env_var="PLUGIN_PROTOCOL_VERSION",
    )

    # Magic cookie configuration
    plugin_magic_cookie_key: str = field(
        default="PLUGIN_MAGIC_COOKIE",
        description="Environment variable name for the magic cookie",
        env_var="PLUGIN_MAGIC_COOKIE_KEY",
    )

    plugin_magic_cookie_value: str = field(
        default="default-magic-cookie-value",
        description="Magic cookie value for handshake authentication",
        env_var="PLUGIN_MAGIC_COOKIE_VALUE",
    )

    # Helper methods
    def magic_cookie_key(self) -> str:
        """Get the magic cookie key."""
        return self.plugin_magic_cookie_key

    def magic_cookie_value(self) -> str:
        """Get the magic cookie value."""
        return self.plugin_magic_cookie_value