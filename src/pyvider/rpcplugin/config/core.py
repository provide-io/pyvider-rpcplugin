"""Core protocol and magic cookie configuration."""

from attrs import define, field
from provide.foundation.config import validate_choice, validate_range

from pyvider.rpcplugin.defaults import (
    DEFAULT_PLUGIN_PROTOCOL_VERSIONS,
    DEFAULT_SUPPORTED_PROTOCOL_VERSIONS,
)


@define(slots=True)
class CoreConfig:
    """Core protocol and magic cookie configuration."""

    # =====================================================
    # Protocol Configuration
    # =====================================================

    plugin_core_version: int = field(
        default=1,
        validator=validate_choice(DEFAULT_SUPPORTED_PROTOCOL_VERSIONS),
        description="Core protocol version supported by this plugin",
        env_var="PLUGIN_CORE_VERSION",
    )

    plugin_protocol_versions: list[int] = field(  # noqa: RUF009
        factory=lambda: DEFAULT_PLUGIN_PROTOCOL_VERSIONS.copy(),
        description="List of protocol versions this plugin supports",
        env_var="PLUGIN_PROTOCOL_VERSIONS",
    )

    plugin_protocol_version: int = field(
        default=1,
        validator=validate_choice(DEFAULT_SUPPORTED_PROTOCOL_VERSIONS),
        description="Preferred protocol version for communication",
        env_var="PLUGIN_PROTOCOL_VERSION",
    )

    supported_protocol_versions: list[int] = field(  # noqa: RUF009
        factory=lambda: DEFAULT_SUPPORTED_PROTOCOL_VERSIONS.copy(),
        description="List of supported protocol versions (reference)",
        env_var="SUPPORTED_PROTOCOL_VERSIONS",
    )

    # =====================================================
    # Magic Cookie Configuration
    # =====================================================

    plugin_magic_cookie_key: str = field(
        default="PLUGIN_MAGIC_COOKIE",
        description="Environment variable name for the magic cookie",
        env_var="PLUGIN_MAGIC_COOKIE_KEY",
    )

    plugin_magic_cookie_value: str = field(
        default="test_cookie_value",
        description="Magic cookie value for handshake authentication",
        env_var="PLUGIN_MAGIC_COOKIE_VALUE",
        sensitive=True,
    )

    # =====================================================
    # Logging Configuration
    # =====================================================

    plugin_log_level: str = field(
        default="INFO",
        validator=validate_choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
        description="Logging level for the plugin",
        env_var="PLUGIN_LOG_LEVEL",
    )