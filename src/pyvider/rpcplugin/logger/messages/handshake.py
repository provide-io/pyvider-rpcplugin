from enum import Enum

from pyvider.rpcplugin.logger import logger


class HandshakeLogMessages(Enum):
    # Transport Validation
    handshake_debug_validate_transport_start = "🤝🚂🔍 Checking transport: {transport_name} against supported list: {supported_transports}"
    handshake_error_validate_transport_failed = (
        "🤝🚂❌ Unsupported transport detected: {transport_name}"
    )
    handshake_debug_validate_transport_success = (
        "🤝🚂✅ Transport '{transport_name}' is supported."
    )

    # Protocol Version Negotiation
    handshake_debug_protocol_negotiation_start = (
        "🤝🔄 Negotiating protocol version. Server supports: {server_versions}"
    )
    handshake_info_protocol_selected = "🤝✅ Selected protocol version: {version}"
    handshake_error_protocol_negotiation_failed = "🤝❌ Protocol negotiation failed: No compatible version found. Server supports: {server_versions}, Client supports: {SUPPORTED_PROTOCOL_VERSIONS}"

    # Transport Negotiation
    handshake_debug_transport_negotiation_start = "🗣️🚊 (Transport Negotiation: Starting) => Available transports: {server_transports}"
    handshake_error_transport_negotiation_no_options = (
        "🗣️🚊❌ (Transport Negotiation: Failed) => No transport options provided"
    )
    handshake_debug_transport_selected_tcp = (
        "🗣️🚊👥 (Transport Negotiation: Selected TCP) => TCP transport is available"
    )
    handshake_debug_transport_selected_unix = "🗣️🚊🧦 (Transport Negotiation: Selected Unix) => Unix socket transport is available"
    handshake_error_transport_negotiation_failed = (
        "🗣️🚊❌ (Transport Negotiation: Failed) => No supported transport found"
    )
    handshake_error_transport_negotiation_exception = "🗣️🚊❌ (Transport Negotiation: Exception) => Error during transport negotiation: {error}"

    # Handshake Parts Validation
    handshake_debug_validate_handshake_parts = (
        "🔍✅ TypeGuard: Handshake response format validated."
    )
    handshake_error_invalid_handshake_parts = "🔍❌ Invalid handshake response format."

    # Magic Cookie Validation
    handshake_debug_magic_cookie_validation_start = (
        "🍪🔍 Starting magic cookie validation..."
    )
    handshake_debug_magic_cookie_key = "🍪 cookie_key: {cookie_key}"
    handshake_debug_magic_cookie_value = "🍪 cookie_value: {cookie_value}"
    handshake_debug_magic_cookie_provided = "🍪 cookie_provided: {cookie_provided}"
    handshake_error_magic_cookie_key_missing = "🍪🪄❌ cookie_key not found"
    handshake_error_magic_cookie_value_missing = "🍪🪄❌ Magic cookie value not found."
    handshake_error_magic_cookie_provided_missing = "🍪🪄❌ Magic cookie not provided."
    handshake_error_magic_cookie_mismatch = (
        "🍪❌ cookie_provided does not match required cookie_value"
    )

    # Handshake Response Building
    handshake_debug_build_handshake_response_start = (
        "🤝📝🔄 Building handshake response..."
    )
    handshake_error_tcp_requires_port = "🤝📝❌ TCP transport requires a valid port."
    handshake_debug_tcp_endpoint_set = "🤝📝✅ TCP endpoint set: {endpoint}"
    handshake_debug_unix_transport_listening = (
        "🤝📝🔄 Waiting for Unix transport to listen..."
    )
    handshake_debug_unix_transport_received = (
        "🤝📝✅ Unix transport endpoint received: {endpoint}"
    )
    handshake_error_unsupported_transport_type = (
        "🤝📝❌ Unsupported transport type: {transport_name}"
    )
    handshake_debug_handshake_base_response = (
        "🤝📝🔄 Base response structure: {response_parts}"
    )
    handshake_debug_handshake_cert_processing = (
        "🤝🔐🔄 Processing server certificate..."
    )
    handshake_error_invalid_certificate_format = "🤝🔐❌ Invalid certificate format."
    handshake_debug_handshake_cert_added = "🤝🔐✅ Certificate data added to response."
    handshake_debug_handshake_response_success = (
        "🤝📝✅ Handshake response successfully built: {handshake_response}"
    )
    handshake_error_handshake_response_failed = (
        "🤝📝❌ Handshake response build failed: {error}"
    )

    # Handshake Response Parsing
    handshake_debug_handshake_parsing_start = (
        "📡🔍 Starting handshake response parsing for: {response}"
    )
    handshake_debug_handshake_parsing_split = (
        "📡🔍 Split handshake response into parts: {parts}"
    )
    handshake_error_invalid_handshake_format = (
        "📡❌ Invalid handshake response format. Expected 6 parts, got {parts_count}"
    )
    handshake_error_invalid_network_type = "📡❌ Invalid network type: {network}"
    handshake_debug_handshake_cert_padding = (
        "📡🔐 Restored certificate padding for handshake parsing."
    )
    handshake_debug_handshake_parsing_success = "📡✅ Handshake parsing success: core_version={core_version}, plugin_version={plugin_version}, network={network}, address={address}, protocol={protocol}, server_cert={'present' if server_cert else 'none'}"
    handshake_error_handshake_parsing_failed = "📡❌ Handshake parsing failed: {error}"

    @property
    def level(self) -> str:
        """Extract log level from enum name."""
        if "debug" in self.name:
            return "debug"
        if "info" in self.name:
            return "info"
        if "warning" in self.name:
            return "warning"
        if "error" in self.name:
            return "error"
        return "info"  # Default level


# Logging function using this system
def log_handshake_message(message: HandshakeLogMessages, **kwargs) -> None:
    log_func = getattr(logger, message.level, logger.info)
    log_func(message.value.format(**kwargs))
