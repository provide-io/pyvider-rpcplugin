# pyvider/rpcplugin/logger/crypto.py

from enum import Enum

from pyvider.rpcplugin.logger import logger


class CryptoLogMessages(Enum):
    # CertificateBase Logs
    crypto_debug_certificate_create_start = (
        "📜📝🚀 CertificateBase.create: Starting certificate base creation."
    )
    crypto_debug_certificate_utc_time = (
        "📜⏳✅ CertificateBase.create: Current UTC time: {now}"
    )
    crypto_debug_certificate_validity_period = "📜⏳✅ CertificateBase.create: Validity period: before={not_valid_before}, after={not_valid_after}"
    crypto_debug_certificate_adjusted_validity = (
        "📜⏳✅ CertificateBase.create: Adjusted {field} to UTC."
    )
    crypto_debug_certificate_generate_rsa_key = (
        "📜🔑🚀 CertificateBase.create: Generating RSA key (size: {key_size})."
    )
    crypto_debug_certificate_generate_ecdsa_key = (
        "📜🔑🚀 CertificateBase.create: Generating ECDSA key (curve: {curve_choice})."
    )
    crypto_error_certificate_invalid_key_type = (
        "📜❌ CertificateBase.create: Unsupported key type: {key_type}"
    )
    crypto_debug_certificate_subject_issuer_created = (
        "📜📝✅ CertificateBase.create: Created subject and issuer: {subject}"
    )
    crypto_debug_certificate_serial_number = (
        "📜🔑✅ CertificateBase.create: Generated serial number: {serial_number}"
    )
    crypto_debug_certificate_creation_complete = "📜📝✅ CertificateBase.create: Certificate base creation completed successfully."
    crypto_error_certificate_creation_failed = (
        "📜❌ CertificateBase.create: Failed to create certificate base: {error}"
    )

    # Certificate Initialization
    crypto_debug_certificate_init_keypair = (
        "📜🔑🚀 Certificate.__init__: Generating new keypair as requested."
    )
    crypto_debug_certificate_init_config = (
        "📜🔑🚀 Certificate.__init__: Keypair generation config: {config}"
    )
    crypto_debug_certificate_init_cert_created = "📜🔑✅ Certificate.__init__: Generated certificate and key converted to PEM successfully."
    crypto_error_certificate_init_missing_cert = (
        "📜❌ Certificate.__init__: No certificate data provided."
    )
    crypto_debug_certificate_init_loading_pem = (
        "📜🔑🚀 Certificate.__init__: Loading certificate from provided data."
    )
    crypto_debug_certificate_init_loaded_pem = (
        "📜🔑✅ Certificate.__init__: X.509 certificate loaded successfully from PEM."
    )
    crypto_debug_certificate_init_private_key = (
        "📜🔑🚀 Certificate.__init__: Loading private key from provided data."
    )
    crypto_debug_certificate_init_private_key_loaded = (
        "📜🔑✅ Certificate.__init__: Private key loaded successfully."
    )
    crypto_debug_certificate_init_trust_chain = (
        "📜📝✅ Certificate.__init__: Trust chain initialized."
    )
    crypto_error_certificate_init_failed = (
        "📜❌ Certificate.__init__: Failed to initialize certificate: {error}"
    )

    # Certificate Validation
    crypto_debug_certificate_verify_trust_start = (
        "📜🔍🚀 verify_trust: Starting trust verification."
    )
    crypto_error_certificate_verify_trust_none = (
        "📜🔍❌ verify_trust: Other certificate is None."
    )
    crypto_debug_certificate_verify_trust_invalid = (
        "📜🔍⚠️ verify_trust: Other certificate is not valid (expired or not yet valid)."
    )
    crypto_error_certificate_verify_trust_no_key = (
        "📜🔍❌ verify_trust: Other certificate has no public key."
    )
    crypto_debug_certificate_verify_trust_self_signed = (
        "📜🔍✅ verify_trust: Self-signed certificate verified by itself."
    )
    crypto_debug_certificate_verify_trust_found_chain = (
        "📜🔍✅ verify_trust: Other certificate found in trust chain."
    )
    crypto_debug_certificate_verify_trust_failed = "📜🔍❌ verify_trust: Certificate verification failed; certificate is not trusted."

    # Certificate Creation & Signing
    crypto_debug_certificate_x509_create_start = (
        "📜📝🚀 _create_x509_certificate: Starting certificate creation process."
    )
    crypto_debug_certificate_x509_validity_period = "📜⏳✅ _create_x509_certificate: Validity period: not_valid_before={not_valid_before}, not_valid_after={not_valid_after}"
    crypto_debug_certificate_x509_builder_init = "📜📝🚀 _create_x509_certificate: Certificate builder initialized with base data."
    crypto_debug_certificate_x509_san_extension = (
        "📜📝✅ _create_x509_certificate: Added Subject Alternative Names"
    )
    crypto_debug_certificate_x509_constraints = (
        "📜📝✅ _create_x509_certificate: Added Basic Constraints extension."
    )
    crypto_debug_certificate_x509_key_usage = (
        "📜📝✅ _create_x509_certificate: Added Key Usage extension."
    )
    crypto_debug_certificate_x509_extended_key_usage = (
        "📜📝✅ _create_x509_certificate: Added Extended Key Usage extension."
    )
    crypto_debug_certificate_x509_signing = (
        "📜📝✅ _create_x509_certificate: Certificate signed successfully."
    )
    crypto_error_certificate_x509_sign_failed = (
        "📜❌ _create_x509_certificate: Failed to sign certificate: {error}"
    )

    # Certificate Trust Chain
    crypto_debug_certificate_trust_chain_retrieving = (
        "📜📝✅ trust_chain: Retrieving trust chain."
    )
    crypto_debug_certificate_trust_chain_updating = (
        "📜📝✅ trust_chain: Updating trust chain."
    )

    # Certificate Comparison
    crypto_debug_certificate_eq_other_not_certificate = (
        "📜🔍❌ __eq__: Other object is not a Certificate."
    )
    crypto_debug_certificate_eq_comparison_result = (
        "📜🔍✅ __eq__: Equality result: {eq}"
    )
    crypto_debug_certificate_hash_value = "📜🔍✅ __hash__: Hash value: {h}"
    crypto_debug_certificate_repr = "📜🔍✅ __repr__: {rep}"

    # Certificate Validation Utilities
    crypto_debug_certificate_validate_cert_start = (
        "📜🔍🚀 _validate_cert: Starting validation against trusted certificate."
    )
    crypto_debug_certificate_validate_cert_mismatch = (
        "📜🔍❌ _validate_cert: Issuer mismatch between trusted and other certificate."
    )
    crypto_debug_certificate_validate_cert_verified = (
        "📜🔍✅ _validate_cert: Certificate signature verified successfully."
    )
    crypto_error_certificate_validate_cert_failed = (
        "📜🔍❌ _validate_cert: Signature verification failed: {error}"
    )

    # Key Details & PEM Handling
    crypto_debug_certificate_key_details_start = (
        "🔑📂🚀 display_key_details: Starting extraction of private key details."
    )
    crypto_debug_certificate_key_details_type = "🔑 Key Type: {key_type}"
    crypto_debug_certificate_key_details_size = "📏 Key Size: {key_size}"
    crypto_debug_certificate_key_details_extracted = (
        "🔑📂🚀 display_key_details: Private key details extracted successfully."
    )
    crypto_error_certificate_key_details_failed = (
        "🔑🚨 Could not extract key details: {error}"
    )

    # PEM Loading
    crypto_debug_certificate_pem_loaded_file = (
        "📜📂✅ _load_from_uri_or_pem: Loaded data from file.",
    )
    crypto_debug_certificate_pem_loaded_string = (
        "📜📂✅ _load_from_uri_or_pem: Loaded data from PEM string."
    )
    crypto_error_certificate_pem_load_failed = (
        "📜📂❌ _load_from_uri_or_pem: Failed to load data: {error}"
    )

    # General Errors
    crypto_error_certificate_extraction_failed = (
        "📜🚨 Could not extract certificate details: {error}"
    )
    crypto_error_certificate_invalid_extension = (
        "📜❌ Certificate extension retrieval failed: {error}"
    )

    @property
    def level(self) -> str:  # pragma: no cover
        """Extract log level from enum name."""
        if "debug" in self.name:
            return "debug"
        elif "info" in self.name:
            return "info"
        elif "warning" in self.name:
            return "warning"
        elif "error" in self.name:
            return "error"
        return "info"


def log_crypto_message(
    message: CryptoLogMessages, **kwargs
) -> None:  # pragma: no cover
    log_func = getattr(logger, message.level, logger.info)
    log_func(message.value.format(**kwargs))
