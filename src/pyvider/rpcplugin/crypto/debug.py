
# pyvider/crypto/debug.py


from cryptography import x509
from cryptography.x509.oid import NameOID

# from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import SecurityError


def display_cert_details(cert: x509.Certificate, logger) -> None:
    """Log certificate details in a structured format with emojis."""
    try:
        logger.debug("📜 Certificate Information:")

        # Log serial number in hex notation
        serial_number_hex = ":".join(f"{cert.serial_number:02x}"[i:i + 2] for i in range(0, len(f"{cert.serial_number:02x}"), 2))
        logger.debug(f"   🔢 Serial Number: {serial_number_hex}")
        logger.debug(f"   🏷️  Subject: {cert.subject}")
        logger.debug(f"   🏢 Organization: {', '.join(org.value for org in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))}")
        logger.debug(f"   🌐 Common Name: {cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        logger.debug(f"   📆 Valid From: {cert.not_valid_before_utc}")
        logger.debug(f"   📆 Valid To: {cert.not_valid_after_utc}")

        # Get key usage as a list of enabled usages
        if key_usage_ext := cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE):
            usages = []
            for usage_attr in ['digital_signature', 'content_commitment', 'key_encipherment',
                              'data_encipherment', 'key_agreement', 'key_cert_sign',
                              'crl_sign', 'encipher_only', 'decipher_only']:
                if getattr(key_usage_ext.value, usage_attr):
                    usages.append(usage_attr)
            logger.debug(f"   🔑 Key Usage: {', '.join(usages)}")
    except Exception:
        logger.debug("📜🚨 Could not extract certificate details.")
        raise SecurityError("📜🚨 Could not extract certificate details.")

###