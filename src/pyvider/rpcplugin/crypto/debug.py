#
# pyvider/crypto/debug.py
#

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


# from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.telemetry import logger
from pyvider.rpcplugin.exception import CertificateError, SecurityError

def display_cert_details(cert) -> None:
    """
    📜📂🚀 display_cert_details: Logs detailed certificate information.

    This method extracts and logs:
      - Serial number (in hex, grouped in two-character segments).
      - Subject and issuer.
      - Validity period.
      - Key Usage (if present).
      - Extended Key Usage (if present).
      - Basic Constraints.
      - Public key algorithm, size, and PEM-encoded public key.

    Raises:
      CertificateError: If any certificate detail cannot be extracted.
    """
    cert = self._cert  # x509 certificate object

    try:
        logger.debug(
            "📜📂🚀 display_cert_details: Starting extraction of certificate details."
        )

        # Format serial number as hex grouped in two-character segments.
        serial_str = f"{cert.serial_number:0x}"
        serial_number_hex = ":".join(
            serial_str[i : i + 2] for i in range(0, len(serial_str), 2)
        )
        logger.debug(f"  🔢 Serial Number: {serial_number_hex}")

        # Log Subject and Issuer.
        logger.debug(f"  🏷️ Subject: {cert.subject.rfc4514_string()}")
        logger.debug(f"  📢 Issuer: {cert.issuer.rfc4514_string()}")

        # Log Validity period.
        logger.debug(f"  📆 Valid From: {cert.not_valid_before_utc.isoformat()}")
        logger.debug(f"  📆 Valid To: {cert.not_valid_after_utc.isoformat()}")

        # Key Usage extension.
        try:
            key_usage_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            )
            usages = []
            if key_usage_ext.value.digital_signature:
                usages.append("digital_signature")
            if key_usage_ext.value.content_commitment:
                usages.append("content_commitment")
            if key_usage_ext.value.key_encipherment:
                usages.append("key_encipherment")
            if key_usage_ext.value.data_encipherment:
                usages.append("data_encipherment")
            if key_usage_ext.value.key_agreement:
                usages.append("key_agreement")
            if key_usage_ext.value.key_cert_sign:
                usages.append("key_cert_sign")
            if key_usage_ext.value.crl_sign:
                usages.append("crl_sign")
            if key_usage_ext.value.encipher_only:
                usages.append("encipher_only")
            if key_usage_ext.value.decipher_only:
                usages.append("decipher_only")
            logger.debug(
                f"  🔑 Key Usage: {', '.join(usages) if usages else 'None'}"
            )
        except x509.ExtensionNotFound:
            logger.debug("  🔑 Key Usage: Not present")

        # Extended Key Usage extension.
        try:
            ext_key_usage_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
            )
            eku_oids = [oid.dotted_string for oid in ext_key_usage_ext.value]
            # Use the attribute 'dotted_string' as a fallback for names.
            eku_names = [
                getattr(oid, "name", oid.dotted_string)
                for oid in ext_key_usage_ext.value
            ]
            logger.debug(
                f"  ✨ Extended Key Usage (OID): {', '.join(eku_oids) if eku_oids else 'None'}"
            )
            logger.debug(
                f"  ✨ Extended Key Usage (Name): {', '.join(eku_names) if eku_names else 'None'}"
            )
        except x509.ExtensionNotFound:
            logger.debug("  ✨ Extended Key Usage: Not present")

        # Basic Constraints extension.
        try:
            bc_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            ca_info = "CA" if bc_ext.value.ca else "Not CA"
            path_length = (
                f" (Path Length: {bc_ext.value.path_length})"
                if bc_ext.value.path_length is not None
                else ""
            )
            logger.debug(f"  ⛓️ Basic Constraints: {ca_info}{path_length}")
        except x509.ExtensionNotFound:
            logger.debug("  ⛓️ Basic Constraints: Not present")

        # Public Key details.
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = "ECDSA"
            key_size = public_key.curve.name
        else:
            key_type = "Unknown"
            key_size = "Unknown"
        logger.debug(f"  🔑 Public Key: {key_type} ({key_size})")
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        logger.debug(f"  🔑 PEM Encoded Public Key:\n{pem_public_key}")

        logger.debug(
            "📜📂🚀 display_cert_details: Certificate details extracted successfully."
        )
    except Exception as e:
        logger.error(
            f"📜🚨 Could not extract certificate details: {e}",
            extra={"error": str(e)},
        )
        raise CertificateError("Could not extract certificate details") from e

def display_key_details(key) -> None:
    """
    🔑📂🚀 display_key_details: Logs private key details in a structured format.

    Logs:
      - The key type and size.
      - The PEM-encoded private key.

    Raises:
      CertificateError: If key details cannot be extracted.
    """
    #key = self._private_key
    if key is None:
        logger.warning(
            "🔑⚠️ display_key_details: No private key available to display."
        )
        return

    try:
        logger.debug(
            "🔑📂🚀 display_key_details: Starting extraction of private key details."
        )
        if isinstance(key, rsa.RSAPrivateKey):
            key_type = "RSA"
            key_size = key.key_size
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            key_type = "ECDSA"
            key_size = key.curve.name
        else:
            key_type = "Unknown"
            key_size = "Unknown"
        logger.debug(f"  🔑 Key Type: {key_type}")
        logger.debug(f"  📏 Key Size: {key_size}")
        pem_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        logger.debug(f"  🔑 PEM Encoded Private Key:\n{pem_key}")
        logger.debug(
            "🔑📂🚀 display_key_details: Private key details extracted successfully."
        )
    except Exception as e:
        logger.error(
            f"🔑🚨 Could not extract key details: {e}", extra={"error": str(e)}
        )
        raise CertificateError("Could not extract key details") from e

# 🐍🏗️🔌
