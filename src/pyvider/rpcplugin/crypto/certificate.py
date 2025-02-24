# pyvider/rpcplugin/crypto/certificate.py

import os
from datetime import UTC, datetime, timedelta
from enum import StrEnum, auto
from functools import cached_property
from pathlib import Path
from typing import NotRequired, Self, TypedDict

import attrs
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pyvider.rpcplugin.exception import CertificateError
from pyvider.rpcplugin.logger import logger

# =============================================================================
# Supported Key Types and Curve Types
# ====================================================================:=========


class KeyType(StrEnum):
    RSA = auto()
    ECDSA = auto()


class CurveType(StrEnum):
    SECP256R1 = auto()
    SECP384R1 = auto()
    SECP521R1 = auto()


# =============================================================================
# CertificateConfig: Dictionary for certificate generation settings.
# =============================================================================


class CertificateConfig(TypedDict):
    common_name: str
    organization: str
    alt_names: list[str]
    key_type: KeyType
    validity_days: NotRequired[int]
    key_size: NotRequired[int]
    curve: NotRequired[CurveType]


type KeyPair = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
type PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey

# =============================================================================
# CertificateBase: Immutable certificate base data
# =============================================================================


@attrs.define(slots=True, frozen=True)
class CertificateBase:
    """Immutable base certificate data."""

    subject: x509.Name
    issuer: x509.Name
    public_key: PublicKey
    not_valid_before: datetime
    not_valid_after: datetime
    serial_number: int

    @classmethod
    def create(cls, config: CertificateConfig) -> tuple[Self, KeyPair]:
        """
        📜📝🚀 CertificateBase.create: Create a new certificate base and private key.

        Logs:
          - Current UTC time and validity period settings.
          - Key generation (RSA/ECDSA) parameters.
          - Creation of subject/issuer names.
          - Generation of a random serial number.

        Raises:
          CertificateError: If any step of the creation fails.
        """
        try:
            logger.debug(
                "📜📝🚀 CertificateBase.create: Starting certificate base creation."
            )
            now = datetime.now(UTC)
            logger.debug(f"📜⏳✅ CertificateBase.create: Current UTC time: {now}")

            # Get validity period from config or set defaults.
            not_valid_before = config.get("not_valid_before", now)
            not_valid_after = config.get(
                "not_valid_after", not_valid_before + timedelta(days=365)
            )
            logger.debug(
                f"📜⏳✅ CertificateBase.create: Validity period: before={not_valid_before}, after={not_valid_after}"
            )

            # Ensure both dates are timezone-aware.
            if not_valid_before.tzinfo is None:
                not_valid_before = not_valid_before.replace(tzinfo=UTC)
                logger.debug(
                    "📜⏳✅ CertificateBase.create: Adjusted not_valid_before to UTC."
                )
            if not_valid_after.tzinfo is None:
                not_valid_after = not_valid_after.replace(tzinfo=UTC)
                logger.debug(
                    "📜⏳✅ CertificateBase.create: Adjusted not_valid_after to UTC."
                )

            # Generate the private key according to the specified type.
            match config["key_type"]:
                case KeyType.RSA:
                    key_size = config.get("key_size", 2048)
                    logger.debug(
                        f"📜🔑🚀 CertificateBase.create: Generating RSA key (size: {key_size})."
                    )
                    private_key = rsa.generate_private_key(
                        public_exponent=65537, key_size=key_size
                    )
                case KeyType.ECDSA:
                    curve_choice = config.get("curve", CurveType.SECP384R1)
                    logger.debug(
                        f"📜🔑🚀 CertificateBase.create: Generating ECDSA key (curve: {curve_choice})."
                    )
                    curve = getattr(ec, curve_choice.name)()
                    private_key = ec.generate_private_key(curve)
                case _:
                    logger.error(
                        f"📜❌ CertificateBase.create: Unsupported key type: {config['key_type']}"
                    )
                    raise ValueError(f"Unsupported key type: {config['key_type']}")

            # Create subject and issuer names.
            subject = cls._create_name(config["common_name"], config["organization"])
            issuer = cls._create_name(config["common_name"], config["organization"])
            logger.debug(
                f"📜📝✅ CertificateBase.create: Created subject and issuer: {subject}"
            )

            # Generate a random serial number.
            serial_number = int.from_bytes(os.urandom(16), "big")
            logger.debug(
                f"📜🔑✅ CertificateBase.create: Generated serial number: {serial_number}"
            )

            base = cls(
                subject=subject,
                issuer=issuer,
                public_key=private_key.public_key(),
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                serial_number=serial_number,
            )
            logger.debug(
                "📜📝✅ CertificateBase.create: Certificate base creation completed successfully."
            )
            return base, private_key

        except Exception as e:
            logger.error(
                f"📜❌ CertificateBase.create: Failed to create certificate base: {e}",
                extra={"error": str(e)},
            )
            raise CertificateError(f"Failed to generate certificate: {e}")

    @staticmethod
    def _create_name(common_name: str, org: str) -> x509.Name:
        """
        📜📝🚀 _create_name: Helper method to construct an X.509 name.

        Returns:
          An x509.Name object with the common name and organization.
        """
        logger.debug(
            f"📜📝🚀 _create_name: Creating name with common_name='{common_name}', organization='{org}'."
        )
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            ]
        )


# =============================================================================
# Certificate: Backward compatibility layer for certificate management.
# =============================================================================


class Certificate:
    """
    Certificate: Encapsulates X.509 certificate functionality.

    This class supports generating new certificates or loading existing PEM data.
    All major operations are logged in detail.
    """

    def __init__(
        self,
        cert: str | None = None,
        key: str | None = None,
        generate_keypair: bool = False,
        key_type: str = "ecdsa",
        key_size: int = 2048,
        ecdsa_curve: str = "secp384r1",
        common_name: str = "localhost",
        alt_names: list[str] = None,
        organization_name: str = "HashiCorp",
        **kwargs,
    ) -> None:
        try:
            if generate_keypair:
                logger.debug(
                    "📜🔑🚀 Certificate.__init__: Generating new keypair as requested."
                )
                conf: CertificateConfig = {
                    "common_name": common_name,
                    "organization": organization_name,
                    "alt_names": alt_names or ["localhost"],
                    "key_type": KeyType.ECDSA
                    if key_type.lower() == "ecdsa"
                    else KeyType.RSA,
                    "key_size": key_size if key_type.lower() == "rsa" else None,
                    "curve": CurveType[ecdsa_curve.upper()]
                    if key_type.lower() == "ecdsa"
                    else None,
                    "not_valid_before": kwargs.get(
                        "not_valid_before", datetime.now(UTC)
                    ),
                    "not_valid_after": kwargs.get(
                        "not_valid_after", datetime.now(UTC) + timedelta(days=365)
                    ),
                }
                logger.debug(
                    f"📜🔑🚀 Certificate.__init__: Keypair generation config: {conf}"
                )
                base, private_key = CertificateBase.create(conf)
                self._base = base
                self._private_key = private_key
                self._cert = self._create_x509_certificate()
                self.cert = self._cert.public_bytes(serialization.Encoding.PEM).decode()
                self.key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode()
                logger.debug(
                    "📜🔑✅ Certificate.__init__: Generated certificate and key converted to PEM successfully."
                )
            else:
                if not cert:
                    logger.error(
                        "📜❌ Certificate.__init__: No certificate data provided."
                    )
                    raise CertificateError("Certificate data required")
                logger.debug(
                    "📜🔑🚀 Certificate.__init__: Loading certificate from provided data."
                )
                cert_data = self._load_from_uri_or_pem(cert)
                x509_cert = x509.load_pem_x509_certificate(cert_data.encode())
                logger.debug(
                    "📜🔑✅ Certificate.__init__: X.509 certificate loaded successfully from PEM."
                )

                key_data = None
                private_key = None
                if key:
                    logger.debug(
                        "📜🔑🚀 Certificate.__init__: Loading private key from provided data."
                    )
                    key_data = self._load_from_uri_or_pem(key)
                    private_key = load_pem_private_key(key_data.encode(), password=None)
                    logger.debug(
                        "📜🔑✅ Certificate.__init__: Private key loaded successfully."
                    )

                self._base = CertificateBase(
                    subject=x509_cert.subject,
                    issuer=x509_cert.issuer,
                    public_key=x509_cert.public_key(),
                    not_valid_before=(
                        x509_cert.not_valid_before_utc.replace(tzinfo=UTC)
                        if x509_cert.not_valid_before_utc.tzinfo is None
                        else x509_cert.not_valid_before_utc
                    ),
                    not_valid_after=(
                        x509_cert.not_valid_after_utc.replace(tzinfo=UTC)
                        if x509_cert.not_valid_after_utc.tzinfo is None
                        else x509_cert.not_valid_after_utc
                    ),
                    serial_number=x509_cert.serial_number,
                )
                self._private_key = private_key
                self._cert = x509_cert
                self.cert = cert_data
                self.key = key_data
                logger.debug(
                    "📜🔑✅ Certificate.__init__: Loaded certificate and key from PEM successfully."
                )

                # Log certificate details (this may raise an error if extraction fails)
                self.display_cert_details()

            self._trust_chain = []
            logger.debug("📜📝✅ Certificate.__init__: Trust chain initialized.")

        except Exception as e:
            logger.error(
                f"📜❌ Certificate.__init__: Failed to initialize certificate: {e}",
                extra={"error": str(e)},
            )
            raise CertificateError(f"Failed to initialize certificate: {e}")

    def _create_x509_certificate(self) -> x509.Certificate:
        """
        📜📝🚀 _create_x509_certificate: Builds and signs an X.509 certificate.

        Steps:
          1. Calculate validity period.
          2. Initialize the certificate builder with subject, issuer, public key, serial number, and validity.
          3. Add extensions: Basic Constraints, Key Usage, and Extended Key Usage.
          4. Log key details.
          5. Sign the certificate using SHA512.

        Raises:
          CertificateError: On any failure during the building or signing process.
        """
        try:
            logger.debug(
                "📜📝🚀 _create_x509_certificate: Starting certificate creation process."
            )
            try:
                now = datetime.now(UTC)
                not_valid_before = now - timedelta(seconds=30)
                # Set expiration 30 years from now with a fixed hour.
                not_valid_after = now.replace(year=now.year + 30, hour=12)
                logger.debug(
                    f"📜⏳✅ _create_x509_certificate: Validity period: not_valid_before={not_valid_before}, not_valid_after={not_valid_after}"
                )
            except Exception as e:
                logger.error(
                    f"📜❌ _create_x509_certificate: Validity period calculation failed: {e}",
                    extra={"error": str(e)},
                )
                raise CertificateError(f"Failed to calculate validity period: {e}")

            builder = (
                x509.CertificateBuilder()
                .subject_name(self._base.subject)
                .issuer_name(self._base.issuer)
                .public_key(self._base.public_key)
                .serial_number(self._base.serial_number)
                .not_valid_before(not_valid_before)
                .not_valid_after(not_valid_after)
            )
            logger.debug(
                "📜📝🚀 _create_x509_certificate: Certificate builder initialized with base data."
            )

            # Add Subject Alternative Names (SANs)
            san = x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    # x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    # x509.IPAddress(ipaddress.IPv6Address("::1"))
                ]
            )
            builder = builder.add_extension(san, critical=False)
            logger.debug(
                "📜📝✅ _create_x509_certificate: Added Subject Alternative Names"
            )

            # Add Basic Constraints extension (indicates CA status).
            try:
                builder = builder.add_extension(
                    x509.BasicConstraints(ca=True, path_length=None), critical=True
                )
                logger.debug(
                    "📜📝✅ _create_x509_certificate: Added Basic Constraints extension."
                )
            except Exception as e:
                logger.error(
                    f"📜❌ _create_x509_certificate: Failed to add Basic Constraints extension: {e}",
                    extra={"error": str(e)},
                )
                raise CertificateError(
                    "Failed to add Basic Constraints extension"
                ) from e

            # Add Key Usage extension.
            try:
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=True,
                        key_cert_sign=True,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                logger.debug(
                    "📜📝✅ _create_x509_certificate: Added Key Usage extension."
                )
            except Exception as e:
                logger.error(
                    f"📜❌ _create_x509_certificate: Failed to add Key Usage extension: {e}",
                    extra={"error": str(e)},
                )
                raise CertificateError("Failed to add Key Usage extension") from e

            # Add Extended Key Usage extension.
            try:
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage(
                        [
                            ExtendedKeyUsageOID.CLIENT_AUTH,
                            ExtendedKeyUsageOID.SERVER_AUTH,
                        ]
                    ),
                    critical=False,
                )
                logger.debug(
                    "📜📝✅ _create_x509_certificate: Added Extended Key Usage extension."
                )
            except Exception as e:
                logger.error(
                    f"📜❌ _create_x509_certificate: Failed to add Extended Key Usage extension: {e}",
                    extra={"error": str(e)},
                )
                raise CertificateError(
                    "Failed to add Extended Key Usage extension"
                ) from e

            # Log private key details for debugging.
            self.display_key_details()

            # Sign the certificate.
            try:
                signed_cert = builder.sign(
                    private_key=self._private_key,
                    algorithm=hashes.SHA512(),
                    backend=default_backend(),
                )
                logger.debug(
                    "📜📝✅ _create_x509_certificate: Certificate signed successfully."
                )
                return signed_cert
            except Exception as e:
                logger.error(
                    f"📜❌ _create_x509_certificate: Failed to sign certificate: {e}",
                    extra={"error": str(e)},
                )
                raise CertificateError("Failed to sign certificate") from e

        except CertificateError:
            raise
        except Exception as e:
            logger.error(
                f"📜❌ _create_x509_certificate: Failed to create X.509 certificate: {e}",
                extra={"error": str(e)},
            )
            raise CertificateError(f"Failed to create X.509 certificate: {e}")

    @staticmethod
    def _load_from_uri_or_pem(data: str) -> str:
        """
        📜📂🚀 _load_from_uri_or_pem: Loads PEM data either from a file (if prefixed with 'file://')
        or directly from the provided string.

        Returns:
          The stripped PEM data as a string.

        Raises:
          CertificateError: If the data cannot be loaded.
        """
        try:
            if data.startswith("file://"):
                path = Path(data.replace("file://", ""))
                with path.open("r", encoding="utf-8") as f:
                    loaded_data = f.read().strip()
                    logger.debug(
                        "📜📂✅ _load_from_uri_or_pem: Loaded data from file.",
                        extra={"path": str(path)},
                    )
                    return loaded_data
            loaded_data = data.strip()
            logger.debug("📜📂✅ _load_from_uri_or_pem: Loaded data from PEM string.")
            return loaded_data
        except Exception as e:
            logger.error(
                f"📜📂❌ _load_from_uri_or_pem: Failed to load data: {e}",
                extra={"error": str(e)},
            )
            raise CertificateError(f"Failed to load data: {e}")

    @property
    def trust_chain(self) -> list["Certificate"]:
        logger.debug("📜📝✅ trust_chain: Retrieving trust chain.")
        return self._trust_chain

    @trust_chain.setter
    def trust_chain(self, value: list["Certificate"]) -> None:
        logger.debug("📜📝✅ trust_chain: Updating trust chain.")
        self._trust_chain = value

    @cached_property
    def is_valid(self) -> bool:
        """Check if the certificate is currently valid."""
        now = datetime.now(UTC)
        valid = self._base.not_valid_before <= now <= self._base.not_valid_after
        logger.debug(f"📜⏳✅ is_valid: Certificate validity check result: {valid}")
        return valid

    def verify_trust(self, other_cert: "Certificate") -> bool:
        """
        📜🔍🚀 verify_trust: Verifies that the other certificate is trusted.

        Checks if:
          - The other certificate is not None.
          - It is currently valid.
          - It has a public key.
          - It is either self-signed (and matches) or present/validated in the trust chain.

        Returns:
          True if trusted, False otherwise.

        Raises:
          CertificateError: If required fields are missing.
        """
        logger.debug("📜🔍🚀 verify_trust: Starting trust verification.")
        if other_cert is None:
            logger.error("📜🔍❌ verify_trust: Other certificate is None.")
            raise CertificateError("Cannot verify trust: other_cert is None")
        if not other_cert.is_valid:
            logger.debug(
                "📜🔍⚠️ verify_trust: Other certificate is not valid (expired or not yet valid)."
            )
            return False
        if other_cert.public_key is None:
            logger.error("📜🔍❌ verify_trust: Other certificate has no public key.")
            raise CertificateError("Unsupported public key algorithm: key is None")
        # If self-signed and identical, consider trusted.
        if self.subject == self.issuer and other_cert == self:
            logger.debug(
                "📜🔍✅ verify_trust: Self-signed certificate verified by itself."
            )
            return True
        if other_cert in self._trust_chain:
            logger.debug("📜🔍✅ verify_trust: Other certificate found in trust chain.")
            return True
        # Otherwise, validate against each certificate in the trust chain.
        for trusted in self._trust_chain:
            valid = self._validate_cert(trusted, other_cert)
            logger.debug(
                f"📜🔍🔁 verify_trust: Validation against a trusted certificate returned: {valid}"
            )
            if valid:
                return True
        logger.debug(
            "📜🔍❌ verify_trust: Certificate verification failed; certificate is not trusted."
        )
        return False

    def _validate_cert(self, trusted: "Certificate", other_cert: "Certificate") -> bool:
        """
        📜🔍🚀 _validate_cert: Validates the other certificate against a trusted certificate.

        Verifies:
          - That the trusted certificate’s issuer matches the other certificate’s subject.
          - That the signature on the other certificate is valid using the trusted certificate’s public key.

        Returns:
          True if validation is successful, False otherwise.
        """
        logger.debug(
            "📜🔍🚀 _validate_cert: Starting validation against trusted certificate."
        )
        if trusted._base.issuer != other_cert._base.subject:
            logger.debug(
                "📜🔍❌ _validate_cert: Issuer mismatch between trusted and other certificate."
            )
            return False
        try:
            public_key = trusted._base.public_key
            signature = other_cert._cert.signature
            data = other_cert._cert.tbs_certificate_bytes
            hash_algo = other_cert._cert.signature_hash_algorithm
            # Choose verification method based on key type.
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(signature, data, padding.PKCS1v15(), hash_algo)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, data, ec.ECDSA(hash_algo))
            else:
                logger.error(
                    "📜🔍❌ _validate_cert: Unsupported public key type for signature verification."
                )
                return False
            logger.debug(
                "📜🔍✅ _validate_cert: Certificate signature verified successfully."
            )
            return True
        except Exception as e:
            logger.error(
                f"📜🔍❌ _validate_cert: Signature verification failed: {e}",
                extra={"error": str(e)},
            )
            return False

    @property
    def is_ca(self) -> bool:
        """
        📜🔍🚀 is_ca: Determines whether the certificate is a Certificate Authority (CA).

        Returns:
          True if the certificate is a CA, False otherwise.
        """
        try:
            ext = self._cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            ca = ext.value.ca
            logger.debug(f"📜🔍✅ is_ca: Certificate CA flag: {ca}")
            return ca
        except (x509.ExtensionNotFound, AttributeError) as e:
            logger.error(
                f"📜🔍❌ is_ca: Failed to retrieve CA flag: {e}",
                extra={"error": str(e)},
            )
            return False

    @property
    def subject(self) -> str:
        """Legacy property: Returns the certificate subject as a string."""
        subject_str = self._base.subject.rfc4514_string()
        logger.debug(f"📜🔍✅ subject: {subject_str}")
        return subject_str

    @property
    def issuer(self) -> str:
        """Legacy property: Returns the certificate issuer as a string."""
        issuer_str = self._base.issuer.rfc4514_string()
        logger.debug(f"📜🔍✅ issuer: {issuer_str}")
        return issuer_str

    @property
    def public_key(self) -> PublicKey:
        logger.debug("📜🔑✅ public_key: Retrieving public key from certificate base.")
        return self._base.public_key

    def __repr__(self) -> str:
        """Return a consistent string representation of the certificate."""
        rep = f"<Certificate subject={self.subject} issuer={self.issuer} valid={self.is_valid} ca={self.is_ca}>"
        logger.debug(f"📜🔍✅ __repr__: {rep}")
        return rep

    def display_cert_details(self) -> None:
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

    def display_key_details(self) -> None:
        """
        🔑📂🚀 display_key_details: Logs private key details in a structured format.

        Logs:
          - The key type and size.
          - The PEM-encoded private key.

        Raises:
          CertificateError: If key details cannot be extracted.
        """
        key = self._private_key
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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Certificate):
            logger.debug("📜🔍❌ __eq__: Other object is not a Certificate.")
            return NotImplemented
        eq = (
            self._base.subject == other._base.subject
            and self._base.serial_number == other._base.serial_number
        )
        logger.debug(f"📜🔍✅ __eq__: Equality result: {eq}")
        return eq

    def __hash__(self) -> int:
        h = hash((self._base.subject, self._base.serial_number))
        logger.debug(f"📜🔍✅ __hash__: Hash value: {h}")
        return h

    def __repr__(self) -> str:
        """Return a consistent string representation of the certificate."""
        rep = f"<Certificate subject={self.subject} issuer={self.issuer} valid={self.is_valid} ca={self.is_ca}>"
        logger.debug(f"📜🔍✅ __repr__: {rep}")
        return rep
