"""
Certificate Generation and Management.

This module provides the `Certificate` class for generating, loading,
and managing X.509 certificates for use in secure communication within
the Pyvider RPC Plugin system. It leverages the `cryptography` library
for underlying cryptographic operations.
"""

import os
import traceback
from datetime import UTC, datetime, timedelta
from enum import StrEnum, auto
from functools import cached_property
from pathlib import Path
from typing import NotRequired, Self, TypedDict, cast  # Added cast here

# Use attrs imports
from attrs import Factory, define, field
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Rename imported Certificate to avoid naming collision
from cryptography.x509 import Certificate as X509Certificate
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pyvider.rpcplugin.exception import CertificateError
from pyvider.telemetry import logger

# =============================================================================
# Supported Key Types and Curve Types
# =============================================================================


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
    # Add validity dates here if they need to be passed explicitly
    not_valid_before: datetime
    not_valid_after: datetime
    # Optional key generation parameters
    key_size: NotRequired[int]
    curve: NotRequired[CurveType]


type KeyPair = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
type PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey

# =============================================================================
# CertificateBase: Immutable certificate base data (already uses attrs)
# =============================================================================


@define(slots=True, frozen=True)
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
        """
        try:
            logger.debug("📜📝🚀 CertificateBase.create: Starting base creation.")
            # Use validity dates directly from the config dict
            not_valid_before = config["not_valid_before"]
            not_valid_after = config["not_valid_after"]

            # Ensure timezone awareness (redundant if already set, but safe)
            if not_valid_before.tzinfo is None:
                not_valid_before = not_valid_before.replace(tzinfo=UTC)
            if not_valid_after.tzinfo is None:
                not_valid_after = not_valid_after.replace(tzinfo=UTC)

            logger.debug(
                f"📜⏳✅ CertificateBase.create: Using validity: {not_valid_before} to {not_valid_after}"
            )

            # Generate the private key
            private_key: KeyPair  # Explicitly type hint private_key
            match config["key_type"]:
                case KeyType.RSA:
                    key_size = config.get("key_size", 2048)
                    logger.debug(f"📜🔑🚀 Generating RSA key (size: {key_size}).")
                    private_key = rsa.generate_private_key(
                        public_exponent=65537, key_size=key_size
                    )
                case KeyType.ECDSA:
                    curve_choice = config.get("curve", CurveType.SECP384R1)
                    logger.debug(
                        f"📜🔑🚀 Generating ECDSA key (curve: {curve_choice})."
                    )
                    curve = getattr(ec, curve_choice.name)()  # Get curve object
                    private_key = ec.generate_private_key(curve)
                case _:  # Should be validated before calling
                    raise ValueError(
                        f"Internal Error: Unsupported key type: {config['key_type']}"
                    )

            # Create subject and issuer names
            subject = cls._create_name(config["common_name"], config["organization"])
            issuer = cls._create_name(config["common_name"], config["organization"])

            # Generate a random serial number.
            serial_number = x509.random_serial_number()  # Use crypto library func
            logger.debug(f"📜🔑✅ Generated serial number: {serial_number}")

            base = cls(
                subject=subject,
                issuer=issuer,
                public_key=private_key.public_key(),
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                serial_number=serial_number,
            )
            logger.debug("📜📝✅ CertificateBase.create: Base creation complete.")
            return base, private_key

        except Exception as e:
            logger.error(
                f"📜❌ CertificateBase.create: Failed: {e}",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            # Wrap in CertificateError for consistent exception type
            raise CertificateError(f"Failed to generate certificate base: {e}") from e

    @staticmethod
    def _create_name(common_name: str, org: str) -> x509.Name:
        """Helper method to construct an X.509 name."""
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            ]
        )


# =============================================================================
# Certificate: Refactored main class using attrs
# =============================================================================


# Tell attrs *not* to generate default eq/hash methods, we provide our own.
# Also, set repr=False as we are providing a custom __repr__ method.
@define(slots=True, eq=False, hash=False, repr=False)
class Certificate:
    """
    Certificate: Encapsulates X.509 certificate functionality using attrs.

    Supports generating new certificates or loading existing PEM data.
    Initialization logic is handled in __attrs_post_init__.
    Provides properties for accessing certificate details and PEM strings.
    Implements custom __eq__ and __hash__ based on subject and serial number.
    """

    # --- Parameters for attrs constructor (keyword-only for clarity) ---
    cert_pem_or_uri: str | None = field(default=None, kw_only=True)
    key_pem_or_uri: str | None = field(default=None, kw_only=True)
    generate_keypair: bool = field(default=False, kw_only=True)
    key_type: str = field(default="ecdsa", kw_only=True)  # 'rsa' or 'ecdsa'
    key_size: int = field(default=2048, kw_only=True)  # For RSA
    ecdsa_curve: str = field(default="secp384r1", kw_only=True)  # For ECDSA
    common_name: str = field(default="localhost", kw_only=True)
    alt_names: list[str] | None = field(
        default=Factory(lambda: ["localhost"]), kw_only=True
    )
    organization_name: str = field(default="HashiCorp", kw_only=True)
    validity_days: int = field(default=365, kw_only=True)  # For generation

    # --- Internal state fields (not part of constructor, set in post_init) ---
    # Mark internal fields as non-representing for cleaner default repr
    _base: CertificateBase = field(init=False, repr=False)  # Underlying base data
    _private_key: KeyPair | None = field(
        init=False, default=None, repr=False
    )  # Actual key object
    _cert: X509Certificate = field(
        init=False, repr=False
    )  # Actual cryptography cert object
    _trust_chain: list["Certificate"] = field(init=False, factory=list, repr=False)

    # --- Public PEM representations (derived, set in post_init) ---
    # Let 'cert' (the PEM string) be part of the repr for identification
    cert: str = field(
        init=False, default="", repr=True
    )  # Public PEM certificate string
    # Keep key PEM out of repr
    key: str | None = field(
        init=False, default=None, repr=False
    )  # Public PEM key string (sensitive)

    def __attrs_post_init__(self) -> None:
        """
        Handles loading or generation logic after attrs initializes basic fields.
        """
        try:
            if self.generate_keypair:
                # --- Generate New Certificate ---
                logger.debug(
                    "📜🔑🚀 Certificate.__attrs_post_init__: Generating new keypair."
                )

                # Prepare config for CertificateBase.create
                now = datetime.now(UTC)  # Or use the existing import for timezone.utc

                # Set not_valid_before to be 1 day in the past to ensure immediate validity.
                not_valid_before = now - timedelta(days=1)
                # Set not_valid_after based on validity_days from now.
                not_valid_after = now + timedelta(days=self.validity_days)

                # Ensure that 'now' (for the purpose of the certificate's "creation moment" logging)
                # is still relevant or adjust if needed, though the key is the relation
                # between not_valid_before and not_valid_after for the cryptography library.
                # The existing 'now' variable is fine for general reference.

                # Validate self.key_type string and determine KeyType enum
                normalized_key_type_str = self.key_type.lower()
                match normalized_key_type_str:
                    case "rsa":
                        gen_key_type = KeyType.RSA
                    case "ecdsa":
                        gen_key_type = KeyType.ECDSA
                    case _:
                        # This will be caught by the general try-except in __attrs_post_init__
                        # and re-raised as a CertificateError.
                        raise ValueError(
                            f"Unsupported key_type string: '{self.key_type}'. Must be 'rsa' or 'ecdsa'."
                        )

                # gen_key_type is already set above
                gen_curve: CurveType | None = None
                gen_key_size = None

                if gen_key_type == KeyType.ECDSA:
                    try:
                        gen_curve = CurveType[self.ecdsa_curve.upper()]
                    except KeyError:
                        raise ValueError(
                            f"Unsupported ECDSA curve: {self.ecdsa_curve}"
                        )  # This will also be wrapped
                else:  # RSA
                    gen_key_size = self.key_size

                conf: CertificateConfig = {
                    "common_name": self.common_name,
                    "organization": self.organization_name,
                    "alt_names": self.alt_names or ["localhost"],  # Ensure list
                    "key_type": gen_key_type,  # Use the validated gen_key_type
                    # "curve": gen_curve, # Added conditionally below
                    # "key_size": gen_key_size, # Added conditionally below
                    "not_valid_before": not_valid_before,
                    "not_valid_after": not_valid_after,
                }
                if gen_curve is not None:
                    conf["curve"] = gen_curve
                if gen_key_size is not None:
                    conf["key_size"] = gen_key_size
                logger.debug(f"📜🔑🚀 Generation config: {conf}")

                # Create base info and private key
                self._base, self._private_key = CertificateBase.create(conf)

                # Create the X.509 certificate object using the base and key
                # For self-signed, it's typically a CA, and not specifically a client cert by default.
                self._cert = self._create_x509_certificate(
                    is_ca=False, is_client_cert=True # MODIFIED FOR CLIENT CERT
                )

                # Store public PEM representations
                if (
                    self._cert is None
                ):  # Should not happen if _create_x509_certificate is correct
                    raise CertificateError(
                        "Certificate object (_cert) is None after creation."
                    )
                self.cert = self._cert.public_bytes(serialization.Encoding.PEM).decode(
                    "utf-8"
                )
                if self._private_key:  # Ensure private key exists before encoding
                    self.key = self._private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    ).decode("utf-8")
                else:
                    self.key = None  # Should not happen if generate_keypair is True

                logger.debug(
                    "📜🔑✅ Certificate.__attrs_post_init__: Generated cert and key."
                )

            else:
                # --- Load Existing Certificate ---
                if not self.cert_pem_or_uri:
                    raise CertificateError(
                        "cert_pem_or_uri required when not generating"
                    )

                logger.debug("📜🔑🚀 Loading certificate from provided data.")
                cert_data = self._load_from_uri_or_pem(self.cert_pem_or_uri)
                self.cert = cert_data  # Store raw PEM provided

                # Load the cryptography certificate object
                logger.debug(
                    f"📜🔑🔍 Attempting to load X.509 certificate from PEM data (first 100 chars): {cert_data[:100]}"
                )
                logger.debug(
                    f"📜🔑🔍 Full PEM data for cert (len {len(cert_data)}):\n{cert_data}"
                )
                self._cert = x509.load_pem_x509_certificate(cert_data.encode("utf-8"))
                logger.debug("📜🔑✅ X.509 certificate object loaded from PEM.")

                # Load the private key if provided
                if self.key_pem_or_uri:
                    logger.debug("📜🔑🚀 Loading private key.")
                    key_data = self._load_from_uri_or_pem(self.key_pem_or_uri)
                    self.key = key_data  # Store raw PEM provided
                    logger.debug(
                        f"📜🔑🔍 Attempting to load private key from PEM data (first 100 chars): {key_data[:100]}"
                    )
                    logger.debug(
                        f"📜🔑🔍 Full PEM data for key (len {len(key_data)}):\n{key_data}"
                    )
                    loaded_priv_key = load_pem_private_key(
                        key_data.encode("utf-8"), password=None
                    )
                    if not isinstance(
                        loaded_priv_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)
                    ):
                        raise CertificateError(
                            f"Loaded private key is of unsupported type: {type(loaded_priv_key)}. "
                            "Expected RSA or ECDSA private key."
                        )
                    self._private_key = loaded_priv_key
                    logger.debug("📜🔑✅ Private key object loaded and type validated.")
                else:
                    self.key = None  # Explicitly None if not loaded

                # Reconstruct the CertificateBase from the loaded certificate object
                # Ensure dates are timezone-aware
                loaded_not_valid_before = self._cert.not_valid_before_utc
                loaded_not_valid_after = self._cert.not_valid_after_utc
                if loaded_not_valid_before.tzinfo is None:
                    loaded_not_valid_before = loaded_not_valid_before.replace(
                        tzinfo=UTC
                    )
                if loaded_not_valid_after.tzinfo is None:
                    loaded_not_valid_after = loaded_not_valid_after.replace(tzinfo=UTC)

                cert_public_key = self._cert.public_key()
                if not isinstance(
                    cert_public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)
                ):
                    raise CertificateError(
                        f"Certificate's public key is of unsupported type: {type(cert_public_key)}. "
                        "Expected RSA or ECDSA public key."
                    )

                self._base = CertificateBase(
                    subject=self._cert.subject,
                    issuer=self._cert.issuer,
                    public_key=cert_public_key,  # Use validated public key
                    not_valid_before=loaded_not_valid_before,
                    not_valid_after=loaded_not_valid_after,
                    serial_number=self._cert.serial_number,
                )
                logger.debug("📜🔑✅ Reconstructed CertificateBase from loaded cert.")

        except Exception as e:
            # Log original error clearly
            logger.error(
                f"📜❌ Certificate.__attrs_post_init__: Failed. Error: {type(e).__name__}: {e}",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            # Re-raise as CertificateError for consistency
            raise CertificateError(
                f"Failed to initialize certificate. Original error: {type(e).__name__}"
            ) from e

    def _create_x509_certificate(
        self,
        issuer_name_override: x509.Name | None = None,
        signing_key_override: KeyPair | None = None,
        is_ca: bool = False,
        is_client_cert: bool = False,
    ) -> X509Certificate:
        """
        Internal helper to build and sign the X.509 certificate object.
        Uses self._base and self._private_key (or overrides) which must be set beforehand.

        Args:
            issuer_name_override: If provided, use this as the issuer name.
            signing_key_override: If provided, use this private key for signing.
            is_ca: Whether this certificate should be marked as a CA.
            is_client_cert: Whether this certificate is for client authentication.

        Returns:
            The generated X509Certificate object.

        Raises:
            CertificateError: If prerequisites are missing or signing fails.
        """
        if not hasattr(self, "_base"):  # Defensive check
            raise CertificateError(
                "Cannot create certificate without base information."
            )

        try:
            logger.debug("📜📝🚀 _create_x509_certificate: Building certificate.")

            actual_issuer_name = (
                issuer_name_override if issuer_name_override else self._base.issuer
            )
            actual_signing_key = (
                signing_key_override if signing_key_override else self._private_key
            )

            if not actual_signing_key:
                raise CertificateError(
                    "Cannot sign certificate without a signing key (either own or override)."
                )

            builder = (
                x509.CertificateBuilder()
                .subject_name(self._base.subject)
                .issuer_name(actual_issuer_name)
                .public_key(self._base.public_key)
                .serial_number(self._base.serial_number)
                .not_valid_before(self._base.not_valid_before)
                .not_valid_after(self._base.not_valid_after)
            )

            # Add Subject Alternative Names (SANs)
            san_list = [x509.DNSName(name) for name in (self.alt_names or []) if name]
            if san_list:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_list), critical=False
                )
                logger.debug(f"📜📝✅ Added SANs: {self.alt_names or []}")

            # --- Add standard extensions based on certificate type ---
            builder = builder.add_extension(
                x509.BasicConstraints(
                    ca=is_ca, path_length=None
                ),  # path_length is None for non-CA or CA with no limit
                critical=True,
            )

            if is_ca:
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=False,  # CA key usage differs
                        key_encipherment=False,
                        key_agreement=False,
                        content_commitment=False,
                        data_encipherment=False,
                        key_cert_sign=True,  # Must be true for CA
                        crl_sign=True,  # Typically true for CA
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                # ExtendedKeyUsage is typically not set or has specific CA usages if needed,
                # but for simplicity, we can omit it for a self-signed CA being generated here.
                # If it were signing, ExtendedKeyUsage might be relevant.
            else:  # End-entity certificate
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True,  # Required for TLS
                        key_encipherment=True
                        if not is_client_cert
                        and isinstance(self._base.public_key, rsa.RSAPublicKey)
                        else False,  # For server RSA key exchange
                        key_agreement=True
                        if isinstance(self._base.public_key, ec.EllipticCurvePublicKey)
                        else False,  # For ECDH
                        content_commitment=False,
                        data_encipherment=False,
                        key_cert_sign=False,  # Must be false for end-entity
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                extended_usages = []
                if is_client_cert:
                    extended_usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
                else:  # Server certificate or other non-client end-entity
                    extended_usages.append(ExtendedKeyUsageOID.SERVER_AUTH)

                if extended_usages:  # Only add if there are usages specified
                    builder = builder.add_extension(
                        x509.ExtendedKeyUsage(extended_usages),
                        critical=False,
                    )

            logger.debug(
                f"📜📝✅ Added BasicConstraints (is_ca={is_ca}), KeyUsage, ExtendedKeyUsage (is_client_cert={is_client_cert})."
            )

            # Sign the certificate
            signed_cert = builder.sign(
                private_key=actual_signing_key,
                algorithm=hashes.SHA256(),  # Consider SHA384 for ECDSA P-384 keys if policy dictates
                backend=default_backend(),
            )
            logger.debug("📜📝✅ Certificate signed successfully.")
            return signed_cert

        except Exception as e:
            logger.error(
                f"📜❌ _create_x509_certificate: Failed: {e}",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise CertificateError("Failed to create X.509 certificate object") from e

    @staticmethod
    def _load_from_uri_or_pem(data: str) -> str:
        """
        Loads PEM data either directly from a string or from a file URI.

        If the `data` string starts with "file://", it's treated as a URI,
        and the certificate/key data is read from the specified file.
        Otherwise, the data string itself is assumed to be the PEM content.
        The method also strips leading/trailing whitespace.

        Args:
            data: The PEM data string or a file URI (e.g., "file:///path/to/cert.pem").

        Returns:
            The loaded PEM data as a string.

        Raises:
            CertificateError: If loading from a file URI fails or the data is invalid.
        """
        try:
            if data.startswith("file://"):
                path_str = data.removeprefix("file://")
                if os.name == "nt" and path_str.startswith("//"):
                    path = Path(path_str)
                else:
                    path_str = path_str.lstrip("/")
                    if os.name != "nt" and data.startswith("file:///"):
                        path_str = "/" + path_str
                    path = Path(path_str)

                logger.debug(f"📜📂🚀 Loading data from file: {path}")
                with path.open("r", encoding="utf-8") as f:
                    loaded_data = f.read().strip()
                logger.debug("📜📂✅ Loaded data from file.")
                return loaded_data

            loaded_data = data.strip()
            if not loaded_data.startswith("-----BEGIN"):
                logger.warning("📜📂⚠️ Data doesn't look like PEM format.")
            return loaded_data
        except Exception as e:
            logger.error(f"📜📂❌ Failed to load data: {e}", extra={"error": str(e)})
            raise CertificateError(f"Failed to load data: {e}") from e

    # --- Properties ---
    @property
    def trust_chain(self) -> list["Certificate"]:
        """Returns the list of trusted certificates associated with this one."""
        return self._trust_chain

    @trust_chain.setter
    def trust_chain(self, value: list["Certificate"]) -> None:
        """Sets the list of trusted certificates."""
        self._trust_chain = value

    @cached_property
    def is_valid(self) -> bool:
        """Checks if the certificate is currently valid based on its dates."""
        if not hasattr(self, "_base"):  # Check if base exists
            return False
        now = datetime.now(UTC)
        valid = self._base.not_valid_before <= now <= self._base.not_valid_after
        return valid

    @property
    def is_ca(self) -> bool:
        """Checks if the certificate has the Basic Constraints CA flag set to True."""
        if not hasattr(self, "_cert"):  # Check if cert obj exists
            return False
        try:
            ext = self._cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            if isinstance(ext.value, x509.BasicConstraints):
                return ext.value.ca
            return False
        except x509.ExtensionNotFound:
            logger.debug("📜🔍⚠️ is_ca: Basic Constraints extension not found.")
            return False

    @property
    def subject(self) -> str:
        """Returns the certificate subject as an RFC4514 string."""
        if not hasattr(self, "_base"):
            return "SubjectNotInitialized"
        return self._base.subject.rfc4514_string()

    @property
    def issuer(self) -> str:
        """Returns the certificate issuer as an RFC4514 string."""
        if not hasattr(self, "_base"):
            return "IssuerNotInitialized"
        return self._base.issuer.rfc4514_string()

    @property
    def public_key(self) -> PublicKey | None:
        """Returns the public key object from the certificate."""
        if not hasattr(self, "_base"):
            return None
        return self._base.public_key

    @property
    def serial_number(self) -> int | None:
        """Returns the certificate serial number."""
        if not hasattr(self, "_base"):
            return None
        return self._base.serial_number

    # --- Core Logic Methods ---
    # _create_x509_certificate is defined above by the previous SEARCH/REPLACE block

    @classmethod
    def create_ca(
        cls,
        common_name: str,
        organization_name: str,
        validity_days: int,
        key_type: str = "ecdsa",
        key_size: int = 2048,
        ecdsa_curve: str = "secp384r1",
    ) -> "Certificate":
        """
        Creates a new self-signed CA certificate.
        """
        logger.info(
            f"📜🔑🏭 Creating new CA certificate: CN={common_name}, Org={organization_name}"
        )
        # __attrs_post_init__ will call _create_x509_certificate.
        # The first fix makes it (is_ca=False, is_client_cert=True) initially.
        ca_cert_obj = cls(
            generate_keypair=True,
            common_name=common_name,
            organization_name=organization_name,
            validity_days=validity_days,
            key_type=key_type,
            key_size=key_size,
            ecdsa_curve=ecdsa_curve,
            alt_names=[common_name],  # CA often has its CN as SAN
        )
        # Explicitly re-sign to ensure CA flags are correctly set for a CA
        logger.info("📜🔑🏭 Re-signing generated CA certificate to ensure is_ca=True, is_client_cert=False flags.")
        actual_ca_x509_cert = ca_cert_obj._create_x509_certificate(
            is_ca=True, is_client_cert=False # Correct CA flags
        )
        ca_cert_obj._cert = actual_ca_x509_cert
        ca_cert_obj.cert = actual_ca_x509_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return ca_cert_obj

    @classmethod
    def create_signed_certificate(
        cls,
        ca_certificate: "Certificate",
        common_name: str,
        organization_name: str,
        validity_days: int,
        alt_names: list[str] | None = None,
        key_type: str = "ecdsa",
        key_size: int = 2048,
        ecdsa_curve: str = "secp384r1",
        is_client_cert: bool = False,
    ) -> "Certificate":
        """
        Creates a new certificate signed by the provided CA certificate.
        """
        logger.info(
            f"📜🔑🏭 Creating new certificate signed by CA '{ca_certificate.subject}': "
            f"CN={common_name}, Org={organization_name}, ClientCert={is_client_cert}"
        )
        if not ca_certificate._private_key:
            raise CertificateError(
                message="CA certificate's private key is not available for signing.",
                hint="Ensure the CA certificate object was loaded or created with its private key.",
            )
        if not ca_certificate.is_ca:
            logger.warning(
                f"📜🔑⚠️ Signing certificate (Subject: {ca_certificate.subject}) is not marked as a CA. This might lead to validation issues."
            )

        # 1. Create a new certificate object - this will generate a new keypair and base attributes
        new_cert_obj = cls(
            generate_keypair=True,  # Important: new keypair for the new cert
            common_name=common_name,
            organization_name=organization_name,
            validity_days=validity_days,
            alt_names=alt_names
            or [common_name],  # Default SAN to common_name if not provided
            key_type=key_type,
            key_size=key_size,
            ecdsa_curve=ecdsa_curve,
        )

        # 2. Re-sign this new certificate using the CA's details
        # The _base object of new_cert_obj has the correct subject, serial, public_key, validity for the new cert.
        # We override the issuer and signing key with the CA's.
        signed_x509_cert = new_cert_obj._create_x509_certificate(
            issuer_name_override=ca_certificate._base.subject,  # CA's subject is the new cert's issuer
            signing_key_override=ca_certificate._private_key,  # CA's private key signs it
            is_ca=False,  # This new cert is an end-entity cert, not a CA
            is_client_cert=is_client_cert,
        )

        # 3. Update the new_cert_obj with the CA-signed X509Certificate and its PEM representation
        new_cert_obj._cert = signed_x509_cert
        new_cert_obj.cert = signed_x509_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode("utf-8")

        # Optionally, link the CA to the new certificate's trust chain (conceptual)
        # new_cert_obj._trust_chain.append(ca_certificate) # This depends on how trust_chain is used

        logger.info(
            f"📜🔑✅ Successfully created and signed certificate for CN={common_name} by CA='{ca_certificate.subject}'"
        )
        return new_cert_obj

    @classmethod
    def create_self_signed_server_cert(
        cls,
        common_name: str,
        organization_name: str,
        validity_days: int,
        alt_names: list[str] | None = None,
        key_type: str = "ecdsa",
        key_size: int = 2048,
        ecdsa_curve: str = "secp384r1",
    ) -> "Certificate":
        """
        Creates a new self-signed end-entity certificate suitable for a server.
        """
        logger.info(
            f"📜🔑🏭 Creating new self-signed SERVER certificate: CN={common_name}, Org={organization_name}"
        )

        cert_obj = cls(
            generate_keypair=True,
            common_name=common_name,
            organization_name=organization_name,
            validity_days=validity_days,
            alt_names=alt_names or [common_name],
            key_type=key_type,
            key_size=key_size,
            ecdsa_curve=ecdsa_curve,
        )

        if not cert_obj._private_key:
            raise CertificateError(
                "Private key not generated for self-signed server certificate."
            )

        actual_x509_cert = cert_obj._create_x509_certificate(
            is_ca=False,  # Self-signed server cert is NOT a CA
            is_client_cert=False,  # It's a server cert
        )

        cert_obj._cert = actual_x509_cert
        # Ensure cert_obj.cert (the PEM string) is updated from the newly created _cert object
        cert_obj.cert = actual_x509_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode("utf-8")

        logger.info(
            f"📜🔑✅ Successfully created self-signed SERVER certificate for CN={common_name}"
        )
        return cert_obj

    def verify_trust(self, other_cert: Self) -> bool:
        """Verifies if the `other_cert` is trusted based on this certificate's trust chain."""
        if other_cert is None:
            raise CertificateError("Cannot verify trust: other_cert is None")

        # Now it's safe to access other_cert attributes
        logger.debug(
            f"📜🔍🚀 Verifying trust for cert S/N {other_cert.serial_number} against chain of S/N {self.serial_number}"
        )

        if not other_cert.is_valid:
            logger.debug(
                "📜🔍⚠️ Trust verification failed: Other certificate is not valid."
            )
            return False
        if not other_cert.public_key:
            raise CertificateError(
                "Cannot verify trust: Other certificate has no public key."
            )

        # Check 1: Is it the same certificate? (Uses custom __eq__)
        if self == other_cert:
            logger.debug(
                "📜🔍✅ Trust verified: Certificates are identical (based on subject/serial)."
            )
            return True

        # Check 2: Is the other certificate directly in our trust chain? (Uses custom __eq__)
        if other_cert in self._trust_chain:
            logger.debug(
                "📜🔍✅ Trust verified: Other certificate found in trust chain."
            )
            return True

        # Check 3: Is the other certificate signed by *any* certificate in our trust chain?
        for trusted_cert in self._trust_chain:
            logger.debug(
                f"📜🔍🔁 Checking signature against trusted cert S/N {trusted_cert.serial_number}"
            )
            if self._validate_signature(
                signed_cert=other_cert, signing_cert=trusted_cert
            ):
                logger.debug(
                    f"📜🔍✅ Trust verified: Other cert signed by trusted cert S/N {trusted_cert.serial_number}."
                )
                return True

        logger.debug(
            "📜🔍❌ Trust verification failed: Other certificate not identical, not in chain, and not signed by any cert in chain."
        )
        return False

    def _validate_signature(
        self, signed_cert: "Certificate", signing_cert: "Certificate"
    ) -> bool:
        """Internal helper: Validates signature and issuer/subject match."""
        if not hasattr(signed_cert, "_cert") or not hasattr(signing_cert, "_cert"):
            logger.error(
                "📜🔍❌ Cannot validate signature: Certificate object(s) not initialized."
            )
            return False

        # Check Issuer(signed) == Subject(signing) using the Name objects
        if signed_cert._cert.issuer != signing_cert._cert.subject:
            logger.debug(
                f"📜🔍❌ Signature validation failed: Issuer/Subject mismatch. "
                f"Signed Issuer='{signed_cert._cert.issuer}', "
                f"Signing Subject='{signing_cert._cert.subject}'"
            )
            return False

        try:
            signing_public_key = signing_cert.public_key
            if not signing_public_key:
                logger.error(
                    "📜🔍❌ Cannot validate signature: Signing certificate has no public key."
                )
                return False

            signature = signed_cert._cert.signature
            tbs_certificate_bytes = signed_cert._cert.tbs_certificate_bytes
            signature_hash_algorithm = signed_cert._cert.signature_hash_algorithm

            if not signature_hash_algorithm:
                logger.error(
                    "📜🔍❌ Cannot validate signature: Unknown hash algorithm."
                )
                return False

            match type(signing_public_key):
                case rsa.RSAPublicKey:
                    cast(rsa.RSAPublicKey, signing_public_key).verify(
                        signature,
                        tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        signature_hash_algorithm,
                    )
                case ec.EllipticCurvePublicKey:
                    cast(ec.EllipticCurvePublicKey, signing_public_key).verify(
                        signature,
                        tbs_certificate_bytes,
                        ec.ECDSA(signature_hash_algorithm),
                    )
                case _:
                    logger.error(
                        f"📜🔍❌ Unsupported signing public key type: {type(signing_public_key)}"
                    )
                    return False

            return True

        except Exception as e:  # Catches crypto InvalidSignature errors
            logger.debug(f"📜🔍❌ Signature validation failed: {type(e).__name__}: {e}")
            return False

    # --- Custom __eq__ and __hash__ to replicate original behavior ---
    def __eq__(self, other: object) -> bool:
        """Custom equality based on subject and serial number."""
        if not isinstance(other, Certificate):
            return NotImplemented
        # Ensure _base is initialized on both objects before comparing
        if not hasattr(self, "_base") or not hasattr(other, "_base"):
            # If not initialized, they cannot be equal in this context
            return False
        # Compare using the Name object directly for subject
        eq = (
            self._base.subject == other._base.subject
            and self._base.serial_number == other._base.serial_number
        )
        # logger.debug(f"📜🔍✅ __eq__ result: {eq}") # Too verbose
        return eq

    def __hash__(self) -> int:
        """Custom hash based on subject and serial number."""
        # Ensure _base is initialized before hashing
        if not hasattr(self, "_base"):
            # Return a default hash or raise error if called before init?
            # Returning 0 might group uninitialized objects, raising is safer maybe?
            # For consistency with __eq__, let's use a default hash for uninitialized.
            logger.warning("📜🔍⚠️ __hash__ called before _base initialized.")
            return hash((None, None))  # Or some other constant tuple

        # Hash the Name object directly for subject
        h = hash((self._base.subject, self._base.serial_number))
        # logger.debug(f"📜🔍✅ __hash__ value: {h}") # Too verbose
        return h

    # __repr__ is now handled by attrs, using fields marked repr=True

    def __repr__(self) -> str:
        # Use try-except or hasattr to gracefully handle cases where _base or _cert might not be fully initialized
        # (e.g., if repr is called on a partially constructed object, though less likely for this test)
        try:
            subject_str = self.subject  # Relies on self._base
            issuer_str = self.issuer  # Relies on self._base
            valid_str = str(self.is_valid)  # Relies on self._cert (via self._base)
            ca_str = str(self.is_ca)  # Relies on self._cert
        except AttributeError:
            subject_str = "PartiallyInitialized"
            issuer_str = "PartiallyInitialized"
            valid_str = "Unknown"
            ca_str = "Unknown"

        return (
            f"Certificate(subject='{subject_str}', issuer='{issuer_str}', "
            f"common_name='{self.common_name}', valid={valid_str}, ca={ca_str}, "
            f"key_type='{self.key_type}')"
        )


# 🐍🏗️🔌
