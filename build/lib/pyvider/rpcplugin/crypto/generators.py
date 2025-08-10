#
# src/pyvider/rpcplugin/crypto/generators.py
#

"""
Cryptographic Key Generation Utilities.

This module provides functions for generating RSA and ECDSA key pairs,
leveraging the `cryptography` library. It includes validation against
supported key sizes and curve types defined in `crypto.constants`.
"""

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import constants
from .types import KeyPairType


def generate_rsa_keypair(key_size: int) -> KeyPairType:
    """
    Generates an RSA private/public key pair.

    Args:
        key_size: The desired key size in bits (e.g., 2048, 3072, 4096).

    Returns:
        A tuple containing the RSA public key and private key.

    Raises:
        ValueError: If the key_size is not supported (though validation
                    is expected upstream).
    """
    if key_size not in constants.SUPPORTED_RSA_SIZES:
        raise ValueError(
            f"Unsupported RSA key size: {key_size}. Supported: "
            f"{constants.SUPPORTED_RSA_SIZES}"
        )
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return public_key, private_key


def generate_ec_keypair(curve_name: str) -> KeyPairType:
    """
    Generates an ECDSA private/public key pair using a specified curve.

    Args:
        curve_name: The name of the EC curve to use (e.g., "SECP256R1").

    Returns:
        A tuple containing the EC public key and private key.

    Raises:
        ValueError: If the curve_name is not supported (though validation
                    is expected upstream).
        AttributeError: If the curve name does not correspond to a valid curve
                        in `cryptography.hazmat.primitives.asymmetric.ec`.
    """
    if curve_name not in constants.SUPPORTED_EC_CURVES:
        raise ValueError(
            f"Unsupported EC curve: {curve_name}. Supported: "
            f"{constants.SUPPORTED_EC_CURVES}"
        )
    curve = getattr(ec, curve_name.upper())()
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return public_key, private_key


def generate_keypair(
    key_type: str,
    key_size: int | None = None,
    curve_name: str | None = None,
) -> KeyPairType:
    """
    Generates a key pair of the specified type (RSA or ECDSA).

    Args:
        key_type: The type of key to generate ("rsa" or "ecdsa").
        key_size: The key size in bits (required for RSA).
        curve_name: The name of the EC curve (required for ECDSA).

    Returns:
        A tuple (public_key, private_key).

    Raises:
        ValueError: If an invalid key_type, key_size (for RSA), or
                    curve_name (for ECDSA) is provided.
    """
    match key_type.lower():
        case "rsa":
            if key_size is None:
                raise ValueError("key_size is required for RSA key generation.")
            if key_size not in constants.SUPPORTED_RSA_SIZES:
                raise ValueError(
                    f"Unsupported RSA key size: {key_size}. Supported: "
                    f"{constants.SUPPORTED_RSA_SIZES}"
                )
            return generate_rsa_keypair(key_size)
        case "ecdsa":
            if curve_name is None:
                raise ValueError("curve_name is required for ECDSA key generation.")
            if curve_name not in constants.SUPPORTED_EC_CURVES:
                raise ValueError(
                    f"Unsupported EC curve: {curve_name}. Supported: "
                    f"{constants.SUPPORTED_EC_CURVES}"
                )
            return generate_ec_keypair(curve_name)
        case _:
            raise ValueError(
                f"Unsupported key type: {key_type}. Supported types: "
                f"{constants.SUPPORTED_KEY_TYPES}"
            )


# 🐍🏗️🔌
