"""
Cryptographic Key Pair Generators.

This module provides functions for generating RSA and ECDSA key pairs,
used for creating certificates and securing communications in the
Pyvider RPC Plugin system.
"""

from collections.abc import Callable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pyvider.rpcplugin.crypto import constants # Changed import style
from pyvider.rpcplugin.crypto.types import KeyPairType


def generate_rsa_keypair(key_size: int) -> KeyPairType:
    """
    Generates an RSA private key.

    Args:
        key_size: The desired key size in bits. Must be one of SUPPORTED_RSA_SIZES.

    Returns:
        An RSA private key object.

    Raises:
        ValueError: If the key_size is not supported (though validation is expected upstream).
    """
    # Basic validation, though generate_keypair has more robust checks
    if key_size not in constants.SUPPORTED_RSA_SIZES:
        raise ValueError(f"Unsupported RSA key size: {key_size}. Supported: {constants.SUPPORTED_RSA_SIZES}")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    return private_key.public_key(), private_key


def generate_ec_keypair(curve_name: str) -> KeyPairType:
    """
    Generates an ECDSA private key using the specified curve.

    Args:
        curve_name: The name of the elliptic curve (e.g., "secp384r1").
                    Must be one of SUPPORTED_EC_CURVES.

    Returns:
        An ECDSA private key object.

    Raises:
        ValueError: If the curve_name is not supported (though validation is expected upstream).
        AttributeError: If the curve name does not correspond to a valid curve in `cryptography.hazmat.primitives.asymmetric.ec`.
    """
    # Basic validation
    if curve_name not in constants.SUPPORTED_EC_CURVES:
        raise ValueError(f"Unsupported EC curve: {curve_name}. Supported: {constants.SUPPORTED_EC_CURVES}")
    curve = getattr(ec, curve_name.upper())() # Get curve object e.g. ec.SECP384R1()
    private_key = ec.generate_private_key(
        curve=curve, backend=default_backend()
    )
    return private_key.public_key(), private_key

# Dictionary mapping key type strings to their respective generator functions.
KEY_GENERATORS: dict[str, Callable[[int | str], KeyPairType]] = {
    constants.KEY_TYPE_RSA: generate_rsa_keypair, # type: ignore[dict-item]
    constants.KEY_TYPE_ECDSA: generate_ec_keypair, # type: ignore[dict-item]
}


def generate_keypair(
    key_type: str = constants.KEY_TYPE_ECDSA, key_size: int = 2048, curve_name: str = "secp521r1"
) -> KeyPairType:
    """
    Generates an RSA or ECDSA keypair based on the given parameters.

    Args:
        key_type: The type of keypair to generate ("rsa" or "ecdsa").
        key_size: The RSA key size (must be in SUPPORTED_RSA_SIZES).
                  This parameter is ignored if key_type is "ecdsa".
        curve_name: The ECDSA curve name (must be in SUPPORTED_EC_CURVES).
                    This parameter is ignored if key_type is "rsa".

    Returns:
        The generated private key (either RSAPrivateKey or EllipticCurvePrivateKey).

    Raises:
        ValueError: If an invalid key_type, key_size (for RSA), or curve_name (for ECDSA) is provided.
    """
    match key_type:
        case constants.KEY_TYPE_RSA:
            if key_size not in constants.SUPPORTED_RSA_SIZES:
                raise ValueError(f"Unsupported RSA key size: {key_size}. Supported: {constants.SUPPORTED_RSA_SIZES}")
            return generate_rsa_keypair(key_size)
        case constants.KEY_TYPE_ECDSA:
            if curve_name not in constants.SUPPORTED_EC_CURVES:
                raise ValueError(f"Unsupported EC curve: {curve_name}. Supported: {constants.SUPPORTED_EC_CURVES}")
            return generate_ec_keypair(curve_name)
        case _:
            raise ValueError(f"Unsupported key type: {key_type}. Supported types: {constants.SUPPORTED_KEY_TYPES}")

# 🐍🏗️🔌
