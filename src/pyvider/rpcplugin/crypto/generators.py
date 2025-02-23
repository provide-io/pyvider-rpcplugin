
# pyvider/rpcplugin/crypto/generators.py

from collections.abc import Callable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pyvider.rpcplugin.crypto.constants import (
    KEY_TYPE_ECDSA,
    KEY_TYPE_RSA,
    SUPPORTED_EC_CURVES,
    SUPPORTED_RSA_SIZES,
)
from pyvider.rpcplugin.crypto.types import KeyPairType


def generate_rsa_keypair(key_size: int) -> KeyPairType:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_ec_keypair(curve_name: str) -> KeyPairType:
    return ec.generate_private_key(
        curve=getattr(ec, curve_name.upper())(),
        backend=default_backend()
    )


KEY_GENERATORS: dict[str, Callable] = {
    KEY_TYPE_RSA: generate_rsa_keypair,
    KEY_TYPE_ECDSA: generate_ec_keypair,
}

from pyvider.rpcplugin.crypto.constants import KEY_TYPE_ECDSA, KEY_TYPE_RSA
from pyvider.rpcplugin.crypto.types import KeyPairType


def generate_keypair(key_type: str = KEY_TYPE_ECDSA, key_size: int = 2048, curve_name: str = "secp384r1") -> KeyPairType:
    """
    Generates an RSA or ECDSA keypair based on the given parameters.

    Args:
        key_type (str): The type of keypair to generate ("rsa" or "ecdsa").
        key_size (int): The RSA key size (must be in SUPPORTED_RSA_SIZES).
        curve_name (str): The ECDSA curve name (must be in SUPPORTED_EC_CURVES).

    Returns:
        KeyPairType: The generated private key.

    Raises:
        ValueError: If an invalid key_type, key_size, or curve_name is provided.
    """
    if key_type == KEY_TYPE_RSA:
        if key_size not in SUPPORTED_RSA_SIZES:
            raise ValueError(f"Unsupported RSA key size: {key_size}")
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    
    elif key_type == KEY_TYPE_ECDSA:
        if curve_name not in SUPPORTED_EC_CURVES:
            raise ValueError(f"Unsupported EC curve: {curve_name}")
        return ec.generate_private_key(
            curve=getattr(ec, curve_name.upper())(),
            backend=default_backend()
        )

    else:
        raise ValueError(f"Unsupported key type: {key_type}")
