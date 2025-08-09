"""
Pyvider RPC Plugin Crypto Package.

This package provides cryptographic utilities for the RPC plugin system,
including certificate generation, key management, and related type definitions.
It re-exports key components for easy access.
"""

from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.crypto.constants import (
    DEFAULT_ECDSA_CURVE,
    DEFAULT_RSA_KEY_SIZE,
    KEY_TYPE_ECDSA,
    KEY_TYPE_RSA,
    SUPPORTED_EC_CURVES,
    SUPPORTED_KEY_TYPES,
    SUPPORTED_RSA_SIZES,
)

# from pyvider.rpcplugin.crypto.debug import display_cert_details # Removed as function was deleted
from pyvider.rpcplugin.crypto.generators import (
    generate_ec_keypair,
    generate_keypair,
    generate_rsa_keypair,
)
from pyvider.rpcplugin.crypto.types import KeyPairType, PublicKeyType

__all__ = [
    "KEY_TYPE_RSA",
    "KEY_TYPE_ECDSA",
    "DEFAULT_RSA_KEY_SIZE",
    "DEFAULT_ECDSA_CURVE",
    "SUPPORTED_KEY_TYPES",
    "SUPPORTED_RSA_SIZES",
    "SUPPORTED_EC_CURVES",
    "KeyPairType",
    "PublicKeyType",
    "generate_rsa_keypair",
    "generate_ec_keypair",
    "generate_keypair",
    "Certificate",
    # "display_cert_details", # Removed as function was deleted
]

# 🐍🏗️🔌
