"""
Cryptographic Constants.

This module defines constants used throughout the crypto package,
including supported key types, default key sizes, and curve names.
"""

# Key types
KEY_TYPE_RSA: str = "rsa"
KEY_TYPE_ECDSA: str = "ecdsa"

# Default parameters
DEFAULT_RSA_KEY_SIZE: int = 2048
DEFAULT_ECDSA_CURVE: str = "secp521r1"  # Default curve for ECDSA keys

# Supported algorithms
SUPPORTED_KEY_TYPES: list[str] = [KEY_TYPE_RSA, KEY_TYPE_ECDSA]
SUPPORTED_RSA_SIZES: list[int] = [2048, 3072, 4096]  # Supported RSA key sizes in bits
SUPPORTED_EC_CURVES: list[str] = [
    "secp256r1",
    "secp384r1",
    "secp521r1",
]  # Supported ECDSA curves

# 🐍🏗️🔌
