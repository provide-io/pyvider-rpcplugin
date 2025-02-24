# pyvider/rpcplugin/crypto/constants.py


# Key types
KEY_TYPE_RSA = "rsa"
KEY_TYPE_ECDSA = "ecdsa"

# Default parameters
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_ECDSA_CURVE = "secp384r1"

# Supported algorithms
SUPPORTED_KEY_TYPES = [KEY_TYPE_RSA, KEY_TYPE_ECDSA]
SUPPORTED_RSA_SIZES = [2048, 3072, 4096]
SUPPORTED_EC_CURVES = ["secp256r1", "secp384r1", "secp521r1"]
