import datetime
import os
import shutil
from pathlib import Path
from typing import Tuple # Keep Tuple for function signatures if they still return multiple items

from pyvider.rpcplugin.crypto.certificate import Certificate # Use the Certificate class
# generate_keypair might not be needed if Certificate class handles it.
# from pyvider.rpcplugin.crypto.generators import generate_keypair
from pyvider.rpcplugin.crypto.constants import DEFAULT_RSA_KEY_SIZE, KEY_TYPE_RSA, KEY_TYPE_ECDSA # Ensure key types are available if needed by Certificate class
# KeyPair type hint might change or be removed depending on what Certificate methods return

BASE_CERT_DIR = Path(__file__).parent / ".certs"


def ensure_cert_dir_exists():
    BASE_CERT_DIR.mkdir(parents=True, exist_ok=True)


def clear_certs():
    if BASE_CERT_DIR.exists():
        shutil.rmtree(BASE_CERT_DIR)
    ensure_cert_dir_exists()


def generate_ca(version: int) -> Certificate: # Corrected return type to just Certificate
    """Generates a CA certificate and key pair."""
    ensure_cert_dir_exists()
    ca_cert_obj = Certificate.create_ca(
        common_name=f"Example CA v{version}",
        organization_name="Example12 Org", # Added organization_name
        validity_days=365,
        key_type=KEY_TYPE_RSA,
        key_size=DEFAULT_RSA_KEY_SIZE
    )
    # Write to file
    if not ca_cert_obj.key:
        raise RuntimeError(f"CA v{version} key was not generated.")
    with open(BASE_CERT_DIR / f"ca_v{version}.key", "w") as f: # Write as text
        f.write(ca_cert_obj.key)
    with open(BASE_CERT_DIR / f"ca_v{version}.pem", "w") as f: # Write as text
        f.write(ca_cert_obj.cert)
    return ca_cert_obj


def generate_server_cert(
    ca_cert_obj: Certificate, version: int, days_valid: int = 90
) -> Certificate:
    """Generates a server certificate signed by the given CA."""
    ensure_cert_dir_exists()
    server_cert_obj = Certificate.create_signed_certificate(
        ca_certificate=ca_cert_obj,
        common_name=f"localhost_server_v{version}",
        organization_name="Example12 Org",
        validity_days=days_valid,
        alt_names=["localhost", "127.0.0.1"],
        key_type=KEY_TYPE_RSA,
        key_size=DEFAULT_RSA_KEY_SIZE,
        is_client_cert=False
    )
    if not server_cert_obj.key:
        raise RuntimeError(f"Server v{version} key was not generated.")
    with open(BASE_CERT_DIR / f"server_v{version}.key", "w") as f:
        f.write(server_cert_obj.key)
    with open(BASE_CERT_DIR / f"server_v{version}.pem", "w") as f:
        f.write(server_cert_obj.cert)
    return server_cert_obj


def generate_client_cert(
    ca_cert_obj: Certificate, version: int
) -> Certificate:
    """Generates a client certificate signed by the given CA."""
    ensure_cert_dir_exists()
    client_cert_obj = Certificate.create_signed_certificate(
        ca_certificate=ca_cert_obj,
        common_name=f"localhost_client_v{version}",
        organization_name="Example12 Org",
        validity_days=180,
        alt_names=["localhost"],
        key_type=KEY_TYPE_RSA,
        key_size=DEFAULT_RSA_KEY_SIZE,
        is_client_cert=True
    )
    if not client_cert_obj.key:
        raise RuntimeError(f"Client v{version} key was not generated.")
    with open(BASE_CERT_DIR / f"client_v{version}.key", "w") as f:
        f.write(client_cert_obj.key)
    with open(BASE_CERT_DIR / f"client_v{version}.pem", "w") as f:
        f.write(client_cert_obj.cert)
    return client_cert_obj


def get_cert_paths(
    ca_version: int, server_version: int, client_version: int
) -> dict:
    """Returns paths to the specified versions of certs and keys."""
    return {
        "ca_cert_pem": BASE_CERT_DIR / f"ca_v{ca_version}.pem",
        "server_cert_pem": BASE_CERT_DIR / f"server_v{server_version}.pem",
        "server_key_pem": BASE_CERT_DIR / f"server_v{server_version}.key",
        "client_cert_pem": BASE_CERT_DIR / f"client_v{client_version}.pem",
        "client_key_pem": BASE_CERT_DIR / f"client_v{client_version}.key",
    }

def get_ca_cert_pem_path(ca_version: int) -> Path:
    return BASE_CERT_DIR / f"ca_v{ca_version}.pem"

def get_server_cert_pem_path(server_version: int) -> Path:
    return BASE_CERT_DIR / f"server_v{server_version}.pem"

def get_server_key_pem_path(server_version: int) -> Path:
    return BASE_CERT_DIR / f"server_v{server_version}.key"

def get_client_cert_pem_path(client_version: int) -> Path:
    return BASE_CERT_DIR / f"client_v{client_version}.pem"

def get_client_key_pem_path(client_version: int) -> Path:
    return BASE_CERT_DIR / f"client_v{client_version}.key"


if __name__ == "__main__":
    print("Generating initial set of certificates (v1)...")
    clear_certs()
    ca_v1_obj = generate_ca(version=1)
    server_v1_obj = generate_server_cert(
        ca_v1_obj, version=1, days_valid=1 # Expire quickly for testing
    )
    client_v1_obj = generate_client_cert(
        ca_v1_obj, version=1
    )
    print("Initial certificates (v1) generated in:", BASE_CERT_DIR)

    print("\nGenerating second set of certificates (v2) for rotation...")
    # New CA (v2)
    ca_v2_obj = generate_ca(version=2)
    # New server cert (v2) signed by new CA (v2)
    server_v2_obj = generate_server_cert(
        ca_v2_obj, version=2, days_valid=90
    )
    # New client cert (v2) signed by new CA (v2) - optional, for full rotation demo
    client_v2_obj = generate_client_cert(
        ca_v2_obj, version=2
    )
    print("Second set of certificates (v2) generated in:", BASE_CERT_DIR)

    # Example of a server cert (v3) signed by the *old* CA (v1)
    # This could be used if only the server cert rotates but CA remains trusted for a while
    print("\nGenerating a server cert (v3) signed by CA v1...")
    server_v3_obj = generate_server_cert(
        ca_v1_obj, version=3, days_valid=90
    )
    print("Server certificate v3 (signed by CA v1) generated.")

    print("\nAll test certificates generated.")
    paths_v1 = get_cert_paths(ca_version=1, server_version=1, client_version=1)
    for name, path in paths_v1.items():
        print(f"  {name}: {path}")

    paths_v2 = get_cert_paths(ca_version=2, server_version=2, client_version=2)
    print("\nCA v2, Server v2, Client v2 paths:")
    for name, path in paths_v2.items():
        print(f"  {name}: {path}")

    print(f"\nServer v3 cert path (signed by CA v1): {get_server_cert_pem_path(3)}")
    print(f"Server v3 key path: {get_server_key_pem_path(3)}")

    # You can load them back like this:
    # loaded_ca_cert = load_pem_certificate(paths_v1["ca_cert_pem"])
    # loaded_ca_key = load_pem_private_key(paths_v1["ca_key_pem"]) # Assuming you need to load private key
    # print(f"\nLoaded CA v1 cert: {loaded_ca_cert.subject}")

    # Simulate time passing: check server_v1 expiry
    now = datetime.datetime.now(datetime.timezone.utc)
    # The Certificate class has an 'is_expired' property and 'not_valid_after' (which is a datetime object)
    # Accessing _base.not_valid_after for the datetime object.
    if not hasattr(server_v1_obj, '_base'): # Should have _base after generation
        print("\nError: server_v1_obj._base not initialized for expiry check.")
    elif server_v1_obj._base.not_valid_after < now:
        print(f"\nServer v1 certificate has expired (as expected for demo). Expiry: {server_v1_obj._base.not_valid_after}")
    else:
        print(f"\nServer v1 certificate still valid. Expiry: {server_v1_obj._base.not_valid_after}")

    one_day_later = now + datetime.timedelta(days=1)
    if hasattr(server_v1_obj, '_base') and server_v1_obj._base.not_valid_after < one_day_later:
        print(f"Server v1 certificate will be expired by tomorrow ({one_day_later}).")

    print("\nCertificates are ready in:", BASE_CERT_DIR.resolve())
    print("Run `python examples/example12_mtls_cert_rotation/server.py` and then `python examples/example12_mtls_cert_rotation/client.py`")
    print("To trigger rotation, the client will call the RotateCert RPC.")
    print("The server's initial cert (server_v1.pem) is set to expire in 1 day for quick testing of rotation logic.")
