import datetime
import os
import shutil
from pathlib import Path
from typing import Tuple

from pyvider.rpcplugin.crypto import Certificate, KeyPair
from pyvider.rpcplugin.crypto.generators import generate_keypair
from pyvider.rpcplugin.crypto.certificate import (
    generate_x509_certificate,
    load_pem_certificate,
    load_pem_private_key,
)

BASE_CERT_DIR = Path(__file__).parent / ".certs"


def ensure_cert_dir_exists():
    BASE_CERT_DIR.mkdir(parents=True, exist_ok=True)


def clear_certs():
    if BASE_CERT_DIR.exists():
        shutil.rmtree(BASE_CERT_DIR)
    ensure_cert_dir_exists()


def generate_ca(version: int) -> Tuple[Certificate, KeyPair]:
    """Generates a CA certificate and key pair."""
    ensure_cert_dir_exists()
    ca_key = generate_keypair("rsa")
    ca_cert = generate_x509_certificate(
        private_key=ca_key.private_key,
        public_key=ca_key.public_key,
        common_name=f"Example CA v{version}",
        is_ca=True,
        days_valid=365,
    )
    with open(BASE_CERT_DIR / f"ca_v{version}.key", "wb") as f:
        f.write(ca_key.private_key_pem)
    with open(BASE_CERT_DIR / f"ca_v{version}.pem", "wb") as f:
        f.write(ca_cert.public_bytes_pem)
    return ca_cert, ca_key


def generate_server_cert(
    ca_cert: Certificate, ca_key: KeyPair, version: int, days_valid: int = 90
) -> Tuple[Certificate, KeyPair]:
    """Generates a server certificate signed by the given CA."""
    ensure_cert_dir_exists()
    server_key = generate_keypair("rsa")
    server_cert = generate_x509_certificate(
        private_key=server_key.private_key,
        public_key=server_key.public_key,
        common_name=f"localhost_server_v{version}",
        is_ca=False,
        issuer_certificate=ca_cert,
        issuer_private_key=ca_key.private_key,
        days_valid=days_valid,
        sans=["localhost", "127.0.0.1"],
    )
    with open(BASE_CERT_DIR / f"server_v{version}.key", "wb") as f:
        f.write(server_key.private_key_pem)
    with open(BASE_CERT_DIR / f"server_v{version}.pem", "wb") as f:
        f.write(server_cert.public_bytes_pem)
    return server_cert, server_key


def generate_client_cert(
    ca_cert: Certificate, ca_key: KeyPair, version: int
) -> Tuple[Certificate, KeyPair]:
    """Generates a client certificate signed by the given CA."""
    ensure_cert_dir_exists()
    client_key = generate_keypair("rsa")
    client_cert = generate_x509_certificate(
        private_key=client_key.private_key,
        public_key=client_key.public_key,
        common_name=f"localhost_client_v{version}",
        is_ca=False,
        issuer_certificate=ca_cert,
        issuer_private_key=ca_key.private_key,
        days_valid=180,
        sans=["localhost"],
    )
    with open(BASE_CERT_DIR / f"client_v{version}.key", "wb") as f:
        f.write(client_key.private_key_pem)
    with open(BASE_CERT_DIR / f"client_v{version}.pem", "wb") as f:
        f.write(client_cert.public_bytes_pem)
    return client_cert, client_key


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
    ca_v1_cert, ca_v1_key = generate_ca(version=1)
    server_v1_cert, server_v1_key = generate_server_cert(
        ca_v1_cert, ca_v1_key, version=1, days_valid=1 # Expire quickly for testing
    )
    client_v1_cert, client_v1_key = generate_client_cert(
        ca_v1_cert, ca_v1_key, version=1
    )
    print("Initial certificates (v1) generated in:", BASE_CERT_DIR)

    print("\nGenerating second set of certificates (v2) for rotation...")
    # New CA (v2)
    ca_v2_cert, ca_v2_key = generate_ca(version=2)
    # New server cert (v2) signed by new CA (v2)
    server_v2_cert, server_v2_key = generate_server_cert(
        ca_v2_cert, ca_v2_key, version=2, days_valid=90
    )
    # New client cert (v2) signed by new CA (v2) - optional, for full rotation demo
    client_v2_cert, client_v2_key = generate_client_cert(
        ca_v2_cert, ca_v2_key, version=2
    )
    print("Second set of certificates (v2) generated in:", BASE_CERT_DIR)

    # Example of a server cert (v3) signed by the *old* CA (v1)
    # This could be used if only the server cert rotates but CA remains trusted for a while
    print("\nGenerating a server cert (v3) signed by CA v1...")
    server_v3_cert, server_v3_key = generate_server_cert(
        ca_v1_cert, ca_v1_key, version=3, days_valid=90
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
    if server_v1_cert.not_valid_after_datetime < now:
        print(f"\nServer v1 certificate has expired (as expected for demo). Expiry: {server_v1_cert.not_valid_after_datetime}")
    else:
        print(f"\nServer v1 certificate still valid. Expiry: {server_v1_cert.not_valid_after_datetime}")

    one_day_later = now + datetime.timedelta(days=1)
    if server_v1_cert.not_valid_after_datetime < one_day_later:
        print(f"Server v1 certificate will be expired by tomorrow ({one_day_later}).")

    print("\nCertificates are ready in:", BASE_CERT_DIR.resolve())
    print("Run `python examples/example12_mtls_cert_rotation/server.py` and then `python examples/example12_mtls_cert_rotation/client.py`")
    print("To trigger rotation, the client will call the RotateCert RPC.")
    print("The server's initial cert (server_v1.pem) is set to expire in 1 day for quick testing of rotation logic.")
