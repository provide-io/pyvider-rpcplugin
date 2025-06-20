from pyvider.rpcplugin.crypto.certificate import Certificate
from pathlib import Path

# Define a directory to store certificates
# Using current directory due to sandbox limitations
cert_dir = Path(".")
# cert_dir.mkdir(exist_ok=True) # Not needed if using current dir

print(f"Certificates will be saved in: {cert_dir.resolve()}")

# Step 1: Create a Root CA
ca_cert_obj = Certificate.create_ca(
    common_name="My Test CA", # Simplified CN for test
    organization_name="Test Org",
    validity_days=365
)

ca_cert_path = cert_dir / "ca.crt"
ca_key_path = cert_dir / "ca.key"
with open(ca_cert_path, "w", encoding="utf-8") as f:
    f.write(ca_cert_obj.cert)
with open(ca_key_path, "w", encoding="utf-8") as f:
    if ca_cert_obj.key:
        f.write(ca_cert_obj.key)
print(f"CA certificate saved to: {ca_cert_path}")
print(f"CA private key saved to: {ca_key_path}")

# Step 2: Create a Server Certificate signed by the CA
server_cert_obj = Certificate.create_signed_certificate(
    ca_certificate=ca_cert_obj,
    common_name="test-server.example.com", # Simplified CN
    organization_name="Test Org Servers",
    validity_days=90,
    alt_names=["localhost", "127.0.0.1"],
    is_client_cert=False
)

server_cert_path = cert_dir / "server.crt"
server_key_path = cert_dir / "server.key"
with open(server_cert_path, "w", encoding="utf-8") as f:
    f.write(server_cert_obj.cert)
with open(server_key_path, "w", encoding="utf-8") as f:
    if server_cert_obj.key:
        f.write(server_cert_obj.key)
print(f"Server certificate saved to: {server_cert_path}")
print(f"Server private key saved to: {server_key_path}")

# Step 3: Create a Client Certificate signed by the CA
client_cert_obj = Certificate.create_signed_certificate(
    ca_certificate=ca_cert_obj,
    common_name="test-client-001", # Simplified CN
    organization_name="Test Org Clients",
    validity_days=30,
    is_client_cert=True
)

client_cert_path = cert_dir / "client.crt"
client_key_path = cert_dir / "client.key"
with open(client_cert_path, "w", encoding="utf-8") as f:
    f.write(client_cert_obj.cert)
with open(client_key_path, "w", encoding="utf-8") as f:
    if client_cert_obj.key:
        f.write(client_cert_obj.key)
print(f"Client certificate saved to: {client_cert_path}")
print(f"Client private key saved to: {client_key_path}")

print("Certificate generation complete.")
