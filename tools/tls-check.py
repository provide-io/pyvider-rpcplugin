#!/usr/bin/env python3
"""
TLS Connection Checker

This tool comprehensively checks the TLS handshake and credential configuration.
It displays detailed information about the SSL context, connection parameters,
and certificate details. In addition, for every certificate or key loaded from a PEM
string, it displays the first 32 and last 32 characters so you can verify that the
correct data is being used.
"""

import ssl
import socket
import os
import binascii
import traceback
import argparse
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.table import Table

from cryptography import x509
from cryptography.hazmat.primitives import hashes

# ------------------------------------------------------------------------------
# Data classes for connection and certificate details
# ------------------------------------------------------------------------------

@dataclass
class ConnectionTarget:
    """[🔌] Connection target details."""
    type: str             # 'tcp' or 'unix'
    address: str          # hostname:port or unix socket path
    display_address: str  # formatted address for display

    @classmethod
    def from_string(cls, target: str) -> 'ConnectionTarget':
        """[🔌] Parse a connection string into a ConnectionTarget.
        
        Supported formats:
          - hostname:port (e.g., "localhost:50051")
          - unix://path (e.g., "unix:///tmp/test.sock")
          - unix:/path (e.g., "unix:/tmp/test.sock")
          - /path (e.g., "/tmp/test.sock" assumed to be a Unix socket)
        """
        if target.startswith('unix://'):
            path = target[7:]
            return cls('unix', path, f"Unix socket: {path}")
        elif target.startswith('unix:/'):
            path = target[6:]
            return cls('unix', path, f"Unix socket: {path}")
        elif target.startswith('/'):
            return cls('unix', target, f"Unix socket: {target}")
        elif ':' in target:
            host, port = target.rsplit(':', 1)
            return cls('tcp', f"{host}:{port}", f"TCP {host}:{port}")
        else:
            raise ValueError("Invalid connection target. Use 'host:port' or 'unix:///path' or '/path'.")

@dataclass
class ConnectionInfo:
    """[🔌] Connection information captured from the TLS handshake."""
    protocol: str
    cipher_suite: str
    cipher_bits: int
    target: ConnectionTarget
    client_auth_status: str
    alpn_protocol: Optional[str]
    session_reused: bool
    server_hostname: str
    compression: Optional[str]

@dataclass
class CertificateDetails:
    """[📜] Certificate details extracted from an X.509 certificate."""
    subject: dict[str, str]
    issuer: dict[str, str]
    version: int
    serial_number: str
    valid_from: str
    valid_until: str
    fingerprint_sha1: str
    fingerprint_sha256: str
    key_type: str
    key_size: int
    signature_algorithm: str
    extensions: list[str]

    @classmethod
    def from_cryptography_cert(cls, cert: x509.Certificate) -> 'CertificateDetails':
        subject_dict = {attr.oid._name: attr.value for attr in cert.subject}
        issuer_dict = {attr.oid._name: attr.value for attr in cert.issuer}
        serial_hex = format(cert.serial_number, 'x')
        if len(serial_hex) % 2 != 0:
            serial_hex = '0' + serial_hex
        return cls(
            subject=subject_dict,
            issuer=issuer_dict,
            version=cert.version.value,
            serial_number=serial_hex.lower(),
            valid_from=cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
            valid_until=cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
            fingerprint_sha1=binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode('utf-8').lower(),
            fingerprint_sha256=binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode('utf-8').lower(),
            key_type=cert.public_key().__class__.__name__,
            key_size=cls._get_key_size(cert.public_key()),
            signature_algorithm=cert.signature_algorithm_oid._name,
            extensions=[ext.oid._name for ext in cert.extensions]
        )

    @staticmethod
    def _get_key_size(key) -> int:
        try:
            return key.key_size
        except AttributeError:
            return 0

def format_hex_with_colons(hex_str: str) -> str:
    """[📜] Format a hex string with colons every two characters."""
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    return ':'.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2)).lower()

def truncate_content(content: str, length: int = 32) -> str:
    """[📜] Return the first and last `length` characters of content."""
    content = content.strip().replace('\n', '')
    if len(content) <= (2 * length):
        return content
    return f"{content[:length]} ... {content[-length:]}"

# ------------------------------------------------------------------------------
# TLSChecker: Comprehensive tool to verify TLS connection and credentials.
# ------------------------------------------------------------------------------

class TLSChecker:
    def __init__(self):
        self.console = Console()
        self.load_certificates()

    def load_certificates(self) -> None:
        """[🛠] Load certificates from environment variables."""
        self.client_cert = os.getenv('PLUGIN_CLIENT_CERT')
        self.client_key = os.getenv('PLUGIN_CLIENT_KEY')
        self.server_cert = os.getenv('PLUGIN_SERVER_CERT')

        try:
            if self.server_cert:
                self.server_cert_obj = x509.load_pem_x509_certificate(self.server_cert.encode())
                self.console.log("[🛠] [green]Server certificate loaded from environment.[/green]")
                self.console.log(f"[🛠] Server Cert Preview: {truncate_content(self.server_cert)}")
            else:
                self.server_cert_obj = None
                self.console.log("[🛠] [yellow]No server certificate provided.[/yellow]")

            if self.client_cert:
                self.client_cert_obj = x509.load_pem_x509_certificate(self.client_cert.encode())
                self.console.log("[🛠] [green]Client certificate loaded from environment.[/green]")
                self.console.log(f"[🛠] Client Cert Preview: {truncate_content(self.client_cert)}")
            else:
                self.client_cert_obj = None
                self.console.log("[🛠] [yellow]No client certificate provided.[/yellow]")
        except Exception as e:
            self.console.log(f"[🛠] [red]Error loading certificates: {e}[/red]")
            traceback.print_exc()
            self.server_cert_obj = None
            self.client_cert_obj = None

    def display_ssl_context_details(self, context: ssl.SSLContext) -> None:
        """[🔐] Display SSLContext configuration details."""
        table = Table(title="SSL Context Details", show_header=True, header_style="bold magenta")
        table.add_column("Setting", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Check Hostname", str(context.check_hostname))
        table.add_row("Verify Mode", str(context.verify_mode))
        try:
            ciphers = context.get_ciphers()
            if ciphers:
                cipher_list = "\n".join(f"{cipher['name']} ({cipher['protocol']})" for cipher in ciphers)
            else:
                cipher_list = "None"
        except Exception as e:
            cipher_list = f"Error retrieving ciphers: {e}"
        table.add_row("Ciphers", cipher_list)
        self.console.print(table)
        self.console.print()

    def display_certificate_details(self, cert_details: CertificateDetails, title: str) -> None:
        """[📜] Display detailed certificate information."""
        cert_table = Table(title=title, show_header=False)
        cert_table.add_column("Field", style="cyan", no_wrap=True)
        cert_table.add_column("Value", style="white", overflow="fold")
        cert_table.add_row("Subject", self.format_subject_or_issuer(cert_details.subject))
        cert_table.add_row("Issuer", self.format_subject_or_issuer(cert_details.issuer))
        cert_table.add_row("Valid From", cert_details.valid_from)
        cert_table.add_row("Valid Until", cert_details.valid_until)
        cert_table.add_row("Serial Number", format_hex_with_colons(cert_details.serial_number))
        cert_table.add_row("Version", f"v{cert_details.version}")
        cert_table.add_row("SHA1 Fingerprint", format_hex_with_colons(cert_details.fingerprint_sha1))
        cert_table.add_row("SHA256 Fingerprint", format_hex_with_colons(cert_details.fingerprint_sha256))
        cert_table.add_row("Public Key Type", cert_details.key_type)
        cert_table.add_row("Public Key Size", f"{cert_details.key_size} bits")
        cert_table.add_row("Signature Algorithm", cert_details.signature_algorithm)
        if cert_details.extensions:
            cert_table.add_row("Extensions", "\n".join(f"• {ext}" for ext in cert_details.extensions))
        self.console.print(cert_table)
        self.console.print()

    def format_subject_or_issuer(self, data: dict[str, str]) -> str:
        """[📜] Format subject or issuer information into a human‑readable string."""
        parts = []
        field_order = ['commonName', 'organizationName', 'organizationalUnitName',
                       'countryName', 'stateOrProvinceName', 'localityName']
        mapping = {
            'commonName': 'CN',
            'organizationName': 'O',
            'organizationalUnitName': 'OU',
            'countryName': 'C',
            'stateOrProvinceName': 'ST',
            'localityName': 'L'
        }
        for field in field_order:
            if field in data:
                parts.append(f"{mapping.get(field, field)}={data[field]}")
        for k, v in data.items():
            if k not in field_order:
                parts.append(f"{k}={v}")
        return ", ".join(parts)

    def display_connection_details(self, conn_info: ConnectionInfo) -> None:
        """[🔌] Display connection details in a table."""
        conn_table = Table(title="Connection Details", show_header=False)
        conn_table.add_column("Field", style="cyan", no_wrap=True)
        conn_table.add_column("Value", style="white")
        conn_table.add_row("Connection Type", conn_info.target.type.upper())
        conn_table.add_row("Connected To", conn_info.target.display_address)
        conn_table.add_row("Protocol Version", conn_info.protocol)
        conn_table.add_row("Cipher Suite", conn_info.cipher_suite)
        conn_table.add_row("Cipher Strength", f"{conn_info.cipher_bits} bits")
        if conn_info.target.type == 'tcp':
            conn_table.add_row("Server Hostname", conn_info.server_hostname or "[yellow]Not Set[/yellow]")
        conn_table.add_row("ALPN Protocol", conn_info.alpn_protocol or "[yellow]None Negotiated[/yellow]")
        conn_table.add_row("Session Reused", "Yes" if conn_info.session_reused else "No")
        conn_table.add_row("Compression", conn_info.compression or "[yellow]None[/yellow]")
        self.console.print(conn_table)
        self.console.print()

    def create_connection(self, target: ConnectionTarget) -> socket.socket:
        """[🔌] Create a socket based on the connection target."""
        if target.type == 'unix':
            return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def create_ssl_context(self, is_unix_socket: bool = False) -> ssl.SSLContext:
        """[🔐] Create and configure an SSLContext based on available certificates."""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if is_unix_socket:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.console.log("[🔐] [yellow]Unix socket detected – disabling hostname verification.[/yellow]")
        # Load client certificate chain if available.
        if self.client_cert and self.client_key:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as cert_file, tempfile.NamedTemporaryFile(delete=False) as key_file:
                try:
                    cert_file.write(self.client_cert.encode())
                    cert_file.flush()
                    key_file.write(self.client_key.encode())
                    key_file.flush()
                    context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
                    self.console.log("[🔐] [green]Loaded client certificate chain into SSL context.[/green]")
                    self.console.log(f"[🔐] Client Cert Chain Preview: {truncate_content(self.client_cert)}")
                finally:
                    os.unlink(cert_file.name)
                    os.unlink(key_file.name)
        # Load server certificate for verification if provided.
        if self.server_cert:
            context.load_verify_locations(cadata=self.server_cert)
            self.console.log("[🔐] [green]Loaded server certificate into SSL context for verification.[/green]")
            self.console.log(f"[🔐] Server Cert Preview: {truncate_content(self.server_cert)}")
        elif not is_unix_socket:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.console.log("[🔐] [yellow]No server certificate provided – disabling certificate verification.[/yellow]")
        return context

    def display_ssl_context_details(self, context: ssl.SSLContext) -> None:
        """[🔐] Display the SSLContext settings in a table."""
        table = Table(title="SSL Context Details", show_header=True, header_style="bold magenta")
        table.add_column("Setting", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Check Hostname", str(context.check_hostname))
        table.add_row("Verify Mode", str(context.verify_mode))
        try:
            ciphers = context.get_ciphers()
            if ciphers:
                cipher_list = "\n".join(f"{cipher['name']} ({cipher['protocol']})" for cipher in ciphers)
            else:
                cipher_list = "None"
        except Exception as e:
            cipher_list = f"Error: {e}"
        table.add_row("Ciphers", cipher_list)
        self.console.print(table)
        self.console.print()

    def verify_client_auth(self, ssl_sock: ssl.SSLSocket) -> str:
        """[🤝] Verify client authentication by sending a simple test message."""
        try:
            ssl_sock.write(b"VERIFY\n")
            response = ssl_sock.read(1024)
            if response:
                return "Successful"
            else:
                return "[red]No response received[/red]"
        except Exception as e:
            return f"Failed: {str(e)}"

    def check_connection(self, target_str: str = 'localhost:50051') -> None:
        """[🔍] Perform a TLS connection check and display all details."""
        self.console.print("[bold blue]\n=== TLS Connection Checker ===[/bold blue]\n")
        
        # Step 1: Parse Connection Target
        self.console.print("[bold]Step 1: Parse Connection Target[/bold]")
        try:
            target = ConnectionTarget.from_string(target_str)
            self.console.print(f"[blue]Parsed target:[/blue] {target.display_address}\n")
        except Exception as e:
            self.console.print(f"[red]Error parsing connection target: {e}[/red]")
            return

        # Step 2: Create SSL Context and display details
        self.console.print("[bold]Step 2: Create SSL Context[/bold]")
        context = self.create_ssl_context(is_unix_socket=(target.type == 'unix'))
        self.display_ssl_context_details(context)

        # Step 3: Create Base Socket
        self.console.print("[bold]Step 3: Create Base Socket[/bold]")
        sock = self.create_connection(target)
        self.console.print(f"[blue]Socket created for {target.type.upper()} connection.[/blue]\n")

        # Step 4: Wrap Socket with SSL and Connect
        self.console.print("[bold]Step 4: Wrap Socket with SSL and Connect[/bold]")
        if target.type == 'unix':
            self.console.print("[blue]Unix socket detected – connecting first then wrapping.[/blue]")
            sock.connect(target.address)
            ssl_sock = context.wrap_socket(sock)
        else:
            self.console.print("[blue]TCP socket detected – wrapping with SSL and connecting.[/blue]")
            try:
                host, port_str = target.address.split(":")
                port = int(port_str)
            except Exception as e:
                self.console.print(f"[red]Error parsing TCP target address: {e}[/red]")
                return
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
        self.console.print("[blue]SSL socket established.[/blue]\n")

        # Step 5: Retrieve Peer Certificate
        try:
            with ssl_sock:
                self.console.print("[bold blue]\n=== Establishing TLS Connection ===[/bold blue]")
                self.console.print("[bold]Step 5: Retrieve Peer Certificate[/bold]")
                if not self.server_cert_obj:
                    cert_binary = ssl_sock.getpeercert(binary_form=True)
                    if cert_binary:
                        self.server_cert_obj = x509.load_der_x509_certificate(cert_binary)
                        self.console.print("[green]Peer certificate loaded from connection.[/green]")
                    else:
                        self.console.print("[yellow]No peer certificate received.[/yellow]")
                else:
                    self.console.print("[green]Using pre‑loaded server certificate from environment.[/green]")

                # Step 6: Retrieve Connection Information
                self.console.print("[bold]Step 6: Retrieve Connection Information[/bold]")
                conn_info = ConnectionInfo(
                    protocol=ssl_sock.version(),
                    cipher_suite=ssl_sock.cipher()[0],
                    cipher_bits=ssl_sock.cipher()[2],
                    target=target,
                    client_auth_status=self.verify_client_auth(ssl_sock),
                    alpn_protocol=ssl_sock.selected_alpn_protocol() or "[yellow]None[/yellow]",
                    session_reused=ssl_sock.session_reused,
                    server_hostname="",  # Not applicable for Unix sockets
                    compression=ssl_sock.compression() or "[yellow]None[/yellow]"
                )
                self.console.print("[green]Connection information retrieved.[/green]\n")

                # Step 7: Display Certificate Details
                self.console.print("[bold]Step 7: Display Certificate Details[/bold]")
                if self.server_cert_obj:
                    server_cert_details = CertificateDetails.from_cryptography_cert(self.server_cert_obj)
                    self.display_certificate_details(server_cert_details, "Server Certificate")
                else:
                    self.console.print("[yellow]No server certificate details available.[/yellow]\n")
                if self.client_cert_obj:
                    client_cert_details = CertificateDetails.from_cryptography_cert(self.client_cert_obj)
                    self.display_certificate_details(client_cert_details, "Client Certificate")
                else:
                    self.console.print("[yellow]No client certificate details available.[/yellow]\n")

                # Step 8: Display Connection Details
                self.console.print("[bold]Step 8: Display Connection Details[/bold]")
                self.display_connection_details(conn_info)

                status_color = "green" if "Successful" in conn_info.client_auth_status else "red"
                self.console.print(f"[bold]Client Authentication Status:[/bold] [{status_color}]{conn_info.client_auth_status}[/{status_color}]\n")
                self.console.print("[bold green]✓ TLS Connection Established Successfully.[/bold green]\n")
        except Exception as e:
            self.console.print(f"\n[red]Error during TLS connection check: {e}[/red]", style="bold red")
            self.console.print(f"[red]Error type: {type(e).__name__}[/red]")
            self.console.print("[red]Traceback:[/red]\n" + traceback.format_exc())
        finally:
            ssl_sock.close()
            self.console.print("[blue]SSL socket closed.[/blue]")

    def check_all(self, target: str = 'localhost:50051') -> None:
        """[🔍] Run the full TLS connection check process."""
        self.check_connection(target)

def main():
    parser = argparse.ArgumentParser(description='TLS Connection Checker')
    parser.add_argument('target', nargs='?', default='localhost:50051',
                        help='Connection target (e.g., host:port, unix:///path, or /path)')
    args = parser.parse_args()
    checker = TLSChecker()
    checker.check_all(args.target)

if __name__ == "__main__":
    main()
