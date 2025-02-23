package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
)

// Define custom error types for better error handling
type ValidationError struct {
	Component string
	Message   string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("❌ %s: %s", e.Component, e.Message)
}

func debugLogEnvironmentVariables() {
	vars := []string{
		"PLUGIN_AUTO_MTLS",
		"PLUGIN_CLIENT_CERT",
		"PLUGIN_CLIENT_KEY",
		"PLUGIN_SERVER_CERT",
		"PLUGIN_SERVER_KEY",
	}

	log.Println("🔍 Environment Variables:")
	for _, v := range vars {
		value := os.Getenv(v)
		if value != "" {
			preview := value
			if len(preview) > 50 {
				preview = preview[:47] + "..."
			}
			log.Printf("🔧 %s: %s\n", v, preview)
		} else {
			log.Printf("⚠️ %s: not set\n", v)
		}
	}
}

func validatePEMBlock(pemContent string, expectedType string) (*pem.Block, error) {
	if pemContent == "" {
		return nil, fmt.Errorf("empty PEM content")
	}

	block, _ := pem.Decode([]byte(pemContent))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	}

	if !strings.Contains(block.Type, expectedType) {
		return nil, fmt.Errorf("unexpected PEM type: got %s, want %s", block.Type, expectedType)
	}

	return block, nil
}

func formatHexSerial(serial []byte) string {
	var hexStr string
	for i, b := range serial {
		if i > 0 {
			hexStr += ":"
		}
		hexStr += fmt.Sprintf("%02x", b)
	}
	return hexStr
}

func debugLogCertificate(content string, label string) error {
	log.Printf("🔍 Analyzing %s:\n", label)
	
	if content == "" {
		log.Printf("  ⚠️ Content is empty\n")
		return fmt.Errorf("empty certificate content")
	}

	// Determine expected type based on label
	expectedType := "CERTIFICATE"
	if strings.Contains(strings.ToLower(label), "key") {
		expectedType = "PRIVATE KEY"
	}

	block, err := validatePEMBlock(content, expectedType)
	if err != nil {
		log.Printf("  ❌ PEM validation failed: %v\n", err)
		return fmt.Errorf("PEM validation failed: %v", err)
	}

	if expectedType == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("  ❌ Certificate parsing failed: %v\n", err)
			return fmt.Errorf("certificate parsing failed: %v", err)
		}

		// Get serial number in hex format
		serialHex := formatHexSerial(cert.SerialNumber.Bytes())

		log.Printf("  ✅ Certificate Details:\n")
		log.Printf("    • Serial Number: %s\n", serialHex)
		log.Printf("    • Subject: %v\n", cert.Subject)
		log.Printf("    • Issuer: %v\n", cert.Issuer)
		log.Printf("    • Valid from: %v\n", cert.NotBefore)
		log.Printf("    • Valid until: %v\n", cert.NotAfter)
		
		// Basic certificate verification
		roots := x509.NewCertPool()
		roots.AddCert(cert) // Self-signed cert as root
		opts := x509.VerifyOptions{
			Roots: roots,
		}
		
		if _, err := cert.Verify(opts); err != nil {
			log.Printf("  ⚠️ Certificate verification failed: %v\n", err)
			return fmt.Errorf("certificate verification failed: %v", err)
		}
		log.Printf("  ✅ Certificate verification successful\n")
	} else {
		// For private keys, verify we can parse it
		var keyParsed bool
		var lastErr error
		
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			keyParsed = true
		} else {
			lastErr = err
			if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				keyParsed = true
			} else {
				lastErr = err
				if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
					keyParsed = true
				} else {
					lastErr = err
				}
			}
		}

		if !keyParsed {
			log.Printf("  ❌ Private key parsing failed: %v\n", lastErr)
			return fmt.Errorf("private key parsing failed: %v", lastErr)
		}
		log.Printf("  ✅ Private key validated successfully\n")
	}
	
	return nil
}

func validateAndLoadTLSConfig(autoMTLS bool) (*tls.Config, error) {
	log.Println("\n📋 Starting TLS Configuration Validation")
	debugLogEnvironmentVariables()

	clientCert := os.Getenv("PLUGIN_CLIENT_CERT")
	clientKey := os.Getenv("PLUGIN_CLIENT_KEY")
	serverCert := os.Getenv("PLUGIN_SERVER_CERT")
	serverKey := os.Getenv("PLUGIN_SERVER_KEY")

	log.Println("\n📋 Certificate Analysis:")
	var certErrors []error
	
	// Check client certificate status
	log.Println("🔍 Checking Client Certificate Configuration:")
	if clientCert == "" && clientKey == "" {
		log.Println("  ℹ️ No client certificates configured")
	} else if clientCert == "" || clientKey == "" {
		log.Println("  ❌ Client certificate configuration is incomplete:")
		if clientCert == "" {
			log.Println("    • Missing PLUGIN_CLIENT_CERT")
		}
		if clientKey == "" {
			log.Println("    • Missing PLUGIN_CLIENT_KEY")
		}
	} else {
		if err := debugLogCertificate(clientCert, "PLUGIN_CLIENT_CERT"); err != nil {
			certErrors = append(certErrors, fmt.Errorf("client certificate error: %w", err))
		}
		if err := debugLogCertificate(clientKey, "PLUGIN_CLIENT_KEY"); err != nil {
			certErrors = append(certErrors, fmt.Errorf("client key error: %w", err))
		}
	}
	
	// Check server certificate status
	log.Println("\n🔍 Checking Server Certificate Configuration:")
	if serverCert == "" && serverKey == "" {
		log.Println("  ℹ️ No server certificates configured")
	} else if serverCert == "" || serverKey == "" {
		log.Println("  ❌ Server certificate configuration is incomplete:")
		if serverCert == "" {
			log.Println("    • Missing PLUGIN_SERVER_CERT")
		}
		if serverKey == "" {
			log.Println("    • Missing PLUGIN_SERVER_KEY")
		}
	} else {
		if err := debugLogCertificate(serverCert, "PLUGIN_SERVER_CERT"); err != nil {
			certErrors = append(certErrors, fmt.Errorf("server certificate error: %w", err))
		}
		if err := debugLogCertificate(serverKey, "PLUGIN_SERVER_KEY"); err != nil {
			certErrors = append(certErrors, fmt.Errorf("server key error: %w", err))
		}
	}
	
	if len(certErrors) > 0 {
		var errMsg string
		for i, err := range certErrors {
			if i > 0 {
				errMsg += "; "
			}
			errMsg += err.Error()
		}
		return nil, &ValidationError{
			Component: "Certificate Validation",
			Message:   errMsg,
		}
	}

	// AutoMTLS validation
	if autoMTLS {
		if clientCert != "" || clientKey != "" || serverCert != "" || serverKey != "" {
			return nil, &ValidationError{
				Component: "AutoMTLS",
				Message:   "AutoMTLS is enabled but manual certificates are present. Either disable AutoMTLS or remove manual certificates.",
			}
		}
		log.Println("✅ AutoMTLS is enabled; using default TLS configuration")
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
		}, nil
	}

	// Certificate/Key pairing validation
	hasClientCert := clientCert != ""
	hasClientKey := clientKey != ""
	hasServerCert := serverCert != ""
	hasServerKey := serverKey != ""

	// Validate client cert/key pairing
	if hasClientCert != hasClientKey {
		if hasClientCert {
			return nil, &ValidationError{
				Component: "Client Certificates",
				Message:   "PLUGIN_CLIENT_CERT is set but PLUGIN_CLIENT_KEY is missing",
			}
		} else {
			return nil, &ValidationError{
				Component: "Client Certificates",
				Message:   "PLUGIN_CLIENT_KEY is set but PLUGIN_CLIENT_CERT is missing",
			}
		}
	}

	// Validate server cert/key pairing
	if hasServerCert != hasServerKey {
		if hasServerCert {
			return nil, &ValidationError{
				Component: "Server Certificates",
				Message:   "PLUGIN_SERVER_CERT is set but PLUGIN_SERVER_KEY is missing",
			}
		} else {
			return nil, &ValidationError{
				Component: "Server Certificates",
				Message:   "PLUGIN_SERVER_KEY is set but PLUGIN_SERVER_CERT is missing",
			}
		}
	}

	// Load client certificates if present
	if hasClientCert && hasClientKey {
		cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			return nil, &ValidationError{
				Component: "Client Certificates",
				Message:   fmt.Sprintf("Failed to load client certificate pair: %v", err),
			}
		}
		log.Println("✅ Client certificates loaded successfully")
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	// Load server certificates if present
	if hasServerCert && hasServerKey {
		cert, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
		if err != nil {
			return nil, &ValidationError{
				Component: "Server Certificates",
				Message:   fmt.Sprintf("Failed to load server certificate pair: %v", err),
			}
		}
		log.Println("✅ Server certificates loaded successfully")
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	log.Println("⚠️ No TLS configuration provided")
	return nil, nil
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	
	autoMTLS := os.Getenv("PLUGIN_AUTO_MTLS") == "true"
	
	tlsConfig, err := validateAndLoadTLSConfig(autoMTLS)
	if err != nil {
		if validationErr, ok := err.(*ValidationError); ok {
			log.Fatalf("❌ Configuration Error: %v", validationErr)
		}
		log.Fatalf("❌ Unexpected Error: %v", err)
	}

	if tlsConfig != nil {
		log.Println("✅ TLS configuration loaded successfully")
	} else {
		log.Println("⚠️ No TLS configuration provided; using unencrypted channel")
	}
}
