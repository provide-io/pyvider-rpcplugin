package shared

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/hashicorp/go-hclog"
)

func GenerateTLSConfig(logger hclog.Logger, keyType, curveName string, rsaBits int) (*tls.Config, error) {
	logger.Info("📜🔑🏭 Generating TLS config", "keyType", keyType, "curve", curveName, "rsaBits", rsaBits)
	var priv interface{}
	var err error
	switch keyType {
	case "ecdsa":
		logger.Debug("📜🔑🚀 Generating ECDSA private key", "curve", curveName)
		var curve elliptic.Curve
		switch curveName {
		case "secp256r1":
			curve = elliptic.P256()
		case "secp384r1":
			curve = elliptic.P384()
		case "secp521r1":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %s", curveName)
		}
		priv, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "rsa":
		logger.Debug("📜🔑🚀 Generating RSA private key", "bits", rsaBits)
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
	if err != nil {
		logger.Error("📜🔑❌ Failed to generate private key", "error", err)
		return nil, err
	}
	logger.Debug("📜🔑✅ Private key generated successfully.")
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		logger.Error("📜🔑❌ Failed to generate serial number", "error", err)
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pyvider-RPCPlugin Example"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		logger.Error("📜🔑❌ Failed to create certificate", "error", err)
		return nil, err
	}
	logger.Debug("📜🔑✅ Self-signed certificate created.")
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logger.Error("📜🔑❌ Failed to marshal private key", "error", err)
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		logger.Error("📜🔑❌ Failed to create TLS key pair from PEM data", "error", err)
		return nil, err
	}
	logger.Debug("📜🔑✅ TLS key pair created from PEM data.")
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}, nil
}
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
