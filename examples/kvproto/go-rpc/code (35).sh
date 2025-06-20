#!/bin/bash
# This script will recreate the Go source files for the kvproto example.
# It is designed to be run from within the 'go-rpc' directory.

echo "🚀 Preparing to generate the final, corrected Go plugin files..."
set -e

# --- Create Directories ---
echo "📁 Creating directory structure..."
mkdir -p shared proto plugin-go-server plugin-go-client bin

# --- shared/interface.go (The Core Fix) ---
echo "📄 Writing shared/interface.go with the CORRECT magic cookie value..."
cat <<'EOM' > shared/interface.go
package shared

import (
	"context"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/hashicorp/go-plugin/examples/kv/proto"
)

// Handshake is a common handshake that is shared by plugin and host.
// This is the definitive configuration that both client and server will use.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "hello", // This value now correctly matches the expected value.
}

type KV interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
}

type KVPlugin struct {
	plugin.Plugin
	Impl   KV
	Logger hclog.Logger
}

func (p *KVPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	p.Logger.Debug("🔌📝✅ Registering KV gRPC server")
	proto.RegisterKVServer(s, &KVGRPCServer{Impl: p.Impl, Logger: p.Logger})
	return nil
}

func (p *KVPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	if p.Logger == nil {
		return &KVGRPCClient{Client: proto.NewKVClient(c)}, nil
	}
	p.Logger.Debug("📡📝✅ Creating KV gRPC client")
	return &KVGRPCClient{Client: proto.NewKVClient(c), Logger: p.Logger}, nil
}
EOM

# --- plugin-go-client/main.go (Ensuring it uses the shared config) ---
echo "📄 Writing plugin-go-client/main.go to correctly pass the environment..."
cat <<'EOM' > plugin-go-client/main.go
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/examples/kv/shared"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "kv-plugin-client",
		Output: os.Stderr,
		Level:  hclog.Debug,
	})

	keyType := flag.String("key-type", "ecdsa", "Key type for server's mTLS cert (rsa or ecdsa)")
	curve := flag.String("curve", "secp521r1", "Curve for server's ECDSA cert (secp256r1, secp384r1, secp521r1)")
	rsaBits := flag.Int("rsa-bits", 2048, "Bit size for server's RSA key")
	autoMTLS := flag.Bool("auto-mtls", true, "Enable or disable automatic mTLS for the server")
	flag.Parse()

	serverPath := os.Getenv("PLUGIN_SERVER_PATH")
	if serverPath == "" {
		serverPath = "./bin/kv-go-server"
		logger.Info("🔌⚙️ `PLUGIN_SERVER_PATH` not set, using default server path", "path", serverPath)
	} else {
		logger.Info("🔌⚙️ Using server path from `PLUGIN_SERVER_PATH` environment variable", "path", serverPath)
	}

	clientArgs := flag.Args()
	if len(clientArgs) == 0 {
		logger.Error("‼️ No command provided. Usage: go run ./plugin-go-client <command> [args]")
		os.Exit(1)
	}

	serverArgs := []string{
		"-key-type", *keyType,
		"-curve", *curve,
		"-rsa-bits", fmt.Sprintf("%d", *rsaBits),
		"-auto-mtls", fmt.Sprintf("%t", *autoMTLS),
	}

	logger.Info("🚀✅ Starting KV plugin client...")
	logger.Info("🚀⚙️ Launching server", "path", serverPath, "args", serverArgs)

	pluginMap := map[string]plugin.Plugin{
		"kv": &shared.KVPlugin{Logger: logger},
	}

	// The host (this client) must create the magic cookie environment variable
	// for the plugin subprocess. The variable's NAME is the MagicCookieKey,
	// and its VALUE is the MagicCookieValue from the shared handshake config.
	cmd := exec.Command(serverPath, serverArgs...)
	cmd.Env = os.Environ() // Start with the current environment
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", shared.Handshake.MagicCookieKey, shared.Handshake.MagicCookieValue))
	logger.Debug("🤝✅ Forwarding correct magic cookie to plugin subprocess", "key", shared.Handshake.MagicCookieKey, "value", shared.Handshake.MagicCookieValue)

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  shared.Handshake,
		Plugins:          pluginMap,
		Cmd:              cmd, // Use the command with the modified environment
		Logger:           logger,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
	})
	defer client.Kill()

	rpcClient, err := client.Client()
	if err != nil {
		logger.Error("🚀❌ Failed to create RPC client", "error", err)
		os.Exit(1)
	}

	raw, err := rpcClient.Dispense("kv")
	if err != nil {
		logger.Error("🚀❌ Failed to dispense 'kv' plugin", "error", err)
		os.Exit(1)
	}

	kv := raw.(shared.KV)

	command := clientArgs[0]
	switch command {
	case "get":
		if len(clientArgs) != 2 {
			logger.Error("‼️ Invalid arguments for 'get'", "usage", "get <key>")
			os.Exit(1)
		}
		key := clientArgs[1]
		logger.Info("➡️  GET", "key", key)
		resp, err := kv.Get(key)
		if err != nil {
			logger.Error("❌ GET failed", "key", key, "error", err)
			os.Exit(1)
		}
		fmt.Printf("✅ GET successful. Value for '%s': %s\n", key, string(resp))

	case "put":
		if len(clientArgs) != 3 {
			logger.Error("‼️ Invalid arguments for 'put'", "usage", "put <key> <value>")
			os.Exit(1)
		}
		key := clientArgs[1]
		value := []byte(clientArgs[2])
		logger.Info("➡️  PUT", "key", key, "value", string(value))
		err := kv.Put(key, value)
		if err != nil {
			logger.Error("❌ PUT failed", "key", key, "error", err)
			os.Exit(1)
		}
		fmt.Printf("✅ PUT successful for key '%s'\n", key)

	default:
		logger.Error("‼️ Unknown command", "command", command)
		os.Exit(1)
	}
}
EOM

# --- Other files (unchanged from last working version but included for completeness) ---

# go.mod
cat <<'EOM' > go.mod
module github.com/hashicorp/go-plugin/examples/kv

go 1.22

require (
	github.com/fatih/color v1.18.0
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-plugin v1.6.1
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.34.2
)

require (
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	go.opentelemetry.io/otel v1.28.0 // indirect
	go.opentelemetry.io/otel/trace v1.28.0 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240722135656-d784300faade // indirect
)
EOM

# shared/certutil.go
cat <<'EOM' > shared/certutil.go
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
EOM

# shared/grpc.go
cat <<'EOM' > shared/grpc.go
package shared
import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin/examples/kv/proto"
)
type KVGRPCServer struct {
	Impl   KV
	Logger hclog.Logger
	proto.UnimplementedKVServer
}
func (m *KVGRPCServer) Put(ctx context.Context, req *proto.PutRequest) (*proto.Empty, error) {
	m.Logger.Info("🔌➡️📥 Received Put request", "key", req.Key)
	err := m.Impl.Put(req.Key, req.Value)
	if err != nil {
		m.Logger.Error("🔌❌ Put operation failed", "key", req.Key, "error", err)
	} else {
		m.Logger.Debug("🔌✅ Put operation successful", "key", req.Key)
	}
	return &proto.Empty{}, err
}
func (m *KVGRPCServer) Get(ctx context.Context, req *proto.GetRequest) (*proto.GetResponse, error) {
	m.Logger.Info("🔌➡️📥 Received Get request", "key", req.Key)
	v, err := m.Impl.Get(req.Key)
	if err != nil {
		m.Logger.Error("🔌❌ Get operation failed", "key", req.Key, "error", err)
		return nil, err
	}
	m.Logger.Debug("🔌✅ Get operation successful", "key", req.Key)
	return &proto.GetResponse{Value: v}, nil
}
type KVGRPCClient struct {
	Client proto.KVClient
	Logger hclog.Logger
}
func (m *KVGRPCClient) Put(key string, value []byte) error {
	m.Logger.Info("📡➡️📤 Sending Put request", "key", key)
	_, err := m.Client.Put(context.Background(), &proto.PutRequest{
		Key:   key,
		Value: value,
	})
	if err != nil {
		m.Logger.Error("📡❌ Put request failed", "key", key, "error", err)
	} else {
		m.Logger.Debug("📡✅ Put request successful", "key", key)
	}
	return err
}
func (m *KVGRPCClient) Get(key string) ([]byte, error) {
	m.Logger.Info("📡➡️📤 Sending Get request", "key", key)
	resp, err := m.Client.Get(context.Background(), &proto.GetRequest{
		Key: key,
	})
	if err != nil {
		m.Logger.Error("📡❌ Get request failed", "key", key, "error", err)
		return nil, err
	}
	m.Logger.Debug("📡✅ Get request successful", "key", key)
	return resp.Value, nil
}
EOM

# plugin-go-server/main.go
cat <<'EOM' > plugin-go-server/main.go
package main
import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"sync"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/examples/kv/shared"
)
type KV struct {
	logger hclog.Logger
	data   map[string][]byte
	mutex  sync.Mutex
}
func (k *KV) Put(key string, value []byte) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	k.logger.Debug("💾✅ Storing value", "key", key)
	k.data[key] = value
	return nil
}
func (k *KV) Get(key string) ([]byte, error) {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	k.logger.Debug("💾🔍 Retrieving value", "key", key)
	val, ok := k.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return val, nil
}
func main() {
	keyType := flag.String("key-type", "ecdsa", "Type of key to generate (rsa or ecdsa)")
	curve := flag.String("curve", "secp521r1", "ECDSA curve to use (secp256r1, secp384r1, secp521r1)")
	rsaBits := flag.Int("rsa-bits", 2048, "Bit size for RSA key")
	autoMTLS := flag.Bool("auto-mtls", true, "Enable or disable automatic mTLS")
	flag.Parse()
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "kv-plugin-server",
		Level:  hclog.Debug,
		Output: os.Stderr,
	})
	if os.Getenv(shared.Handshake.MagicCookieKey) != shared.Handshake.MagicCookieValue {
		fmt.Println("This binary is a plugin. These are not meant to be executed directly.")
		fmt.Println("Please execute the program that consumes these plugins, which will")
		fmt.Println("load any plugins automatically")
		os.Exit(1)
	}
	logger.Info("🔌🚀✅ Starting KV plugin server...")
	logger.Info("🔌⚙️✅ Server configuration", "key-type", *keyType, "curve", *curve, "rsa-bits", *rsaBits, "auto-mtls", *autoMTLS)
	kv := &KV{
		logger: logger,
		data:   make(map[string][]byte),
	}
	pluginMap := map[string]plugin.Plugin{
		"kv": &shared.KVPlugin{Impl: kv, Logger: logger},
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.Handshake,
		Plugins:         pluginMap,
		GRPCServer:      plugin.DefaultGRPCServer,
		Logger:          logger,
		TLSProvider: func() (*tls.Config, error) {
			if !*autoMTLS {
				logger.Info("🔌🔐❌ Auto mTLS is disabled. Running insecurely.")
				return nil, nil
			}
			logger.Info("🔌🔐✅ Auto mTLS is enabled. Generating TLS config...")
			tlsConfig, err := shared.GenerateTLSConfig(logger, *keyType, *curve, *rsaBits)
			if err != nil {
				logger.Error("🔌🔐❌ Failed to generate TLS config", "error", err)
				return nil, err
			}
			logger.Info("🔌🔐✅ TLS config generated successfully.")
			return tlsConfig, nil
		},
	})
	logger.Info("🔌🛑✅ Plugin server shut down.")
}
EOM

# build.sh
cat <<'EOM' > build.sh
#!/bin/bash
set -e
echo "🧼 Cleaning up previous builds..."
rm -rf ./bin
echo "🚚 Ensuring Go dependencies are correct and tidy..."
go mod tidy
echo "🛠️ Building client and server..."
go build -o ./bin/kv-go-server ./plugin-go-server
go build -o ./bin/kv-go-client ./plugin-go-client
echo "✅ Build complete."
EOM

# test.sh
cat <<'EOM' > test.sh
#!/bin/bash
set -e
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
echo -e "${YELLOW}🚀 Running build script first...${NC}"
./build.sh
echo ""
run_test() {
    TITLE=$1
    shift
    CLIENT_ARGS=("$@")
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${YELLOW}  TEST: $TITLE${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    ./bin/kv-go-client "${CLIENT_ARGS[@]}" put mykey "hello world from test: $TITLE"
    ./bin/kv-go-client "${CLIENT_ARGS[@]}" get mykey
    echo ""
}
run_test "Default (ECDSA with secp521r1) and Auto mTLS"
run_test "ECDSA with secp384r1 and Auto mTLS" --curve secp384r1
run_test "RSA with 2048 bits and Auto mTLS" --key-type rsa --rsa-bits 2048
run_test "Insecure (Auto mTLS disabled)" --auto-mtls=false
echo -e "${GREEN}✅ All tests completed successfully.${NC}"
EOM

echo "✅ All files have been written successfully."
echo "➡️  You can now run './build.sh' and then './test.sh' to verify the solution."