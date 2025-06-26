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
