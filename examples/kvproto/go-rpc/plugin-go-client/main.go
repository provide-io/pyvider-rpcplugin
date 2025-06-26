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
	cmd := exec.Command(serverPath, serverArgs...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", shared.Handshake.MagicCookieKey, shared.Handshake.MagicCookieValue))
	logger.Debug("🤝✅ Forwarding correct magic cookie to plugin subprocess", "key", shared.Handshake.MagicCookieKey, "value", shared.Handshake.MagicCookieValue)
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  shared.Handshake,
		Plugins:          pluginMap,
		Cmd:              cmd,
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
