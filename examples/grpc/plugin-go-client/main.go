package main

import (
    "fmt"
    "os"
    "os/exec"
    "strconv"
    "time"

    //"crypto/tls"
    "crypto/x509"
    "encoding/pem"

    "github.com/hashicorp/go-hclog"
    "github.com/hashicorp/go-plugin"
    "github.com/provide-io/pyvider-rpcplugin/examples/grpc/shared"
)

// DisplayCertificate logs the certificate details.
func displayCertificate(cert *x509.Certificate) {
    fmt.Println("📜 Received Certificate:")
    fmt.Printf("   🔑 Serial Number: %s\n", cert.SerialNumber.Text(16))
    fmt.Printf("   🏷️ Subject: %s\n", cert.Subject)
    fmt.Printf("   🏢 Issuer: %s\n", cert.Issuer)
    fmt.Printf("   📆 Valid From: %s\n", cert.NotBefore)
    fmt.Printf("   📆 Valid To: %s\n", cert.NotAfter)
    fmt.Printf("   🌐 DNS Names: %v\n", cert.DNSNames)

    // PEM encode the certificate for debugging
    pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
    fmt.Println("   🔐 PEM Encoded Certificate:")
    fmt.Println(string(pemBytes))
}

func run() error {
    // Create logger with more verbose debugging
    logger := hclog.New(&hclog.LoggerOptions{
        Name:       "🌐 kv-client",
        Level:      hclog.Trace,
        Output:     os.Stderr,
        JSONFormat: false,
    })

    // Display environment variables based on the toggle and filter
    shared.DisplayFilteredEnv(logger, []string{
        "PLUGIN",
        "GRPC",
        "DEBUG",
    })

    logger.Info("🚀 starting KV client application")

    // Validate environment variables
    pluginPath := os.Getenv("PLUGIN_SERVER_PATH")
    if pluginPath == "" {
        logger.Error("🔍❌ PLUGIN_SERVER_PATH environment variable must be set")
        return fmt.Errorf("PLUGIN_SERVER_PATH environment variable must be set")
    }
    logger.Debug("🔍✅ found PLUGIN_SERVER_PATH path", "path", pluginPath)

    // Verify plugin executable exists
    if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
        logger.Error("🔍❌ plugin executable not found", "path", pluginPath)
        return fmt.Errorf("plugin executable not found at: %s", pluginPath)
    }
    logger.Debug("🔍✅ verified plugin executable exists")

    // Check if AutoMTLS should be enabled
    autoMTLS := true // Default to secure mode
    if envAutoMTLS := os.Getenv("PLUGIN_AUTO_MTLS"); envAutoMTLS != "" {
        var err error
        autoMTLS, err = strconv.ParseBool(envAutoMTLS)
        if err != nil {
            logger.Warn("🔐⚠️ invalid PLUGIN_AUTO_MTLS value, defaulting to enabled", 
                "value", envAutoMTLS,
                "error", err)
        }
    }

    // Validate certificates if AutoMTLS is enabled
    if autoMTLS {
        logger.Info("🔐 AutoMTLS is enabled. Proceeding with TLS setup...")

        clientCert := os.Getenv("PLUGIN_CLIENT_CERT")
        serverCert := os.Getenv("PLUGIN_SERVER_CERT")

        if clientCert != "" || serverCert != "" {
            logger.Error("❌🔒 AutoMTLS is enabled, but PLUGIN_CLIENT_CERT and/or PLUGIN_SERVER_CERT are set, which is not allowed")
        }
    } else {
        logger.Info("🚫 AutoMTLS is disabled. Skipping TLS setup.")
    }

    config := &plugin.ClientConfig{
        HandshakeConfig:   shared.Handshake,
        Plugins: map[string]plugin.Plugin{
            "kv_grpc": &shared.KVGRPCPlugin{},
        },
        Cmd:              exec.Command(pluginPath),
        Logger:           logger,
        AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
        StartTimeout:     5 * time.Second,
        Managed:         true,
        AutoMTLS:        autoMTLS,
    }

    logger.Debug("🔧✅ plugin client configuration complete",
        "timeout", config.StartTimeout,
        "managed", config.Managed,
        "auto_mtls", autoMTLS)

    // Create plugin client
    logger.Debug("🔌 creating new plugin client")
    client := plugin.NewClient(config)
    defer func() {
        logger.Debug("🧹 cleaning up plugin client")
        client.Kill()
    }()

    // Connect via RPC
    logger.Debug("🤝 attempting to establish RPC connection")
    rpcClient, err := client.Client()
    if err != nil {
        logger.Error("🤝❌ failed to create RPC client",
            "error", err,
            "error_type", fmt.Sprintf("%T", err))
        return fmt.Errorf("error creating RPC client: %w", err)
    }
    logger.Debug("🤝✅ RPC connection established")

    // Get the RPC address
    logger.Debug("🔌 starting RPC client")
    rpcAddr, err := client.Start()
    if err != nil {
        logger.Error("🔌❌ failed to start RPC client", "error", err)
        return fmt.Errorf("error starting RPC client: %w", err)
    }

// Get protocol info
protocol := client.Protocol()
version := client.NegotiatedVersion()

logger.Debug("🔌✅ RPC client started successfully",
    "network", rpcAddr.Network(),
    "address", rpcAddr.String(),
    "protocol", protocol,
    "version", version,
    "secure", autoMTLS)
/*
    // Adjust TLS config for Unix sockets if needed
    if rpcAddr.Network() == "unix" && tlsConfig != nil {
        logger.Debug("🔧 adjusting TLS config for Unix socket")
        tlsConfig.InsecureSkipVerify = true
        tlsConfig.ServerName = ""
    }
    */

    // Request the plugin
    logger.Debug("🔌 attempting to dispense plugin")
    raw, err := rpcClient.Dispense("kv_grpc")
    if err != nil {
        logger.Error("🔌❌ error dispensing plugin",
            "error", err,
            "error_type", fmt.Sprintf("%T", err))
        return fmt.Errorf("error dispensing plugin: %w", err)
    }
    logger.Debug("🔌✅ plugin dispensed successfully")

    // Type assert
    kv, ok := raw.(shared.KV)
    if !ok {
        logger.Error("🔌❌ type assertion failed",
            "actual_type", fmt.Sprintf("%T", raw))
        return fmt.Errorf("failed to convert plugin to KV interface (got type: %T)", raw)
    }
    logger.Debug("✅ type assertion successful")

    // Process commands
    if err := handleCommand(logger, kv); err != nil {
        return err
    }

    logger.Info("🏁 operation completed successfully")
    return nil
}

func handleCommand(logger hclog.Logger, kv shared.KV) error {
    if len(os.Args) < 2 {
        logger.Error("❌ insufficient command line arguments")
        return fmt.Errorf("usage: %s [get|put] key [value]", os.Args[0])
    }

    switch os.Args[1] {
    case "get":
        if len(os.Args) != 3 {
            logger.Error("❌ invalid number of arguments for get operation")
            return fmt.Errorf("usage: %s get key", os.Args[0])
        }
        logger.Debug("📥 executing get operation", "key", os.Args[2])
        result, err := kv.Get(os.Args[2])
        if err != nil {
            logger.Error("📥❌ get operation failed",
                "key", os.Args[2],
                "error", err)
            return fmt.Errorf("error getting value: %w", err)
        }
        logger.Debug("📥✅ get operation successful",
            "key", os.Args[2],
            "value_length", len(result))
        fmt.Println(string(result))

    case "put":
        if len(os.Args) != 4 {
            logger.Error("❌ invalid number of arguments for put operation")
            return fmt.Errorf("usage: %s put key value", os.Args[0])
        }
        logger.Debug("📤 executing put operation",
            "key", os.Args[2],
            "value_length", len(os.Args[3]))
        if err := kv.Put(os.Args[2], []byte(os.Args[3])); err != nil {
            logger.Error("📤❌ put operation failed",
                "key", os.Args[2],
                "error", err)
            return fmt.Errorf("error putting value: %w", err)
        }
        logger.Info("📤✅ successfully put value", "key", os.Args[2])

    default:
        logger.Error("❓❌ unknown command", "command", os.Args[1])
        return fmt.Errorf("unknown command: %q (use 'get' or 'put')", os.Args[1])
    }

    return nil
}

func main() {
    if err := run(); err != nil {
        fmt.Fprintf(os.Stderr, "❌ error: %v\n", err)
        os.Exit(1)
    }
}
