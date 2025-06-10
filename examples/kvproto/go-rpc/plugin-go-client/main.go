//
// pyvider-rpcplugin/examples/kvproto/go-plugin/plugin-go-client/main.go
//

package main

import (
    "flag"
    "fmt"
    "os"
    "os/exec"
    "strconv"
    "time"
    "strings" // Required for strings.ToUpper

    //"crypto/tls"
    "crypto/x509"
    "encoding/pem"

    "github.com/hashicorp/go-hclog"
    "github.com/hashicorp/go-plugin"
    "github.com/provide-io/pyvider-rpcplugin/examples/kvproto/go-plugin/shared"
)

// Global flag variable for log level
var logLevelFlag string

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

func run(args []string) error {
    // Determine log level from flag
    parsedLevel := hclog.Warn // Default to WARN
    switch strings.ToUpper(logLevelFlag) {
    case "TRACE":
        parsedLevel = hclog.Trace
    case "DEBUG":
        parsedLevel = hclog.Debug
    case "INFO":
        parsedLevel = hclog.Info
    case "WARN":
        parsedLevel = hclog.Warn
    case "ERROR":
        parsedLevel = hclog.Error
    case "OFF":
        parsedLevel = hclog.Off
    default:
        // This case should ideally not be reached if flag parsing works with a default.
        // However, if logLevelFlag somehow contains an unexpected value after parsing,
        // this provides a fallback.
        // If flag has a default, this message might appear if default is invalid,
        // or if user provides an invalid value not caught by flag package's own validation (if any).
        fmt.Fprintf(os.Stderr, "⚠️ Invalid log level '%s' provided. Defaulting to WARN.\n", logLevelFlag)
        // parsedLevel is already hclog.Warn
    }

    // Create logger with the determined level
    logger := hclog.New(&hclog.LoggerOptions{
        Name:       "🐿️ C> kv-client",
        Level:      parsedLevel, // Use parsed level
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

    // Determine plugin path: flag overrides environment variable
    var pluginPath string
    if serverPathFlag != nil && *serverPathFlag != "" {
        pluginPath = *serverPathFlag
        logger.Debug("🔌 using server path from --server-path flag", "path", pluginPath)
    } else {
        pluginPath = os.Getenv("PLUGIN_SERVER_PATH")
        logger.Debug("🔌 using server path from PLUGIN_SERVER_PATH env var", "path", pluginPath)
    }

    if pluginPath == "" {
        logger.Error("🔍❌ plugin server path must be set via --server-path flag or PLUGIN_SERVER_PATH environment variable")
        return fmt.Errorf("plugin server path must be set via --server-path flag or PLUGIN_SERVER_PATH environment variable")
    }
    logger.Info("🔌 Using server executable", "path", pluginPath) // Log level changed and message added

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
    logger.Info("🤝 attempting to establish RPC connection") // Log level changed
    rpcClient, err := client.Client()
    if err != nil {
        logger.Error("🤝❌ failed to create RPC client",
            "error", err,
            "error_type", fmt.Sprintf("%T", err))
        return fmt.Errorf("error creating RPC client: %w", err)
    }
    logger.Info("🤝✅ RPC connection established") // Log level changed

    // Get the RPC address
    logger.Info("🔌 starting RPC client") // Log level changed
    rpcAddr, err := client.Start()
    if err != nil {
        logger.Error("🔌❌ failed to start RPC client", "error", err)
        return fmt.Errorf("error starting RPC client: %w", err)
    }

// Get protocol info
protocol := client.Protocol()
version := client.NegotiatedVersion()

logger.Info("🔌✅ RPC client started successfully", // Log level changed
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
    if err := handleCommand(logger, kv, args); err != nil {
        return err
    }

    logger.Info("🏁 operation completed successfully")
    return nil
}

func handleCommand(logger hclog.Logger, kv shared.KV, args []string) error { // Added args []string
    // args now contains only the command and its parameters, after flag parsing.
    // Example: ["get", "mykey"] or ["put", "mykey", "myvalue"]

    if len(args) < 1 {
        // This case should ideally be caught in main() before calling run(),
        // but as a safeguard / for clarity if handleCommand was called directly.
        logger.Error("❌ internal error: handleCommand called with no arguments")
        // flag.Usage() might be more appropriate if this were user-facing,
        // but this indicates a programming error if reached.
        return fmt.Errorf("internal error: no command provided to handleCommand")
    }

    command := args[0]
    switch command {
    case "get":
        if len(args) != 2 {
            logger.Error("❌ invalid number of arguments for 'get' operation", "expected_count", 1, "actual_count", len(args)-1, "arguments", args[1:])
            // Suggest correct usage, flag.Usage() could also be an option if accessible easily.
            return fmt.Errorf("usage: get <key>")
        }
        key := args[1]
        logger.Info("📥 executing get operation", "key", key) // Log level changed
        result, err := kv.Get(key)
        if err != nil {
            logger.Error("📥❌ get operation failed",
                "key", key,
                "error", err)
            return fmt.Errorf("error getting value for key '%s': %w", key, err)
        }
        logger.Info("📥✅ get operation successful", // Log level changed
            "key", key,
            "value_length", len(result))
        fmt.Println(string(result))

    case "put":
        if len(args) != 3 {
            logger.Error("❌ invalid number of arguments for 'put' operation", "expected_count", 2, "actual_count", len(args)-1, "arguments", args[1:])
            return fmt.Errorf("usage: put <key> <value>")
        }
        key := args[1]
        value := args[2]
        logger.Info("📤 executing put operation", // Log level changed
            "key", key,
            "value_length", len(value))
        if err := kv.Put(key, []byte(value)); err != nil {
            logger.Error("📤❌ put operation failed",
                "key", key,
                "error", err)
            return fmt.Errorf("error putting value for key '%s': %w", key, err)
        }
        logger.Info("📤✅ successfully put value", "key", key)

    default:
        logger.Error("❓❌ unknown command", "command", command)
        // Suggest running with --help for usage details.
        return fmt.Errorf("unknown command: %q. Expected 'get' or 'put'.\nRun with --help for usage.", command)
    }

    return nil
}

// serverPathFlag is a pointer to the string value of the --server-path flag.
// It's defined globally so it can be accessed in run() if needed, though primarily used in main.
var serverPathFlag *string
// logLevelFlag is already defined globally

func main() {
    // Define flags
    // The serverPathFlag is defined globally so it can be accessed in `run`
    serverPathFlag = flag.String("server-path", "", "Path to the server executable. Overrides PLUGIN_SERVER_PATH environment variable.")
    // Define the log-level flag
    flag.StringVar(&logLevelFlag, "log-level", "WARN", "Set the logging level (TRACE, DEBUG, INFO, WARN, ERROR, OFF)")

    // originalUsage := flag.Usage // This line will be removed
    flag.Usage = func() {
        // Using flag.CommandLine.Output() for consistent output channel (defaults to os.Stderr)
        fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [--server-path <path>] [--log-level <level>] <get|put> <key> [value]\n\n", os.Args[0])
        fmt.Fprintf(flag.CommandLine.Output(), "Commands:\n")
        fmt.Fprintf(flag.CommandLine.Output(), "  get <key>          Get a value for a key\n")
        fmt.Fprintf(flag.CommandLine.Output(), "  put <key> <value>  Put a key/value pair\n\n")
        fmt.Fprintf(flag.CommandLine.Output(), "Flags:\n")
        flag.PrintDefaults()
    }
    flag.Parse()

    // Get non-flag arguments (the command and its parameters)
    args := flag.Args()

    // Validate command is present
    if len(args) < 1 {
        // Log directly to Stderr as logger might not be initialized if run() isn't called.
        fmt.Fprintf(os.Stderr, "❌ Error: No command provided. Expected 'get' or 'put'.\n")
        flag.Usage()
        os.Exit(1)
    }

    // Pass non-flag arguments to run
    if err := run(args); err != nil {
        // Logger might not be initialized yet, or error happened before logger, so use fmt.Fprintf
        // The run() function's logger will handle logging for errors within run() itself.
        // This Fprintf is for errors returned by run() that prevent logger initialization or occur very early.
        fmt.Fprintf(os.Stderr, "❌ Error executing command: %v\n", err)
        os.Exit(1)
    }
}
