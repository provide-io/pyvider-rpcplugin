// The pyvider-rpcplugin-bridge acts as a connector between Terraform and Python-based providers
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// Version information
const (
	BridgeVersion = "0.2.0"
	BridgeName    = "pyvider-rpcplugin-bridge"
)

// BridgeConfig represents the configuration structure
type BridgeConfig struct {
	Environment map[string]string `yaml:"environment"`
	Python      struct {
		Args string `yaml:"args"`
	} `yaml:"python"`
	Bridge struct {
		BufferSize   int64  `yaml:"buffer_size"`
		LogFile      string `yaml:"log_file"`
		DebugEnabled bool   `yaml:"debug_enabled"`
	} `yaml:"bridge"`
}

var (
	// Command line flags
	debug      = flag.Bool("debug", false, "Enable debug logging")
	logFile    = flag.String("log-file", "", "Log file path (default: stderr only)")
	version    = flag.Bool("version", false, "Show version information")
	configFile = flag.String("config", "", "Path to configuration file")
	bufferSize = flag.Int64("buffer-size", 4*1024*1024, "Buffer size for I/O operations (bytes)")
	
	// Configuration
	config BridgeConfig
	
	// Path to the executable directory - will be set during initialization
	executableDir string
)

// Get the directory of the current executable
func getExecutableDir() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	return filepath.Dir(execPath), nil
}

// Initialize logging to file if specified
func setupLogging() {
	if config.Bridge.LogFile != "" {
		// If log file path is relative, make it relative to executable directory
		if !filepath.IsAbs(config.Bridge.LogFile) {
			config.Bridge.LogFile = filepath.Join(executableDir, config.Bridge.LogFile)
		}
		
		f, err := os.OpenFile(config.Bridge.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("WARNING: Failed to open log file: %v, falling back to stderr", err)
		} else {
			log.SetOutput(f)
		}
	}

	// Set debug level if configured
	if config.Bridge.DebugEnabled {
		*debug = true
	}
}

// Load configuration from file
func loadConfig(path string) error {
	// Default configuration
	config = BridgeConfig{
		Environment: make(map[string]string),
		Bridge: struct {
			BufferSize   int64  "yaml:\"buffer_size\""
			LogFile      string "yaml:\"log_file\""
			DebugEnabled bool   "yaml:\"debug_enabled\""
		}{
			BufferSize: 4 * 1024 * 1024, // 4MB default
		},
	}

	// If no config file specified, try default locations
	if path == "" {
		// First check in the same directory as the executable
		execDirConfig := filepath.Join(executableDir, "pyvider.yaml")
		if _, err := os.Stat(execDirConfig); err == nil {
			path = execDirConfig
			log.Printf("Found configuration file at %s", path)
		}
		
		// If not found, check current working directory
		if path == "" {
			if _, err := os.Stat("pyvider.yaml"); err == nil {
				path = "pyvider.yaml"
				log.Printf("Found configuration file at %s", path)
			}
		}
	}

	// Load config file if it exists
	if path != "" {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse config file: %w", err)
		}
		
		log.Printf("Loaded configuration from %s", path)
	}

	// Override with command line flags
	if *logFile != "" {
		config.Bridge.LogFile = *logFile
	}
	if *debug {
		config.Bridge.DebugEnabled = true
	}
	if *bufferSize != 0 {
		config.Bridge.BufferSize = *bufferSize
	}

	return nil
}

// Set up the Python environment including PYTHONPATH
func setupPythonEnv() map[string]string {
	env := make(map[string]string)
	
	// Add all current environment variables
	for _, envPair := range os.Environ() {
		parts := strings.SplitN(envPair, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}
	
	// Add configuration environment variables
	for key, value := range config.Environment {
		env[key] = value
	}
	
	// Ensure Python doesn't buffer output
	env["PYTHONUNBUFFERED"] = "1"
	
	// Add our version for debugging
	env["PYVIDER_BRIDGE_VERSION"] = BridgeVersion
	
	// Special handling for PYTHONPATH - add executable directory
	if pyPath, exists := env["PYTHONPATH"]; exists {
		sep := string(os.PathListSeparator)
		env["PYTHONPATH"] = executableDir + sep + pyPath
	} else {
		env["PYTHONPATH"] = executableDir
	}
	
	// Debug flag
	if config.Bridge.DebugEnabled {
		env["PYVIDER_DEBUG"] = "1"
	}
	
	return env
}

func main() {
	// Parse command line flags
	flag.Parse()

	// Show version and exit if requested
	if *version {
		fmt.Printf("%s v%s\n", BridgeName, BridgeVersion)
		os.Exit(0)
	}
	
	// Get the executable directory
	var err error
	executableDir, err = getExecutableDir()
	if err != nil {
		log.Fatalf("Failed to determine executable directory: %v", err)
	}
	
	// Load configuration
	if err := loadConfig(*configFile); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}
	
	// Set up logging
	setupLogging()
	
	log.Printf("%s v%s starting from %s", BridgeName, BridgeVersion, executableDir)
	
	// Set up environment variables
	env := setupPythonEnv()
	
	// Convert env map to slice for exec.Command
	envSlice := make([]string, 0, len(env))
	for key, value := range env {
		envSlice = append(envSlice, key+"="+value)
	}
	
	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	// Find uv executable
	uvPath, err := exec.LookPath("uv")
	if err != nil {
		log.Fatalf("Failed to find 'uv' executable in PATH: %v", err)
	}
	log.Printf("Using uv executable: %s", uvPath)
	
	// Prepare Python command arguments
	pythonArgs := []string{"run", "python3", "-mpyvider"}
	
	// Add any additional args from config
	if config.Python.Args != "" {
		pythonArgs = append(pythonArgs, strings.Fields(config.Python.Args)...)
	}
	
	// Add -v flag for Python verbosity if debug is enabled
	if config.Bridge.DebugEnabled {
		// Insert -v before -mpyvider
		pythonArgs = []string{"run", "python3", "-v", "-mpyvider"}
		if config.Python.Args != "" {
			pythonArgs = append(pythonArgs, strings.Fields(config.Python.Args)...)
		}
	}
	
	// Start the Python process
	proc, err := launchPyvider(uvPath, pythonArgs, envSlice, config.Bridge.BufferSize)
	if err != nil {
		log.Fatalf("Failed to launch Python process: %v", err)
	}
	
	// Set up a goroutine to handle signals
	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v, forwarding to child process", sig)
		
		// Forward the signal to the child process
		if err := proc.Signal(sig); err != nil {
			log.Printf("Error forwarding signal to child process: %v", err)
			proc.Kill() // Force kill if forwarding fails
		}
	}()
	
	// Wait for process completion
	ps, err := proc.Wait()
	signal.Stop(sigChan) // Stop signal handling
	
	// Check exit status
	if err != nil {
		log.Printf("Python process exited with error: %v", err)
		if exiterr, ok := err.(*exec.ExitError); ok {
			os.Exit(exiterr.ExitCode())
		}
		os.Exit(1)
	}
	
	if !ps.Success() {
		exitCode := 1
		if runtime.GOOS != "windows" {
			// Extract exit code on Unix-like systems
			if status, ok := ps.Sys().(syscall.WaitStatus); ok {
				exitCode = status.ExitStatus()
			}
		}
		log.Printf("Python process exited with non-zero status: %d", exitCode)
		os.Exit(exitCode)
	}
	
	log.Printf("Python process completed successfully")
}
