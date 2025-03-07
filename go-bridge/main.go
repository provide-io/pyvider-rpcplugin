// Main entry point for the RPC Plugin Bridge
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

var (
	// Command line flags
	debug             = flag.Bool("debug", false, "Enable debug logging")
	pythonExecutable  = flag.String("python", "", "Path to Python executable (default: auto-detect)")
	pythonModule      = flag.String("module", "pyvider", "Python module to run")
	installDeps       = flag.Bool("install-deps", true, "Automatically install dependencies if missing")
	logFile           = flag.String("log-file", "", "Log file path (default: stderr only)")
	version           = flag.Bool("version", false, "Show version information")
	noProxy           = flag.Bool("no-proxy", false, "Skip proxying to Python (debugging only)")
)

// Version information
const (
	BridgeVersion = "0.1.0"
	BridgeName    = "pyvider-rpcplugin-bridge"
)

func main() {
	// Parse command line flags
	flag.Parse()

	// Setup logging
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Warning: Failed to open log file: %v, falling back to stderr", err)
		} else {
			defer f.Close()
			log.SetOutput(f)
		}
	}

	// Show version and exit if requested
	if *version {
		fmt.Printf("%s v%s\n", BridgeName, BridgeVersion)
		os.Exit(0)
	}

	log.Printf("%s v%s starting...", BridgeName, BridgeVersion)

	// Automatically find Python if not specified
	pythonPath := *pythonExecutable
	if pythonPath == "" {
		var err error
		pythonPath, err = findPythonExecutable()
		if err != nil {
			log.Fatalf("Failed to find Python executable: %v", err)
		}
	}

	log.Printf("Using Python executable: %s", pythonPath)

	// Set up signal handling before starting processes
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Skip actually proxying for debugging
	if *noProxy {
		log.Printf("Skipping proxy mode (--no-proxy flag set)")
		return
	}

	// Start the Python process
	proc, err := launchPyvider(pythonPath, *pythonModule, *installDeps)
	if err != nil {
		log.Fatalf("Failed to launch Python process: %v", err)
	}

	// Set up a go routine to handle signals
	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v, forwarding to child process", sig)
		
		// Forward the signal to the child process
		if err := proc.Signal(sig); err != nil {
			log.Printf("Error forwarding signal to child process: %v", err)
			proc.Kill() // Force kill if forwarding fails
		}
	}()

	// Set up another go routine to handle process termination
	waitChan := make(chan error, 1)
	go func() {
		ps, err := proc.Wait()
		if err != nil {
			waitChan <- err
		} else if !ps.Success() {
			waitChan <- fmt.Errorf("process exited with code %d", ps.ExitCode())
		} else {
			waitChan <- nil
		}
	}()

	// Wait for completion
	err = <-waitChan
	signal.Stop(sigChan)

	// Check exit status
	if err != nil {
		log.Printf("Python process exited with error: %v", err)
		if exiterr, ok := err.(*exec.ExitError); ok {
			os.Exit(exiterr.ExitCode())
		}
		os.Exit(1)
	}

	log.Printf("Python process completed successfully")
}

// findPythonExecutable attempts to find a Python executable in the PATH
func findPythonExecutable() (string, error) {
	// Try Python 3 first, then fall back to just 'python'
	candidates := []string{"python3", "python", "python3.12", "python3.11", "python3.10", "python3.9", "python3.8"}
	
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate)
		if err == nil {
			// Verify it's Python 3
			cmd := exec.Command(path, "--version")
			output, err := cmd.CombinedOutput()
			if err == nil && strings.Contains(string(output), "Python 3") {
				return path, nil
			}
		}
	}
	
	return "", fmt.Errorf("no suitable Python 3 executable found in PATH")
}
