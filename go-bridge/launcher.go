package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

// Constants for environment variables
const (
	TFPluginMagicCookieKey   = "TF_PLUGIN_MAGIC_COOKIE"
	PyviderMagicCookieKey    = "PLUGIN_MAGIC_COOKIE"
	PyviderMagicCookieValue  = "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2"
)

// launchPyvider starts the Python Pyvider process and sets up I/O proxying
func launchPyvider(pythonPath, pythonModule string, installDeps bool) (*os.Process, error) {
	// Check if the Python executable exists
	if _, err := os.Stat(pythonPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Python executable not found at: %s", pythonPath)
	}

	// If installDeps is enabled, try to install dependencies
	if installDeps {
		if err := ensureDependencies(pythonPath, pythonModule); err != nil {
			log.Printf("Warning: Failed to ensure dependencies: %v", err)
			// Continue anyway, the module might already be installed
		}
	}

	// Prepare arguments to run the Python module
	args := []string{"-m", pythonModule}
	if *debug {
		args = append([]string{"-v"}, args...)
	}

	// Create the command
	cmd := exec.Command(pythonPath, args...)

	// Set up environment
	cmd.Env = os.Environ()

	// Forward the magic cookie
	tfCookie := os.Getenv(TFPluginMagicCookieKey)
	if tfCookie != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", PyviderMagicCookieKey, tfCookie))
	} else {
		// If not set by Terraform, set the default value
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", PyviderMagicCookieKey, PyviderMagicCookieValue))
	}

	// Set up stdin/stdout/stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	
	// For stderr, we want to see it but also log it
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
	}
	
	// Start the process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start Python process: %v", err)
	}

	// Start goroutine to handle stderr
	go func() {
		// Create a multi-writer to both os.Stderr and our log
		multiWriter := io.MultiWriter(os.Stderr, writeLogger{})
		if _, err := io.Copy(multiWriter, stderrPipe); err != nil {
			log.Printf("Error reading from stderr pipe: %v", err)
		}
	}()

	log.Printf("Started Python process (PID: %d)", cmd.Process.Pid)
	return cmd.Process, nil
}

// ensureDependencies makes sure the required Python dependencies are installed
func ensureDependencies(pythonPath, pythonModule string) error {
	// First check if the module can be imported
	checkCmd := exec.Command(pythonPath, "-c", fmt.Sprintf("import %s", pythonModule))
	if err := checkCmd.Run(); err == nil {
		// Module can be imported, no need to install
		return nil
	}

	log.Printf("Module %s not found, attempting to install...", pythonModule)

	// Try to install the module using pip
	pipArgs := []string{"-m", "pip", "install", "--user", pythonModule}
	installCmd := exec.Command(pythonPath, pipArgs...)
	
	// Capture output for logging
	output, err := installCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pip install failed: %v\nOutput: %s", err, output)
	}
	
	log.Printf("Successfully installed %s module", pythonModule)
	return nil
}

// writeLogger is a helper type that implements io.Writer to redirect to log
type writeLogger struct{}

func (wl writeLogger) Write(p []byte) (n int, err error) {
	log.Print(string(p))
	return len(p), nil
}
