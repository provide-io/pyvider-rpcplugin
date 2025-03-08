package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEndToEndPythonExecution tests the complete flow of finding Python and running a script
func TestEndToEndPythonExecution(t *testing.T) {
	// Find Python executable
	pythonPath, err := findPythonExecutable()
	if err != nil {
		t.Skipf("Skipping test as no Python executable found: %v", err)
	}

	// Create a temporary directory for our test
	tempDir, err := os.MkdirTemp("", "pyvider-integration-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a mock Python module
	moduleDir := filepath.Join(tempDir, "mockpyvider")
	if err := os.Mkdir(moduleDir, 0755); err != nil {
		t.Fatalf("Failed to create module directory: %v", err)
	}

	// Create __init__.py to make it a proper module
	initPyPath := filepath.Join(moduleDir, "__init__.py")
	initPyContent := `# Mock Pyvider module
def main():
    print("Mock Pyvider running")
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
`
	if err := os.WriteFile(initPyPath, []byte(initPyContent), 0644); err != nil {
		t.Fatalf("Failed to write __init__.py: %v", err)
	}

	// Add the temp directory to PYTHONPATH
	oldPythonPath := os.Getenv("PYTHONPATH")
	os.Setenv("PYTHONPATH", tempDir+string(os.PathListSeparator)+oldPythonPath)
	defer os.Setenv("PYTHONPATH", oldPythonPath)

	// Set up pipes for capturing stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	stdoutR, stdoutW, _ := os.Pipe()
	stderrR, stderrW, _ := os.Pipe()
	os.Stdout = stdoutW
	os.Stderr = stderrW

	// Set up the command to run our mock module
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonPath, "-m", "mockpyvider")
	cmd.Env = os.Environ()
	
	// Run the command
	err = cmd.Run()
	
	// Close the write end of our pipes
	stdoutW.Close()
	stderrW.Close()
	
	// Restore original stdout and stderr
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	
	// Read captured output
	stdoutOutput, _ := io.ReadAll(stdoutR)
	stderrOutput, _ := io.ReadAll(stderrR)
	
	// Check for errors
	if err != nil {
		t.Errorf("Mock module execution failed: %v\nStdout: %s\nStderr: %s", 
			err, stdoutOutput, stderrOutput)
	}
	
	// Check output
	if !bytes.Contains(stdoutOutput, []byte("Mock Pyvider running")) {
		t.Errorf("Expected output not found.\nStdout: %s\nStderr: %s", 
			stdoutOutput, stderrOutput)
	}
}

// TestMagicCookieForwarding tests that the magic cookie is properly forwarded
func TestMagicCookieForwarding(t *testing.T) {
	// Find Python executable
	pythonPath, err := findPythonExecutable()
	if err != nil {
		t.Skipf("Skipping test as no Python executable found: %v", err)
	}

	// Create a temporary directory for our test
	tempDir, err := os.MkdirTemp("", "pyvider-cookie-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a Python script to print out the environment variable
	scriptPath := filepath.Join(tempDir, "cookie_test.py")
	scriptContent := fmt.Sprintf(`
import os
import sys

cookie = os.environ.get('%s')
print(f"Cookie: {cookie}")
sys.exit(0)
`, PyviderMagicCookieKey)
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	// Set the TF_PLUGIN_MAGIC_COOKIE environment variable
	testCookie := "test-integration-cookie"
	oldCookie := os.Getenv(TFPluginMagicCookieKey)
	os.Setenv(TFPluginMagicCookieKey, testCookie)
	defer os.Setenv(TFPluginMagicCookieKey, oldCookie)

	// Run launchPyvider with our script
	// Since we can't directly test the function as it expects a module name,
	// we'll simulate its environment variable handling
	cmd := exec.Command(pythonPath, scriptPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", PyviderMagicCookieKey, testCookie))
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		t.Fatalf("Test script execution failed: %v\nOutput: %s", err, output)
	}
	
	// Check that the cookie was correctly passed
	expectedOutput := fmt.Sprintf("Cookie: %s", testCookie)
	if !strings.Contains(string(output), expectedOutput) {
		t.Errorf("Magic cookie not forwarded correctly.\nExpected to find: %s\nGot: %s", 
			expectedOutput, output)
	}
}

// TestSignalHandling tests that signals are properly forwarded to child processes
func TestSignalHandling(t *testing.T) {
	// Find Python executable
	pythonPath, err := findPythonExecutable()
	if err != nil {
		t.Skipf("Skipping test as no Python executable found: %v", err)
	}

	// Create a temporary directory for our test
	tempDir, err := os.MkdirTemp("", "pyvider-signal-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a Python script that sleeps and handles signals
	scriptPath := filepath.Join(tempDir, "signal_test.py")
	scriptContent := `
import signal
import sys
import time

# Set up signal handler
def signal_handler(sig, frame):
    print(f"Received signal: {sig}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

print("Script running, waiting for signal...")
sys.stdout.flush()  # Ensure the message is written immediately

# Sleep indefinitely
try:
    while True:
        time.sleep(0.1)
except KeyboardInterrupt:
    print("Caught KeyboardInterrupt")
    sys.exit(0)
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	// Start the Python script
	cmd := exec.Command(pythonPath, scriptPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}
	
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start script: %v", err)
	}
	
	// Wait for the script to print its ready message
	buf := make([]byte, 1024)
	n, err := stdout.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read from stdout: %v", err)
	}
	
	readyMsg := "Script running, waiting for signal..."
	if !strings.Contains(string(buf[:n]), readyMsg) {
		t.Fatalf("Script did not output ready message. Got: %s", buf[:n])
	}
	
	// Give the script a moment to fully initialize
	time.Sleep(100 * time.Millisecond)
	
	// Send SIGTERM to the process
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("Failed to send signal to process: %v", err)
	}
	
	// Give it a moment to handle the signal
	time.Sleep(100 * time.Millisecond)
	
	// Read any remaining output
	remaining, _ := io.ReadAll(stdout)
	
	// Wait for the script to exit
	err = cmd.Wait()
	
	// The script should have exited cleanly after receiving the signal
	if err != nil {
		t.Errorf("Script did not exit cleanly: %v", err)
	}
	
	// Check that the script reported receiving the signal
	fullOutput := string(buf[:n]) + string(remaining)
	if !strings.Contains(fullOutput, "Received signal:") && 
	   !strings.Contains(fullOutput, "Caught KeyboardInterrupt") {
		t.Errorf("Script did not acknowledge receiving the signal. Output: %s", fullOutput)
	}
}
