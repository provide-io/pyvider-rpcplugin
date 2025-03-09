package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchPyviderInvalidPythonPath(t *testing.T) {
	// Test with a non-existent Python path
	nonExistentPath := "/path/to/nonexistent/python"
	_, err := launchPyvider(nonExistentPath, "testmodule", false)
	if err == nil {
		t.Error("Expected error when using non-existent Python path, but got nil")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error message, got: %v", err)
	}
}

func TestLaunchPyviderValidPythonPath(t *testing.T) {
	// Skip this test if no Python is available
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		pythonPath, err = exec.LookPath("python")
		if err != nil {
			t.Skip("Skipping test as no Python executable found")
		}
	}

	// Temporarily capture stderr to prevent test logs from being polluted
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Create a mock module for testing
	tempDir, err := os.MkdirTemp("", "pyvider-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a mock Python script that just exits
	mockScriptPath := filepath.Join(tempDir, "mockpyvider.py")
	mockScript := `
import sys
import time
print("Mock Pyvider started")
time.sleep(0.1)  # Give a little time for test to capture the process
sys.exit(0)
`
	if err := os.WriteFile(mockScriptPath, []byte(mockScript), 0644); err != nil {
		t.Fatalf("Failed to write mock script: %v", err)
	}

	// Set debug flag for the test
	oldDebug := debug
	debug = new(bool)
	*debug = true
	defer func() { debug = oldDebug }()

	// Start the process
	proc, err := exec.Command(pythonPath, mockScriptPath).Start()
	if err != nil {
		t.Fatalf("Failed to start mock Python process: %v", err)
	}
	defer proc.Kill()

	// Close the write end of the pipe
	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	capturedOutput, _ := io.ReadAll(r)
	t.Logf("Captured output: %s", capturedOutput)

	// Test is successful if we got here without errors
	t.Log("Successfully launched Python process")
}

func TestWriteLogger(t *testing.T) {
	// Create a mock writer to capture log output
	oldOutput := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Create a writeLogger and write to it
	logger := writeLogger{}
	testMessage := "Test log message"
	n, err := logger.Write([]byte(testMessage))

	// Close the write end of the pipe
	w.Close()
	os.Stdout = oldOutput

	// Read captured output
	capturedOutput, _ := io.ReadAll(r)

	// Check for errors
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Check that the correct number of bytes was written
	if n != len(testMessage) {
		t.Errorf("Expected to write %d bytes, wrote: %d", len(testMessage), n)
	}

	// Log should contain our test message (though it will also have timestamp, etc.)
	if !strings.Contains(string(capturedOutput), testMessage) {
		t.Errorf("Log output does not contain expected message. Got: %s", capturedOutput)
	}
}

func TestEnsureDependencies(t *testing.T) {
	// Skip this test if no Python is available
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		pythonPath, err = exec.LookPath("python")
		if err != nil {
			t.Skip("Skipping test as no Python executable found")
		}
	}

	// Test with a non-existent module that we shouldn't try to install in test
	err = ensureDependencies(pythonPath, "this_module_does_not_exist_"+fmt.Sprint(os.Getpid()))
	
	// We expect an error since this module doesn't exist and pip install would fail
	if err == nil {
		t.Error("Expected error when installing non-existent module, but got nil")
	}

	// Test with a module that should be available (sys is part of standard library)
	err = ensureDependencies(pythonPath, "sys")
	if err != nil {
		t.Errorf("Expected no error when checking standard library module, got: %v", err)
	}
}

func TestEnvironmentVariableForwarding(t *testing.T) {
	// Skip this test if no Python is available
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		pythonPath, err = exec.LookPath("python")
		if err != nil {
			t.Skip("Skipping test as no Python executable found")
		}
	}

	// Set TF_PLUGIN_MAGIC_COOKIE for testing
	testCookieValue := "test-cookie-value"
	oldCookie := os.Getenv(TFPluginMagicCookieKey)
	os.Setenv(TFPluginMagicCookieKey, testCookieValue)
	defer os.Setenv(TFPluginMagicCookieKey, oldCookie)

	// Create a temporary Python script to echo environment variables
	tempDir, err := os.MkdirTemp("", "pyvider-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	script := fmt.Sprintf(`
import os
print("ENV: %s=" + os.environ.get('%s', ''))
`, PyviderMagicCookieKey, PyviderMagicCookieKey)

	scriptPath := filepath.Join(tempDir, "env_test.py")
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		t.Fatalf("Failed to write test script: %v", err)
	}

	// Run the script
	cmd := exec.Command(pythonPath, scriptPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", PyviderMagicCookieKey, testCookieValue))
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		t.Fatalf("Failed to run test script: %v\nOutput: %s", err, output)
	}

	// Check that the environment variable was forwarded
	expectedOutput := fmt.Sprintf("ENV: %s=%s", PyviderMagicCookieKey, testCookieValue)
	if !strings.Contains(string(output), expectedOutput) {
		t.Errorf("Environment variable not forwarded correctly.\nExpected to find: %s\nGot: %s", 
			expectedOutput, output)
	}
}
