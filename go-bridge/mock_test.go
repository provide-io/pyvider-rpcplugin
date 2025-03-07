
package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// MockPython is a test helper that provides a controlled environment for testing
// Python interactions without requiring an actual Python installation
type MockPython struct {
	t           *testing.T
	tempDir     string
	pythonPath  string
	moduleDir   string
	moduleInit  string
	mockStdout  *bytes.Buffer
	mockStderr  *bytes.Buffer
	environment []string
}

// NewMockPython creates a new MockPython instance
func NewMockPython(t *testing.T) *MockPython {
	// Create a temporary directory for our mock Python environment
	tempDir, err := os.MkdirTemp("", "mock-python-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create a mock Python script
	pythonPath := filepath.Join(tempDir, "mock-python")
	if os.Getenv("GOOS") == "windows" {
		pythonPath += ".bat"
	}

	// Create the mock script based on platform
	var script string
	if os.Getenv("GOOS") == "windows" {
		script = `@echo off
echo Mock Python %*
if "%1"=="-c" (
    echo Executing: %2
    if "%2"=="import mockpyvider" (
        exit 0
    ) else (
        exit 1
    )
) else if "%1"=="-m" (
    if "%2"=="pip" (
        echo Mock pip install
        exit 0
    ) else if "%2"=="mockpyvider" (
        echo Mock module running
        exit 0
    ) else (
        echo Unknown module: %2
        exit 1
    )
) else (
    echo Unknown command
    exit 1
)
`
	} else {
		script = `#!/bin/sh
echo "Mock Python $@"
if [ "$1" = "-c" ]; then
    echo "Executing: $2"
    if [ "$2" = "import mockpyvider" ]; then
        exit 0
    else
        exit 1
    fi
elif [ "$1" = "-m" ]; then
    if [ "$2" = "pip" ]; then
        echo "Mock pip install"
        exit 0
    elif [ "$2" = "mockpyvider" ]; then
        echo "Mock module running"
        exit 0
    else
        echo "Unknown module: $2"
        exit 1
    fi
else
    echo "Unknown command"
    exit 1
fi
`
	}

	// Write the script to a file
	if err := os.WriteFile(pythonPath, []byte(script), 0755); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to write mock Python script: %v", err)
	}

	// Create the module directory
	moduleDir := filepath.Join(tempDir, "mockpyvider")
	if err := os.Mkdir(moduleDir, 0755); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create module directory: %v", err)
	}

	// Create a mock __init__.py
	moduleInit := filepath.Join(moduleDir, "__init__.py")
	if err := os.WriteFile(moduleInit, []byte("# Mock module\n"), 0644); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to write module __init__.py: %v", err)
	}

	return &MockPython{
		t:           t,
		tempDir:     tempDir,
		pythonPath:  pythonPath,
		moduleDir:   moduleDir,
		moduleInit:  moduleInit,
		mockStdout:  &bytes.Buffer{},
		mockStderr:  &bytes.Buffer{},
		environment: os.Environ(),
	}
}

// Cleanup removes the temporary directory
func (m *MockPython) Cleanup() {
	os.RemoveAll(m.tempDir)
}

// SetEnv adds an environment variable for the mock Python
func (m *MockPython) SetEnv(key, value string) {
	m.environment = append(m.environment, key+"="+value)
}

// ExecuteCommand runs a command with the mock Python
func (m *MockPython) ExecuteCommand(args ...string) (string, string, error) {
	cmd := exec.Command(m.pythonPath, args...)
	cmd.Env = m.environment
	
	// Set up pipes for capturing stdout and stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", err
	}
	
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "", err
	}
	
	// Start the command
	if err := cmd.Start(); err != nil {
		return "", "", err
	}
	
	// Read stdout and stderr
	var stdout, stderr bytes.Buffer
	go io.Copy(&stdout, stdoutPipe)
	go io.Copy(&stderr, stderrPipe)
	
	// Wait for the command to finish
	err = cmd.Wait()
	
	return stdout.String(), stderr.String(), err
}

// TestMockPython tests the MockPython helper
func TestMockPython(t *testing.T) {
	mock := NewMockPython(t)
	defer mock.Cleanup()
	
	// Test basic command execution
	stdout, stderr, err := mock.ExecuteCommand("-c", "print('hello')")
	if err != nil {
		t.Errorf("Mock Python execution failed: %v", err)
	}
	
	if !strings.Contains(stdout, "Mock Python") {
		t.Errorf("Expected stdout to contain 'Mock Python', got: %s", stdout)
	}
	
	if len(stderr) > 0 {
		t.Errorf("Expected stderr to be empty, got: %s", stderr)
	}
	
	// Test import check (should succeed)
	stdout, stderr, err = mock.ExecuteCommand("-c", "import mockpyvider")
	if err != nil {
		t.Errorf("Import check failed: %v", err)
	}
	
	// Test import check (should fail)
	stdout, stderr, err = mock.ExecuteCommand("-c", "import nonexistent")
	if err == nil {
		t.Errorf("Expected import of nonexistent module to fail")
	}
	
	// Test module execution
	stdout, stderr, err = mock.ExecuteCommand("-m", "mockpyvider")
	if err != nil {
		t.Errorf("Module execution failed: %v", err)
	}
	
	if !strings.Contains(stdout, "Mock module running") {
		t.Errorf("Expected stdout to contain 'Mock module running', got: %s", stdout)
	}
}

// TestWithMockPython tests the launcher functions using MockPython
func TestWithMockPython(t *testing.T) {
	mock := NewMockPython(t)
	defer mock.Cleanup()
	
	// Test ensureDependencies
	err := ensureDependencies(mock.pythonPath, "mockpyvider")
	if err != nil {
		t.Errorf("ensureDependencies failed: %v", err)
	}
	
	// Test launchPyvider
	// This won't actually work with our mock since it doesn't handle all the required args,
	// but we can at least make sure it attempts to start the process
	proc, err := launchPyvider(mock.pythonPath, "mockpyvider", false)
	if err != nil {
		// This is expected with our simple mock
		t.Logf("launchPyvider failed as expected: %v", err)
	} else {
		// If it somehow succeeds, clean up
		proc.Kill()
		t.Log("launchPyvider succeeded unexpectedly")
	}
}

// TestFindMockPython tests findPythonExecutable with a mock in PATH
func TestFindMockPython(t *testing.T) {
	mock := NewMockPython(t)
	defer mock.Cleanup()
	
	// Save the original PATH
	oldPath := os.Getenv("PATH")
	defer os.Setenv("PATH", oldPath)
	
	// Add our mock Python directory to the beginning of PATH
	newPath := mock.tempDir + string(os.PathListSeparator) + oldPath
	os.Setenv("PATH", newPath)
	
	// Create a copy of our mock Python with a standard name
	pythonName := "python3"
	if os.Getenv("GOOS") == "windows" {
		pythonName = "python3.exe"
	}
	
	mockPythonStandard := filepath.Join(mock.tempDir, pythonName)
	err := copyFile(mock.pythonPath, mockPythonStandard)
	if err != nil {
		t.Fatalf("Failed to copy mock Python: %v", err)
	}
	
	// Test findPythonExecutable
	pythonPath, err := findPythonExecutable()
	if err != nil {
		t.Errorf("findPythonExecutable failed: %v", err)
	} else if !strings.Contains(pythonPath, mock.tempDir) {
		t.Errorf("findPythonExecutable found wrong Python: %s", pythonPath)
	}
}

// Helper function to copy a file
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	
	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()
	
	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}
	
	// Make the file executable
	return os.Chmod(dst, 0755)
}
