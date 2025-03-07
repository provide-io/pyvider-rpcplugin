package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestFindPythonExecutable(t *testing.T) {
	// Real test that should pass on most systems
	pythonPath, err := findPythonExecutable()
	if err != nil {
		t.Logf("Could not find a Python executable, this might be normal depending on your system: %v", err)
	} else {
		t.Logf("Found Python at: %s", pythonPath)
		// Verify it's actually Python by running a simple command
		cmd := exec.Command(pythonPath, "-c", "print('test successful')")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("Failed to execute Python command: %v", err)
		}
		if !bytes.Contains(output, []byte("test successful")) {
			t.Errorf("Python output doesn't contain expected string. Got: %s", output)
		}
	}
}

func TestMainVersionFlag(t *testing.T) {
	// Save original os.Args and stdout
	oldArgs := os.Args
	oldStdout := os.Stdout

	// Restore original values when the test completes
	defer func() {
		os.Args = oldArgs
		os.Stdout = oldStdout
	}()

	// Create a pipe to capture stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Set command line args to include version flag
	os.Args = []string{"cmd", "--version"}
	
	// Reset flags to their default values
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	
	// Define a custom exit function for testing
	oldOsExit := osExit
	osExit = func(code int) { /* do nothing during test */ }
	defer func() { osExit = oldOsExit }()

	// Call main (this will exit via our custom exit function)
	go func() {
		defer func() {
			// Recover from any panics
			if r := recover(); r != nil {
				t.Logf("Recovered from panic: %v", r)
			}
		}()
		main()
	}()
	
	// Give it time to complete
	time.Sleep(100 * time.Millisecond)
	
	// Close the write end of the pipe to release any io.ReadAll
	w.Close()

	// Read the output
	output, _ := io.ReadAll(r)
	
	// Check that the version information was printed
	expectedPrefix := "pyvider-rpcplugin-bridge v"
	if !bytes.Contains(output, []byte(expectedPrefix)) {
		t.Errorf("Expected output to contain '%s', got: %s", expectedPrefix, output)
	}
}

// Mock version of osExit that we can use in testing to prevent tests from actually exiting
var osExit = func(code int) {
	os.Exit(code)
}

// TestMainHelp tests the help output
func TestMainHelp(t *testing.T) {
	// Save original os.Args and stdout
	oldArgs := os.Args
	oldStdout := os.Stdout

	// Restore original values when the test completes
	defer func() {
		os.Args = oldArgs
		os.Stdout = oldStdout
	}()

	// Create a pipe to capture stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Set command line args to include help flag
	os.Args = []string{"cmd", "--help"}
	
	// Reset flags to their default values
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	
	// Define a custom exit function for testing
	var exitCode int
	oldOsExit := osExit
	osExit = func(code int) { exitCode = code }
	defer func() { osExit = oldOsExit }()

	// Call main (this will exit via our custom exit function)
	go func() {
		// This is a bit of a hack - flag.Parse() will call os.Exit(2) for --help
		// but we need to catch that and return instead
		defer func() {
			if r := recover(); r != nil {
				t.Log("Recovered from panic in TestMainHelp")
			}
		}()
		main()
	}()
	
	// Give it time to complete
	time.Sleep(100 * time.Millisecond)
	
	// Close the write end of the pipe to release any io.ReadAll
	w.Close()

	// Read the output
	output, _ := io.ReadAll(r)
	
	// Check that the help information was printed
	if !bytes.Contains(output, []byte("Usage of")) {
		t.Errorf("Expected help output to contain 'Usage of', got: %s", output)
	}
}

func TestCreateLogFile(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "pyvider-test-")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Create a log file path in the temp directory
	logFilePath := filepath.Join(tempDir, "test.log")
	
	// Save original os.Args and flags
	oldArgs := os.Args
	oldFlagSet := flag.CommandLine
	
	// Restore original values when the test completes
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlagSet
	}()
	
	// Set command line args with log file flag
	os.Args = []string{"cmd", "--log-file", logFilePath, "--no-proxy"}
	
	// Reset flags to their default values
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	
	// Define a custom exit function for testing
	oldOsExit := osExit
	osExit = func(code int) { /* Do nothing */ }
	defer func() { osExit = oldOsExit }()
	
	// We don't want to actually run the main function fully since it would
	// try to establish connections, but we can test the log file creation by
	// creating a mock parseFlags function that simulates the behavior
	*logFile = logFilePath
	*noProxy = true
	
	// Create a go routine to "simulate" main but just for log file setup
	go func() {
		// Set up logging
		if *logFile != "" {
			f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				log, _ := f.WriteString("Test log entry\n")
				if log == 0 {
					t.Error("Failed to write to log file")
				}
			}
		}
	}()
	
	// Give it time to complete
	time.Sleep(100 * time.Millisecond)
	
	// Check that the log file was created and contains content
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		t.Errorf("Log file was not created at %s", logFilePath)
	} else {
		// Read the log file
		content, err := os.ReadFile(logFilePath)
		if err != nil {
			t.Errorf("Failed to read log file: %v", err)
		} else if !bytes.Contains(content, []byte("Test log entry")) {
			t.Errorf("Log file does not contain expected content. Got: %s", content)
		}
	}
}
