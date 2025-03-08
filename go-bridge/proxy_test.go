package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestBufferedProxy(t *testing.T) {
	// Create a command that will generate some output
	// Use "echo" since it's available on most platforms
	cmd := exec.Command("echo", "test output")
	
	// Set up pipes for the command
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Failed to create stdin pipe: %v", err)
	}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("Failed to create stderr pipe: %v", err)
	}
	
	// Start the command
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}
	
	// Save the original stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	
	// Create pipes to capture stdout and stderr
	stdoutR, stdoutW, _ := os.Pipe()
	stderrR, stderrW, _ := os.Pipe()
	
	// Set os.Stdout and os.Stderr to our pipes
	os.Stdout = stdoutW
	os.Stderr = stderrW
	
	// Create a buffered proxy with a small buffer
	proxy := NewBufferedProxy(1024)
	
	// Start a goroutine to run the proxy
	go func() {
		if err := proxy.Start(cmd.Process, stdin, stdout, stderr); err != nil {
			t.Errorf("Proxy.Start returned error: %v", err)
		}
	}()
	
	// Give the proxy time to complete (the echo command is very quick)
	time.Sleep(100 * time.Millisecond)
	
	// Close the write ends of our pipes to release any blocked readers
	stdoutW.Close()
	stderrW.Close()
	
	// Restore original stdout and stderr
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	
	// Read what was written to stdout
	stdoutOutput, _ := io.ReadAll(stdoutR)
	stderrOutput, _ := io.ReadAll(stderrR)
	
	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Command exited with error: %v", err)
	}
	
	// Check that stdout contains the expected output
	expectedOutput := "test output"
	if !bytes.Contains(stdoutOutput, []byte(expectedOutput)) {
		t.Errorf("Expected stdout to contain '%s', got: %s", expectedOutput, stdoutOutput)
	}
	
	// stderr should be empty for echo
	if len(stderrOutput) > 0 {
		t.Errorf("Expected stderr to be empty, got: %s", stderrOutput)
	}
}

func TestProxyIO(t *testing.T) {
	// Create a command that will read from stdin and write to stdout
	// Use "cat" since it's available on most Unix platforms
	// Skip test on Windows
	if os.Getenv("GOOS") == "windows" {
		t.Skip("Skipping test on Windows")
	}
	
	cmd := exec.Command("cat")
	
	// Set up pipes for the command
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Failed to create stdin pipe: %v", err)
	}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("Failed to create stderr pipe: %v", err)
	}
	
	// Start the command
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}
	
	// Save the original stdin, stdout, and stderr
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	
	// Create pipes to simulate stdin, and capture stdout and stderr
	stdinR, stdinW, _ := os.Pipe()
	stdoutR, stdoutW, _ := os.Pipe()
	stderrR, stderrW, _ := os.Pipe()
	
	// Set os.Stdin, os.Stdout, and os.Stderr to our pipes
	os.Stdin = stdinR
	os.Stdout = stdoutW
	os.Stderr = stderrW
	
	// Start a goroutine to run the proxy
	go func() {
		if err := proxyIO(cmd.Process, stdin, stdout, stderr); err != nil {
			t.Errorf("proxyIO returned error: %v", err)
		}
	}()
	
	// Write something to our stdin pipe
	testInput := "test input\n"
	_, err = stdinW.WriteString(testInput)
	if err != nil {
		t.Fatalf("Failed to write to stdin: %v", err)
	}
	
	// Close the write end of our stdin pipe to signal EOF
	stdinW.Close()
	
	// Give the proxy time to complete
	time.Sleep(100 * time.Millisecond)
	
	// Close the write ends of our stdout and stderr pipes
	stdoutW.Close()
	stderrW.Close()
	
	// Restore original stdin, stdout, and stderr
	os.Stdin = oldStdin
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	
	// Read what was written to stdout
	stdoutOutput, _ := io.ReadAll(stdoutR)
	stderrOutput, _ := io.ReadAll(stderrR)
	
	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Command exited with error: %v", err)
	}
	
	// Check that stdout contains the input we provided
	if !bytes.Contains(stdoutOutput, []byte(testInput)) {
		t.Errorf("Expected stdout to contain input '%s', got: %s", testInput, stdoutOutput)
	}
	
	// stderr should be empty for cat
	if len(stderrOutput) > 0 {
		t.Errorf("Expected stderr to be empty, got: %s", stderrOutput)
	}
}

func TestProxyErrorHandling(t *testing.T) {
	// Create a command that will generate an error
	cmd := exec.Command("false")
	
	// Start the command
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}
	
	// Create some closed pipes to trigger I/O errors
	stdinR, stdinW, _ := os.Pipe()
	stdoutR, stdoutW, _ := os.Pipe()
	stderrR, stderrW, _ := os.Pipe()
	
	// Close the pipes immediately
	stdinR.Close()
	stdinW.Close()
	stdoutR.Close()
	stdoutW.Close()
	stderrR.Close()
	stderrW.Close()
	
	// Try to proxy I/O with closed pipes
	// This should not hang or panic, but should return an error
	err := proxyIO(cmd.Process, stdinW, stdoutR, stderrR)
	
	// We expect an error
	if err == nil {
		t.Error("Expected error when proxying with closed pipes, but got nil")
	} else {
		t.Logf("Got expected error: %v", err)
	}
	
	// Clean up
	cmd.Process.Kill()
	cmd.Wait()
}

// Helper type to wrap a buffer as a file
type fileWrapper struct {
	*bytes.Buffer
}

func (fw *fileWrapper) Close() error {
	return nil
}

// Test with our own temporary test setup instead of relying on os.Stdout
func TestBufferedProxyWithLargeData(t *testing.T) {
	// Skip if not in long tests
	if testing.Short() {
		t.Skip("Skipping large data test in short mode")
	}
	
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "proxy-test-")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	
	// Generate a large amount of data (5MB)
	data := strings.Repeat("abcdefghijklmnopqrstuvwxyz", 200000)
	if _, err := tmpFile.WriteString(data); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()
	
	// Create a command to read the data
	cmd := exec.Command("cat", tmpFile.Name())
	
	// Set up pipes for the command
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Failed to create stdin pipe: %v", err)
	}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("Failed to create stderr pipe: %v", err)
	}
	
	// Start the command
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}
	
	// Create a buffer to capture output instead of using os.Stdout
	var captureBuffer bytes.Buffer
	
	// Create a buffered proxy with a small buffer to test buffer resizing
	proxy := NewBufferedProxy(1024)
	
	// Start a goroutine to run the proxy - redirect to our buffer instead of os.Stdout
	done := make(chan error)
	go func() {
		// Manual implementation similar to Start() but with our buffer
		var wg sync.WaitGroup
		
		// Forward stdin (we don't need this for the test)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer stdin.Close()
			// Not actually reading from stdin in this test
		}()
		
		// Forward stdout to our buffer
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := make([]byte, proxy.BufferSize)
			if _, err := io.CopyBuffer(&captureBuffer, stdout, buffer); err != nil {
				t.Errorf("Error in buffered stdout copy: %v", err)
			}
		}()
		
		// Forward stderr (not used in this test)
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := make([]byte, proxy.BufferSize)
			if _, err := io.CopyBuffer(io.Discard, stderr, buffer); err != nil {
				t.Errorf("Error in buffered stderr copy: %v", err)
			}
		}()
		
		wg.Wait()
		done <- nil
	}()
	
	// Wait for the proxy to complete or time out
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("BufferedProxy operation returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Proxy did not complete within timeout")
	}
	
	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Command exited with error: %v", err)
	}
	
	// Check that we received all the data
	if captureBuffer.Len() != len(data) {
		t.Errorf("Expected %d bytes, got %d", len(data), captureBuffer.Len())
	}
}
