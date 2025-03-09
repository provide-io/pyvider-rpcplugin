package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Launches the Python Pyvider process using uv and sets up bidirectional I/O
func launchPyvider(uvPath string, args []string, env []string, bufferSize int64) (*os.Process, error) {
	log.Printf("Launching Pyvider with uv: %s %v", uvPath, args)
	
	// Create the command
	cmd := exec.Command(uvPath, args...)
	
	// Set environment variables
	cmd.Env = env
	
	// Set up pipes for stdin/stdout/stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %v", err)
	}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
	}
	
	// Create a buffer to capture initial stderr output for debugging
	stderrBuffer := bytes.NewBuffer(nil)
	
	// Start the process
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return nil, fmt.Errorf("failed to start Python process: %v", err)
	}
	
	process := cmd.Process
	log.Printf("Started Python process via uv (PID: %d)", process.Pid)
	
	// Start goroutines for proxying I/O
	var wg sync.WaitGroup
	
	// Capture stderr to both our log and pass through to Terraform
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		// Use a tee reader to capture stderr to our buffer while also forwarding it
		teeReader := io.TeeReader(stderr, stderrBuffer)
		
		// Create a multi-writer to send to both stderr and our log
		multiWriter := io.MultiWriter(os.Stderr, writeLogger{})
		
		// Use the optimized buffer size
		buf := make([]byte, bufferSize)
		
		// Copy with our larger buffer
		_, err := io.CopyBuffer(multiWriter, teeReader, buf)
		if err != nil && err != io.EOF {
			log.Printf("Error reading from stderr: %v", err)
		}
	}()
	
	// Forward stdin from Terraform to Pyvider
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdin.Close()
		
		// Use the optimized buffer size for large Terraform state
		buf := make([]byte, bufferSize)
		
		// Copy with timeout protection to avoid deadlocks
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		
		go func() {
			_, err := io.CopyBuffer(stdin, os.Stdin, buf)
			if err != nil && err != io.EOF {
				log.Printf("Error writing to stdin: %v", err)
			}
			cancel() // Signal completion
		}()
		
		// Wait for either completion or process termination
		<-ctx.Done()
	}()
	
	// Forward stdout from Pyvider to Terraform
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		// Use the optimized buffer size for large state files
		buf := make([]byte, bufferSize)
		
		// Create a context with timeout for the first line (handshake)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		// Check for handshake with a deadline
		handshakeComplete := make(chan bool, 1)
		
		// Monitor the first line of output separately
		go func() {
			// Read just enough for the handshake
			handshakeBuf := make([]byte, 1024)
			n, err := stdout.Read(handshakeBuf)
			if err != nil {
				log.Printf("Error reading handshake: %v", err)
				handshakeComplete <- false
				return
			}
			
			// Write the handshake to stdout
			if _, err := os.Stdout.Write(handshakeBuf[:n]); err != nil {
				log.Printf("Error writing handshake to stdout: %v", err)
			}
			
			// Signal handshake completion
			handshakeComplete <- true
		}()
		
		// Wait for handshake with timeout
		select {
		case success := <-handshakeComplete:
			if !success {
				// If handshake failed, dump the stderr buffer for debugging
				log.Printf("Handshake failed, stderr contents: %s", stderrBuffer.String())
			} else {
				log.Printf("Handshake received successfully, continuing stream")
			}
		case <-ctx.Done():
			// Handshake timed out
			log.Printf("Handshake timed out, stderr contents: %s", stderrBuffer.String())
			process.Kill()
			return
		}
		
		// Continue streaming the remaining stdout
		_, err := io.CopyBuffer(os.Stdout, stdout, buf)
		if err != nil && err != io.EOF {
			log.Printf("Error forwarding stdout: %v", err)
		}
	}()
	
	// Don't wait for the goroutines to finish - they'll continue running
	// as long as the process is alive
	
	return process, nil
}

// writeLogger implements io.Writer to forward messages to the log
type writeLogger struct{}

func (wl writeLogger) Write(p []byte) (n int, err error) {
	log.Print(string(p))
	return len(p), nil
}
