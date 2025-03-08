
package main

import (
	"io"
	"log"
	"os"
	"sync"
)

// proxyIO handles the bidirectional I/O proxying between processes
func proxyIO(proc *os.Process, stdin io.WriteCloser, stdout, stderr io.ReadCloser) error {
	var wg sync.WaitGroup
	
	// Forward stdin from os.Stdin to the process
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdin.Close()
		
		if _, err := io.Copy(stdin, os.Stdin); err != nil {
			log.Printf("Error copying stdin: %v", err)
		}
	}()
	
	// Forward stdout from the process to os.Stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		if _, err := io.Copy(os.Stdout, stdout); err != nil {
			log.Printf("Error copying stdout: %v", err)
		}
	}()
	
	// Forward stderr from the process to os.Stderr
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		// Create a multi-writer to both os.Stderr and our log
		multiWriter := io.MultiWriter(os.Stderr, writeLogger{})
		if _, err := io.Copy(multiWriter, stderr); err != nil {
			log.Printf("Error copying stderr: %v", err)
		}
	}()
	
	// Wait for all copying to complete
	wg.Wait()
	return nil
}

// BufferedProxy implements a buffered proxy with configurable buffer size
// This can be useful for large Terraform state transfers
type BufferedProxy struct {
	BufferSize int
}

// NewBufferedProxy creates a new buffered proxy with the specified buffer size
func NewBufferedProxy(bufferSize int) *BufferedProxy {
	return &BufferedProxy{
		BufferSize: bufferSize,
	}
}

// Start begins proxying I/O with buffering
func (bp *BufferedProxy) Start(proc *os.Process, stdin io.WriteCloser, stdout, stderr io.ReadCloser) error {
	var wg sync.WaitGroup
	
	// Forward stdin with buffering
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdin.Close()
		
		buffer := make([]byte, bp.BufferSize)
		if _, err := io.CopyBuffer(stdin, os.Stdin, buffer); err != nil {
			log.Printf("Error in buffered stdin copy: %v", err)
		}
	}()
	
	// Forward stdout with buffering
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		buffer := make([]byte, bp.BufferSize)
		if _, err := io.CopyBuffer(os.Stdout, stdout, buffer); err != nil {
			log.Printf("Error in buffered stdout copy: %v", err)
		}
	}()
	
	// Forward stderr with buffering
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		multiWriter := io.MultiWriter(os.Stderr, writeLogger{})
		buffer := make([]byte, bp.BufferSize)
		if _, err := io.CopyBuffer(multiWriter, stderr, buffer); err != nil {
			log.Printf("Error in buffered stderr copy: %v", err)
		}
	}()
	
	wg.Wait()
	return nil
}
