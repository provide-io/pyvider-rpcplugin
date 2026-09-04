// Copyright (c) provide.io llc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// A host that launches a pyvider plugin through go-plugin itself.
//
// The point is that nothing here is a replica. plugin.NewClient performs the
// handshake, generates the AutoMTLS client certificate (go-plugin/mtls.go, an
// ECDSA P-521 key), exports it as PLUGIN_CLIENT_CERT, pins the plugin's
// certificate from the sixth handshake field, and dials. Ping() then health
// checks the service name go-plugin requires. A Python gRPC client cannot
// stand in for this: it would generate a certificate its own TLS stack can
// present, which is exactly the case that never fails.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// nullPlugin satisfies the interface so a plugin set can be declared. Nothing
// is dispensed: the handshake, the mTLS negotiation and the health check are
// the whole subject.
type nullPlugin struct{ plugin.NetRPCUnsupportedPlugin }

func (nullPlugin) GRPCServer(*plugin.GRPCBroker, *grpc.Server) error { return nil }

func (nullPlugin) GRPCClient(ctx interface{ Done() <-chan struct{} }, b *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return nil, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: goclient <plugin-command> [args...]")
		os.Exit(2)
	}

	// Terraform offers the protocol versions its provider plugins serve; a host
	// that offers one the plugin does not is a version-negotiation test, not a
	// TLS one. Default to what pyvider serves.
	version := 6
	if raw := os.Getenv("PLUGIN_TEST_PROTOCOL_VERSION"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad PLUGIN_TEST_PROTOCOL_VERSION %q: %v\n", raw, err)
			os.Exit(2)
		}
		version = parsed
	}

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	// go-plugin appends its own variables to cmd.Env; starting from nil would
	// hand the child only those, losing PATH and PYTHONPATH.
	cmd.Env = os.Environ()

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			ProtocolVersion:  uint(version),
			MagicCookieKey:   os.Getenv("PLUGIN_MAGIC_COOKIE_KEY"),
			MagicCookieValue: os.Getenv(os.Getenv("PLUGIN_MAGIC_COOKIE_KEY")),
		},
		VersionedPlugins: map[int]plugin.PluginSet{version: {"test": &nullPlugin{}}},
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
	})
	defer client.Kill()

	rpc, err := client.Client()
	if err != nil {
		fmt.Printf("CONNECT FAILED: %v\n", err)
		os.Exit(1)
	}
	if err := rpc.Ping(); err != nil {
		fmt.Printf("PING FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PING OK")
}
