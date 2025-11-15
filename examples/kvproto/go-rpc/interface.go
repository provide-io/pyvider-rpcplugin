package shared

import (
	"log"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/hashicorp/go-plugin/examples/kv/proto"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "hello",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	"kv": &KVPlugin{},
}

// KV is the interface that we're exposing as a plugin.
type KV interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
}

// KVPlugin is the implementation of plugin.Plugin so we can serve/consume this.
type KVPlugin struct {
	plugin.Plugin
	Impl KV
}

func (p *KVPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	log.Println("[DEBUG] plugin: Registering KV gRPC server.")
	proto.RegisterKVServer(s, &KVGRPCServer{Impl: p.Impl})
	return nil
}

func (p *KVPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	log.Println("[DEBUG] plugin: Creating KV gRPC client.")
	return &KVGRPCClient{client: proto.NewKVClient(c)}, nil
}
