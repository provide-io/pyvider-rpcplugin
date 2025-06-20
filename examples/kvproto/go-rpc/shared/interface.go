package shared

import (
	"context"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/hashicorp/go-plugin/examples/kv/proto"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "rpcplugin-default-cookie",
}

// KV is the interface that we're exposing as a plugin.
type KV interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
}

// This is the implementation of plugin.Plugin so we can serve/consume this.
type KVPlugin struct {
	plugin.Plugin
	Impl   KV
	Logger hclog.Logger
}

func (p *KVPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	p.Logger.Debug("🔌📝✅ Registering KV gRPC server")
	proto.RegisterKVServer(s, &KVGRPCServer{Impl: p.Impl, Logger: p.Logger})
	return nil
}

func (p *KVPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	if p.Logger == nil {
		// This can happen on the client side if the PluginMap isn't initialized with a logger.
		// We'll proceed, but the KVGRPCClient won't have a logger.
		// The main client process logger will still function.
		return &KVGRPCClient{Client: proto.NewKVClient(c)}, nil
	}
	p.Logger.Debug("📡📝✅ Creating KV gRPC client")
	return &KVGRPCClient{Client: proto.NewKVClient(c), Logger: p.Logger}, nil
}
