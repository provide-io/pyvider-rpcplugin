package shared
import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"github.com/hashicorp/go-plugin/examples/kv/proto"
)
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "hello",
}
type KV interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
}
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
		return &KVGRPCClient{Client: proto.NewKVClient(c)}, nil
	}
	p.Logger.Debug("📡📝✅ Creating KV gRPC client")
	return &KVGRPCClient{Client: proto.NewKVClient(c), Logger: p.Logger}, nil
}
