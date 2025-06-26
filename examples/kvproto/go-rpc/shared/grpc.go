package shared
import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin/examples/kv/proto"
)
type KVGRPCServer struct {
	Impl   KV
	Logger hclog.Logger
	proto.UnimplementedKVServer
}
func (m *KVGRPCServer) Put(ctx context.Context, req *proto.PutRequest) (*proto.Empty, error) {
	m.Logger.Info("🔌➡️📥 Received Put request", "key", req.Key)
	err := m.Impl.Put(req.Key, req.Value)
	if err != nil {
		m.Logger.Error("🔌❌ Put operation failed", "key", req.Key, "error", err)
	} else {
		m.Logger.Debug("🔌✅ Put operation successful", "key", req.Key)
	}
	return &proto.Empty{}, err
}
func (m *KVGRPCServer) Get(ctx context.Context, req *proto.GetRequest) (*proto.GetResponse, error) {
	m.Logger.Info("🔌➡️📥 Received Get request", "key", req.Key)
	v, err := m.Impl.Get(req.Key)
	if err != nil {
		m.Logger.Error("🔌❌ Get operation failed", "key", req.Key, "error", err)
		return nil, err
	}
	m.Logger.Debug("🔌✅ Get operation successful", "key", req.Key)
	return &proto.GetResponse{Value: v}, nil
}
type KVGRPCClient struct {
	Client proto.KVClient
	Logger hclog.Logger
}
func (m *KVGRPCClient) Put(key string, value []byte) error {
	m.Logger.Info("📡➡️📤 Sending Put request", "key", key)
	_, err := m.Client.Put(context.Background(), &proto.PutRequest{
		Key:   key,
		Value: value,
	})
	if err != nil {
		m.Logger.Error("📡❌ Put request failed", "key", key, "error", err)
	} else {
		m.Logger.Debug("📡✅ Put request successful", "key", key)
	}
	return err
}
func (m *KVGRPCClient) Get(key string) ([]byte, error) {
	m.Logger.Info("📡➡️📤 Sending Get request", "key", key)
	resp, err := m.Client.Get(context.Background(), &proto.GetRequest{
		Key: key,
	})
	if err != nil {
		m.Logger.Error("📡❌ Get request failed", "key", key, "error", err)
		return nil, err
	}
	m.Logger.Debug("📡✅ Get request successful", "key", key)
	return resp.Value, nil
}
