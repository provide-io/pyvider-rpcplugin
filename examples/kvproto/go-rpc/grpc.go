package shared

import (
	"context"
	"log"

	"github.com/hashicorp/go-plugin/examples/kv/proto"
)

// KVGRPCServer is the gRPC server that GRPCClient talks to.
type KVGRPCServer struct {
	// This is the real implementation
	Impl KV

	proto.UnimplementedKVServer
}

func (m *KVGRPCServer) Put(ctx context.Context, req *proto.PutRequest) (*proto.PutResponse, error) {
	log.Printf("[INFO] server: Received Put request for key '%s'", req.Key)
	err := m.Impl.Put(req.Key, req.Value)
	if err != nil {
		log.Printf("[ERROR] server: Failed to execute Put for key '%s': %v", req.Key, err)
	} else {
		log.Printf("[DEBUG] server: Successfully executed Put for key '%s'", req.Key)
	}
	return &proto.PutResponse{}, err
}

func (m *KVGRPCServer) Get(ctx context.Context, req *proto.GetRequest) (*proto.GetResponse, error) {
	log.Printf("[INFO] server: Received Get request for key '%s'", req.Key)
	v, err := m.Impl.Get(req.Key)
	if err != nil {
		log.Printf("[ERROR] server: Failed to execute Get for key '%s': %v", req.Key, err)
		return nil, err
	}

	log.Printf("[DEBUG] server: Successfully executed Get for key '%s', returning value.", req.Key)
	return &proto.GetResponse{Value: v}, nil
}

// KVGRPCClient is an implementation of KV that talks over RPC.
type KVGRPCClient struct {
	client proto.KVClient
}

func (m *KVGRPCClient) Put(key string, value []byte) error {
	log.Printf("[INFO] client: Sending Put request for key '%s'", key)
	_, err := m.client.Put(context.Background(), &proto.PutRequest{
		Key:   key,
		Value: value,
	})
	if err != nil {
		log.Printf("[ERROR] client: Failed to send Put request for key '%s': %v", key, err)
	} else {
		log.Printf("[DEBUG] client: Put request for key '%s' successful", key)
	}
	return err
}

func (m *KVGRPCClient) Get(key string) ([]byte, error) {
	log.Printf("[INFO] client: Sending Get request for key '%s'", key)
	resp, err := m.client.Get(context.Background(), &proto.GetRequest{
		Key: key,
	})
	if err != nil {
		log.Printf("[ERROR] client: Failed to send Get request for key '%s': %v", key, err)
		return nil, err
	}

	log.Printf("[DEBUG] client: Get request for key '%s' successful.", key)
	return resp.Value, nil
}
