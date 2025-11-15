# Required Examples Directory Structure

This document outlines the actual structure of the `examples/` directory.

\`\`\`
examples/
├── README.md                     # Examples overview and setup instructions
├── 01_quick_start.py            # Basic server/client setup
├── 02_server_setup.py           # Server configuration patterns
├── 03_client_connection.py      # Client implementation examples
├── 04_transport_options.py      # Unix socket vs TCP configuration
├── 05_security_mtls.py          # mTLS certificate setup
├── 06_async_patterns.py         # Best async practices
├── 07_error_handling.py         # Robust error management
├── 08_production_config.py      # Production deployment patterns
├── 09_custom_protocols.py       # Custom protocol definitions & middleware
├── 10_performance_tuning.py     # Performance benchmarking & optimization
├── __init__.py                  # Makes 'examples' a package (if needed)
├── dummy_server.sh              # Dummy server script for some examples
├── demo/                        # Subdirectory for the Echo demo
│   ├── __init__.py
│   ├── echo.proto
│   ├── echo_client.py
│   ├── echo_pb2.py
│   ├── echo_pb2.pyi
│   ├── echo_pb2_grpc.py
│   ├── echo_server.py
│   └── env.sh
└── kvproto/                     # Subdirectory for the Key-Value demo
    ├── __init__.py
    ├── env.sh                   # Environment setup for KV demos
    ├── go-rpc/                  # Go language RPC example for KV
    │   ├── ... (contents of go-rpc)
    ├── py_rpc/                  # Python RPC implementation for KV
    │   ├── __init__.py
    │   ├── proto/               # Protobuf definitions for Python KV
    │   │   ├── __init__.py
    │   │   ├── kv.proto
    │   │   ├── kv_pb2.py
    │   │   ├── kv_pb2.pyi
    │   │   └── kv_pb2_grpc.py
    │   ├── py_kv_client.py      # Python KV client
    │   └── py_kv_server.py      # Python KV server
    └── tests/                   # Tests specific to KV examples
        ├── ... (contents of tests)
\`\`\`

The historical "Priority Implementation Order" section has been removed as it's outdated.
