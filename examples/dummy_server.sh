#!/bin/sh
echo "1|1|unix|/tmp/dummy_server.sock|grpc|"
# Keep it running for a short while so the client's initial process checks (if any) can pass.
# With client.start() commented out, this sleep is less critical for connection,
# but good practice for a dummy script that might be launched.
sleep 2
echo "Dummy server finished."
