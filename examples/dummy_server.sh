#!/bin/sh
# This dummy server just prints the handshake string and exits after a delay.
# It does not create a real socket or run a gRPC server.
echo "1|1|unix|/tmp/dummy_server.sock|grpc|"
echo "Dummy server: Handshake sent. Will sleep for 10 seconds then exit." >&2
sleep 10
echo "Dummy server: Exiting." >&2
exit 0
