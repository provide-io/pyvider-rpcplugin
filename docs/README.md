# pyvider rpcplugin

## What Pyvider RPC Plugin Has

* Emoji logging! 😃 It makes it so much easier to debug walls of text.
* `attrs` integration!


## What Pyvider RPC Plugin Does Not Do

* Plugin discovery.

## What It Needs To Do

* Better Magic Cookie error handling for the example go server.
* PLUGIN_MULTIPLEX_GRPC
* Stub out `logger.trace()`? That way it can be distributed independently...? Or
  require a `pyvider-core` package?
* Allow `file://` in the env vars.
* Ensure that when both a cert/key get set in a Certificate that it verifies them
  upon setting - either durning or during runtime. i.e. a cert is already added, then someone tries to add a key - which would normally be passed in when creating the Certificate()
* Possibly leverage `uvloop`?


### Error Handling

* When "PLUGIN_TRANSPORTS" is invalid it should error out unstead of silently
  allow an invalid value.
* Stop swallowing the errors.

## Assumptions

1. Core Facts:
- The Go server (`kv-go-server`) is working correctly
- The protobuf definitions and generated files are correct
- Environment variables for magic cookies and plugin paths are set correctly
- Protocol version 1 is correct for this implementation
- Transport configuration (unix/tcp) is flexible and working

2. Focus Areas for `py-client.py`:
- gRPC channel establishment and management in Python client
- Lifecycle management of client connections
- Command-line interface implementation
- Asynchronous operation handling
- Error handling and reporting
- Resource cleanup

3. Debug Strategy:
- Issue must be in the Python client implementation
- We can reference working Go client behavior as a baseline
- Logging output comparison between Go and Python clients would be valuable
- Channel and connection state monitoring would be useful

Would you like to share the specific behavior or errors you're seeing with `py-client.py`?
* There is no Protocol Mismatch. The `py-client.py`, and current example, are v1. Higher versions may be indicative of other plugins. This is expected. Version negotiation failures must be handled and raised.

* There can be a single transport, or both. It is meant to be user definable and assume the Go server supports it.
  
* The appropriate environment variables are set accurately, and the cookie logic is working as expected.

* The go-based K/V client and server are working as expected with Auto MTLS on and off.
