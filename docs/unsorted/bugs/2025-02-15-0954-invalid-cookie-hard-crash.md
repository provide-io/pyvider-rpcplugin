2025-02-15 09:53:40    [DEBUG]        rpcplugin.server 🏗️ 🫴  | 🛎️ Entering serve(); starting server setup...
2025-02-15 09:53:40    [DEBUG]        rpcplugin.server 🏗️ 🫴  | 🛎️ Registering signal handlers for graceful shutdown...
2025-02-15 09:53:40    [DEBUG]        rpcplugin.server 🏗️ 🫴  | 🛎️ Signal handler registered for SIGINT.
2025-02-15 09:53:40    [DEBUG]        rpcplugin.server 🏗️ 🫴  | 🛎️ Signal handler registered for SIGTERM.
2025-02-15 09:53:40    [DEBUG]        rpcplugin.server 🏗️ 🫴  | 🤝 Starting handshake negotiation...
2025-02-15 09:53:40    [DEBUG]     rpcplugin.handshake 🐍🏗️  | 🍪🔍 Starting magic cookie validation...
2025-02-15 09:53:40    [DEBUG]     rpcplugin.handshake 🐍🏗️  | 🍪 cookie_key: BASIC_PLUGIN
2025-02-15 09:53:40    [DEBUG]     rpcplugin.handshake 🐍🏗️  | 🍪 cookie_value: d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2
2025-02-15 09:53:40    [DEBUG]     rpcplugin.handshake 🐍🏗️  | 🍪 cookie_provided: hello
2025-02-15 09:53:40    [ERROR]     rpcplugin.handshake 🐍🏗️  | 🍪❌ cookie_provided does not match required cookie_value
2025-02-15 09:53:40    [ERROR]        rpcplugin.server 🏗️ 🫴  | 🤝❌ Handshake negotiation failed
2025-02-15 09:53:40    [ERROR]        rpcplugin.server 🏗️ 🫴  | 🛎️❌ Serve() failed during setup
2025-02-15 09:53:40    [ERROR]                __main__ 🐍🏗️  | 🛎️❗ Fatal error: Handshake negotiation failed: cookie_provided does not match required cookie_value
2025-02-15 09:53:40    [ERROR]                __main__ 🐍🏗️  | 🛎️❗ Server: Server failed: Handshake negotiation failed: cookie_provided does not match required cookie_value
Traceback (most recent call last):
  File "/REDACTED_ABS_PATH", line 258, in _negotiate_handshake
    validate_magic_cookie()
    ~~~~~~~~~~~~~~~~~~~~~^^
  File "/REDACTED_ABS_PATH", line 204, in validate_magic_cookie
    raise HandshakeError("cookie_provided does not match required cookie_value")
pyvider.rpcplugin.exception.HandshakeError: cookie_provided does not match required cookie_value

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/REDACTED_ABS_PATH", line 188, in <module>
    asyncio.run(serve())
    ~~~~~~~~~~~^^^^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.2/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 195, in run
    return runner.run(main)
           ~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.2/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 118, in run
    return self._loop.run_until_complete(task)
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.2/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/base_events.py", line 725, in run_until_complete
    return future.result()
           ~~~~~~~~~~~~~^^
  File "/REDACTED_ABS_PATH", line 168, in serve
    await server.serve()
  File "/REDACTED_ABS_PATH", line 308, in serve
    await self._negotiate_handshake()
  File "/REDACTED_ABS_PATH", line 281, in _negotiate_handshake
    raise HandshakeError(f"Handshake negotiation failed: {e}") from e
pyvider.rpcplugin.exception.HandshakeError: Handshake negotiation failed: cookie_provided does not match required cookie_value
2025-02-15 09:53:40  [WARNING]        rpcplugin.server 🏗️ 🫴  | RPCPluginServer __del__ called but shutdown was not properly requested.
2025-02-15 09:53:40    [ERROR]   rpcplugin.client.base 💻 ⚙️ | 🤝📖❌ Server stdout stream closed without handshake
2025-02-15 09:53:40    [ERROR]   rpcplugin.client.base 💻 ⚙️ | 🤝📖❌ Error reading handshake: Server stdout closed without handshake response
2025-02-15 09:53:40    [DEBUG]   rpcplugin.client.base 💻 ⚙️ | 🤝📖🔒 Cleaning up stderr reader task
2025-02-15 09:53:40    [ERROR]                __main__ 🐍🏗️  | 🚨 Failed to connect to KV server: I/O operation on closed file.
2025-02-15 09:53:40     [INFO]   rpcplugin.client.base 💻 ⚙️ | 🔄 Stopping RPC plugin client...
2025-02-15 09:53:40     [INFO]   rpcplugin.client.base 💻 ⚙️ | 🔄 Server process terminated.
2025-02-15 09:53:40    [DEBUG]                __main__ 🐍🏗️  | 🚨 Could not connect the client.
Traceback (most recent call last):
  File "/REDACTED_ABS_PATH", line 218, in _read_handshake_response
    response = await asyncio.wait_for(
               ^^^^^^^^^^^^^^^^^^^^^^^
    ...<2 lines>...
    )
    ^
  File "/opt/homebrew/Cellar/python@3.13/3.13.2/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/tasks.py", line 507, in wait_for
    return await fut
           ^^^^^^^^^
  File "/REDACTED_ABS_PATH", line 209, in read_stdout
    raise HandshakeError("Server stdout closed without handshake response")
pyvider.rpcplugin.exception.HandshakeError: Server stdout closed without handshake response

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/REDACTED_ABS_PATH", line 136, in main
    await client.connect()
  File "/REDACTED_ABS_PATH", line 55, in connect
    await self._client.start()
  File "/REDACTED_ABS_PATH", line 397, in start
    await self._perform_handshake()
  File "/REDACTED_ABS_PATH", line 94, in _perform_handshake
    response_str = await self._read_handshake_response()
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/REDACTED_ABS_PATH", line 238, in _read_handshake_response
    stderr_output = self._process.stderr.read()
ValueError: I/O operation on closed file.

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/REDACTED_ABS_PATH", line 152, in <module>
    asyncio.run(main())
    ~~~~~~~~~~~^^^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.2/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 195, in run
    return runner.run(main)
           ~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.2/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 118, in run
    return self._loop.run_until_complete(task)
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.2/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/base_events.py", line 725, in run_until_complete
    return future.result()
           ~~~~~~~~~~~~~^^
  File "/REDACTED_ABS_PATH", line 147, in main
    raise Exception
Exception
