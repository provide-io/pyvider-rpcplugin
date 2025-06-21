#!/usr/bin/env python3

import os
import sys

# Ensure /app/src and /app are in sys.path for module resolution
# This is a workaround for potential PYTHONPATH/editable install issues in the test environment
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src"))
)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))


import argparse  # Added for CLI argument parsing
import asyncio
import logging
import os
import sys
import time
import traceback
from pathlib import Path

import grpc  # Added for specific gRPC error handling

from examples.kvproto.py_rpc.proto import (
    KVProtocol,
    kv_pb2,
    kv_pb2_grpc,
)
from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.telemetry import logger

# Configure logging
logging.basicConfig(
    level=logging.WARNING,  # Default level set here
    format="%(asctime)s.%(msecs)03d [%(levelname)-7s] %(name)s: 🐍 C> %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class KVClient:
    """Client for KV plugin server with improved error handling & diagnostics."""

    def __init__(self, server_path: str) -> None:
        self.server_path = server_path
        self._client = None
        self._stub = None
        self.connection_timeout = 15.0  # seconds

        # These env vars are primarily for the *plugin server process*
        self.plugin_env_for_server = {
            "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
            # The value for PLUGIN_MAGIC_COOKIE_KEY (BASIC_PLUGIN)
            "BASIC_PLUGIN": "hello",  # This was missing, this is what go-plugin checks
            "PLUGIN_MAGIC_COOKIE_VALUE": "hello",  # For pyvider's own config if it reads it
            "PLUGIN_PROTOCOL_VERSIONS": "1",  # For pyvider server
            "PLUGIN_TRANSPORTS": "unix",
            "PLUGIN_AUTO_MTLS": "true",  # For pyvider server
            "PYTHONUNBUFFERED": "1",  # Good for any Python server
            "GODEBUG": "asyncpreemptoff=1,panicasync=1",  # For Go server debugging
        }
        # For the client's own operations, it will read from its environment
        # (e.g. PLUGIN_SERVER_PATH if needed, or direct config)

    async def start(self) -> None:
        start_time = time.time()
        try:
            logger.debug(
                f"🤝 Creating an RPCPluginClient for server path: {self.server_path}"
            )

            if not os.path.exists(self.server_path):
                logger.error(f"🚨 Server executable not found at {self.server_path}")
                raise FileNotFoundError(
                    f"Server executable not found at {self.server_path}"
                )

            if not os.access(self.server_path, os.X_OK):
                logger.error(
                    f"🚨 Server executable is not executable: {self.server_path}"
                )
                raise PermissionError(
                    f"Server executable is not executable: {self.server_path}"
                )

            self._client = RPCPluginClient(
                command=[self.server_path],
                config={
                    "plugins": {"kv": KVProtocol()},
                    # Pass the prepared env vars for the server process
                    "env": self.plugin_env_for_server,
                },
            )

            logger.debug(f"▶️ Starting the client, timeout={self.connection_timeout}s")
            await asyncio.wait_for(
                self._client.start(), timeout=self.connection_timeout
            )

            # Start stderr relay only if the process and its stderr are available
            if self._client and self._client._process and self._client._process.stderr:
                self._relay_stderr()
            else:
                logger.warning(
                    "📝 Server process or stderr not available for relay at client start."
                )

            if hasattr(self._client, "_transport") and self._client._transport:
                transport_type = type(self._client._transport).__name__
                endpoint = getattr(self._client._transport, "endpoint", "unknown")
                logger.debug(f"🤝✅ Connected via {transport_type} to {endpoint}")

            # Wait a bit for server to be fully ready, especially if it's slow to init
            await asyncio.sleep(0.5)

            self._stub = kv_pb2_grpc.KVStub(self._client.grpc_channel)
            logger.info(
                f"✅ Connected to KV server successfully in {time.time() - start_time:.3f}s"
            )

        except TimeoutError:
            logger.error(
                f"🚨 Connection to KV server timed out after {time.time() - start_time:.3f}s"
            )
            if (
                self._client
                and self._client._process
                and self._client._process.poll() is None
            ):
                logger.debug("📝 Server process is still running after client timeout.")
            raise
        except Exception as e:
            logger.error(
                f"🚨 Failed to connect/start KV server: {type(e).__name__} - {e}"
            )
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def _relay_stderr(self) -> None:
        import threading

        # Ensure process and stderr are valid at the moment of thread creation
        if not (
            self._client and self._client._process and self._client._process.stderr
        ):
            logger.warning(
                "📝 stderr relay: client process or stderr not available at relay setup."
            )
            return

        stderr_pipe = self._client._process.stderr

        def read_stderr_thread():
            logger.debug("📝 stderr relay thread started.")
            while True:
                try:
                    # Check if stderr is closed directly, or if process is gone
                    if stderr_pipe.closed:
                        logger.debug("📝 stderr relay: stream pipe is closed.")
                        break
                    if (
                        not self._client or not self._client._process
                    ):  # Client or process might be cleaned up
                        logger.debug(
                            "📝 stderr relay: client or process no longer exists."
                        )
                        break

                    line_bytes = stderr_pipe.readline()
                    if not line_bytes:  # EOF
                        logger.debug("📝 stderr relay: EOF reached on stderr pipe.")
                        break
                    decoded = line_bytes.decode("utf-8", errors="replace").strip()
                    if decoded:
                        logger.debug(f"📝 SERVER_STDERR: {decoded}")
                except ValueError:  # readline from a closed pipe
                    logger.debug("📝 stderr relay: ValueError (likely pipe closed).")
                    break
                except Exception as e:
                    logger.error(
                        f"📝 Error in stderr relay thread: {type(e).__name__} - {e}"
                    )
                    break
            logger.debug("📝 stderr relay thread finished.")

        thread = threading.Thread(target=read_stderr_thread, daemon=True)
        thread.start()

    async def close(self) -> None:
        if hasattr(self, "_client") and self._client:
            logger.debug("🔒 Closing client connection...")
            try:
                # Ensure stderr relay is stopped or can handle process termination
                # The relay thread is daemon, so it should exit if main thread exits
                # If process is alive, try to close client gracefully
                if self._client._process and self._client._process.returncode is None:
                    if hasattr(self._client, "close") and asyncio.iscoroutinefunction(
                        self._client.close
                    ):
                        await self._client.close()
                    elif hasattr(self._client, "close"):
                        self._client.close()
                    logger.debug("🔒 RPCPluginClient close called.")
                else:
                    logger.debug(
                        "🔒 RPCPluginClient process already terminated or not started."
                    )
            except Exception as e:
                logger.error(
                    f"🔒 Error during RPCPluginClient.close(): {type(e).__name__} - {e}"
                )
                logger.error(traceback.format_exc())
            finally:
                self._client = None  # Ensure it's reset even if close fails
                self._stub = None
                logger.debug("🔒 Client attributes _client and _stub reset to None.")
        else:
            logger.debug(
                "🔒 Close called but _client was not initialized or already None."
            )

    async def put(self, key: str, value: bytes) -> None:
        if not self._stub:
            raise RuntimeError("Not connected to KV server (no stub).")
        if not isinstance(value, bytes):
            logger.error(f"Invalid type for value: expected bytes, got {type(value)}.")
            raise TypeError("Value for put must be bytes.")

        try:
            logger.debug(
                f"🗣️ 📝 Client: Sending Put request - key='{key}', value_size={len(value)} bytes."
            )
            await asyncio.wait_for(
                self._stub.Put(kv_pb2.PutRequest(key=key, value=value)), timeout=5.0
            )
            logger.info(f"🗣️ 📝 Client: Put successful for key='{key}'.")
        except TimeoutError:
            logger.error(f"🗣️ 📝 Client: Put operation timed out for key='{key}'.")
            raise
        except Exception as e:
            logger.error(
                f"🗣️ 📝 Client: Put operation failed for key='{key}'. Error: {type(e).__name__} - {e}"
            )
            raise

    async def get(self, key: str) -> bytes | None:
        if not self._stub:
            raise RuntimeError("Not connected to KV server (no stub).")
        try:
            logger.debug(f"🗣️ 📚 Client: Sending Get request - key='{key}'.")
            response = await asyncio.wait_for(
                self._stub.Get(kv_pb2.GetRequest(key=key)), timeout=5.0
            )

            # For a bytes field in proto3 (not explicitly optional),
            # it will be present as empty bytes if not set.
            # Accessing it directly is safe. Check its truthiness (non-empty).
            if response and response.value:
                value = response.value
                logger.info(
                    f"🗣️ 📚 Client: Get successful for key='{key}', retrieved {len(value)} bytes."
                )
                return value
            elif response:  # Response exists, but response.value is empty (b"")
                logger.info(
                    f"🗣️ 📚 Client: Get for key='{key}' returned an empty value."
                )
                return response.value  # Return b""
            else:  # Should ideally not be reached if gRPC error handling is correct
                logger.warning(
                    f"🗣️ 📚 Client: Get for key='{key}' returned no response (should have been caught by gRPC error)."
                )
                return None
        except TimeoutError:
            logger.error(f"🗣️ 📚 Client: Get operation timed out for key='{key}'.")
            raise
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.NOT_FOUND:
                logger.info(
                    f"🗣️ 📚 Client: Key='{key}' not found on server (gRPC StatusCode.NOT_FOUND)."
                )
                return None
            logger.error(
                f"🗣️ 📚 Client: Get operation for key='{key}' failed with gRPC error {e.code()}: {e.details()}"
            )
            raise
        except Exception as e:
            logger.error(
                f"🗣️ 📚 Client: Get operation for key='{key}' failed. Error: {type(e).__name__} - {e}"
            )
            raise


async def main() -> None:
    parser = argparse.ArgumentParser(description="KV Client for pyvider-rpcplugin demo")
    parser.add_argument(
        "command", choices=["get", "put"], help="Command to execute (get or put)"
    )
    parser.add_argument("key", help="The key for the operation")
    parser.add_argument(
        "value", nargs="?", help="The value for the put operation (required for put)"
    )
    parser.add_argument(
        "--server-path",
        help="Optional path to the server executable. Overrides PLUGIN_SERVER_PATH env var.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="WARNING",
        type=str.upper,  # Convert to uppercase for case-insensitive matching
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )

    args = parser.parse_args()

    # Set log level based on command line argument
    # Get the numeric level (e.g., logging.DEBUG for "DEBUG")
    numeric_log_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_log_level, int):
        raise ValueError(f"Invalid log level: {args.log_level}")

    # Get the root logger and set its level.
    # This will affect all loggers unless they have their own level set explicitly.
    # The pyvider.telemetry.logger is likely a child of the root logger or configured separately.
    # For basicConfig to take effect for handlers, it should be called before this.
    # If pyvider.telemetry.logger is a separate instance/configured independently,
    # its level might also need to be set if it doesn't propagate from root.
    # However, standard practice is that child loggers inherit from root or propagate to root's handlers.
    logging.getLogger().setLevel(numeric_log_level)
    # Also explicitly set the level for the pyvider.telemetry logger if it's managed separately
    # from the root logger's basicConfig settings.
    # from pyvider.telemetry import logger as pyvider_logger # already imported as logger
    # logger.setLevel(numeric_log_level) # PyviderLogger may not have setLevel, rely on root logger + basicConfig

    if args.command == "put" and args.value is None:
        parser.error("For 'put' command, 'value' argument is required.")

    script_dir = Path(__file__).parent.resolve()
    default_go_server_path = (
        script_dir.parent / "go-rpc" / "bin" / "kv-go-server"
    ).resolve()
    default_py_server_path = (script_dir / "py_kv_server.py").resolve()

    resolved_server_path_str = None

    # Priority: --server-path CLI arg, then PLUGIN_SERVER_PATH env var, then defaults
    if args.server_path:
        logger.info(
            f"Using server path from --server-path argument: {args.server_path}"
        )
        temp_path = Path(args.server_path)
        if temp_path.exists() and os.access(temp_path, os.X_OK):
            resolved_server_path_str = str(temp_path.resolve())
        else:
            logger.error(
                f"🚨 Server path from --server-path ('{args.server_path}') does not exist or is not executable."
            )
            sys.exit(1)
    else:
        server_path_env = os.environ.get("PLUGIN_SERVER_PATH")
        if server_path_env:
            logger.info(
                f"Using server path from PLUGIN_SERVER_PATH environment variable: {server_path_env}"
            )
            temp_path = Path(server_path_env)
            base_dirs_for_relative = [
                Path.cwd(),
                Path("/app") if Path("/app").exists() else None,
                script_dir,
            ]
            base_dirs_for_relative = [
                d for d in base_dirs_for_relative if d
            ]  # Filter out None

            search_paths = (
                [temp_path]
                if temp_path.is_absolute()
                else [base / temp_path for base in base_dirs_for_relative]
            )

            found_env_path = False
            for sp in search_paths:
                sp_resolved = sp.resolve()
                if sp_resolved.exists():
                    if os.access(sp_resolved, os.X_OK):
                        resolved_server_path_str = str(sp_resolved)
                        logger.info(
                            f"Found server via PLUGIN_SERVER_PATH ('{server_path_env}' -> '{resolved_server_path_str}')"
                        )
                        found_env_path = True
                        break
                    else:
                        logger.warning(
                            f"Server path {sp_resolved} from PLUGIN_SERVER_PATH exists but is not executable."
                        )
            if not found_env_path:
                logger.warning(
                    f"⚠️ PLUGIN_SERVER_PATH '{server_path_env}' not found or not executable. Trying defaults."
                )

        if not resolved_server_path_str:  # If env var not set or path not valid
            logger.info("Attempting to use default server paths as fallback.")
            if default_go_server_path.exists() and os.access(
                default_go_server_path, os.X_OK
            ):
                resolved_server_path_str = str(default_go_server_path)
                logger.info(f"Using default Go server: {resolved_server_path_str}")
            elif default_py_server_path.exists() and os.access(
                default_py_server_path, os.X_OK
            ):
                resolved_server_path_str = str(default_py_server_path)
                logger.info(f"Using default Python server: {resolved_server_path_str}")
            else:
                logger.error(
                    f"🚨 Default Go server ({default_go_server_path}) and Python server ({default_py_server_path}) not found or not executable."
                )
                sys.exit(1)

    logger.info(f"🚀 Starting KV client. Target server: {resolved_server_path_str}")

    client = KVClient(resolved_server_path_str)
    client_started_successfully = False

    try:
        logger.info("🔌 Attempting to connect to server...")
        await client.start()
        client_started_successfully = True
        logger.info("🔌 Connection to server successful.")

        if args.command == "put":
            put_value_bytes = args.value.encode("utf-8")
            logger.info(
                f"📝 Executing PUT: key='{args.key}', value (bytes)={put_value_bytes!r}"
            )
            await client.put(args.key, put_value_bytes)
        elif args.command == "get":
            logger.info(f"📚 Executing GET: key='{args.key}'")
            value = await client.get(args.key)
            if (
                value is not None
            ):  # This now correctly handles b"" as a valid (empty) value
                sys.stdout.buffer.write(value)
                sys.stdout.buffer.flush()
                sys.stdout.write("\n")
                sys.stdout.flush()

    except Exception as e:
        logger.error(f"❌ An error occurred: {type(e).__name__} - {e}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)
    finally:
        if client_started_successfully:
            logger.info(
                "🔒 Closing client connection in `finally` block (client was started)."
            )
            await client.close()
        elif hasattr(client, "_client") and client._client is not None:
            logger.info(
                "🔒 Client start failed or did not complete, attempting cleanup of partially initialized client."
            )
            await client.close()
        else:
            logger.info(
                "🏁 Operation completed (client was not started or already cleaned up)."
            )
        logger.info("👋 KV Client Finished.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Client interrupted by user (Ctrl+C).")
        sys.exit(130)
    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e:
        logger.critical(
            f"🚨 Critical unhandled error in script execution: {type(e).__name__} - {e}"
        )
        logger.critical(traceback.format_exc())
        sys.exit(1)
