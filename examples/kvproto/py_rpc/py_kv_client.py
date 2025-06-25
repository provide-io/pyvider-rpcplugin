#!/usr/bin/env python3

import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, cast

import grpc

# Ensure /app/src and /app are in sys.path for module resolution
# Assuming __file__ is examples/kvproto/py_rpc/py_kv_client.py
# Go up 4 levels to reach /app (project root)
project_root_dir = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../..")
)
src_dir_abs = os.path.join(project_root_dir, "src")

if os.path.exists(src_dir_abs) and src_dir_abs not in sys.path:
    sys.path.insert(0, src_dir_abs)
if project_root_dir not in sys.path:  # Add project root too for 'examples.demo' etc.
    sys.path.insert(0, project_root_dir)

# Generated code import
# Assuming py_kv_client.py is in examples/kvproto/py_rpc/
# and proto files are in examples/kvproto/py_rpc/proto/
try:
    from .proto import kv_pb2, kv_pb2_grpc
except ImportError:
    # Fallback for scenarios where CWD might be /app or /app/examples
    # and the .proto style import is preferred.
    logger.warning("Relative import .proto failed, trying absolute examples.kvproto...")
    from examples.kvproto.py_rpc.proto import kv_pb2, kv_pb2_grpc

from pyvider.rpcplugin.client import RPCPluginClient  # noqa: E402

# KVProtocol itself is not needed by the client directly
# from pyvider.telemetry import logger # Using standard logging

# Configure logging first
print(f"DEBUG: py_kv_client.py sys.path: {sys.path}")
print(f"DEBUG: py_kv_client.py CWD: {os.getcwd()}")
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s.%(msecs)03d [%(levelname)-7s] %(name)s: 🐍 C> %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Generated code import
# Assuming py_kv_client.py is in examples/kvproto/py_rpc/
# and proto files are in examples/kvproto/py_rpc/proto/
try:
    from .proto import kv_pb2, kv_pb2_grpc
except ImportError:
    # Fallback for scenarios where CWD might be /app or /app/examples
    # and the .proto style import is preferred.
    logger.warning("Relative import .proto failed, trying absolute examples.kvproto...")
    from examples.kvproto.py_rpc.proto import kv_pb2, kv_pb2_grpc

from pyvider.rpcplugin.client import RPCPluginClient  # noqa: E402

# KVProtocol itself is not needed by the client directly


class KVClient:
    """Client for KV plugin server with improved error handling & diagnostics."""

    server_path: str
    _client: RPCPluginClient | None
    _stub: kv_pb2_grpc.KVStub | None
    plugin_env_for_server: dict[str, str]
    client_config: dict[str, Any]
    connection_timeout: float

    def __init__(self, server_path: str) -> None:
        self.server_path = server_path
        self._client = None
        self._stub = None
        self.connection_timeout = 15.0

        self.plugin_env_for_server = {
            "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
            "BASIC_PLUGIN": "hello",
            "PLUGIN_MAGIC_COOKIE_VALUE": "hello",  # Server expects this
            "PLUGIN_PROTOCOL_VERSIONS": "1",
            "PLUGIN_TRANSPORTS": "unix",
            "PLUGIN_AUTO_MTLS": "true",
            "PYTHONUNBUFFERED": "1",
            "GODEBUG": "asyncpreemptoff=1,panicasync=1",
        }
        self.client_config = {
            "env": self.plugin_env_for_server,
            "PLUGIN_MAGIC_COOKIE": "hello"  # For client's own handshake validation
        }

    async def start(self) -> bool:
        start_time = time.time()
        try:
            logger.debug(f"🤝 Creating RPCPluginClient for server: {self.server_path}")
            if not os.path.exists(self.server_path):
                logger.error(f"🚨 Server executable not found: {self.server_path}")
                return False
            if not os.access(self.server_path, os.X_OK):
                logger.error(f"🚨 Server not executable: {self.server_path}")
                return False

            self._client = RPCPluginClient(
                command=[self.server_path],
                config=self.client_config,
            )
            logger.debug(f"▶️ Starting client, timeout={self.connection_timeout}s")
            await asyncio.wait_for(
                self._client.start(), timeout=self.connection_timeout
            )

            if self._client._process and self._client._process.stderr:
                self._relay_stderr()

            if not self._client.grpc_channel:
                logger.error("gRPC channel not established after client start.")
                await self.close()
                return False

            self._stub = kv_pb2_grpc.KVStub(self._client.grpc_channel)
            duration = time.time() - start_time
            logger.info(f"✅ KV server connected in {duration:.3f}s")  # Shortened
            return True
        except TimeoutError:
            duration = time.time() - start_time
            logger.error(
                f"🚨 KV server conn timed out after {duration:.3f}s"
            )  # Shortened
            if (
                self._client
                and self._client._process
                and self._client._process.poll() is None
            ):
                logger.debug("📝 Server process still running after client timeout.")
            await self.close()
            return False
        except Exception as e:
            logger.error(f"🚨 Failed to start/connect KV server: {e}", exc_info=True)
            await self.close()
            return False

    def _relay_stderr(self) -> None:
        import threading

        if not (
            self._client and self._client._process and self._client._process.stderr
        ):
            return
        stderr_pipe = self._client._process.stderr

        def read_stderr_thread() -> None:
            logger.debug("📝 stderr relay thread started.")
            while True:
                try:
                    if stderr_pipe.closed:
                        break
                    if not self._client or not self._client._process:
                        break
                    line_bytes = stderr_pipe.readline()
                    if not line_bytes:
                        break
                    decoded = line_bytes.decode("utf-8", errors="replace").strip()
                    if decoded:
                        logger.debug(f"📝 SERVER_STDERR: {decoded}")
                except ValueError:
                    break
                except Exception as e:
                    logger.error(f"📝 Error in stderr relay: {e}")
                    break
            logger.debug("📝 stderr relay thread finished.")

        thread = threading.Thread(target=read_stderr_thread, daemon=True)
        thread.start()

    async def close(self) -> None:
        if self._client:
            logger.debug("🔒 Closing client connection...")
            try:
                await self._client.close()
                logger.debug("🔒 RPCPluginClient close called.")
            except Exception as e:
                logger.error(
                    f"🔒 Error during RPCPluginClient.close(): {e}", exc_info=True
                )
            finally:
                self._client = None
                self._stub = None
        else:
            logger.debug("🔒 Close called but _client was None.")

    async def put(self, key: str, value: bytes) -> None:
        if not self._stub or not (self._client and self._client.is_started):
            raise RuntimeError("Client not started or stub not available.")
        if not isinstance(value, bytes):
            raise TypeError("Value for put must be bytes.")
        try:
            # Shortened log message
            logger.debug(f"🗣️ Client: Put key='{key}', {len(value)}b.")
            await asyncio.wait_for(
                self._stub.Put(kv_pb2.PutRequest(key=key, value=value)), timeout=5.0
            )
            logger.info(f"🗣️ Client: Put successful for key='{key}'.")
        except TimeoutError:
            logger.error(f"🗣️ Client: Put timed out for key='{key}'.")
            raise
        except Exception as e:
            logger.error(f"🗣️ Client: Put failed for key='{key}'. Err: {e}")
            raise

    async def get(self, key: str) -> bytes | None:
        if not self._stub or not (self._client and self._client.is_started):
            raise RuntimeError("Client not started or stub not available.")
        try:
            logger.debug(f"🗣️ Client: Sending Get - key='{key}'.")
            response = await asyncio.wait_for(
                self._stub.Get(kv_pb2.GetRequest(key=key)), timeout=5.0
            )
            if response:
                # Shortened log message
                logger.info(
                    f"🗣️ Client: Get for '{key}' retrieved {len(response.value)}b."
                )
                return response.value
            return None
        except TimeoutError:
            logger.error(f"🗣️ Client: Get timed out for key='{key}'.")
            raise
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.NOT_FOUND:
                return None
            # Shortened log message
            logger.error(
                f"🗣️ Client: Get for '{key}' gRPC err {e.code()}: {e.details()}"
            )
            raise
        except Exception as e:
            logger.error(f"🗣️ Client: Get for '{key}' failed: {e}")
            raise


async def main() -> None:
    parser = argparse.ArgumentParser(description="KV Client for pyvider-rpcplugin demo")
    parser.add_argument("command", choices=["get", "put"], help="Command")
    parser.add_argument("key", help="Key for the operation")
    parser.add_argument("value", nargs="?", help="Value for put operation")
    # Shortened help string
    parser.add_argument(
        "--server-path", help="Path to server exec (overrides PLUGIN_SERVER_PATH)."
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="WARNING",
        type=str.upper,
    )
    args: argparse.Namespace = parser.parse_args()

    numeric_log_level = getattr(logging, args.log_level, logging.WARNING)
    logging.getLogger().setLevel(numeric_log_level)
    logger.setLevel(numeric_log_level)

    if args.command == "put" and args.value is None:
        parser.error("For 'put' command, 'value' argument is required.")

    script_dir = Path(__file__).parent.resolve()
    default_py_server_path = (script_dir / "py_kv_server.py").resolve()
    default_go_server_path = (
        Path(project_root_dir)
        / "examples"
        / "kvproto"
        / "go-rpc"
        / "bin"
        / "kv-go-server"
    )

    resolved_server_path_str: str | None = None
    if args.server_path:
        temp_path = Path(args.server_path)
        if temp_path.exists() and os.access(temp_path, os.X_OK):
            resolved_server_path_str = str(temp_path.resolve())
        else:
            logger.error(f"🚨 Path from --server-path ('{args.server_path}') invalid.")
            sys.exit(1)
    else:
        server_path_env = os.environ.get("PLUGIN_SERVER_PATH")
        if server_path_env:
            temp_path = Path(server_path_env)
            if (
                temp_path.is_absolute()
                and temp_path.exists()
                and os.access(temp_path, os.X_OK)
            ):
                resolved_server_path_str = str(temp_path)
            else:
                temp_path_rel = Path.cwd() / temp_path
                if temp_path_rel.exists() and os.access(temp_path_rel, os.X_OK):
                    resolved_server_path_str = str(temp_path_rel)
            if not resolved_server_path_str:
                logger.warning(
                    f"⚠️ PLUGIN_SERVER_PATH '{server_path_env}' not found/exec."
                )

        if not resolved_server_path_str:
            if default_py_server_path.exists() and os.access(
                default_py_server_path, os.X_OK
            ):
                resolved_server_path_str = str(default_py_server_path)
                logger.info(f"Using default Python server: {resolved_server_path_str}")
            elif default_go_server_path.exists() and os.access(
                default_go_server_path, os.X_OK
            ):
                resolved_server_path_str = str(default_go_server_path)
                logger.info(f"Using default Go server: {resolved_server_path_str}")
            else:
                logger.error("🚨 Default servers not found/executable.")
                sys.exit(1)

    if not resolved_server_path_str:
        logger.error("🚨 No server path resolved.")
        sys.exit(1)

    logger.info(f"🚀 Starting KV client. Target server: {resolved_server_path_str}")
    client: KVClient = KVClient(resolved_server_path_str)
    client_started_successfully = False
    try:
        logger.info("🔌 Attempting to connect to server...")
        client_started_successfully = await client.start()
        if not client_started_successfully:
            logger.error("❌ Client failed to start. Exiting.")
            sys.exit(1)
        logger.info("🔌 Connection to server successful.")

        if args.command == "put":
            value_arg = cast(str, args.value)
            put_value_bytes = value_arg.encode("utf-8")
            logger.info(
                f"📝 Executing PUT: key='{args.key}', value={put_value_bytes!r}"
            )
            await client.put(args.key, put_value_bytes)
        elif args.command == "get":
            logger.info(f"📚 Executing GET: key='{args.key}'")
            value = await client.get(args.key)
            if value is not None:
                sys.stdout.buffer.write(value)
                sys.stdout.buffer.flush()
                sys.stdout.write("\n")
                sys.stdout.flush()
    except Exception as e:
        logger.error(f"❌ An error occurred: {type(e).__name__} - {e}", exc_info=True)
        sys.exit(1)
    finally:
        if client_started_successfully or (
            hasattr(client, "_client") and client._client is not None
        ):
            await client.close()
        logger.info("👋 KV Client Finished.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Client interrupted.")
        sys.exit(130)
    except SystemExit as e:
        sys.exit(e.code)
    except Exception:
        logger.critical("🚨 Critical unhandled error.", exc_info=True)
        sys.exit(1)
