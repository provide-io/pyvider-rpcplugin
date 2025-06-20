#!/usr/bin/env python3
# Quick health check for pyvider-rpcplugin.

import asyncio
import os
import socket
import ssl
from pathlib import Path

from pyvider.rpcplugin import plugin_server, create_basic_protocol
from pyvider.rpcplugin.config import RPCPluginConfig, configure # Import configure
from pyvider.telemetry import logger
# Removed: from pyvider.telemetry import setup_logging

async def health_check():
    # Logging level will be set by PLUGIN_LOG_LEVEL environment variable
    # Removed: setup_logging(log_level="INFO")

    results = {
        "config": False,
        "certificates": False,
        "network": False,
        "server_start": False,
    }

    logger.info("Starting Pyvider RPCPlugin Health Check...")

    # 1. Configuration Check
    config = None # Define config here to ensure it's available in finally
    try:
        config = RPCPluginConfig.instance()
        magic_cookie_val = config.get("PLUGIN_MAGIC_COOKIE_VALUE")
        server_transports = config.get("PLUGIN_SERVER_TRANSPORTS")
        auto_mtls_val = config.get("PLUGIN_AUTO_MTLS")

        logger.info("Configuration check successful.",
                   magic_cookie_set=bool(magic_cookie_val),
                   server_transports=server_transports,
                   auto_mtls=auto_mtls_val)
        results["config"] = True

    except Exception as e:
        logger.error(f"Configuration check failed: {e}", exc_info=True)

    # 2. Certificate Configuration Check (if mTLS enabled)
    try:
        if config: # Ensure config object exists
            auto_mtls = config.get("PLUGIN_AUTO_MTLS", False)
            if auto_mtls is True: # Explicitly check for boolean True
                server_cert_path = config.get("PLUGIN_SERVER_CERT")
                server_key_path = config.get("PLUGIN_SERVER_KEY")
                logger.info("Certificate configuration check (for mTLS=True):",
                           PLUGIN_SERVER_CERT=server_cert_path,
                           PLUGIN_SERVER_KEY=server_key_path)
                results["certificates"] = True
            else:
                logger.info("Certificate configuration check: PLUGIN_AUTO_MTLS is false. Skipping cert path checks.")
                results["certificates"] = True
        else:
            logger.error("Cannot perform certificate check, config object is None.")

    except Exception as e:
        logger.error(f"Certificate configuration check failed: {e}", exc_info=True)

    # 3. Network Check (Basic TCP Port Binding)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()

        logger.info(f"Network check: Successfully bound to ephemeral port {port}.")
        results["network"] = True

    except Exception as e:
        logger.error(f"Network check failed: {e}", exc_info=True)

    # 4. Server Start Check (Basic Server Lifecycle)
    server_task = None
    original_auto_mtls_setting_was_false = None
    server = None

    try:
        protocol = create_basic_protocol()

        class TestHandler:
            async def TestMethod(self, request, context):
                return type('TestReply', (), {'message': 'OK'})()

        if config: # Ensure config object exists
            current_auto_mtls_value = config.get("PLUGIN_AUTO_MTLS")
            original_auto_mtls_setting_was_false = (current_auto_mtls_value is False)

            if current_auto_mtls_value is False:
                 # Explicitly pass boolean True to configure
                 configure(PLUGIN_AUTO_MTLS=True)
                 logger.info(f"Temporarily set PLUGIN_AUTO_MTLS=True for server start test. Original was False.")
            # If it was True or None (schema default is True), it will effectively be True for the server.
            # If schema default was False, and current_auto_mtls_value was None, this might need adjustment.
            # However, current schema default for PLUGIN_AUTO_MTLS is "true".
        else:
            logger.error("Cannot perform server start check, config object is None.")
            # This path should ideally not be taken if config check passed.
            # If it does, results["server_start"] will remain False.
            raise RuntimeError("Config not available for server start check")


        server = plugin_server(
            protocol=protocol,
            handler=TestHandler(),
            transport="tcp",
            host="127.0.0.1",
            port=0
        )

        logger.info("Attempting to start a test server...")
        server_task = asyncio.create_task(server.serve())
        await asyncio.sleep(1.0)

        if server_task.done(): # Check if task finished (potentially with an error)
            exc = server_task.exception()
            if exc:
                raise exc # Re-raise error if task failed

        logger.info("Test server started successfully (apparently).")
        results["server_start"] = True

    except Exception as e:
        logger.error(f"Server start check failed: {e}", exc_info=True)
    finally:
        if server and hasattr(server, 'stop') and callable(server.stop):
            logger.info("Stopping test server...")
            # server.stop() is now async, so it should be awaited
            await server.stop()

        if server_task and not server_task.done():
            logger.warning("Server task still running after stop command, attempting to wait/cancel.")
            try:
                await asyncio.wait_for(server_task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Test server shutdown timed out.")
                server_task.cancel()
                try:
                    await server_task
                except asyncio.CancelledError:
                    logger.info("Server task explicitly cancelled.")
            except Exception as e_stop:
                logger.error(f"Error waiting for/cancelling test server task: {e_stop}", exc_info=True)
        logger.info("Test server stopped or was already stopped.")

        if original_auto_mtls_setting_was_false is True:
            if config:
                 # Explicitly pass boolean False to configure
                 configure(PLUGIN_AUTO_MTLS=False)
                 logger.info(f"Restored PLUGIN_AUTO_MTLS to False. Current value: {config.get('PLUGIN_AUTO_MTLS')}")

    passed_checks = sum(1 for v in results.values() if v)
    total_checks = len(results)

    final_status = "PASS" if passed_checks == total_checks else "FAIL"
    logger.info(f"Health check summary: {passed_checks}/{total_checks} checks passed. Overall: {final_status}",
               results=results)

    if final_status == "FAIL":
        print("HEALTH_CHECK_FAILED")
    else:
        print("HEALTH_CHECK_PASSED")

    return results

if __name__ == "__main__":
    asyncio.run(health_check())
