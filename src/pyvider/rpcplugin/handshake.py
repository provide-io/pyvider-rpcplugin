#!/usr/bin/env python3
# pyvider/rpcplugin/client/handshake.py

import asyncio
import os
import time
import traceback
from typing import Tuple

from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.logger import logger


async def read_handshake_response(process) -> str:
    """
    Robust handshake response reader with multiple strategies to handle
    different Go-Python interop challenges.
    
    The handshake response is a pipe-delimited string with format:
    CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT
    
    Args:
        process: The subprocess.Popen instance representing the plugin
        
    Returns:
        The complete handshake response string
        
    Raises:
        HandshakeError: If handshake fails or times out
        TimeoutError: If process doesn't respond within timeout
    """
    if not process or not process.stdout:
        raise HandshakeError("No plugin process or stdout stream available")
    
    logger.debug("🤝📥🚀 Reading handshake response from plugin process...")
    
    # Use longer timeout for initial handshake
    timeout = 10.0  # seconds
    start_time = time.time()
    buffer = ""
    
    while (time.time() - start_time) < timeout:
        # Check if process has exited
        if process.poll() is not None:
            stderr_output = ""
            if process.stderr:
                try:
                    stderr_output = process.stderr.read().decode('utf-8', errors='replace')
                except Exception as e:
                    stderr_output = f"Error reading stderr: {e}"
            
            logger.error(f"🤝📥❌ Plugin process exited with code {process.returncode} before handshake")
            raise HandshakeError(
                f"Plugin process exited with code {process.returncode} before completing handshake. "
                f"Stderr: {stderr_output}"
            )
            
        # Read strategies
        try:
            # Strategy 1: Try to read a complete line first
            line_bytes = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, lambda: process.stdout.readline()
                ),
                timeout=2.0  # Shorter timeout for individual read attempts
            )
            
            if line_bytes:
                line = line_bytes.decode('utf-8', errors='replace').strip()
                logger.debug(f"🤝📥✅ Read line from stdout: '{line}'")
                
                if "|" in line and line.count("|") >= 5:
                    logger.debug("🤝📥✅ Complete handshake response found in line")
                    return line
                
                # Add to buffer if line doesn't contain complete handshake
                buffer += line
                if "|" in buffer and buffer.count("|") >= 5:
                    logger.debug("🤝📥✅ Complete handshake response found in buffer")
                    return buffer
            
        except asyncio.TimeoutError:
            logger.debug("🤝📥⚠️ Timeout reading line, trying chunk read strategy")
            
            try:
                # Strategy 2: Read a small chunk instead
                chunk = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, lambda: process.stdout.read(1024)
                    ),
                    timeout=1.0
                )
                
                if chunk:
                    chunk_str = chunk.decode('utf-8', errors='replace')
                    buffer += chunk_str
                    logger.debug(f"🤝📥✅ Read chunk: {len(chunk_str)} bytes, buffer now has {len(buffer)} bytes")
                    
                    # Check if buffer contains a complete handshake response
                    if "|" in buffer and buffer.count("|") >= 5:
                        # Extract handshake line from buffer
                        lines = buffer.split('\n')
                        for line in lines:
                            if "|" in line and line.count("|") >= 5:
                                logger.debug(f"🤝📥✅ Found complete handshake in buffer: {line}")
                                return line
                        
                        # If no complete line found, but buffer has enough separators,
                        # use the whole buffer (might have newlines removed)
                        return buffer
            
            except asyncio.TimeoutError:
                logger.debug("🤝📥⚠️ Timeout reading chunk, retrying...")
        
        # Brief delay before next attempt
        await asyncio.sleep(0.2)
    
    # If we get here, we've timed out
    stderr_output = ""
    if process.stderr:
        try:
            stderr_output = process.stderr.read().decode('utf-8', errors='replace')
        except Exception as e:
            stderr_output = f"Error reading stderr: {e}"
    
    raise HandshakeError(
        f"Timed out waiting for handshake after {timeout}s. "
        f"Buffer so far: '{buffer}'. Stderr: {stderr_output}"
    )


async def create_stderr_relay(process):
    """
    Creates a background task that continuously reads and logs stderr from the plugin process.
    Essential for debugging handshake issues, especially with Go plugins.
    
    Args:
        process: The subprocess.Popen instance with stderr pipe
        
    Returns:
        The asyncio.Task managing the stderr relay
    """
    if not process or not process.stderr:
        logger.debug("🤝📤⚠️ No process or stderr stream available for relay")
        return None
    
    async def _stderr_reader():
        """Background task to continuously read stderr"""
        logger.debug("🤝📤🚀 Starting stderr relay task")
        while process.poll() is None:  # While process is running
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, process.stderr.readline
                )
                if not line:
                    await asyncio.sleep(0.1)
                    continue
                    
                text = line.decode('utf-8', errors='replace').rstrip()
                if text:
                    logger.debug(f"🤝📤📝 Plugin stderr: {text}")
            except Exception as e:
                logger.error(f"🤝📤❌ Error in stderr relay: {e}")
                break
                
        logger.debug("🤝📤🛑 Stderr relay task ended")
    
    # Create but don't wait for the task
    relay_task = asyncio.create_task(_stderr_reader())
    logger.debug("🤝📤✅ Created stderr relay task")
    return relay_task


async def parse_and_validate_handshake(
    handshake_line: str
) -> Tuple[int, int, str, str, str, str | None]:
    """
    Parses and validates a handshake response, checking correct format and values.
    Expected format: CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT
    
    Args:
        handshake_line: The complete handshake response string
        
    Returns:
        Tuple of (core_version, plugin_version, network, address, protocol, server_cert)
        
    Raises:
        HandshakeError: If handshake format or values are invalid
    """
    logger.debug(f"🤝🔍🚀 Parsing handshake response: {handshake_line[:50]}...")
    
    try:
        # Split by pipe character
        parts = handshake_line.strip().split('|')
        
        # Validate parts count
        if len(parts) != 6:
            logger.error(f"🤝🔍❌ Invalid handshake format: expected 6 parts, got {len(parts)}")
            raise HandshakeError(f"Invalid handshake format: expected 6 parts, got {len(parts)}")
        
        # Extract and validate individual parts
        try:
            core_version = int(parts[0])
            plugin_version = int(parts[1])
        except ValueError:
            logger.error("🤝🔍❌ Invalid version numbers in handshake")
            raise HandshakeError("Invalid version numbers in handshake")
            
        network = parts[2]
        if network not in ("tcp", "unix"):
            logger.error(f"🤝🔍❌ Invalid network type: {network}")
            raise HandshakeError(f"Invalid network type: {network}")
            
        address = parts[3]
        if not address:
            logger.error("🤝🔍❌ Empty address in handshake")
            raise HandshakeError("Empty address in handshake")
            
        protocol = parts[4]
        if protocol != "grpc":
            logger.error(f"🤝🔍❌ Unsupported protocol: {protocol}")
            raise HandshakeError(f"Unsupported protocol: {protocol}")
            
        server_cert = parts[5] if parts[5] else None
        
        # Handle certificate padding if present
        if server_cert:
            # Add padding if needed (for base64)
            padding = len(server_cert) % 4
            if padding:
                server_cert += "=" * (4 - padding)
                logger.debug("🤝🔍✅ Added certificate padding")
                
        logger.debug(
            f"🤝🔍✅ Handshake parsed successfully: "
            f"core_version={core_version}, plugin_version={plugin_version}, "
            f"network={network}, address={address}, protocol={protocol}, "
            f"server_cert={'present' if server_cert else 'none'}"
        )
        
        return core_version, plugin_version, network, address, protocol, server_cert
        
    except Exception as e:
        logger.error(
            f"🤝🔍❌ Failed to parse handshake: {e}",
            extra={"trace": traceback.format_exc()}
        )
        raise HandshakeError(f"Failed to parse handshake: {e}") from e
### 🐍🏗️🔌
