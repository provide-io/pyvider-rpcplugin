#!/usr/bin/env python3

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import grpc

from pyvider.rpcplugin.protocol import RPCPluginProtocol

logger = logging.getLogger(__name__)

@dataclass
class WatchSubscription:
    """Tracks a watch subscription for configuration changes."""
    namespace: str
    keys: set[str]
    queue: asyncio.Queue
    last_seen: datetime = field(default_factory=datetime.now)

class ConfigStoreProtocol(RPCPluginProtocol):
    """Protocol implementation for configuration store service."""
    
    def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Get the gRPC service descriptors."""
        from proto import configstore_pb2_grpc
        return configstore_pb2_grpc, "ConfigStore"
        
    def add_to_server(self, instance: Any, server: grpc.aio.Server) -> None:
        """Add the ConfigStore service to a gRPC server."""
        from proto import configstore_pb2_grpc
        servicer = ConfigStoreServicer()
        configstore_pb2_grpc.add_ConfigStoreServicer_to_server(servicer, server)

class ConfigStoreServicer:
    """Implementation of ConfigStore service."""
    
    def __init__(self):
        # Store config entries: {namespace: {key: ConfigEntry}}
        self._store: dict[str, dict[str, Any]] = {}
        
        # Track version numbers per namespace
        self._versions: dict[str, int] = {}
        
        # Active watch subscriptions
        self._watchers: set[WatchSubscription] = set()
        
        # Lock for store modifications
        self._lock = asyncio.Lock()
    
    async def Get(self, request, context):
        """Handle Get requests with error checking."""
        
        try:
            if request.namespace not in self._store:
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Namespace not found: {request.namespace}")
                
            store = self._store[request.namespace]
            if request.key not in store:
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Key not found: {request.key}")
                
            return store[request.key]
            
        except Exception as e:
            logger.error(f"Error in Get: {e}")
            await context.abort(grpc.StatusCode.INTERNAL, str(e))
    
    async def Set(self, request, context):
        """Handle Set requests with version tracking."""
        from proto import configstore_pb2
        
        try:
            async with self._lock:
                entry = request.entry
                namespace = entry.namespace
                key = entry.key
                
                # Initialize namespace if needed
                if namespace not in self._store:
                    self._store[namespace] = {}
                    self._versions[namespace] = 0
                    
                # Update version
                self._versions[namespace] += 1
                entry.version = self._versions[namespace]
                
                # Store entry
                self._store[namespace][key] = entry
                
                # Notify watchers
                await self._notify_watchers(entry)
                
                return configstore_pb2.Empty()
                
        except Exception as e:
            logger.error(f"Error in Set: {e}")
            await context.abort(grpc.StatusCode.INTERNAL, str(e))
    
    async def Watch(self, request, context):
        """Handle Watch requests with filtering."""
        # Create subscription queue
        queue = asyncio.Queue()
        
        # Create subscription
        sub = WatchSubscription(
            namespace=request.namespace,
            keys=set(request.keys),
            queue=queue
        )
        
        try:
            # Register subscription
            self._watchers.add(sub)
            
            # Stream changes
            while True:
                entry = await queue.get()
                if entry is None:  # None is our sentinel for shutdown
                    break
                    
                # Only yield if key matches filter
                if not sub.keys or entry.key in sub.keys:
                    yield entry
                    sub.last_seen = datetime.now()
                    
        finally:
            # Cleanup
            if sub in self._watchers:
                self._watchers.remove(sub)
    
    async def List(self, request, context):
        """Handle List requests with filtering."""
        from proto import configstore_pb2
        
        try:
            if request.namespace not in self._store:
                return configstore_pb2.ListResponse(entries=[])
                
            store = self._store[request.namespace]
            entries = []
            
            for key, entry in store.items():
                # Apply prefix filter
                if request.prefix and not key.startswith(request.prefix):
                    continue
                    
                # Apply tag filters
                if request.tags:
                    if not all(entry.tags.get(k) == v for k, v in request.tags.items()):
                        continue
                        
                entries.append(entry)
                
            return configstore_pb2.ListResponse(entries=entries)
            
        except Exception as e:
            logger.error(f"Error in List: {e}")
            await context.abort(grpc.StatusCode.INTERNAL, str(e))
    
    async def BatchGet(self, request, context):
        """Handle BatchGet requests efficiently."""
        from proto import configstore_pb2
        
        try:
            entries = []
            
            # Process all requests
            for item in request.items:
                try:
                    if item.namespace in self._store and item.key in self._store[item.namespace]:
                        entries.append(self._store[item.namespace][item.key])
                except Exception as e:
                    logger.warning(f"Error getting item {item.namespace}/{item.key}: {e}")
                    # Continue processing other items
                    
            return configstore_pb2.BatchGetResponse(entries=entries)
            
        except Exception as e:
            logger.error(f"Error in BatchGet: {e}")
            await context.abort(grpc.StatusCode.INTERNAL, str(e))
    
    async def _notify_watchers(self, entry):
        """Notify all relevant watchers of a configuration change."""
        dead_watchers = set()
        
        for watcher in self._watchers:
            if watcher.namespace == entry.namespace:
                try:
                    await watcher.queue.put(entry)
                except asyncio.QueueFull:
                    dead_watchers.add(watcher)
                    
        # Cleanup dead watchers
        self._watchers -= dead_watchers
