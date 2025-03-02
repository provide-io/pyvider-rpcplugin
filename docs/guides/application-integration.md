---
title: Application Integration
description: How to integrate Pyvider RPC Plugins into your application
---

# Application Integration Guide

This guide explains how to integrate Pyvider RPC Plugin into your application architecture. Whether you're building a plugin system from scratch or adding plugin capabilities to an existing application, this guide will show you how to design a robust and flexible integration.

## Integration Architecture

There are several ways to integrate plugins into your application:

### 1. Direct Integration

In this approach, your application directly launches and communicates with plugins:

```
┌───────────────┐     ┌───────────────┐
│   Your App    │◄────►  Plugin A     │
│  (RPCClient)  │     │  (RPCServer)  │
└───────┬───────┘     └───────────────┘
        │             ┌───────────────┐
        └────────────►│  Plugin B     │
                      │  (RPCServer)  │
                      └───────────────┘
```

This is the simplest approach and works well for applications with straightforward plugin needs.

### 2. Plugin Manager

For more complex scenarios, you might want a dedicated plugin manager:

```
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   Your App    │◄────►Plugin Manager ◄────►│  Plugin A     │
│               │     │  (RPCClient)  │     │  (RPCServer)  │
└───────────────┘     └───────┬───────┘     └───────────────┘
                              │             ┌───────────────┐
                              └────────────►│  Plugin B     │
                                            │  (RPCServer)  │
                                            └───────────────┘
```

This approach provides better separation of concerns and can handle more advanced plugin lifecycle management.

### 3. Plugin Registry

For applications with many plugins, a registry pattern can help:

```
┌───────────────┐     ┌───────────────┐
│   Your App    │◄────►Plugin Registry│
│               │     │               │
└───────┬───────┘     └───────┬───────┘
        │                     │
        │             ┌───────▼───────┐
        │             │Plugin Manager │
        │             │  (RPCClient)  │
        │             └───────┬───────┘
        │                     │
┌───────▼───────┐     ┌───────▼───────┐
│   Plugin A    │     │   Plugin B    │
│  (RPCServer)  │     │  (RPCServer)  │
└───────────────┘     └───────────────┘
```

This model adds a registry for plugin discovery, configuration, and lifecycle management.

## Direct Integration Example

Let's start with a simple direct integration:

```python
#!/usr/bin/env python3
# app.py

import asyncio
import os
from pathlib import Path

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.logger import logger

# Import your plugin service definitions
import calculator_pb2_grpc


class Application:
    """Main application with plugin support."""
    
    def __init__(self):
        self.plugin_clients = {}
        self.plugins_dir = Path("./plugins")
        logger.debug("🙋🚀✅ Initializing application with plugin support")
    
    async def load_plugins(self):
        """Discover and load all plugins in the plugins directory."""
        # Ensure plugins directory exists
        self.plugins_dir.mkdir(exist_ok=True)
        
        # Find all Python files that might be plugins
        plugin_files = list(self.plugins_dir.glob("*_plugin.py"))
        logger.debug(f"🙋🔍✅ Found {len(plugin_files)} potential plugin files")
        
        # Load each plugin
        for plugin_file in plugin_files:
            plugin_name = plugin_file.stem
            logger.debug(f"🙋🚀🔄 Loading plugin: {plugin_name}")
            
            try:
                # Create client for this plugin
                client = RPCPluginClient(
                    command=["python", str(plugin_file)],
                    config={
                        "env": {
                            "PLUGIN_MAGIC_COOKIE_KEY": "APP_PLUGIN",
                            "PLUGIN_MAGIC_COOKIE": "supersecret",
                        }
                    }
                )
                
                # Start the plugin
                await client.start()
                logger.debug(f"🙋🚀✅ Plugin {plugin_name} started successfully")
                
                # Store the client
                self.plugin_clients[plugin_name] = client
                
            except Exception as e:
                logger.error(f"🙋🚀❌ Failed to load plugin {plugin_name}: {e}")
                # Continue loading other plugins
    
    async def get_calculator(self):
        """Get the calculator plugin interface if available."""
        calculator_client = self.plugin_clients.get("calculator_plugin")
        if not calculator_client:
            logger.error("🙋🔍❌ Calculator plugin not found")
            return None
        
        # Get the calculator service interface
        calculator = await calculator_client.get_interface(calculator_pb2_grpc.CalculatorStub)
        logger.debug("🙋🔌✅ Got calculator interface")
        return calculator
    
    async def run(self):
        """Run the application."""
        logger.debug("🙋🚀✅ Starting application")
        
        # Load all available plugins
        await self.load_plugins()
        
        # Use the calculator plugin if available
        calculator = await self.get_calculator()
        if calculator:
            # Use the calculator service
            logger.debug("🙋🔌🔄 Using calculator plugin")
            # Application logic goes here...
        
        logger.debug("🙋🔒✅ Application run completed")
    
    async def shutdown(self):
        """Shut down the application and all plugins."""
        logger.debug("🙋🔒🔄 Shutting down application")
        
        # Close all plugin clients
        shutdown_tasks = []
        for name, client in self.plugin_clients.items():
            logger.debug(f"🙋🔒🔄 Shutting down plugin: {name}")
            shutdown_tasks.append(client.close())
        
        # Wait for all plugins to shut down
        if shutdown_tasks:
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        
        logger.debug("🙋🔒✅ Application shutdown complete")


async def main():
    """Run the application."""
    app = Application()
    try:
        await app.run()
    finally:
        await app.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
```

This example demonstrates a simple application that:
1. Discovers plugins in a "plugins" directory
2. Loads and starts each plugin
3. Provides a method to get a specific plugin interface
4. Properly shuts down all plugins when the application exits

## Plugin Manager Implementation

For more complex applications, a dedicated plugin manager class can provide better organization:

```python
#!/usr/bin/env python3
# plugin_manager.py

import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Type

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.logger import logger

import grpc


class PluginManager:
    """Manages plugin discovery, loading, and lifecycle."""
    
    def __init__(self, plugins_dir: str = "./plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.clients: Dict[str, RPCPluginClient] = {}
        self.interfaces: Dict[str, Dict[str, Any]] = {}
        logger.debug("🙋🚀✅ Initializing PluginManager")
    
    async def discover_plugins(self) -> List[Path]:
        """Discover available plugins."""
        self.plugins_dir.mkdir(exist_ok=True)
        plugin_files = list(self.plugins_dir.glob("*_plugin.py"))
        logger.debug(f"🙋🔍✅ Discovered {len(plugin_files)} plugin files")
        return plugin_files
    
    async def load_plugin(self, plugin_file: Path) -> bool:
        """Load a specific plugin."""
        plugin_name = plugin_file.stem
        logger.debug(f"🙋🚀🔄 Loading plugin: {plugin_name}")
        
        try:
            client = RPCPluginClient(
                command=["python", str(plugin_file)],
                config={
                    "env": {
                        "PLUGIN_MAGIC_COOKIE_KEY": "APP_PLUGIN",
                        "PLUGIN_MAGIC_COOKIE": "supersecret",
                    }
                }
            )
            
            await client.start()
            self.clients[plugin_name] = client
            self.interfaces[plugin_name] = {}
            
            logger.debug(f"🙋🚀✅ Plugin {plugin_name} loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"🙋🚀❌ Failed to load plugin {plugin_name}: {e}")
            return False
    
    async def load_all_plugins(self) -> int:
        """Discover and load all available plugins."""
        plugin_files = await self.discover_plugins()
        load_tasks = [self.load_plugin(plugin_file) for plugin_file in plugin_files]
        results = await asyncio.gather(*load_tasks, return_exceptions=True)
        
        # Count successful loads
        success_count = sum(1 for result in results if result is True)
        logger.debug(f"🙋🚀✅ Loaded {success_count} plugins successfully")
        
        return success_count
    
    async def get_interface(self, plugin_name: str, stub_class: Type) -> Optional[Any]:
        """Get a specific interface from a plugin."""
        client = self.clients.get(plugin_name)
        if not client:
            logger.error(f"🙋🔍❌ Plugin not found: {plugin_name}")
            return None
        
        # Check if we've already created this interface
        interface_key = stub_class.__name__
        cached_interface = self.interfaces[plugin_name].get(interface_key)
        if cached_interface:
            return cached_interface
        
        try:
            # Create the interface
            interface = await client.get_interface(stub_class)
            self.interfaces[plugin_name][interface_key] = interface
            logger.debug(f"🙋🔌✅ Got interface {interface_key} from plugin {plugin_name}")
            return interface
        except Exception as e:
            logger.error(f"🙋🔌❌ Failed to get interface from plugin {plugin_name}: {e}")
            return None
    
    async def shutdown_plugin(self, plugin_name: str) -> bool:
        """Shut down a specific plugin."""
        client = self.clients.get(plugin_name)
        if not client:
            logger.error(f"🙋🔒❌ Plugin not found for shutdown: {plugin_name}")
            return False
        
        try:
            await client.close()
            del self.clients[plugin_name]
            del self.interfaces[plugin_name]
            logger.debug(f"🙋🔒✅ Plugin {plugin_name} shut down successfully")
            return True
        except Exception as e:
            logger.error(f"🙋🔒❌ Error shutting down plugin {plugin_name}: {e}")
            return False
    
    async def shutdown_all(self) -> None:
        """Shut down all plugins."""
        if not self.clients:
            logger.debug("🙋🔒✅ No plugins to shut down")
            return
        
        logger.debug(f"🙋🔒🔄 Shutting down {len(self.clients)} plugins")
        plugin_names = list(self.clients.keys())
        
        for name in plugin_names:
            await self.shutdown_plugin(name)
        
        logger.debug("🙋🔒✅ All plugins shut down")
```

This more sophisticated plugin manager provides:
- Separate discovery and loading phases
- Interface caching to avoid recreating stubs
- Individual plugin shutdown
- Better error isolation between plugins

## Plugin Registry Pattern

For large applications with complex plugin ecosystems, a registry pattern can help with discovery, versioning, and dependency management:

```python
#!/usr/bin/env python3
# plugin_registry.py

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Type

from pyvider.rpcplugin.logger import logger

from plugin_manager import PluginManager


class PluginInfo:
    """Information about a plugin."""
    
    def __init__(self, name: str, version: str, path: Path, dependencies: List[str] = None):
        self.name = name
        self.version = version
        self.path = path
        self.dependencies = dependencies or []
        self.loaded = False
        self.interfaces = set()
    
    def __str__(self) -> str:
        return f"{self.name} v{self.version}"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "path": str(self.path),
            "dependencies": self.dependencies,
            "loaded": self.loaded,
            "interfaces": list(self.interfaces)
        }


class PluginRegistry:
    """Registry for plugin discovery, versioning, and dependencies."""
    
    def __init__(self, plugins_dir: str = "./plugins", manifest_file: str = "plugin_manifest.json"):
        self.plugins_dir = Path(plugins_dir)
        self.manifest_path = self.plugins_dir / manifest_file
        self.plugin_manager = PluginManager(plugins_dir)
        self.plugins: Dict[str, PluginInfo] = {}
        logger.debug("🙋🚀✅ Initializing PluginRegistry")
    
    async def scan_plugins(self) -> int:
        """Scan for plugins and update the registry."""
        # Ensure plugins directory exists
        self.plugins_dir.mkdir(exist_ok=True)
        
        # Look for manifest files first
        loaded_from_manifest = await self._load_from_manifest()
        
        # Then scan for any additional plugins
        plugin_files = await self.plugin_manager.discover_plugins()
        
        # Add any plugins not in the manifest
        for plugin_file in plugin_files:
            plugin_name = plugin_file.stem
            if plugin_name not in self.plugins:
                # No manifest entry, create a basic one
                self.plugins[plugin_name] = PluginInfo(
                    name=plugin_name,
                    version="0.1.0",  # Default version
                    path=plugin_file
                )
                logger.debug(f"🙋🔍✅ Added plugin without manifest: {plugin_name}")
        
        # Save the updated manifest
        await self._save_manifest()
        
        logger.debug(f"🙋🔍✅ Registry contains {len(self.plugins)} plugins")
        return len(self.plugins)
    
    async def _load_from_manifest(self) -> bool:
        """Load plugin information from manifest file."""
        if not self.manifest_path.exists():
            logger.debug("🙋🔍⚠️ No manifest file found")
            return False
        
        try:
            with open(self.manifest_path, "r") as f:
                manifest_data = json.load(f)
            
            for plugin_data in manifest_data.get("plugins", []):
                plugin = PluginInfo(
                    name=plugin_data["name"],
                    version=plugin_data["version"],
                    path=Path(plugin_data["path"]),
                    dependencies=plugin_data.get("dependencies", [])
                )
                self.plugins[plugin.name] = plugin
            
            logger.debug(f"🙋🔍✅ Loaded {len(self.plugins)} plugins from manifest")
            return True
        except Exception as e:
            logger.error(f"🙋🔍❌ Error loading manifest: {e}")
            return False
    
    async def _save_manifest(self) -> bool:
        """Save plugin information to manifest file."""
        try:
            manifest_data = {
                "plugins": [plugin.to_dict() for plugin in self.plugins.values()]
            }
            
            with open(self.manifest_path, "w") as f:
                json.dump(manifest_data, f, indent=2)
            
            logger.debug(f"🙋📝✅ Saved manifest with {len(self.plugins)} plugins")
            return True
        except Exception as e:
            logger.error(f"🙋📝❌ Error saving manifest: {e}")
            return False
    
    async def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin and its dependencies."""
        if plugin_name not in self.plugins:
            logger.error(f"🙋🚀❌ Plugin not found in registry: {plugin_name}")
            return False
        
        plugin = self.plugins[plugin_name]
        if plugin.loaded:
            logger.debug(f"🙋🚀⚠️ Plugin already loaded: {plugin_name}")
            return True
        
        # Check if plugin file exists
        if not plugin.path.exists():
            logger.error(f"🙋🚀❌ Plugin file not found: {plugin.path}")
            return False
        
        # Load dependencies first
        for dep_name in plugin.dependencies:
            if dep_name not in self.plugins:
                logger.error(f"🙋🚀❌ Dependency not found: {dep_name} (required by {plugin_name})")
                return False
            
            # Recursively load the dependency
            dep_loaded = await self.load_plugin(dep_name)
            if not dep_loaded:
                logger.error(f"🙋🚀❌ Failed to load dependency: {dep_name}")
                return False
        
        # Load the plugin
        success = await self.plugin_manager.load_plugin(plugin.path)
        if success:
            plugin.loaded = True
            await self._save_manifest()
            logger.debug(f"🙋🚀✅ Plugin loaded successfully: {plugin_name}")
            return True
        else:
            logger.error(f"🙋🚀❌ Failed to load plugin: {plugin_name}")
            return False
    
    async def load_all_plugins(self) -> int:
        """Load all plugins in dependency order."""
        # First, find plugins with no dependencies
        no_deps = [name for name, plugin in self.plugins.items() if not plugin.dependencies]
        
        # Then, load them and their dependents in order
        loaded_count = 0
        visited: Set[str] = set()
        
        async def load_with_deps(name: str) -> bool:
            if name in visited:
                return self.plugins[name].loaded
            
            visited.add(name)
            plugin = self.plugins[name]
            
            # Check cyclic dependencies
            for dep in plugin.dependencies:
                if dep in visited and not self.plugins[dep].loaded:
                    logger.error(f"🙋🚀❌ Cyclic dependency detected: {name} <-> {dep}")
                    return False
            
            # Load dependencies first
            for dep in plugin.dependencies:
                dep_loaded = await load_with_deps(dep)
                if not dep_loaded:
                    return False
            
            # Now load this plugin
            success = await self.load_plugin(name)
            if success:
                nonlocal loaded_count
                loaded_count += 1
            return success
        
        # Start with no-dependency plugins
        for name in no_deps:
            await load_with_deps(name)
        
        # Try remaining plugins
        for name in self.plugins:
            if name not in visited:
                await load_with_deps(name)
        
        logger.debug(f"🙋🚀✅ Loaded {loaded_count} plugins in dependency order")
        return loaded_count
    
    async def get_interface(self, plugin_name: str, stub_class: Type) -> Optional[Any]:
        """Get a plugin interface."""
        if plugin_name not in self.plugins:
            logger.error(f"🙋🔌❌ Plugin not found: {plugin_name}")
            return None
        
        plugin = self.plugins[plugin_name]
        if not plugin.loaded:
            logger.error(f"🙋🔌❌ Plugin not loaded: {plugin_name}")
            return None
        
        interface = await self.plugin_manager.get_interface(plugin_name, stub_class)
        if interface:
            # Record that this plugin provides this interface
            plugin.interfaces.add(stub_class.__name__)
            await self._save_manifest()
        return interface
    
    async def shutdown(self) -> None:
        """Shut down all plugins."""
        await self.plugin_manager.shutdown_all()
        
        # Mark all as unloaded
        for plugin in self.plugins.values():
            plugin.loaded = False
        
        await self._save_manifest()
        logger.debug("🙋🔒✅ Registry shutdown complete")
```

This advanced registry provides:
- Plugin metadata management (versions, paths)
- Dependency tracking and ordered loading
- Interface discovery
- Persistent manifest file for plugin information across restarts

## Integration Testing

When integrating plugins, it's important to test both the plugins and the integration. Here's a simple test helper:

```python
#!/usr/bin/env python3
# test_integration.py

import asyncio
import pytest

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.logger import logger

import calculator_pb2
import calculator_pb2_grpc


@pytest.fixture
async def calculator_client():
    """Fixture that provides a connected calculator plugin client."""
    client = RPCPluginClient(
        command=["python", "plugins/calculator_plugin.py"],
        config={
            "env": {
                "PLUGIN_MAGIC_COOKIE_KEY": "TEST_PLUGIN",
                "PLUGIN_MAGIC_COOKIE": "test_secret",
            }
        }
    )
    
    try:
        await client.start()
        yield client
    finally:
        await client.close()


@pytest.fixture
async def calculator(calculator_client):
    """Fixture that provides the calculator service interface."""
    return await calculator_client.get_interface(calculator_pb2_grpc.CalculatorStub)


@pytest.mark.asyncio
async def test_calculator_add(calculator):
    """Test the calculator's add method."""
    request = calculator_pb2.AddRequest(a=5, b=3)
    response = await calculator.Add(request)
    assert response.result == 8, f"Expected 5+3=8, got {response.result}"


@pytest.mark.asyncio
async def test_calculator_fibonacci(calculator):
    """Test the calculator's fibonacci streaming method."""
    request = calculator_pb2.FibRequest(count=5)
    expected = [1, 1, 2, 3, 5]
    
    results = []
    async for response in calculator.GenerateFibonacci(request):
        results.append(response.value)
    
    assert results == expected, f"Expected {expected}, got {results}"
```

## Best Practices

When integrating plugins into your application, follow these best practices:

1. **Clear Plugin Interface**: Define a clear contract between your application and plugins
2. **Error Isolation**: Ensure plugin errors don't crash your main application
3. **Resource Management**: Properly start and stop plugins to avoid resource leaks
4. **Versioning**: Handle compatibility between different plugin versions
5. **Security**: Be cautious about what capabilities you expose to plugins
6. **Dependency Management**: Handle plugin dependencies appropriately
7. **Configuration**: Make plugin behavior configurable
8. **Monitoring**: Track plugin health and performance

## Application Design Considerations

When designing your plugin-based application, consider these aspects:

### Plugin Discovery

How will your application find plugins?

- **Filesystem**: Scan a specific directory
- **Configuration**: Read from a config file
- **Registry**: Use a central registry service
- **Network**: Discover over the network

### Plugin Lifecycle

How will you manage the plugin lifecycle?

- **Loading**: When and how plugins are loaded
- **Initialization**: How plugins are initialized with configuration
- **Usage**: How the application uses plugin functionality
- **Shutdown**: Proper cleanup when plugins are no longer needed

### Error Handling

How will you handle plugin errors?

- **Isolation**: Prevent plugin errors from affecting the application
- **Retries**: Retry operations that fail temporarily
- **Fallbacks**: Use alternative plugins when one fails
- **Reporting**: Log and report plugin errors for debugging

## Next Steps

Now that you understand how to integrate plugins into your application, you might want to explore:

- [Server Implementation](server-implementation.md) for creating plugin servers
- [Client Implementation](client-implementation.md) for connecting to plugins
- [Protocol Definition](protocol-definition.md) for designing plugin interfaces

