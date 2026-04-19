# Process Isolation

Implement robust process-level security boundaries for plugin isolation, preventing malicious plugins from affecting the host system or other plugins.

## Overview

Process isolation creates secure, controlled environments where plugins run with limited access to system resources. This is essential for running untrusted or third-party plugins safely.

### Key Benefits

- **Security Boundaries**: Plugins cannot access host system resources
- **Resource Limits**: Control CPU, memory, and disk usage
- **Network Isolation**: Restrict network access to specific hosts/ports
- **Filesystem Protection**: Limit file system access with chroot jails
- **Process Monitoring**: Track and limit plugin resource usage

### Quick Start

```python
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.isolation import ProcessIsolator, SandboxConfig

async def isolated_plugin_example():
    """Run plugin in isolated environment."""

    # Basic isolation configuration
    isolator = ProcessIsolator(
        sandbox_config=SandboxConfig(
            memory_limit="128M",
            cpu_limit="0.5",
            enable_network_isolation=True,
            execution_timeout=300
        )
    )

    # Launch isolated plugin
    async with isolator.create_isolated_process([
        "python", "untrusted_plugin.py"
    ]) as process:

        server = plugin_server(
            services=[ProxyService(process)],
            enable_isolation_monitoring=True
        )

        await server.serve()
```

## Isolation Methods

### 1. **Sandbox Configuration**

Configure comprehensive isolation settings including user/group isolation, filesystem restrictions, network limits, and resource quotas.

→ **Detailed Sandbox Configuration** - Configure comprehensive isolation settings

### 2. **Container Integration**

Use Docker and Kubernetes for robust containerized plugin isolation with industry-standard security boundaries.

→ **Container Integration** - Use Docker and Kubernetes for robust isolation

### 3. **Resource Monitoring**

Monitor and enforce resource limits with real-time tracking of CPU, memory, disk, and network usage.

→ **Process Monitoring** - Monitor and enforce resource limits

## Common Patterns

### Development Environment

```python
# Lenient isolation for development
config = SandboxConfig(
    memory_limit="512M",
    cpu_limit="2.0",
    enable_network_isolation=False,  # Allow network access
    execution_timeout=3600           # 1 hour timeout
)
```

### Production Environment

```python
# Strict isolation for production
config = SandboxConfig(
    memory_limit="128M",
    cpu_limit="0.5",
    enable_network_isolation=True,
    allowed_hosts=["api.example.com"],  # Whitelist specific hosts
    execution_timeout=300,              # 5 minute timeout
    enable_filesystem_isolation=True,
    readonly_paths=["/usr", "/lib"]     # System directories read-only
)
```

### High-Security Environment

```python
# Maximum security isolation
config = SandboxConfig(
    memory_limit="64M",
    cpu_limit="0.2",
    enable_network_isolation=True,
    allowed_hosts=[],                   # No network access
    chroot_directory="/var/sandbox",    # Chroot jail
    run_as_user="sandbox",              # Non-privileged user
    execution_timeout=60,               # 1 minute timeout
    file_descriptor_limit=64            # Minimal file access
)
```

## Error Handling

```python
from pyvider.rpcplugin.exception import IsolationError, ResourceLimitError

async def safe_plugin_execution():
    try:
        async with isolator.create_isolated_process(cmd) as process:
            await server.serve()

    except ResourceLimitError as e:
        logger.error(f"Plugin exceeded resource limits: {e}")
        # Handle resource violations

    except IsolationError as e:
        logger.error(f"Isolation failed: {e}")
        # Handle isolation setup failures

    except TimeoutError:
        logger.error("Plugin execution timed out")
        # Handle timeout scenarios
```

## Best Practices

1. **Start Restrictive**: Begin with tight limits and relax based on monitoring
1. **Monitor Resources**: Track CPU, memory, and network usage patterns
1. **Use Containers**: Leverage Docker/Kubernetes for robust isolation
1. **Test Isolation**: Verify isolation works with malicious test plugins
1. **Log Everything**: Monitor all isolation events for security analysis
1. **Regular Audits**: Review and update isolation policies regularly

## Security Considerations

- **Privilege Escalation**: Never run plugins with elevated privileges
- **Resource Exhaustion**: Set conservative resource limits
- **Data Exfiltration**: Monitor network connections and file access
- **Side Channels**: Be aware of timing and cache-based attacks
- **Container Breakout**: Keep container runtime updated

## Next Steps

- **[Security Overview](index.md)** - Comprehensive security guide
- **[Magic Cookies](magic-cookies.md)** - Plugin authentication
- **[mTLS Security](mtls.md)** - Network-level security
- **[Certificate Management](certificates.md)** - PKI for plugin authentication
