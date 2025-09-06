# Process Isolation

Implement robust process-level security boundaries for plugin isolation. Learn containerization, sandboxing, resource limits, and monitoring for secure plugin execution.

## Overview

Process isolation ensures that plugins run in secure, controlled environments with limited access to system resources. This prevents malicious plugins from affecting the host system or other plugins.

```python
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.isolation import ProcessIsolator, SandboxConfig
import os
import subprocess

async def basic_process_isolation_example():
    """Basic process isolation example."""
    
    # Configure process isolation
    isolator = ProcessIsolator(
        sandbox_config=SandboxConfig(
            enable_network_isolation=True,
            enable_filesystem_isolation=True,
            memory_limit="128M",
            cpu_limit="0.5",
            timeout=300  # 5 minutes
        )
    )
    
    # Run plugin in isolated environment
    async with isolator.create_isolated_process([
        "python", "untrusted_plugin.py"
    ]) as isolated_process:
        
        # Server communicates with isolated plugin
        server = plugin_server(
            services=[ProxyService(isolated_process)],
            enable_isolation_monitoring=True
        )
        
        try:
            await server.start()
            print("🔒 Server with isolated plugin started")
            
            # Plugin runs in secure sandbox
            await server.wait_for_termination()
        
        finally:
            await server.stop()

# Usage
await basic_process_isolation_example()
```

## Sandbox Configuration

### Comprehensive Sandbox Setup

```python
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from pathlib import Path
import resource
import os
import pwd
import grp

@dataclass
class SandboxConfig:
    """Configuration for plugin sandboxing."""
    
    # User and group isolation
    run_as_user: Optional[str] = None          # Username to run as
    run_as_group: Optional[str] = None         # Group to run as
    create_new_user: bool = False              # Create temporary user
    
    # Filesystem isolation
    enable_filesystem_isolation: bool = True   # Enable filesystem restrictions
    chroot_directory: Optional[str] = None     # Chroot jail directory
    readonly_paths: List[str] = None           # Read-only mount paths
    writable_paths: List[str] = None           # Writable paths (limited)
    blocked_paths: List[str] = None            # Completely blocked paths
    
    # Network isolation
    enable_network_isolation: bool = True      # Enable network restrictions
    allowed_hosts: List[str] = None            # Allowed network destinations
    allowed_ports: List[int] = None            # Allowed network ports
    enable_loopback: bool = True               # Allow loopback interface
    
    # Resource limits
    memory_limit: str = "256M"                 # Memory limit
    cpu_limit: str = "1.0"                     # CPU limit (cores)
    disk_limit: str = "1G"                     # Disk usage limit
    file_descriptor_limit: int = 256           # Max open files
    process_limit: int = 10                    # Max processes
    
    # Time limits
    execution_timeout: int = 600               # Max execution time (seconds)
    idle_timeout: int = 300                    # Idle timeout (seconds)
    
    # Security features
    enable_seccomp: bool = True                # Enable syscall filtering
    enable_capabilities: bool = True           # Drop dangerous capabilities
    enable_namespace_isolation: bool = True    # Use Linux namespaces
    
    # Monitoring
    enable_resource_monitoring: bool = True    # Monitor resource usage
    enable_syscall_monitoring: bool = False    # Monitor system calls (expensive)
    enable_network_monitoring: bool = True     # Monitor network activity
    
    def to_dict(self) -> Dict:
        """Convert configuration to dictionary."""
        return {
            field.name: getattr(self, field.name)
            for field in self.__dataclass_fields__.values()
        }

class ProcessIsolator:
    """Manages process isolation and sandboxing."""
    
    def __init__(self, sandbox_config: SandboxConfig):
        self.config = sandbox_config
        self.isolated_processes: Dict[str, Dict] = {}
        self.logger = logging.getLogger("process_isolator")
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self):
        """Validate sandbox configuration."""
        
        # Check if running as root for advanced isolation features
        if os.geteuid() != 0 and (
            self.config.enable_namespace_isolation or 
            self.config.chroot_directory or
            self.config.run_as_user
        ):
            self.logger.warning(
                "Advanced isolation features require root privileges. "
                "Some features may be disabled."
            )
        
        # Validate resource limits
        self._validate_resource_limits()
        
        # Validate paths
        if self.config.chroot_directory:
            chroot_path = Path(self.config.chroot_directory)
            if not chroot_path.exists():
                raise ValueError(f"Chroot directory does not exist: {chroot_path}")
    
    def _validate_resource_limits(self):
        """Validate resource limit specifications."""
        
        # Parse and validate memory limit
        memory_limit = self.config.memory_limit
        if memory_limit:
            try:
                self._parse_memory_limit(memory_limit)
            except ValueError as e:
                raise ValueError(f"Invalid memory limit '{memory_limit}': {e}")
        
        # Validate CPU limit
        cpu_limit = self.config.cpu_limit
        if cpu_limit:
            try:
                cpu_value = float(cpu_limit)
                if cpu_value <= 0:
                    raise ValueError("CPU limit must be positive")
            except ValueError:
                raise ValueError(f"Invalid CPU limit '{cpu_limit}': must be a number")
    
    def _parse_memory_limit(self, memory_str: str) -> int:
        """Parse memory limit string to bytes."""
        
        memory_str = memory_str.upper().strip()
        
        if memory_str.endswith('K'):
            return int(memory_str[:-1]) * 1024
        elif memory_str.endswith('M'):
            return int(memory_str[:-1]) * 1024 * 1024
        elif memory_str.endswith('G'):
            return int(memory_str[:-1]) * 1024 * 1024 * 1024
        else:
            return int(memory_str)  # Assume bytes
    
    async def create_isolated_process(self, command: List[str], 
                                    process_id: str = None) -> 'IsolatedProcess':
        """Create isolated process with sandbox configuration."""
        
        process_id = process_id or f"process_{len(self.isolated_processes)}"
        
        # Prepare isolation environment
        isolation_env = await self._prepare_isolation_environment(process_id)
        
        # Create isolated process
        isolated_process = IsolatedProcess(
            process_id=process_id,
            command=command,
            config=self.config,
            isolation_env=isolation_env,
            isolator=self
        )
        
        # Register process
        self.isolated_processes[process_id] = {
            "process": isolated_process,
            "created_at": datetime.now(),
            "status": "created"
        }
        
        return isolated_process
    
    async def _prepare_isolation_environment(self, process_id: str) -> Dict:
        """Prepare isolated environment for process."""
        
        isolation_env = {
            "process_id": process_id,
            "temp_directory": None,
            "chroot_prepared": False,
            "user_created": False,
            "network_configured": False
        }
        
        # Create temporary directory for process
        if self.config.enable_filesystem_isolation:
            temp_dir = Path(f"/tmp/plugin_sandbox_{process_id}")
            temp_dir.mkdir(mode=0o700, exist_ok=True)
            isolation_env["temp_directory"] = str(temp_dir)
        
        # Prepare chroot environment if configured
        if self.config.chroot_directory:
            await self._prepare_chroot_environment(process_id, isolation_env)
        
        # Create temporary user if configured
        if self.config.create_new_user:
            await self._create_temporary_user(process_id, isolation_env)
        
        # Configure network isolation
        if self.config.enable_network_isolation:
            await self._configure_network_isolation(process_id, isolation_env)
        
        return isolation_env
    
    async def _prepare_chroot_environment(self, process_id: str, isolation_env: Dict):
        """Prepare chroot jail environment."""
        
        chroot_dir = Path(self.config.chroot_directory)
        process_chroot = chroot_dir / process_id
        
        # Create process-specific chroot
        process_chroot.mkdir(parents=True, exist_ok=True)
        
        # Copy essential files and directories
        essential_dirs = ["/bin", "/lib", "/lib64", "/usr/lib", "/usr/bin/python3"]
        
        for dir_path in essential_dirs:
            if Path(dir_path).exists():
                await self._copy_to_chroot(dir_path, process_chroot)
        
        # Create device files
        dev_dir = process_chroot / "dev"
        dev_dir.mkdir(exist_ok=True)
        
        # Create /dev/null, /dev/zero, etc.
        await self._create_device_files(dev_dir)
        
        isolation_env["chroot_directory"] = str(process_chroot)
        isolation_env["chroot_prepared"] = True
    
    async def _copy_to_chroot(self, source_path: str, chroot_dir: Path):
        """Copy files/directories to chroot environment."""
        
        source = Path(source_path)
        if not source.exists():
            return
        
        target = chroot_dir / source_path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        
        if source.is_file():
            # Copy file
            subprocess.run(["cp", "-p", str(source), str(target)], check=True)
        elif source.is_dir():
            # Copy directory
            subprocess.run(["cp", "-rp", str(source), str(target.parent)], check=True)
    
    async def _create_device_files(self, dev_dir: Path):
        """Create essential device files in chroot."""
        
        devices = [
            ("null", "c", 1, 3),
            ("zero", "c", 1, 5),
            ("random", "c", 1, 8),
            ("urandom", "c", 1, 9)
        ]
        
        for name, dev_type, major, minor in devices:
            device_path = dev_dir / name
            try:
                subprocess.run([
                    "mknod", str(device_path), dev_type, str(major), str(minor)
                ], check=True)
                device_path.chmod(0o666)
            except subprocess.CalledProcessError:
                # May not have permissions - skip
                pass
    
    async def _create_temporary_user(self, process_id: str, isolation_env: Dict):
        """Create temporary user for process isolation."""
        
        username = f"plugin_{process_id}"
        
        try:
            # Create user
            subprocess.run([
                "useradd", "--system", "--no-create-home", 
                "--shell", "/bin/false", username
            ], check=True)
            
            isolation_env["temporary_user"] = username
            isolation_env["user_created"] = True
            
            self.logger.info(f"Created temporary user: {username}")
        
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to create temporary user: {e}")
    
    async def _configure_network_isolation(self, process_id: str, isolation_env: Dict):
        """Configure network isolation using network namespaces."""
        
        # This is a simplified version - full implementation would use:
        # - Network namespaces
        # - Virtual network interfaces
        # - Firewall rules (iptables/nftables)
        
        # For now, just mark as configured
        isolation_env["network_configured"] = True
        self.logger.info(f"Network isolation configured for {process_id}")
    
    def cleanup_isolated_process(self, process_id: str):
        """Clean up isolated process resources."""
        
        if process_id not in self.isolated_processes:
            return
        
        process_info = self.isolated_processes[process_id]
        isolation_env = process_info.get("isolation_env", {})
        
        # Clean up temporary directory
        temp_dir = isolation_env.get("temp_directory")
        if temp_dir:
            try:
                subprocess.run(["rm", "-rf", temp_dir], check=True)
            except subprocess.CalledProcessError:
                pass
        
        # Remove temporary user
        if isolation_env.get("user_created"):
            username = isolation_env.get("temporary_user")
            if username:
                try:
                    subprocess.run(["userdel", username], check=True)
                except subprocess.CalledProcessError:
                    pass
        
        # Clean up chroot
        chroot_dir = isolation_env.get("chroot_directory")
        if chroot_dir:
            try:
                subprocess.run(["rm", "-rf", chroot_dir], check=True)
            except subprocess.CalledProcessError:
                pass
        
        # Remove from registry
        del self.isolated_processes[process_id]
        
        self.logger.info(f"Cleaned up isolated process: {process_id}")
    
    def get_process_status(self, process_id: str) -> Optional[Dict]:
        """Get status of isolated process."""
        
        return self.isolated_processes.get(process_id)
    
    def list_isolated_processes(self) -> List[Dict]:
        """List all isolated processes."""
        
        return [
            {
                "process_id": pid,
                "created_at": info["created_at"].isoformat(),
                "status": info["status"]
            }
            for pid, info in self.isolated_processes.items()
        ]

class IsolatedProcess:
    """Represents an isolated process with resource monitoring."""
    
    def __init__(self, process_id: str, command: List[str], 
                 config: SandboxConfig, isolation_env: Dict,
                 isolator: ProcessIsolator):
        self.process_id = process_id
        self.command = command
        self.config = config
        self.isolation_env = isolation_env
        self.isolator = isolator
        
        # Process management
        self.process: Optional[subprocess.Popen] = None
        self.started_at: Optional[datetime] = None
        self.terminated_at: Optional[datetime] = None
        
        # Resource monitoring
        self.resource_monitor: Optional['ResourceMonitor'] = None
        
        self.logger = logging.getLogger(f"isolated_process_{process_id}")
    
    async def __aenter__(self) -> 'IsolatedProcess':
        """Start isolated process."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Stop isolated process."""
        await self.stop()
    
    async def start(self):
        """Start the isolated process."""
        
        if self.process:
            raise RuntimeError("Process already started")
        
        # Prepare execution environment
        exec_env = self._prepare_execution_environment()
        
        # Start resource monitoring if enabled
        if self.config.enable_resource_monitoring:
            self.resource_monitor = ResourceMonitor(self.process_id, self.config)
            await self.resource_monitor.start()
        
        # Start the isolated process
        try:
            self.process = subprocess.Popen(
                self.command,
                env=exec_env["environment"],
                cwd=exec_env["working_directory"],
                preexec_fn=exec_env["preexec_fn"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            
            self.started_at = datetime.now()
            
            # Update isolator registry
            if self.process_id in self.isolator.isolated_processes:
                self.isolator.isolated_processes[self.process_id]["status"] = "running"
                self.isolator.isolated_processes[self.process_id]["pid"] = self.process.pid
            
            self.logger.info(f"Started isolated process (PID: {self.process.pid})")
        
        except Exception as e:
            self.logger.error(f"Failed to start isolated process: {e}")
            
            # Clean up monitoring
            if self.resource_monitor:
                await self.resource_monitor.stop()
            
            raise
    
    def _prepare_execution_environment(self) -> Dict:
        """Prepare execution environment for isolated process."""
        
        exec_env = {
            "environment": self._prepare_environment_variables(),
            "working_directory": self._prepare_working_directory(),
            "preexec_fn": self._create_preexec_function()
        }
        
        return exec_env
    
    def _prepare_environment_variables(self) -> Dict[str, str]:
        """Prepare environment variables for isolated process."""
        
        # Start with minimal environment
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/tmp",
            "USER": "plugin",
            "TMPDIR": "/tmp"
        }
        
        # Add sandbox-specific variables
        env["PLUGIN_SANDBOX"] = "true"
        env["PLUGIN_PROCESS_ID"] = self.process_id
        
        # Limit environment size
        if self.config.enable_filesystem_isolation:
            env["HOME"] = self.isolation_env.get("temp_directory", "/tmp")
        
        return env
    
    def _prepare_working_directory(self) -> str:
        """Prepare working directory for isolated process."""
        
        if self.config.chroot_directory:
            return "/"  # Inside chroot
        elif self.isolation_env.get("temp_directory"):
            return self.isolation_env["temp_directory"]
        else:
            return "/tmp"
    
    def _create_preexec_function(self):
        """Create preexec function for process setup."""
        
        def preexec_fn():
            """Function executed in child process before exec."""
            
            try:
                # Set process group
                os.setpgrp()
                
                # Apply resource limits
                self._apply_resource_limits()
                
                # Drop capabilities if enabled
                if self.config.enable_capabilities:
                    self._drop_capabilities()
                
                # Change to specified user/group
                self._change_user_group()
                
                # Apply chroot if configured
                if self.config.chroot_directory and self.isolation_env.get("chroot_prepared"):
                    os.chroot(self.isolation_env["chroot_directory"])
                    os.chdir("/")
            
            except Exception as e:
                print(f"Error in preexec function: {e}", file=sys.stderr)
                sys.exit(1)
        
        return preexec_fn
    
    def _apply_resource_limits(self):
        """Apply resource limits to process."""
        
        # Memory limit
        if self.config.memory_limit:
            memory_bytes = self.isolator._parse_memory_limit(self.config.memory_limit)
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        
        # File descriptor limit
        if self.config.file_descriptor_limit:
            resource.setrlimit(
                resource.RLIMIT_NOFILE,
                (self.config.file_descriptor_limit, self.config.file_descriptor_limit)
            )
        
        # Process limit
        if self.config.process_limit:
            resource.setrlimit(
                resource.RLIMIT_NPROC,
                (self.config.process_limit, self.config.process_limit)
            )
        
        # CPU time limit (execution timeout)
        if self.config.execution_timeout:
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (self.config.execution_timeout, self.config.execution_timeout)
            )
    
    def _drop_capabilities(self):
        """Drop dangerous capabilities from process."""
        
        # This would use libcap-python or similar
        # For now, just log the intention
        self.logger.debug("Dropping dangerous capabilities")
    
    def _change_user_group(self):
        """Change process user and group."""
        
        if self.config.run_as_group:
            try:
                group_info = grp.getgrnam(self.config.run_as_group)
                os.setgid(group_info.gr_gid)
            except KeyError:
                self.logger.warning(f"Group not found: {self.config.run_as_group}")
        
        if self.config.run_as_user:
            try:
                user_info = pwd.getpwnam(self.config.run_as_user)
                os.setuid(user_info.pw_uid)
            except KeyError:
                self.logger.warning(f"User not found: {self.config.run_as_user}")
    
    async def stop(self, timeout: int = 10):
        """Stop the isolated process."""
        
        if not self.process:
            return
        
        self.logger.info(f"Stopping isolated process (PID: {self.process.pid})")
        
        try:
            # Try graceful termination first
            self.process.terminate()
            
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Force kill if timeout
                self.logger.warning("Process did not terminate gracefully, force killing")
                self.process.kill()
                self.process.wait()
            
            self.terminated_at = datetime.now()
        
        except Exception as e:
            self.logger.error(f"Error stopping process: {e}")
        
        finally:
            # Stop resource monitoring
            if self.resource_monitor:
                await self.resource_monitor.stop()
            
            # Update isolator registry
            if self.process_id in self.isolator.isolated_processes:
                self.isolator.isolated_processes[self.process_id]["status"] = "stopped"
            
            # Clean up isolation resources
            self.isolator.cleanup_isolated_process(self.process_id)
    
    def is_running(self) -> bool:
        """Check if process is running."""
        
        return self.process and self.process.poll() is None
    
    def get_pid(self) -> Optional[int]:
        """Get process ID."""
        
        return self.process.pid if self.process else None
    
    def get_runtime_stats(self) -> Dict:
        """Get runtime statistics for process."""
        
        stats = {
            "process_id": self.process_id,
            "pid": self.get_pid(),
            "is_running": self.is_running(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "terminated_at": self.terminated_at.isoformat() if self.terminated_at else None
        }
        
        if self.started_at:
            if self.terminated_at:
                runtime = self.terminated_at - self.started_at
            else:
                runtime = datetime.now() - self.started_at
            
            stats["runtime_seconds"] = runtime.total_seconds()
        
        # Add resource monitor stats if available
        if self.resource_monitor:
            stats["resource_usage"] = self.resource_monitor.get_current_stats()
        
        return stats

# Usage example
async def process_isolation_example():
    """Example of process isolation implementation."""
    
    # Configure comprehensive sandbox
    sandbox_config = SandboxConfig(
        # User isolation
        create_new_user=True,
        
        # Filesystem isolation
        enable_filesystem_isolation=True,
        readonly_paths=["/usr", "/lib", "/lib64"],
        writable_paths=["/tmp"],
        blocked_paths=["/etc/passwd", "/etc/shadow"],
        
        # Network isolation
        enable_network_isolation=True,
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[80, 443],
        enable_loopback=True,
        
        # Resource limits
        memory_limit="128M",
        cpu_limit="0.5",
        disk_limit="100M",
        file_descriptor_limit=64,
        process_limit=5,
        
        # Time limits
        execution_timeout=300,  # 5 minutes
        idle_timeout=60,        # 1 minute
        
        # Security features
        enable_seccomp=True,
        enable_capabilities=True,
        enable_namespace_isolation=True,
        
        # Monitoring
        enable_resource_monitoring=True,
        enable_syscall_monitoring=False,  # Can be expensive
        enable_network_monitoring=True
    )
    
    # Create process isolator
    isolator = ProcessIsolator(sandbox_config)
    
    # Test commands to run in isolation
    test_commands = [
        ["python3", "-c", "print('Hello from isolated Python!')"],
        ["python3", "-c", """
import os
import sys
print(f'PID: {os.getpid()}')
print(f'UID: {os.getuid()}')
print(f'Working directory: {os.getcwd()}')
print(f'Environment variables: {len(os.environ)}')
try:
    with open('/etc/passwd', 'r') as f:
        print('ERROR: Could read /etc/passwd!')
except PermissionError:
    print('SUCCESS: Cannot read /etc/passwd (blocked)')
        """],
        ["sh", "-c", "echo 'Shell in sandbox'; ls -la /"]
    ]
    
    for i, command in enumerate(test_commands):
        try:
            print(f"\n🔒 Running isolated command {i+1}: {' '.join(command)}")
            
            async with await isolator.create_isolated_process(
                command=command,
                process_id=f"test_{i+1}"
            ) as isolated_process:
                
                # Wait for process to complete
                while isolated_process.is_running():
                    await asyncio.sleep(0.1)
                
                # Get runtime statistics
                stats = isolated_process.get_runtime_stats()
                print(f"   Runtime: {stats.get('runtime_seconds', 0):.2f}s")
                print(f"   PID: {stats.get('pid', 'N/A')}")
                
                # Get process output
                if isolated_process.process:
                    stdout, stderr = isolated_process.process.communicate()
                    
                    if stdout:
                        print("   Output:")
                        for line in stdout.decode().strip().split('\n'):
                            print(f"     {line}")
                    
                    if stderr:
                        print("   Errors:")
                        for line in stderr.decode().strip().split('\n'):
                            print(f"     {line}")
        
        except Exception as e:
            print(f"❌ Command {i+1} failed: {e}")
    
    # Show isolator statistics
    processes = isolator.list_isolated_processes()
    print(f"\n📊 Isolator processed {len(processes)} total processes")

# Usage
await process_isolation_example()
```

## Resource Monitoring

### Comprehensive Resource Monitor

```python
import psutil
import asyncio
from typing import Dict, List, Any, Optional
import time
from dataclasses import dataclass, field

@dataclass
class ResourceUsageSnapshot:
    """Snapshot of resource usage at a point in time."""
    
    timestamp: float
    cpu_percent: float
    memory_bytes: int
    memory_percent: float
    disk_read_bytes: int
    disk_write_bytes: int
    network_bytes_sent: int
    network_bytes_recv: int
    open_files: int
    num_processes: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "cpu_percent": self.cpu_percent,
            "memory_bytes": self.memory_bytes,
            "memory_percent": self.memory_percent,
            "disk_read_bytes": self.disk_read_bytes,
            "disk_write_bytes": self.disk_write_bytes,
            "network_bytes_sent": self.network_bytes_sent,
            "network_bytes_recv": self.network_bytes_recv,
            "open_files": self.open_files,
            "num_processes": self.num_processes
        }

class ResourceMonitor:
    """Monitors resource usage of isolated processes."""
    
    def __init__(self, process_id: str, config: SandboxConfig):
        self.process_id = process_id
        self.config = config
        self.logger = logging.getLogger(f"resource_monitor_{process_id}")
        
        # Monitoring state
        self.target_process: Optional[psutil.Process] = None
        self.monitoring_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Resource usage history
        self.usage_history: List[ResourceUsageSnapshot] = []
        self.max_history_size = 1000
        
        # Alert thresholds
        self.memory_alert_threshold = 0.8  # 80% of limit
        self.cpu_alert_threshold = 0.9     # 90% of limit
        self.disk_alert_threshold = 0.8    # 80% of limit
        
        # Statistics
        self.stats = {
            "monitoring_started": None,
            "monitoring_stopped": None,
            "total_samples": 0,
            "alerts_triggered": 0,
            "peak_memory_bytes": 0,
            "peak_cpu_percent": 0.0
        }
    
    async def start(self, target_pid: int = None):
        """Start monitoring process resources."""
        
        if self._running:
            return
        
        if target_pid:
            try:
                self.target_process = psutil.Process(target_pid)
            except psutil.NoSuchProcess:
                raise ValueError(f"Process {target_pid} not found")
        
        self._running = True
        self.stats["monitoring_started"] = datetime.now()
        
        # Start monitoring loop
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        self.logger.info(f"Started resource monitoring for process {target_pid}")
    
    async def stop(self):
        """Stop resource monitoring."""
        
        self._running = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        self.stats["monitoring_stopped"] = datetime.now()
        self.logger.info("Stopped resource monitoring")
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        
        while self._running:
            try:
                if self.target_process and self.target_process.is_running():
                    # Collect resource usage snapshot
                    snapshot = self._collect_resource_snapshot()
                    
                    if snapshot:
                        self.usage_history.append(snapshot)
                        self.stats["total_samples"] += 1
                        
                        # Limit history size
                        if len(self.usage_history) > self.max_history_size:
                            self.usage_history.pop(0)
                        
                        # Check for alerts
                        await self._check_resource_alerts(snapshot)
                        
                        # Update peak statistics
                        self._update_peak_stats(snapshot)
                
                await asyncio.sleep(1.0)  # Sample every second
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5.0)  # Wait before retry
    
    def _collect_resource_snapshot(self) -> Optional[ResourceUsageSnapshot]:
        """Collect current resource usage snapshot."""
        
        try:
            if not self.target_process:
                return None
            
            # Get process tree (including children)
            processes = [self.target_process] + self.target_process.children(recursive=True)
            
            # Aggregate resource usage
            total_cpu = 0.0
            total_memory = 0
            total_memory_percent = 0.0
            total_disk_read = 0
            total_disk_write = 0
            total_network_sent = 0
            total_network_recv = 0
            total_open_files = 0
            total_processes = len(processes)
            
            for process in processes:
                try:
                    # CPU usage
                    total_cpu += process.cpu_percent(interval=None)
                    
                    # Memory usage
                    memory_info = process.memory_info()
                    total_memory += memory_info.rss
                    total_memory_percent += process.memory_percent()
                    
                    # Disk I/O
                    io_counters = process.io_counters()
                    total_disk_read += io_counters.read_bytes
                    total_disk_write += io_counters.write_bytes
                    
                    # Network I/O (if available)
                    try:
                        net_connections = process.connections()
                        # This is simplified - real implementation would track network bytes
                        total_network_sent += len(net_connections) * 1024  # Placeholder
                        total_network_recv += len(net_connections) * 1024  # Placeholder
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Open files
                    try:
                        total_open_files += len(process.open_files())
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process may have terminated or access denied
                    continue
            
            return ResourceUsageSnapshot(
                timestamp=time.time(),
                cpu_percent=total_cpu,
                memory_bytes=total_memory,
                memory_percent=total_memory_percent,
                disk_read_bytes=total_disk_read,
                disk_write_bytes=total_disk_write,
                network_bytes_sent=total_network_sent,
                network_bytes_recv=total_network_recv,
                open_files=total_open_files,
                num_processes=total_processes
            )
        
        except Exception as e:
            self.logger.error(f"Error collecting resource snapshot: {e}")
            return None
    
    async def _check_resource_alerts(self, snapshot: ResourceUsageSnapshot):
        """Check for resource usage alerts."""
        
        alerts_triggered = False
        
        # Memory alert
        if self.config.memory_limit:
            memory_limit_bytes = self._parse_memory_limit(self.config.memory_limit)
            memory_usage_ratio = snapshot.memory_bytes / memory_limit_bytes
            
            if memory_usage_ratio > self.memory_alert_threshold:
                self.logger.warning(
                    f"Memory usage alert: {memory_usage_ratio:.1%} of limit "
                    f"({snapshot.memory_bytes} / {memory_limit_bytes} bytes)"
                )
                alerts_triggered = True
        
        # CPU alert
        if self.config.cpu_limit:
            cpu_limit = float(self.config.cpu_limit) * 100  # Convert to percentage
            if snapshot.cpu_percent > cpu_limit * self.cpu_alert_threshold:
                self.logger.warning(
                    f"CPU usage alert: {snapshot.cpu_percent:.1f}% "
                    f"(threshold: {cpu_limit * self.cpu_alert_threshold:.1f}%)"
                )
                alerts_triggered = True
        
        # File descriptor alert
        if self.config.file_descriptor_limit:
            fd_usage_ratio = snapshot.open_files / self.config.file_descriptor_limit
            if fd_usage_ratio > 0.8:  # 80% threshold
                self.logger.warning(
                    f"File descriptor usage alert: {fd_usage_ratio:.1%} of limit "
                    f"({snapshot.open_files} / {self.config.file_descriptor_limit})"
                )
                alerts_triggered = True
        
        # Process count alert
        if self.config.process_limit:
            if snapshot.num_processes > self.config.process_limit:
                self.logger.warning(
                    f"Process count alert: {snapshot.num_processes} > {self.config.process_limit}"
                )
                alerts_triggered = True
        
        if alerts_triggered:
            self.stats["alerts_triggered"] += 1
    
    def _update_peak_stats(self, snapshot: ResourceUsageSnapshot):
        """Update peak usage statistics."""
        
        if snapshot.memory_bytes > self.stats["peak_memory_bytes"]:
            self.stats["peak_memory_bytes"] = snapshot.memory_bytes
        
        if snapshot.cpu_percent > self.stats["peak_cpu_percent"]:
            self.stats["peak_cpu_percent"] = snapshot.cpu_percent
    
    def _parse_memory_limit(self, memory_str: str) -> int:
        """Parse memory limit string to bytes."""
        
        memory_str = memory_str.upper().strip()
        
        if memory_str.endswith('K'):
            return int(memory_str[:-1]) * 1024
        elif memory_str.endswith('M'):
            return int(memory_str[:-1]) * 1024 * 1024
        elif memory_str.endswith('G'):
            return int(memory_str[:-1]) * 1024 * 1024 * 1024
        else:
            return int(memory_str)
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics."""
        
        if not self.usage_history:
            return {"status": "no_data"}
        
        latest = self.usage_history[-1]
        
        # Calculate averages over last 60 seconds
        recent_snapshots = [
            s for s in self.usage_history 
            if latest.timestamp - s.timestamp <= 60
        ]
        
        if recent_snapshots:
            avg_cpu = sum(s.cpu_percent for s in recent_snapshots) / len(recent_snapshots)
            avg_memory = sum(s.memory_bytes for s in recent_snapshots) / len(recent_snapshots)
        else:
            avg_cpu = latest.cpu_percent
            avg_memory = latest.memory_bytes
        
        return {
            "current": latest.to_dict(),
            "averages_60s": {
                "cpu_percent": avg_cpu,
                "memory_bytes": avg_memory
            },
            "peaks": {
                "memory_bytes": self.stats["peak_memory_bytes"],
                "cpu_percent": self.stats["peak_cpu_percent"]
            },
            "monitoring_stats": {
                "total_samples": self.stats["total_samples"],
                "alerts_triggered": self.stats["alerts_triggered"],
                "monitoring_duration_seconds": (
                    (datetime.now() - self.stats["monitoring_started"]).total_seconds()
                    if self.stats["monitoring_started"] else 0
                )
            }
        }
    
    def get_usage_history(self, last_seconds: int = 300) -> List[Dict[str, Any]]:
        """Get resource usage history for specified time period."""
        
        if not self.usage_history:
            return []
        
        cutoff_time = time.time() - last_seconds
        
        return [
            snapshot.to_dict()
            for snapshot in self.usage_history
            if snapshot.timestamp >= cutoff_time
        ]
    
    def generate_usage_report(self) -> str:
        """Generate human-readable usage report."""
        
        if not self.usage_history:
            return "No resource usage data available"
        
        stats = self.get_current_stats()
        current = stats["current"]
        peaks = stats["peaks"]
        monitoring_stats = stats["monitoring_stats"]
        
        report = []
        report.append(f"📊 Resource Usage Report - Process {self.process_id}")
        report.append("=" * 50)
        
        # Current usage
        report.append(f"\n🔄 Current Usage:")
        report.append(f"  CPU: {current['cpu_percent']:.1f}%")
        report.append(f"  Memory: {current['memory_bytes'] / 1024 / 1024:.1f} MB ({current['memory_percent']:.1f}%)")
        report.append(f"  Open Files: {current['open_files']}")
        report.append(f"  Processes: {current['num_processes']}")
        
        # Peak usage
        report.append(f"\n📈 Peak Usage:")
        report.append(f"  Peak Memory: {peaks['memory_bytes'] / 1024 / 1024:.1f} MB")
        report.append(f"  Peak CPU: {peaks['cpu_percent']:.1f}%")
        
        # Monitoring statistics
        report.append(f"\n📋 Monitoring Statistics:")
        report.append(f"  Duration: {monitoring_stats['monitoring_duration_seconds']:.0f} seconds")
        report.append(f"  Samples Collected: {monitoring_stats['total_samples']}")
        report.append(f"  Alerts Triggered: {monitoring_stats['alerts_triggered']}")
        
        # Resource limit compliance
        report.append(f"\n🎯 Resource Limit Compliance:")
        
        if self.config.memory_limit:
            memory_limit = self._parse_memory_limit(self.config.memory_limit)
            memory_usage = current['memory_bytes'] / memory_limit
            compliance_icon = "✅" if memory_usage < 0.8 else "⚠️" if memory_usage < 1.0 else "❌"
            report.append(f"  Memory: {compliance_icon} {memory_usage:.1%} of {self.config.memory_limit}")
        
        if self.config.cpu_limit:
            cpu_limit = float(self.config.cpu_limit) * 100
            cpu_compliance = current['cpu_percent'] / cpu_limit if cpu_limit > 0 else 0
            compliance_icon = "✅" if cpu_compliance < 0.8 else "⚠️" if cpu_compliance < 1.0 else "❌"
            report.append(f"  CPU: {compliance_icon} {cpu_compliance:.1%} of {self.config.cpu_limit} cores")
        
        if self.config.file_descriptor_limit:
            fd_usage = current['open_files'] / self.config.file_descriptor_limit
            compliance_icon = "✅" if fd_usage < 0.8 else "⚠️" if fd_usage < 1.0 else "❌"
            report.append(f"  File Descriptors: {compliance_icon} {fd_usage:.1%} of {self.config.file_descriptor_limit}")
        
        return "\n".join(report)

# Usage example with resource monitoring
async def resource_monitoring_example():
    """Example of comprehensive resource monitoring."""
    
    # Configure sandbox with tight limits for testing
    config = SandboxConfig(
        memory_limit="64M",         # Small memory limit
        cpu_limit="0.25",           # Quarter CPU core
        file_descriptor_limit=32,   # Limited file descriptors
        process_limit=3,            # Limited processes
        execution_timeout=120,      # 2 minute limit
        enable_resource_monitoring=True
    )
    
    isolator = ProcessIsolator(config)
    
    # Test script that uses resources progressively
    resource_test_script = """
import time
import os
import threading

def memory_consumer():
    # Gradually consume memory
    data = []
    for i in range(100):
        data.append([0] * 10000)  # ~400KB each iteration
        time.sleep(0.1)
    print(f"Memory consumer finished, allocated ~40MB")

def cpu_consumer():
    # Consume CPU cycles
    end_time = time.time() + 30
    count = 0
    while time.time() < end_time:
        count += 1
        if count % 1000000 == 0:
            time.sleep(0.001)  # Brief pause
    print(f"CPU consumer finished, {count} iterations")

def file_consumer():
    # Open many files
    files = []
    for i in range(20):
        try:
            f = open(f'/tmp/test_file_{i}', 'w')
            f.write(f'Test data {i}\\n')
            files.append(f)
            time.sleep(0.5)
        except Exception as e:
            print(f"File error: {e}")
    
    # Clean up
    for f in files:
        f.close()
    print(f"File consumer finished, opened {len(files)} files")

print(f"Starting resource test (PID: {os.getpid()})")

# Start resource consumers
threads = [
    threading.Thread(target=memory_consumer),
    threading.Thread(target=cpu_consumer),
    threading.Thread(target=file_consumer)
]

for t in threads:
    t.start()

for t in threads:
    t.join()

print("Resource test completed")
    """
    
    try:
        # Create isolated process with resource monitoring
        async with await isolator.create_isolated_process([
            "python3", "-c", resource_test_script
        ], process_id="resource_test") as isolated_process:
            
            print("🔄 Running resource-intensive test in isolated environment...")
            print(f"   PID: {isolated_process.get_pid()}")
            print(f"   Memory limit: {config.memory_limit}")
            print(f"   CPU limit: {config.cpu_limit} cores")
            
            # Monitor process while it runs
            monitor = isolated_process.resource_monitor
            
            if monitor:
                # Report resource usage every 10 seconds
                for i in range(15):  # Up to 150 seconds
                    if not isolated_process.is_running():
                        break
                    
                    await asyncio.sleep(10)
                    
                    # Get current stats
                    stats = monitor.get_current_stats()
                    if stats and "current" in stats:
                        current = stats["current"]
                        print(f"\n📊 Resource usage at {i*10}s:")
                        print(f"   CPU: {current['cpu_percent']:.1f}%")
                        print(f"   Memory: {current['memory_bytes'] / 1024 / 1024:.1f} MB")
                        print(f"   Open files: {current['open_files']}")
                        print(f"   Processes: {current['num_processes']}")
                
                # Generate final report
                print("\n" + monitor.generate_usage_report())
                
                # Show usage history chart (simplified)
                history = monitor.get_usage_history(last_seconds=120)
                if history:
                    print(f"\n📈 Memory Usage History (last {len(history)} samples):")
                    for i, sample in enumerate(history[::10]):  # Every 10th sample
                        memory_mb = sample['memory_bytes'] / 1024 / 1024
                        bar_length = int(memory_mb / 2)  # 2MB per character
                        bar = "█" * bar_length
                        print(f"   {i*10:3d}s: {bar} {memory_mb:.1f}MB")
            
            # Get final process statistics
            final_stats = isolated_process.get_runtime_stats()
            print(f"\n🏁 Final Process Statistics:")
            print(f"   Runtime: {final_stats.get('runtime_seconds', 0):.1f}s")
            print(f"   Status: {'Running' if isolated_process.is_running() else 'Completed'}")
    
    except Exception as e:
        print(f"❌ Resource monitoring example failed: {e}")

# Usage
await resource_monitoring_example()
```

## Container Integration

### Docker Integration

```python
import docker
from typing import Dict, List, Any, Optional
import tempfile
import yaml
import json

class DockerIsolator:
    """Docker-based process isolation."""
    
    def __init__(self, image: str = "python:3.11-slim"):
        self.base_image = image
        self.docker_client = docker.from_env()
        self.containers: Dict[str, docker.models.containers.Container] = {}
        self.logger = logging.getLogger("docker_isolator")
    
    async def create_isolated_container(self, 
                                     command: List[str],
                                     process_id: str,
                                     config: SandboxConfig) -> 'DockerIsolatedProcess':
        """Create isolated Docker container."""
        
        # Prepare container configuration
        container_config = self._prepare_container_config(command, process_id, config)
        
        # Create and start container
        container = self.docker_client.containers.run(
            image=self.base_image,
            command=command,
            **container_config,
            detach=True
        )
        
        self.containers[process_id] = container
        self.logger.info(f"Created Docker container {container.id[:12]} for process {process_id}")
        
        return DockerIsolatedProcess(process_id, container, config, self)
    
    def _prepare_container_config(self, command: List[str], 
                                process_id: str, 
                                config: SandboxConfig) -> Dict[str, Any]:
        """Prepare Docker container configuration."""
        
        container_config = {
            "name": f"plugin_{process_id}",
            "hostname": f"plugin-{process_id}",
            "remove": True,  # Auto-remove when stopped
            "init": True,    # Use init system
        }
        
        # Memory limits
        if config.memory_limit:
            memory_bytes = self._parse_memory_limit(config.memory_limit)
            container_config["mem_limit"] = memory_bytes
        
        # CPU limits
        if config.cpu_limit:
            cpu_count = float(config.cpu_limit)
            container_config["cpu_count"] = int(cpu_count)
            container_config["cpu_percent"] = int(cpu_count * 100)
        
        # Network isolation
        if config.enable_network_isolation:
            if config.allowed_hosts or config.allowed_ports:
                # Create custom network with restrictions
                container_config["network_mode"] = "bridge"
            else:
                # No network access
                container_config["network_disabled"] = True
        
        # Filesystem isolation
        volumes = {}
        
        # Read-only volumes
        if config.readonly_paths:
            for path in config.readonly_paths:
                if Path(path).exists():
                    volumes[path] = {"bind": path, "mode": "ro"}
        
        # Writable volumes (limited)
        if config.writable_paths:
            for path in config.writable_paths:
                volumes[path] = {"bind": path, "mode": "rw"}
        
        # Temporary directory
        temp_dir = tempfile.mkdtemp(prefix=f"plugin_{process_id}_")
        volumes[temp_dir] = {"bind": "/tmp", "mode": "rw"}
        
        container_config["volumes"] = volumes
        
        # Security options
        container_config["security_opt"] = ["no-new-privileges:true"]
        
        # Drop capabilities
        if config.enable_capabilities:
            container_config["cap_drop"] = ["ALL"]
            container_config["cap_add"] = ["CHOWN", "SETGID", "SETUID"]  # Minimal caps
        
        # Resource limits
        if config.file_descriptor_limit:
            container_config["ulimits"] = [
                docker.types.Ulimit(name="nofile", soft=config.file_descriptor_limit, hard=config.file_descriptor_limit)
            ]
        
        # Environment variables
        container_config["environment"] = {
            "PLUGIN_SANDBOX": "docker",
            "PLUGIN_PROCESS_ID": process_id,
            "PYTHONUNBUFFERED": "1"
        }
        
        return container_config
    
    def _parse_memory_limit(self, memory_str: str) -> int:
        """Parse memory limit string to bytes."""
        
        memory_str = memory_str.upper().strip()
        
        if memory_str.endswith('K'):
            return int(memory_str[:-1]) * 1024
        elif memory_str.endswith('M'):
            return int(memory_str[:-1]) * 1024 * 1024
        elif memory_str.endswith('G'):
            return int(memory_str[:-1]) * 1024 * 1024 * 1024
        else:
            return int(memory_str)
    
    def cleanup_container(self, process_id: str):
        """Clean up Docker container."""
        
        if process_id not in self.containers:
            return
        
        container = self.containers[process_id]
        
        try:
            # Stop and remove container
            container.stop(timeout=10)
            container.remove()
            self.logger.info(f"Cleaned up container for process {process_id}")
        
        except Exception as e:
            self.logger.error(f"Error cleaning up container: {e}")
        
        finally:
            del self.containers[process_id]

class DockerIsolatedProcess:
    """Docker-based isolated process."""
    
    def __init__(self, process_id: str, container: docker.models.containers.Container,
                 config: SandboxConfig, isolator: DockerIsolator):
        self.process_id = process_id
        self.container = container
        self.config = config
        self.isolator = isolator
        self.logger = logging.getLogger(f"docker_process_{process_id}")
        
        # Monitoring
        self.started_at = datetime.now()
        self.terminated_at: Optional[datetime] = None
    
    async def __aenter__(self) -> 'DockerIsolatedProcess':
        """Container already started in constructor."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Stop container."""
        await self.stop()
    
    def is_running(self) -> bool:
        """Check if container is running."""
        
        try:
            self.container.reload()
            return self.container.status == "running"
        except docker.errors.NotFound:
            return False
    
    async def stop(self, timeout: int = 10):
        """Stop the container."""
        
        try:
            if self.is_running():
                self.container.stop(timeout=timeout)
            
            self.terminated_at = datetime.now()
            
        except Exception as e:
            self.logger.error(f"Error stopping container: {e}")
        
        finally:
            # Clean up
            self.isolator.cleanup_container(self.process_id)
    
    def get_container_stats(self) -> Dict[str, Any]:
        """Get container resource statistics."""
        
        try:
            # Get container stats (generator, get first item)
            stats = next(self.container.stats(decode=True, stream=False))
            
            # Parse Docker stats
            cpu_usage = self._calculate_cpu_percent(stats)
            memory_usage = stats["memory_stats"].get("usage", 0)
            memory_limit = stats["memory_stats"].get("limit", 0)
            
            network_rx = 0
            network_tx = 0
            
            if "networks" in stats:
                for network in stats["networks"].values():
                    network_rx += network.get("rx_bytes", 0)
                    network_tx += network.get("tx_bytes", 0)
            
            return {
                "cpu_percent": cpu_usage,
                "memory_bytes": memory_usage,
                "memory_limit_bytes": memory_limit,
                "memory_percent": (memory_usage / memory_limit * 100) if memory_limit > 0 else 0,
                "network_rx_bytes": network_rx,
                "network_tx_bytes": network_tx,
                "container_id": self.container.id[:12],
                "status": self.container.status
            }
        
        except Exception as e:
            self.logger.error(f"Error getting container stats: {e}")
            return {}
    
    def _calculate_cpu_percent(self, stats: Dict) -> float:
        """Calculate CPU usage percentage from Docker stats."""
        
        try:
            # Docker CPU calculation
            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                       stats["precpu_stats"]["cpu_usage"]["total_usage"]
            
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                          stats["precpu_stats"]["system_cpu_usage"]
            
            if system_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * len(stats["cpu_stats"]["cpu_usage"]["percpu_usage"]) * 100
                return round(cpu_percent, 2)
        
        except (KeyError, ZeroDivisionError):
            pass
        
        return 0.0
    
    def get_runtime_stats(self) -> Dict[str, Any]:
        """Get runtime statistics."""
        
        runtime_seconds = 0
        if self.started_at:
            end_time = self.terminated_at or datetime.now()
            runtime_seconds = (end_time - self.started_at).total_seconds()
        
        stats = {
            "process_id": self.process_id,
            "container_id": self.container.id[:12],
            "is_running": self.is_running(),
            "runtime_seconds": runtime_seconds,
            "started_at": self.started_at.isoformat(),
            "terminated_at": self.terminated_at.isoformat() if self.terminated_at else None
        }
        
        # Add container stats if running
        if self.is_running():
            stats["resource_usage"] = self.get_container_stats()
        
        return stats
    
    def get_logs(self, tail: int = 100) -> str:
        """Get container logs."""
        
        try:
            logs = self.container.logs(tail=tail, timestamps=True)
            return logs.decode('utf-8', errors='replace')
        except Exception as e:
            return f"Error getting logs: {e}"

# Usage example with Docker
async def docker_isolation_example():
    """Example using Docker-based isolation."""
    
    try:
        # Configure Docker-based isolation
        config = SandboxConfig(
            memory_limit="128M",
            cpu_limit="0.5",
            enable_network_isolation=True,
            enable_filesystem_isolation=True,
            execution_timeout=120
        )
        
        docker_isolator = DockerIsolator("python:3.11-slim")
        
        # Test script for Docker environment
        docker_test_script = """
import os
import sys
import time
import psutil

print("=== Docker Isolated Process Test ===")
print(f"PID: {os.getpid()}")
print(f"UID: {os.getuid()}")
print(f"GID: {os.getgid()}")
print(f"Working directory: {os.getcwd()}")
print(f"Hostname: {os.uname().nodename}")

# Check environment
print(f"Environment variables: {len(os.environ)}")
print(f"Sandbox type: {os.environ.get('PLUGIN_SANDBOX', 'unknown')}")
print(f"Process ID: {os.environ.get('PLUGIN_PROCESS_ID', 'unknown')}")

# Test filesystem access
print("\\n=== Filesystem Access Test ===")
try:
    with open('/etc/hostname', 'r') as f:
        print(f"Hostname file: {f.read().strip()}")
except Exception as e:
    print(f"Cannot read /etc/hostname: {e}")

try:
    with open('/etc/passwd', 'r') as f:
        lines = f.readlines()
        print(f"Passwd file has {len(lines)} entries")
except Exception as e:
    print(f"Cannot read /etc/passwd: {e}")

# Test network access
print("\\n=== Network Access Test ===")
import socket
try:
    socket.create_connection(("8.8.8.8", 53), timeout=5)
    print("Network access: ALLOWED")
except Exception as e:
    print(f"Network access: BLOCKED - {e}")

# Resource usage
if psutil:
    process = psutil.Process()
    print(f"\\n=== Resource Usage ===")
    print(f"Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB")
    print(f"CPU percent: {process.cpu_percent()}%")
    print(f"Open files: {len(process.open_files())}")

# Simulate some work
print("\\n=== Simulating Work ===")
data = []
for i in range(10):
    data.append([0] * 100000)  # ~400KB per iteration
    time.sleep(1)
    print(f"Iteration {i+1}/10 - Memory: ~{(i+1) * 0.4:.1f} MB allocated")

print("\\nDocker isolation test completed successfully!")
        """
        
        print("🐳 Starting Docker-based isolation test...")
        
        # Create isolated Docker container
        async with await docker_isolator.create_isolated_container(
            command=["python", "-c", docker_test_script],
            process_id="docker_test",
            config=config
        ) as docker_process:
            
            print(f"   Container ID: {docker_process.container.id[:12]}")
            print(f"   Container started at: {docker_process.started_at}")
            
            # Monitor container while it runs
            while docker_process.is_running():
                await asyncio.sleep(5)
                
                # Get resource stats
                stats = docker_process.get_container_stats()
                if stats:
                    print(f"   📊 Resources: "
                          f"CPU: {stats['cpu_percent']:.1f}%, "
                          f"Memory: {stats['memory_bytes'] / 1024 / 1024:.1f}MB")
            
            # Get final statistics
            final_stats = docker_process.get_runtime_stats()
            print(f"\n🏁 Docker Test Results:")
            print(f"   Runtime: {final_stats['runtime_seconds']:.1f}s")
            print(f"   Status: {final_stats.get('resource_usage', {}).get('status', 'completed')}")
            
            # Show container logs
            logs = docker_process.get_logs(tail=50)
            print(f"\n📋 Container Logs:")
            for line in logs.split('\n')[-20:]:  # Last 20 lines
                if line.strip():
                    print(f"   {line}")
    
    except docker.errors.DockerException as e:
        print(f"❌ Docker error: {e}")
        print("   Make sure Docker is installed and running")
    except Exception as e:
        print(f"❌ Docker isolation example failed: {e}")

# Usage (requires Docker)
await docker_isolation_example()
```

## Best Practices

### Security Hardening Checklist

```python
class ProcessIsolationAuditor:
    """Audits process isolation security."""
    
    @staticmethod
    def audit_isolation_security(isolator: ProcessIsolator) -> Dict[str, Any]:
        """Comprehensive isolation security audit."""
        
        audit_result = {
            "timestamp": datetime.now().isoformat(),
            "isolation_type": "process_isolation",
            "security_score": 0,
            "findings": [],
            "recommendations": [],
            "compliance_checks": {}
        }
        
        config = isolator.config
        
        # Security scoring
        total_score = 0
        max_score = 0
        
        # Check 1: User isolation (20 points)
        max_score += 20
        if config.create_new_user or config.run_as_user:
            total_score += 20
            audit_result["findings"].append("✅ User isolation enabled")
        else:
            audit_result["findings"].append("⚠️ No user isolation - processes run as current user")
            audit_result["recommendations"].append("Enable user isolation with create_new_user or run_as_user")
        
        # Check 2: Filesystem isolation (20 points)
        max_score += 20
        if config.enable_filesystem_isolation:
            total_score += 15
            audit_result["findings"].append("✅ Filesystem isolation enabled")
            
            if config.chroot_directory:
                total_score += 5
                audit_result["findings"].append("✅ Chroot jail configured")
            else:
                audit_result["recommendations"].append("Consider chroot jail for stronger filesystem isolation")
        else:
            audit_result["findings"].append("❌ Filesystem isolation disabled")
            audit_result["recommendations"].append("CRITICAL: Enable filesystem isolation")
        
        # Check 3: Network isolation (15 points)
        max_score += 15
        if config.enable_network_isolation:
            total_score += 10
            audit_result["findings"].append("✅ Network isolation enabled")
            
            if config.allowed_hosts or config.allowed_ports:
                total_score += 5
                audit_result["findings"].append("✅ Network access controls configured")
            else:
                audit_result["recommendations"].append("Configure specific allowed hosts/ports")
        else:
            audit_result["findings"].append("⚠️ Network isolation disabled")
            audit_result["recommendations"].append("Enable network isolation")
        
        # Check 4: Resource limits (15 points)
        max_score += 15
        resource_limits = 0
        
        if config.memory_limit:
            resource_limits += 1
            audit_result["findings"].append("✅ Memory limit configured")
        
        if config.cpu_limit:
            resource_limits += 1
            audit_result["findings"].append("✅ CPU limit configured")
        
        if config.file_descriptor_limit:
            resource_limits += 1
            audit_result["findings"].append("✅ File descriptor limit configured")
        
        if config.process_limit:
            resource_limits += 1
            audit_result["findings"].append("✅ Process limit configured")
        
        total_score += (resource_limits / 4) * 15
        
        if resource_limits < 4:
            audit_result["recommendations"].append("Configure all resource limits (memory, CPU, files, processes)")
        
        # Check 5: Security features (15 points)
        max_score += 15
        security_features = 0
        
        if config.enable_seccomp:
            security_features += 1
            audit_result["findings"].append("✅ Seccomp syscall filtering enabled")
        
        if config.enable_capabilities:
            security_features += 1
            audit_result["findings"].append("✅ Capability dropping enabled")
        
        if config.enable_namespace_isolation:
            security_features += 1
            audit_result["findings"].append("✅ Namespace isolation enabled")
        
        total_score += (security_features / 3) * 15
        
        if security_features < 3:
            audit_result["recommendations"].append("Enable all security features (seccomp, capabilities, namespaces)")
        
        # Check 6: Monitoring (10 points)
        max_score += 10
        if config.enable_resource_monitoring:
            total_score += 10
            audit_result["findings"].append("✅ Resource monitoring enabled")
        else:
            audit_result["findings"].append("⚠️ Resource monitoring disabled")
            audit_result["recommendations"].append("Enable resource monitoring")
        
        # Check 7: Timeout configuration (5 points)
        max_score += 5
        if config.execution_timeout and config.idle_timeout:
            total_score += 5
            audit_result["findings"].append("✅ Execution timeouts configured")
        else:
            audit_result["findings"].append("⚠️ Missing timeout configuration")
            audit_result["recommendations"].append("Configure execution and idle timeouts")
        
        # Calculate final score
        audit_result["security_score"] = (total_score / max_score) * 100 if max_score > 0 else 0
        
        # Compliance checks
        audit_result["compliance_checks"] = {
            "basic_isolation": audit_result["security_score"] >= 60,
            "production_ready": audit_result["security_score"] >= 75,
            "high_security": audit_result["security_score"] >= 90,
            "enterprise_ready": (
                config.create_new_user and
                config.enable_filesystem_isolation and
                config.chroot_directory and
                config.enable_network_isolation and
                config.enable_seccomp and
                config.enable_capabilities
            )
        }
        
        return audit_result
    
    @staticmethod
    def generate_security_report(audit_result: Dict[str, Any]) -> str:
        """Generate isolation security report."""
        
        report = []
        report.append("🔒 Process Isolation Security Audit")
        report.append("=" * 45)
        report.append(f"Generated: {audit_result['timestamp']}")
        
        # Security score
        score = audit_result["security_score"]
        if score >= 90:
            score_icon = "🟢"
            score_rating = "Excellent"
        elif score >= 75:
            score_icon = "🟡"
            score_rating = "Good"
        elif score >= 60:
            score_icon = "🟠"
            score_rating = "Acceptable"
        else:
            score_icon = "🔴"
            score_rating = "Poor"
        
        report.append(f"\n🎯 Security Score: {score_icon} {score:.1f}/100 ({score_rating})")
        
        # Compliance status
        compliance = audit_result["compliance_checks"]
        report.append(f"\n📋 Compliance Status:")
        for check, status in compliance.items():
            icon = "✅" if status else "❌"
            report.append(f"  {icon} {check.replace('_', ' ').title()}: {'Pass' if status else 'Fail'}")
        
        # Findings
        if audit_result["findings"]:
            report.append(f"\n🔍 Security Findings:")
            for finding in audit_result["findings"]:
                report.append(f"  • {finding}")
        
        # Recommendations
        if audit_result["recommendations"]:
            report.append(f"\n💡 Security Recommendations:")
            for i, rec in enumerate(audit_result["recommendations"], 1):
                report.append(f"  {i}. {rec}")
        
        return "\n".join(report)

# Security audit example
async def process_isolation_security_audit():
    """Example of process isolation security audit."""
    
    # Create isolator with various security configurations
    configs = [
        # Minimal security
        ("Minimal", SandboxConfig(
            enable_filesystem_isolation=False,
            enable_network_isolation=False
        )),
        
        # Basic security
        ("Basic", SandboxConfig(
            enable_filesystem_isolation=True,
            enable_network_isolation=True,
            memory_limit="256M",
            cpu_limit="1.0"
        )),
        
        # High security
        ("High Security", SandboxConfig(
            create_new_user=True,
            enable_filesystem_isolation=True,
            chroot_directory="/tmp/chroot",
            enable_network_isolation=True,
            allowed_hosts=["127.0.0.1"],
            memory_limit="128M",
            cpu_limit="0.5",
            file_descriptor_limit=64,
            process_limit=3,
            execution_timeout=300,
            enable_seccomp=True,
            enable_capabilities=True,
            enable_namespace_isolation=True,
            enable_resource_monitoring=True
        ))
    ]
    
    for config_name, config in configs:
        print(f"\n🔍 Auditing {config_name} Configuration:")
        print("-" * 40)
        
        isolator = ProcessIsolator(config)
        
        # Perform security audit
        audit_result = ProcessIsolationAuditor.audit_isolation_security(isolator)
        
        # Generate and display report
        security_report = ProcessIsolationAuditor.generate_security_report(audit_result)
        print(security_report)
        
        # Save audit results
        audit_filename = f"isolation_audit_{config_name.lower().replace(' ', '_')}.json"
        with open(audit_filename, 'w') as f:
            json.dump(audit_result, f, indent=2, default=str)
        
        print(f"\n📊 Audit results saved to: {audit_filename}")

# Usage
await process_isolation_security_audit()
```

## Next Steps

- **[mTLS Configuration](mtls.md)** - Implement mutual TLS authentication for network security
- **[Magic Cookies](magic-cookies.md)** - Use lightweight authentication for local processes  
- **[Certificate Management](certificates.md)** - Learn comprehensive certificate lifecycle management