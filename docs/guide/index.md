# User Guide

The Pyvider RPC Plugin User Guide provides comprehensive documentation for building production-ready RPC plugins with Python. Whether you're new to RPC development or an experienced developer, this guide covers everything from basic concepts to advanced deployment patterns.

## What's Covered

This guide is organized into focused sections that build upon each other:

### 🎯 **Core Concepts**
Understanding the fundamental architecture, transports, protocols, and security model that powers pyvider-rpcplugin.

### 🖥️ **Server Development** 
Learn to build robust plugin servers with service implementation, transport configuration, async patterns, and health monitoring.

### 📱 **Client Development**
Master client development including connection management, error handling, retry logic, and direct connections.

### 🔐 **Security**
Comprehensive security coverage including mTLS configuration, certificate management, magic cookies, and process isolation.

### ⚙️ **Configuration** 
Production-ready configuration management with environment variables, deployment setups, rate limiting, and logging.

### 🚀 **Advanced Topics**
Advanced patterns including custom protocols, performance tuning, middleware development, and plugin lifecycle management.

## Navigation

<div class="grid cards" markdown>

-   :material-lightbulb: **Core Concepts**
    
    ---
    
    RPC architecture, transports, protocols, handshake process, and security model
    
    [:octicons-arrow-right-24: Learn Concepts](concepts/)

-   :material-server: **Server Development**
    
    ---
    
    Build robust plugin servers with async patterns and health monitoring
    
    [:octicons-arrow-right-24: Build Servers](server/)

-   :material-laptop: **Client Development**
    
    ---
    
    Create reliable clients with connection management and retry logic
    
    [:octicons-arrow-right-24: Build Clients](client/)

-   :material-shield-check: **Security**
    
    ---
    
    Implement mTLS, manage certificates, and ensure secure communication
    
    [:octicons-arrow-right-24: Secure Plugins](security/)

-   :material-cog: **Configuration**
    
    ---
    
    Production configuration, environment setup, and deployment patterns
    
    [:octicons-arrow-right-24: Configure Apps](config/)

-   :material-rocket: **Advanced Topics**
    
    ---
    
    Custom protocols, performance tuning, middleware, and lifecycle management
    
    [:octicons-arrow-right-24: Advanced Patterns](advanced/)

</div>

## Learning Approach

### **For Beginners**
If you're new to RPC development, start with:
1. [Core Concepts](concepts/) - Understand the foundation
2. [Server Development](server/) - Build your first server  
3. [Client Development](client/) - Create a client to connect
4. [Security](security/) - Add production-grade security

### **For Experienced Developers**
If you have RPC experience, you might want to:
1. Skim [Core Concepts](concepts/) for pyvider-specific patterns
2. Jump to [Advanced Topics](advanced/) for sophisticated use cases
3. Reference [Configuration](config/) for production deployment
4. Explore custom [Protocols](advanced/custom-protocols.md) and [Middleware](advanced/middleware.md)

## Design Philosophy

Pyvider RPC Plugin follows these core principles:

### **🎯 Simplicity First**
Complex RPC operations should be simple to implement. The framework handles the complexity so you can focus on your business logic.

### **🔒 Security by Default** 
Security features like mTLS and process isolation are built-in and enabled by default, not bolt-on additions.

### **⚡ Performance Oriented**
Async-first design with efficient transports and serialization for high-throughput, low-latency communication.

### **🛠️ Developer Experience**
Comprehensive type safety, clear error messages, and extensive documentation make development productive and enjoyable.

### **🏗️ Production Ready**
Built-in monitoring, logging, rate limiting, and deployment patterns for enterprise environments.

## Related Documentation

- **[API Reference](../api/)** - Detailed API documentation with examples
- **[Examples](../examples/)** - Working code samples and tutorials  
- **[Development](../development/)** - Contributing, testing, and architecture
- **[Getting Started](../getting-started/)** - Quick setup and first steps

Ready to dive in? Start with [Core Concepts](concepts/) or jump to a specific topic that interests you!