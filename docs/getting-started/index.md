# Getting Started

**Path:** [Home](../index.md) → Getting Started

**Build production-ready plugin systems in minutes with Foundation integration**

This guide takes you from installation to your first working plugin with clear learning paths for different experience levels and use cases.

## Learning Outcomes

By the end of this guide, you'll be able to:

- **Deploy plugin systems** using Foundation's configuration patterns and `PLUGIN_*` environment variables
- **Implement secure communication** with automatic mTLS and certificate management
- **Build type-safe services** using modern Python 3.11+ patterns and gRPC Protocol Buffers
- **Integrate with Foundation** for unified logging, configuration, and development workflows
- **Choose appropriate patterns** for your specific use case (microservices, plugin architectures, IPC)

## Prerequisites

**Technical Requirements:**
- **Python 3.11+** with native type annotations (`dict`, `list`, union operators)
- **Basic async/await** knowledge (we'll show the patterns)
- **Foundation familiarity** (optional - we'll explain integration points)

**Experience Levels:**
- **Beginner**: New to RPC or plugin systems → Start with **Installation** then **Quick Start**
- **Experienced**: Familiar with gRPC or microservices → Jump to **First Plugin** for complete examples
- **Foundation User**: Already using provide.foundation → See **Foundation Integration** patterns throughout

## Choose Your Path

<div class="grid cards" markdown>

-   :material-download: **Installation & Setup**
    
    ---
    
    **5 minutes** • Install dependencies and verify environment
    
    Foundation configuration and `PLUGIN_*` environment setup
    
    [:octicons-arrow-right-24: Start Here](installation.md)

-   :material-flash: **Quick Start**
    
    ---
    
    **10 minutes** • Working plugin with automatic process management
    
    Demonstrates core patterns with minimal configuration
    
    [:octicons-arrow-right-24: Quick Start](quick-start.md)

-   :material-puzzle: **Complete Plugin Tutorial**
    
    ---
    
    **25 minutes** • Production-ready echo service with all features
    
    Covers protocols, security, logging, and testing patterns
    
    [:octicons-arrow-right-24: Full Tutorial](first-plugin.md)

-   :material-rocket: **Advanced Patterns**
    
    ---
    
    **Explore examples** • Real-world patterns and production deployments
    
    Database plugins, microservice gateways, and security implementations
    
    [:octicons-arrow-right-24: See Examples](examples.md)

</div>

## Progressive Learning Path

**Foundation Integration Approach:** Each step builds on Foundation patterns

**Beginner Path** (Total: ~45 minutes)
1. **[Installation](installation.md)** (5 min) → Environment setup with Foundation toolchain
2. **[Quick Start](quick-start.md)** (10 min) → Basic plugin with `PLUGIN_*` configuration 
3. **[Simple Custom RPC](simple-custom-rpc.md)** (10 min) → Custom methods without Protocol Buffers
4. **[Complete Tutorial](first-plugin.md)** (20 min) → Production patterns with Protocol Buffers

**Experienced Developer Path** (Total: ~15 minutes)
1. **[Installation](installation.md)** (2 min) → Quick dependency installation
2. **[Complete Tutorial](first-plugin.md)** (10 min) → Skip to production patterns
3. **[Advanced Examples](examples.md)** (3 min) → Real-world implementations

**Next Steps After Completion:**
- **[Security Guide](../guide/security/index.md)** - mTLS, certificates, and authentication patterns
- **[Production Configuration](../guide/config/production.md)** - Environment-driven configuration for deployment
- **[API Reference](../reference/index.md)** - Complete method documentation and advanced usage

## Support & Troubleshooting

**Quick Help:**
- **Common Issues**: Configuration problems, environment setup, import errors
- **Foundation Integration**: Logging not working, configuration not loading
- **Performance**: Transport selection, connection issues, timeout problems

**Resources:**
- 📚 **[User Guide](../guide/index.md)** - Comprehensive concepts and advanced features
- 🔍 **[API Reference](../reference/index.md)** - Complete method documentation with examples
- 💻 **[Working Examples](../examples/index.md)** - Production patterns and real-world implementations
- 🐛 **[GitHub Issues](https://github.com/provide-io/pyvider-rpcplugin/issues)** - Bug reports and feature requests

## Quick Start Options

**Ready to begin?** Choose based on your experience:

<div class="grid" markdown>

[**New to plugins?** Start with Installation :material-arrow-right:](installation.md){ .md-button .md-button--primary }

[**Want to jump in?** Quick Start Guide :material-arrow-right:](quick-start.md){ .md-button }

</div>