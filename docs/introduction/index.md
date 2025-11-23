# Introduction

Welcome to the Pyvider RPC Plugin framework! This section provides an overview of the system architecture and its relationship with the Foundation infrastructure library.

## What is Pyvider RPC Plugin?

**Pyvider RPC Plugin** is a high-performance, type-safe RPC plugin framework for Python built on gRPC. It provides the communication infrastructure layer for the pyvider ecosystem, implementing a Terraform-compatible plugin protocol with:

- **Async-first design** - Built on Python's `asyncio` for maximum concurrency
- **Security by default** - Automatic mTLS with certificate management
- **Flexible transports** - Unix domain sockets and TCP with auto-negotiation
- **Production-focused** - Health checks, rate limiting, and comprehensive error handling
- **Type safety** - Modern Python 3.11+ type annotations throughout

## Foundation Integration

Pyvider RPC Plugin is built on **Foundation** (`provide.foundation`), a comprehensive infrastructure library that provides:

- **Configuration system** - Type-safe, environment-driven configuration
- **Structured logging** - Consistent logging across all components
- **Cryptography** - X.509 certificate management for mTLS
- **Rate limiting** - Token bucket algorithm implementation
- **Utilities** - Common patterns and helper functions

This architecture separates concerns:

- **Foundation** = Infrastructure layer (config, logging, crypto)
- **Pyvider RPC Plugin** = RPC framework (gRPC, transports, protocols)
- **Your Plugin** = Business logic

## Documentation Sections

### [Foundation Overview](foundation/)

Detailed explanation of how Foundation and Pyvider RPC Plugin work together, including:

- The architecture stack and separation of concerns
- What Foundation provides vs. what Pyvider adds
- Practical benefits of the integrated approach
- When to use Foundation directly

**Read this to understand** the infrastructure foundation that powers the framework.

## Getting Started

After understanding the architecture:

1. **[Installation](../getting-started/installation/)** - Set up your development environment
2. **[Quick Start](../getting-started/quick-start/)** - Create your first plugin in 5 minutes
3. **[User Guide](../guide/index/)** - Comprehensive framework documentation

## Why This Architecture?

The Foundation + Pyvider approach provides several key benefits:

1. **Reduced Complexity** - Don't reimplement infrastructure patterns
1. **Ecosystem Consistency** - Unified patterns across all provide.io projects
1. **Battle-Tested** - Foundation's components are production-proven
1. **Focus on Business Logic** - Spend time on your service, not infrastructure

## Next Steps

- **New to the framework?** Start with [Foundation Overview](foundation/) to understand the infrastructure
- **Ready to code?** Jump to [Getting Started](../getting-started/index/) for installation and tutorials
- **Building production services?** See the [User Guide](../guide/index/) for comprehensive patterns

______________________________________________________________________

**Navigation:** [Home](../index/) | [Next: Foundation](foundation/)
