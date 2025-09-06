#
# pyvider/rpcplugin/rate_limiter.py
#
"""
Rate Limiting Utilities for Pyvider RPC Plugin.

This module now imports from provide.foundation and provides backward compatibility.
The TokenBucketRateLimiter implementation has been moved to provide-foundation
for reuse across the provide.io ecosystem.
"""

# Import from provide.foundation for the actual implementation
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

# Re-export for backward compatibility
__all__ = ["TokenBucketRateLimiter"]

# 🐍🏗️🔌



# 🐍🔌📄🪄
