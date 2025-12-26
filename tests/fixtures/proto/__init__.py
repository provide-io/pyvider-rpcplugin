#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Proto fixtures package.

Proto modules are NOT auto-imported to avoid circular import issues with
pytest-xdist parallel test loading. Import them directly:

    from tests.fixtures.proto import echo_pb2, echo_pb2_grpc
    from tests.fixtures.proto import e2e_greeting_pb2, e2e_greeting_pb2_grpc
"""

# Lazy imports - modules are available but not loaded until accessed
__all__ = [
    "echo_pb2",
    "echo_pb2_grpc",
    "e2e_greeting_pb2",
    "e2e_greeting_pb2_grpc",
]


def __getattr__(name: str):
    """Lazy import handler for proto modules."""
    if name == "echo_pb2":
        from . import echo_pb2
        return echo_pb2
    elif name == "echo_pb2_grpc":
        from . import echo_pb2_grpc
        return echo_pb2_grpc
    elif name == "e2e_greeting_pb2":
        from . import e2e_greeting_pb2
        return e2e_greeting_pb2
    elif name == "e2e_greeting_pb2_grpc":
        from . import e2e_greeting_pb2_grpc
        return e2e_greeting_pb2_grpc
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# 🐍🔌📞🔚
