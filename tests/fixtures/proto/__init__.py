#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Proto fixtures package.

Proto modules are imported on-demand to avoid circular import issues with
pytest-xdist parallel test loading. Import them directly:

    from tests.fixtures.proto import echo_pb2, echo_pb2_grpc
    from tests.fixtures.proto import e2e_greeting_pb2, e2e_greeting_pb2_grpc

Or import the specific module first:

    from tests.fixtures.proto.echo_pb2 import EchoRequest
"""

# 🐍🔌📞🔚
