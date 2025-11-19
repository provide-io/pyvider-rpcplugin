#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""TODO: Add module docstring."""

def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.StreamStdio = channel.unary_stream(
                '/plugin.GRPCStdio/StreamStdio',
                request_serializer=google_dot_protobuf_dot_empty__pb2.Empty.SerializeToString,
                response_deserializer=grpc__stdio__pb2.StdioData.FromString,
                _registered_method=True)


class GRPCStdioServicer(object):
    """GRPCStdio is a service that is automatically run by the plugin process
    to stream any stdout/err data so that it can be mirrored on the plugin
    host side.
    """

    def StreamStdio(self, request, context):
        """StreamStdio returns a stream that contains all the stdout/stderr.
        This RPC endpoint must only be called ONCE. Once stdio data is consumed
        it is not sent again.

        Callers should connect early to prevent blocking on the plugin process.
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_GRPCStdioServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'StreamStdio': grpc.unary_stream_rpc_method_handler(
                    servicer.StreamStdio,
                    request_deserializer=google_dot_protobuf_dot_empty__pb2.Empty.FromString,
                    response_serializer=grpc__stdio__pb2.StdioData.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'plugin.GRPCStdio', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('plugin.GRPCStdio', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class GRPCStdio(object):
    """GRPCStdio is a service that is automatically run by the plugin process
    to stream any stdout/err data so that it can be mirrored on the plugin
    host side.
    """

    @staticmethod
    def StreamStdio(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(
            request,
            target,
            '/plugin.GRPCStdio/StreamStdio',
            google_dot_protobuf_dot_empty__pb2.Empty.SerializeToString,
            grpc__stdio__pb2.StdioData.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

# 📞🔌🔚
