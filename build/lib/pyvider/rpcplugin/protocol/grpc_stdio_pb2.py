# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: grpc_stdio.proto
# Protobuf Python Version: 6.30.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    6,
    30,
    0,
    '',
    'grpc_stdio.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10grpc_stdio.proto\x12\x06plugin\x1a\x1bgoogle/protobuf/empty.proto\"u\n\tStdioData\x12*\n\x07\x63hannel\x18\x01 \x01(\x0e\x32\x19.plugin.StdioData.Channel\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\".\n\x07\x43hannel\x12\x0b\n\x07INVALID\x10\x00\x12\n\n\x06STDOUT\x10\x01\x12\n\n\x06STDERR\x10\x02\x32G\n\tGRPCStdio\x12:\n\x0bStreamStdio\x12\x16.google.protobuf.Empty\x1a\x11.plugin.StdioData0\x01\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'grpc_stdio_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_STDIODATA']._serialized_start=57
  _globals['_STDIODATA']._serialized_end=174
  _globals['_STDIODATA_CHANNEL']._serialized_start=128
  _globals['_STDIODATA_CHANNEL']._serialized_end=174
  _globals['_GRPCSTDIO']._serialized_start=176
  _globals['_GRPCSTDIO']._serialized_end=247
# @@protoc_insertion_point(module_scope)
