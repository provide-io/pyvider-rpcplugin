

Updated curve logic for BoringSSL:
https://github.com/grpc/grpc/pull/27547/files#diff-d156f50027c4d27c927b506ac4813b3446b41337e92103513cfab376979aef1d

To build gRPC using Bazel, use the following command:

```sh
bazel build //:all
```

Or, if you want to build only the gRPC library:

```sh
bazel build //src/core:grpc
```

For a specific gRPC target (e.g., C++ version):

```sh
bazel build //:grpc_cpp_plugin
```

If you need to build the Python gRPC plugin:

```sh
bazel build //:grpc_python_plugin
```

For Java:

```sh
bazel build //:grpc_java_plugin
```

If you want to include dependencies, use:

```sh
bazel build --fetch //...
```

Make sure you have the correct Bazel workspace setup with `WORKSPACE` and dependencies in `BUILD` files.

Let me know if you need a specific language binding!
