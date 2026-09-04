# Changelog

## [Unreleased]

### Fixed

- **A Ctrl-C no longer kills the plugin out from under its host.** SIGINT and SIGTERM were both wired to the graceful-shutdown handler. go-plugin deliberately eats SIGINT (`server.go:459-473`), and it has to: the plugin is not put in its own process group (`internal/cmdrunner/cmd_runner.go:72-82` sets no `Setpgid`), so a terminal Ctrl-C during `terraform apply` reaches the whole foreground group, host and plugin alike. Terraform expects to catch that interrupt itself and then drive an orderly `StopProvider` and graceful wait. Acting on it killed the provider first, so in-flight applies died with `Unavailable` and resources already created remotely never reached state. SIGTERM still shuts the server down, and `PLUGIN_IGNORE_SIGINT=false` restores the old behaviour for interactive or in-process use.

## [0.4.2] - 2026-08-22

### Fixed

- **The gRPC server carries messages as large as its client will send.** It was constructed with no size options, leaving both limits at gRPC's 4 MB default while Terraform's is 256 MB, so a message over 4 MB was refused before any handler saw it: `ResourceExhausted: Received message larger than max (6291555 vs. 4194304)`. A resource with a 6 MB configuration attribute was enough to hit it. State stores made it structural rather than occasional: Terraform proposes an 8 MB chunk size and sizes every `WriteStateBytes` chunk from it, so no state file over 8 MB could be written at all. Both limits are raised, since `ReadStateBytes` streams outbound and is chunked the same way.
