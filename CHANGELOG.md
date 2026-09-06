# Changelog

## [Unreleased]

## [0.5.3] - 2026-09-06

### Fixed

- **A TLS connection over TCP verifies the server certificate instead of failing to.** The plugin server's auto-generated certificate carries `DNS:localhost` and no IP SAN. A unix socket presents no hostname to verify against, so the client overrode the TLS target name to `localhost`; a TCP endpoint is dialled by literal address -- `127.0.0.1:<port>`, straight off the handshake line -- which matches a DNS SAN no better, and the override was skipped there on the reasoning that TCP has a hostname.

  gRPC therefore never finished its TLS handshake. The channel stayed not-ready for its full 10s deadline, three retries consumed the client's 30s budget, and the result surfaced as `HandshakeError: Total timeout of 30000.0ms exceeded after 1 attempts` -- describing a handshake that had already succeeded on the first attempt, which is why the failure was read as a handshake problem for as long as it was.

  Only Windows sees it: `DEFAULT_CLIENT_TRANSPORTS` is TCP-only there, while every other platform prefers a unix socket, so the TCP-with-TLS path had no coverage on any platform that runs green.

  This is not a relaxation. `root_certificates` is the server's own certificate, read from the handshake line, so that one certificate is the only thing that can validate the connection and the name check cannot admit anything the pin does not already admit. It is also what go-plugin's own host does -- `go-plugin/client.go:690` sets `ServerName: "localhost"` unconditionally, against certificates its `mtls.go:39` issues with `DNSNames: []string{"localhost"}` and no IP SAN.

  Covered by a test that stands up a real gRPC server with such a certificate on 127.0.0.1 and asserts the channel cannot become ready without the override and can with it, so the regression is caught on every platform rather than only on Windows.

## [0.5.2] - 2026-09-06

### Fixed

- **A plugin slower than the inner handshake timeout is no longer unheard.** `_try_readline_strategy` ran `readline` in an executor under `asyncio.wait_for`. An executor call cannot be cancelled: on timeout the future was abandoned while the thread stayed blocked in the read, still owning the pipe. The line that read eventually returned was discarded, so a plugin that took longer than `DEFAULT_HANDSHAKE_INNER_TIMEOUT` (2s) to print its handshake had it consumed and thrown away -- and every later read waited for bytes that had already been taken, until the outer timeout gave up.

  `_try_chunk_strategy` compounded it by starting a second reader on the same descriptor while the first was still outstanding. Two readers on one pipe means whichever loses the race silently destroys what it took.

  The pending read is now kept and awaited again rather than abandoned, and a chunk read is only attempted when nothing is outstanding.

  This is a race, not a platform limit, and it stayed invisible wherever the plugin printed inside two seconds -- which is every Linux and macOS launch. A cold Windows launch pays process spawn, interpreter start, imports and TLS certificate generation before it can print, lands past the two seconds, and failed every time: `Timed out waiting for handshake response from plugin after 10.0 seconds`, four attempts, against a provider that was up and serving in about one second.

## [0.5.1] - 2026-09-06

### Fixed

- **The handshake-timeout report no longer hangs the client.** `_get_stderr_output()` called `process.stderr.read()` on a `subprocess.Popen` pipe -- no size argument, so a read to EOF. One of its two callers, `_check_process_exit`, runs only once the child has exited: the write end is closed, EOF arrives, the read returns. The other is the handshake-timeout path (`handshake.py:427`), reached only after the loop above it has established the child is still *running*. There the child holds the write end open, so EOF never arrives -- and because Popen pipes are blocking and this runs inside the event loop, the loop stops with it: no timer fires, no cancellation is delivered. The path whose job is to explain a silent plugin was the path that hung, for as long as the plugin stayed up. terraform-provider-pyvider's pytest configuration records the symptom from the other side: a 22-minute stall at ~0% CPU with the main thread blocked in a synchronous read-to-EOF, waiting on a provider that never connected. It was also a second reader on a pipe `_relay_stderr_background` already owns for the life of the process, so the two split the plugin's output and neither saw all of it. The report is now taken from the bounded tail the relay keeps: nothing reads the pipe twice, nothing blocks, and the result no longer depends on the platform's pipe semantics. Both limits live in `defaults.py`.

## [0.5.0] - 2026-09-04

### Breaking

Three of the fixes below change behaviour a deployment may be relying on. Each
is described in full under Fixed.

- **TLS is served only when the host asks for it.** A host that sends no
  `PLUGIN_CLIENT_CERT` now gets a plaintext server and an empty sixth handshake
  field, where it previously got a certificate it never requested.
  `PLUGIN_AUTO_MTLS` no longer decides *whether* to serve TLS -- it decides
  whether a host's certificate is answered with one. Set `PLUGIN_SERVER_CERT`
  and `PLUGIN_SERVER_KEY` if you need TLS without a host certificate. Terraform
  and every other go-plugin host are unaffected, because they always send one.
- **A served plugin ignores SIGINT.** It can be stopped with SIGTERM, SIGQUIT
  or SIGKILL. `PLUGIN_IGNORE_SIGINT=false` restores the old behaviour for
  interactive or in-process servers.
- **A startup failure exits 1 rather than 0.** Supervisors that read exit 0 as
  success will start seeing failures they were previously blind to.

### Fixed

- **A Ctrl-C no longer kills the plugin out from under its host.** SIGINT and SIGTERM were both wired to the graceful-shutdown handler. go-plugin deliberately eats SIGINT (`server.go:459-473`), and it has to: the plugin is not put in its own process group (`internal/cmdrunner/cmd_runner.go:72-82` sets no `Setpgid`), so a terminal Ctrl-C during `terraform apply` reaches the whole foreground group, host and plugin alike. Terraform expects to catch that interrupt itself and then drive an orderly `StopProvider` and graceful wait. Acting on it killed the provider first, so in-flight applies died with `Unavailable` and resources already created remotely never reached state. SIGTERM still shuts the server down, and `PLUGIN_IGNORE_SIGINT=false` restores the old behaviour for interactive or in-process use.
- **TLS is keyed on the host's certificate.** `_read_client_cert()` existed but nothing called it: credentials were decided by `PLUGIN_AUTO_MTLS` alone, which defaults on, so the server always generated a certificate and always advertised it -- with `require_client_auth=False` and no client CA. Two consequences. Any process that could reach the socket could drive the plugin, despite the name auto-mTLS; go-plugin sets `ClientAuth: RequireAndVerifyClientCert` with the host's own certificate as the whole `ClientCAs` pool (`server.go:308-336`). And a host running with TLS disabled -- the `TF_DISABLE_PLUGIN_TLS` path the SDK test harnesses use -- saw a sixth handshake field over 50 characters, called `loadServerCert`, and nil-pointer panicked on `TLSConfig.RootCAs` (`client.go:920-926`, `:950-968`). The server now serves TLS only when the host sent `PLUGIN_CLIENT_CERT` or an operator configured `PLUGIN_SERVER_CERT`/`PLUGIN_SERVER_KEY`, and otherwise serves plaintext with an empty certificate field. It does **not** require a client certificate on the automatic-mTLS path, and cannot: go-plugin's host certificate is ECDSA P-521 (`mtls.go:21`) and BoringSSL does not offer `ecdsa_secp521r1_sha512` in its CertificateRequest, so Go finds no presentable chain, sends an empty Certificate message, and the connection dies as `PEER_DID_NOT_RETURN_A_CERTIFICATE`. Requiring it made every provider unreachable from stock Terraform. Set `PLUGIN_CLIENT_ROOT_CERTS` to require and verify a client certificate you issue yourself. `PLUGIN_AUTO_MTLS` no longer decides *whether* to serve TLS; it decides whether to answer a host's certificate with one, and `false` declines.
- **The advertised protocol version is bounded by what the plugin actually serves.** Negotiation returned the newest version from the *host's* `PLUGIN_PROTOCOL_VERSIONS` that appeared in `SUPPORTED_PROTOCOL_VERSIONS`, whose default is the static range `[1..7]` -- so a plugin registering only `tfplugin6.Provider` answered `PLUGIN_PROTOCOL_VERSIONS=5` with `1|5|...`, and answered an unset variable with `1|1|...`. Terraform happens to send `5,6`, so version 6 was being picked by luck of the default list rather than by anything the plugin knew about itself. go-plugin instead intersects the host's list with `opts.VersionedPlugins`, the plugin sets the server registered (`server.go:170-212`). The served set now comes from the protocol object -- an explicit `supported_protocol_versions`, else a `protocol_version`, else the version named by the registered service, as `tfplugin6.Provider` names 6 -- A host that offered no list at all, or offered nothing this plugin serves, is served the oldest version implemented and left to object: go-plugin says so in as many words at `server.go:145-147` -- "the last version in the config is returned leaving the client to report the incompatibility" -- and does it at `:216-222`. That is the better error, because the host names both version sets to the user, where a plugin that exited during the handshake would surface only "plugin exited before we could connect". The mismatch is logged as a warning naming both sets. `SUPPORTED_PROTOCOL_VERSIONS` still overrides everything, for tests and for plugins whose service name says nothing.
- **A plugin that never came up no longer exits 0.** `_serve_impl` ended in `finally: await self.stop()`, and `stop()` ended in `sys.exit(0)`. On the error path that `SystemExit(0)` replaced the in-flight exception, so every startup failure -- a missing magic cookie, a cookie mismatch, an unsatisfiable protocol version -- exited 0 with nothing but a log line, and Terraform could only report "plugin exited before we could connect" with no cause. go-plugin records `exitCode = 1` for a startup fault and lets a deferred `os.Exit` run it (`server.go:232-266`). Stopping the server and ending the process are now separate: `stop()` only stops, and `serve()` decides the exit code -- 1 when the server never came up, 0 after a clean shutdown. The old behaviour was suppressed by an inline `PYTEST_CURRENT_TEST` check; that is now a documented `PLUGIN_EXIT_ON_STOP` setting, resolved once, which an embedded server can set false so `sys.exit` is never called out from under its caller.
- **The gRPC health service is registered as `plugin`.** It was registered under `pyvider.default.plugin.Service`, derived from a `service_name` attribute most protocol objects do not have. go-plugin's `Ping()` checks the service named exactly `plugin` (`grpc_server.go:26`, `grpc_client.go:127-134`), so every other name answers NOT_FOUND, which a host reads as a dead plugin. The health service now answers to `plugin`, and alongside it to the service the protocol actually registers -- read from `get_grpc_descriptors()` rather than from an optional class attribute. Latent in practice, since Terraform never calls `Ping()`.
- **The graceful shutdown timeout is read instead of ignored.** `PLUGIN_TIMEOUT_GRACEFUL_SHUTDOWN` was accepted from callers -- pyvider passes it on every launch -- while `stop()` hardcoded `grace=0.5`, so a slow in-flight response was cut off half a second into a shutdown no matter what the caller asked for. The value is now used, falling back to the library's own `PLUGIN_GRPC_GRACE_PERIOD`.

## [0.4.2] - 2026-08-22

### Fixed

- **The gRPC server carries messages as large as its client will send.** It was constructed with no size options, leaving both limits at gRPC's 4 MB default while Terraform's is 256 MB, so a message over 4 MB was refused before any handler saw it: `ResourceExhausted: Received message larger than max (6291555 vs. 4194304)`. A resource with a 6 MB configuration attribute was enough to hit it. State stores made it structural rather than occasional: Terraform proposes an 8 MB chunk size and sizes every `WriteStateBytes` chunk from it, so no state file over 8 MB could be written at all. Both limits are raised, since `ReadStateBytes` streams outbound and is chunked the same way.
