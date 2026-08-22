# Changelog

## [0.4.2] - 2026-08-22

### Fixed

- **The gRPC server carries messages as large as its client will send.** It was constructed with no size options, leaving both limits at gRPC's 4 MB default while Terraform's is 256 MB, so a message over 4 MB was refused before any handler saw it: `ResourceExhausted: Received message larger than max (6291555 vs. 4194304)`. A resource with a 6 MB configuration attribute was enough to hit it. State stores made it structural rather than occasional: Terraform proposes an 8 MB chunk size and sizes every `WriteStateBytes` chunk from it, so no state file over 8 MB could be written at all. Both limits are raised, since `ReadStateBytes` streams outbound and is chunked the same way.
