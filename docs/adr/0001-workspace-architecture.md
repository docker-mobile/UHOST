# ADR 0001: Workspace Architecture

Project UHost is organized as a Rust workspace with three layers:

1. Shared crates in `crates/` define stable contracts, storage adapters, HTTP/runtime infrastructure, and testing helpers.
2. Service crates in `services/` hold one bounded context each and can be deployed independently or composed in all-in-one mode.
3. Binaries in `cmd/` stitch those services together for single-node installs, operators, and future split-process deployments.

This layout keeps contracts explicit while still supporting an operationally light single-node mode.
