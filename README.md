# Warden

Autonomous endpoint detection & response for Linux workstations, written in
Rust. No server dependency — everything runs locally as a single hardened
systemd service.

See [PROGRESS.md](PROGRESS.md) for current status, architecture decisions,
and what's tested vs. not.

## Building

Never built or run on the host — see PROGRESS.md's workflow rule. Build
inside the dedicated container:

```sh
docker build -t warden-build:rockylinux -f docker/Dockerfile.build .
docker run --rm -v "$PWD:/build" \
  -v warden-cargo-registry:/usr/local/cargo/registry \
  -w /build warden-build:rockylinux cargo build --release
```

## Status

Early development. The ransomware detection module (fanotify-based, entropy
+ burst heuristics) is implemented and tested end-to-end in Docker. Process
exec/network/persistence/privesc monitoring, an installer script, and
multi-distro test coverage are not built yet.
