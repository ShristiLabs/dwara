# Installation

## Docker images

Two image variants are published from the same static [musl libc](https://en.wikipedia.org/wiki/Musl) binary:

| Image | Size | When to use |
| --- | --- | --- |
| `Dockerfile.scratch` | ~18 MB (aarch64) | absolute minimum; your orchestrator must inject an unprivileged user (`--user`, compose `user:`, Kubernetes `runAsNonRoot`) — scratch has no user database |
| `Dockerfile.distroless` | ~65 MB | baked-in UID 65532 (`nonroot`) plus tzdata and a CA bundle; use this when you cannot inject a user |

The binary is fully static (musl libc, bundled SQLite, aws-lc-rs (Amazon's TLS library, compiled in) compiled
in) — the scratch image carries no base OS layer at all. Outbound TLS
verification uses the Mozilla webpki (Mozilla's public CA root set) root set compiled into the binary,
so no CA bundle is shipped by default; if an upstream or a JWKS endpoint
uses a private CA, point that entity's `trusted_ca_file` at a bundle you
provide (see [Configuration](./configuration)).

Tagged releases (`v*`) publish multi-arch (amd64/arm64) images to GHCR (GitHub Container Registry),
built from cross-compiled, checksum-verified binaries — the image is
byte-identical to the released binary tarball, nothing is compiled a
second time for the image.

## Prebuilt binaries

Release tags produce musl binaries for amd64 and arm64, each under a
25 MB size bar (stripped, [LTO](https://en.wikipedia.org/wiki/Interprocedural_optimization#WPO_and_LTO) (link-time optimization, a whole-program compiler pass) release build). Download the tarball for
your architecture from the release's GitHub artifacts.

## Building from source

Requires Rust 1.94 (pinned via `rust-toolchain.toml` (pins the exact Rust version), installed
automatically by [rustup](https://rust-lang.github.io/rustup/) on first `cargo` invocation), plus cmake and a
C compiler (needed by the aws-lc-rs / musl build).

```sh
git clone https://github.com/shristilabs/dwara.git
cd dwara
cargo build --release -p dwara-bin
```

The binary is at `target/release/dwara`. Companion binaries:
`dwara-cli` (operator CLI, see [CLI](./cli)) and `dwara-admin` is a
library consumed by `dwara-bin`, not a separate binary.

## systemd

A hardened [systemd](https://en.wikipedia.org/wiki/Systemd) unit ships at `packaging/systemd/dwara.service` with install
instructions in its header comment:

```sh
install -Dm755 target/release/dwara /usr/local/bin/dwara
install -Dm644 /path/to/your/dwara.yaml /etc/dwara/dwara.yaml
install -Dm644 packaging/systemd/dwara.service /etc/systemd/system/dwara.service
useradd --system --home /var/lib/dwara --shell /usr/sbin/nologin dwara
systemctl daemon-reload && systemctl enable --now dwara
```

`systemctl reload dwara` sends `SIGHUP` (config hot-reload, see
[Operations](./operations)); `systemctl stop` drains gracefully within
`DWARA_SHUTDOWN_TIMEOUT_SECS`.

## Next steps

[Getting started](./getting-started) walks through running the binary
against a first config, and [Deployment](./deployment) covers the
one-command TLS demo in `quickstart/`.
