#!/usr/bin/env bash
# Builds one of the static Linux CLI release artifacts locally and puts it
# through the same checks the release workflow applies.
#
# The musl targets need a Linux-targeting linker, which a macOS host does
# not have, so the work happens inside containers. Building for a processor
# family other than the host's runs under emulation and is therefore slow,
# but it still produces the real artifact.
#
# The smoke test derives keys with the shipped Argon2id parameters, so the
# container needs more than their 1 GiB of memory. Where Docker itself is
# given less than that, the run is killed part way through key derivation.
#
# Usage: ./scripts/build_static_cli.sh [x86_64|aarch64]   (default: x86_64)

set -euo pipefail

case "${1:-x86_64}" in
    x86_64)
        target="x86_64-unknown-linux-musl"
        platform="linux/amd64"
        ;;
    aarch64)
        target="aarch64-unknown-linux-musl"
        platform="linux/arm64"
        ;;
    *)
        echo "usage: $0 [x86_64|aarch64]" >&2
        exit 2
        ;;
esac

repo="$(cd "$(dirname "$0")/.." && pwd)"
out="$(mktemp -d)"
# Docker may write the copied binary as root, which the host user cannot
# always remove; a leftover temporary directory is not worth an error here.
trap 'rm -rf "$out" 2> /dev/null || true' EXIT

echo "== building $target =="
# The repository is mounted read-only and the build output goes outside it,
# so this never touches the host's own target directory.
docker run --rm --platform "$platform" \
    --volume "$repo:/src:ro" \
    --volume "$out:/out" \
    --env CARGO_TARGET_DIR=/build \
    --workdir /src \
    rust:latest \
    sh -eu -c "
        rustup target add $target > /dev/null
        cargo build --locked --release --target $target -p ferrocrypt-cli
        binary=/build/$target/release/ferrocrypt
        # Captured before being searched, so that a failed readelf stops
        # the run instead of reading as 'no match found'.
        headers=\$(readelf --program-headers \"\$binary\")
        dynamic=\$(readelf --dynamic \"\$binary\")
        if printf '%s\\n' \"\$headers\" | grep -q INTERP; then
            echo 'Names a dynamic loader, so it is not self-contained.' >&2
            exit 1
        fi
        if printf '%s\\n' \"\$dynamic\" | grep -q NEEDED; then
            echo 'Depends on shared libraries, so it is not self-contained.' >&2
            exit 1
        fi
        cp \"\$binary\" /out/ferrocrypt
    "

echo "== smoke-testing $target on Alpine =="
docker run --rm --platform "$platform" \
    --volume "$out/ferrocrypt:/ferrocrypt:ro" \
    --volume "$repo/scripts/smoke_static_cli.sh:/smoke_static_cli.sh:ro" \
    alpine:latest /smoke_static_cli.sh /ferrocrypt

echo "OK: $target builds self-contained and passes the smoke test."
