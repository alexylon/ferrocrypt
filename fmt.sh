#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

cargo fmt --all
(cd ferrocrypt-desktop && cargo fmt)
(cd experiments/armor && cargo fmt)
(cd experiments/ferrocrypt-desktop-dioxus && cargo fmt)
(cd experiments/ferrocrypt-desktop-tauri/src-tauri && cargo fmt)
(cd ferrocrypt-lib/fuzz && cargo fmt)
