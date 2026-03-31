#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

cargo fmt --all
(cd ferrocrypt-gui-slint && cargo fmt)
(cd ferrocrypt-gui-dioxus && cargo fmt)
(cd ferrocrypt-gui-tauri/src-tauri && cargo fmt)
