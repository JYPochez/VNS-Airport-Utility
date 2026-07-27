#!/bin/sh

set -eu

# Make the script independent of the caller's working directory. The app also
# expects to find the Python backend relative to the repository root.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

# Keep SwiftPM and Clang's writable state inside the repository. This also
# makes the launcher work in environments where the user's cache directories
# are read-only or unavailable.
CACHE_ROOT="$SCRIPT_DIR/.build/launcher-cache"
mkdir -p "$CACHE_ROOT/build" "$CACHE_ROOT/swiftpm" \
  "$CACHE_ROOT/configuration" "$CACHE_ROOT/security" "$CACHE_ROOT/clang"

export CLANG_MODULE_CACHE_PATH="$CACHE_ROOT/clang"
export SWIFTPM_MODULECACHE_OVERRIDE="$CACHE_ROOT/clang"

exec swift run \
  --scratch-path "$CACHE_ROOT/build" \
  --cache-path "$CACHE_ROOT/swiftpm" \
  --config-path "$CACHE_ROOT/configuration" \
  --security-path "$CACHE_ROOT/security" \
  "AirPort Utility" "$@"
