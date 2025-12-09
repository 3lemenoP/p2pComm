#!/bin/bash
# Build script for WebAssembly module

set -e

echo "Building P2P WebAssembly module..."

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "Error: wasm-pack is not installed"
    echo "Install it with: cargo install wasm-pack"
    exit 1
fi

# Parse arguments
TARGET="web"
MODE="release"

while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --dev)
            MODE="dev"
            shift
            ;;
        --release)
            MODE="release"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: ./build.sh [--target web|nodejs|bundler] [--dev|--release]"
            exit 1
            ;;
    esac
done

echo "Target: $TARGET"
echo "Mode: $MODE"

# Build command
if [ "$MODE" = "release" ]; then
    wasm-pack build --target "$TARGET" --release --out-dir pkg
else
    wasm-pack build --target "$TARGET" --dev --out-dir pkg
fi

echo "Build complete! Output in ./pkg/"

# Show package size
if [ -f "pkg/wasm_core_bg.wasm" ]; then
    SIZE=$(du -h pkg/wasm_core_bg.wasm | cut -f1)
    echo "WebAssembly binary size: $SIZE"
fi

echo ""
echo "To use in your project:"
echo "  1. Copy ./pkg/ to your web project"
echo "  2. Import: import init, * as p2p from './pkg/wasm_core.js'"
echo "  3. Initialize: await init()"
echo ""
echo "See WASM_API.md for full documentation"
