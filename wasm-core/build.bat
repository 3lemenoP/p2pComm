@echo off
REM Build script for WebAssembly module (Windows)

echo Building P2P WebAssembly module...

REM Check if wasm-pack is installed
where wasm-pack >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: wasm-pack is not installed
    echo Install it with: cargo install wasm-pack
    exit /b 1
)

REM Default values
set TARGET=web
set MODE=release

REM Parse arguments
:parse_args
if "%1"=="--target" (
    set TARGET=%2
    shift
    shift
    goto parse_args
)
if "%1"=="--dev" (
    set MODE=dev
    shift
    goto parse_args
)
if "%1"=="--release" (
    set MODE=release
    shift
    goto parse_args
)
if "%1"=="" goto build

echo Unknown option: %1
echo Usage: build.bat [--target web^|nodejs^|bundler] [--dev^|--release]
exit /b 1

:build
echo Target: %TARGET%
echo Mode: %MODE%

REM Build command
if "%MODE%"=="release" (
    wasm-pack build --target %TARGET% --release --out-dir pkg
) else (
    wasm-pack build --target %TARGET% --dev --out-dir pkg
)

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b 1
)

echo Build complete! Output in .\pkg\

REM Show package size
if exist "pkg\wasm_core_bg.wasm" (
    for %%A in (pkg\wasm_core_bg.wasm) do echo WebAssembly binary size: %%~zA bytes
)

echo.
echo To use in your project:
echo   1. Copy .\pkg\ to your web project
echo   2. Import: import init, * as p2p from './pkg/wasm_core.js'
echo   3. Initialize: await init()
echo.
echo See WASM_API.md for full documentation
