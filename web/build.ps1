param(
    [string]$WasmBindgenVersion = "0.2.129"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

try {
    if (-not (Get-Command wasm-bindgen -ErrorAction SilentlyContinue)) {
        throw "wasm-bindgen-cli was not found. Install it with: cargo install wasm-bindgen-cli --version $WasmBindgenVersion"
    }

    & (Join-Path $root "scripts/fetch-game-data.ps1")

    cargo build --release --target wasm32-unknown-unknown --lib
    wasm-bindgen target/wasm32-unknown-unknown/release/post_irminsul.wasm `
        --target web --out-dir web/pkg --out-name post_irminsul

    Write-Host "Built web/pkg. Serve it with: python -m http.server 8000 -d web"
} finally {
    Pop-Location
}
