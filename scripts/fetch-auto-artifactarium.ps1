param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$revision = "abbbf7a3f58846512250a789a76be2d3cdb115c1"
$repository = "https://github.com/konkers/auto-artifactarium"
$target = Join-Path $root "vendor/auto-artifactarium"
$patches = @(
    (Join-Path $root "patches/auto-artifactarium-web-time.patch"),
    (Join-Path $root "patches/auto-artifactarium-mora.patch")
)

$targetManifest = Join-Path $target "Cargo.toml"
$targetKcp = Join-Path $target "src/kcp.rs"
$targetLib = Join-Path $target "src/lib.rs"

if ((Test-Path $targetManifest) -and -not $Force) {
    $webTimePatched =
        Select-String -Path $targetKcp -Pattern '^use web_time::SystemTime;$' -Quiet
    $moraPatched =
        Select-String -Path $targetLib -Pattern 'matches_player_data_packet' -Quiet

    if (-not ($webTimePatched -and $moraPatched)) {
        throw "vendor/auto-artifactarium exists but is not patched. Re-run with -Force."
    }

    Write-Host "auto-artifactarium is already vendored at $target"
    return
}

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("post-irminsul-aa-" + [guid]::NewGuid().ToString("N"))
$checkout = Join-Path $temporary "auto-artifactarium"

try {
    New-Item -ItemType Directory -Path $temporary | Out-Null

    Write-Host "Fetching auto-artifactarium $revision"
    git clone --quiet $repository $checkout
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to clone $repository"
    }

    git -C $checkout checkout --quiet $revision
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to check out $revision"
    }

    # Apply while this is still the cloned repository. Applying after moving it
    # into gitignored `vendor/` makes git skip the paths.
    foreach ($patch in $patches) {
        Write-Host "Applying $patch"
        git -C $checkout apply $patch
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to apply $patch"
        }
    }

    # The vendor directory only needs the working tree.
    Remove-Item (Join-Path $checkout ".git") -Recurse -Force

    if (Test-Path $target) {
        Remove-Item $target -Recurse -Force
    }
    New-Item -ItemType Directory -Force (Split-Path $target) | Out-Null
    Move-Item $checkout $target
} finally {
    Remove-Item $temporary -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Vendored auto-artifactarium at $target"
