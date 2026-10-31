#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
revision="abbbf7a3f58846512250a789a76be2d3cdb115c1"
repository="https://github.com/konkers/auto-artifactarium"
target="$root/vendor/auto-artifactarium"
patch="$root/patches/auto-artifactarium-web-time.patch"

force=false
if [[ "${1:-}" == "--force" ]]; then
    force=true
fi

if [[ -f "$target/Cargo.toml" && "$force" == false ]]; then
    if ! grep -q '^use web_time::SystemTime;$' "$target/src/kcp.rs"; then
        echo "vendor/auto-artifactarium exists but is not patched. Re-run with --force." >&2
        exit 1
    fi

    echo "auto-artifactarium is already vendored at $target"
    exit 0
fi

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

echo "Fetching auto-artifactarium $revision"
git clone --quiet "$repository" "$temporary/auto-artifactarium"
git -C "$temporary/auto-artifactarium" checkout --quiet "$revision"

# Apply while this is still the cloned repository. Applying after moving it
# into gitignored `vendor/` makes git skip the paths.
echo "Applying $patch"
git -C "$temporary/auto-artifactarium" apply "$patch"

# The vendor directory only needs the working tree.
rm -rf "$temporary/auto-artifactarium/.git"

rm -rf "$target"
mkdir -p "$(dirname "$target")"
mv "$temporary/auto-artifactarium" "$target"

echo "Vendored auto-artifactarium at $target"
