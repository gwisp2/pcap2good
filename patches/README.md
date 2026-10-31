This directory holds patches applied by `scripts/fetch-auto-artifactarium.*`
to the downloaded copy of `auto-artifactarium`. The patched source lives in
`vendor/auto-artifactarium` and is gitignored.

## auto-artifactarium-web-time.patch

- Upstream: <https://github.com/konkers/auto-artifactarium>
- Revision: `abbbf7a3f58846512250a789a76be2d3cdb115c1` (v1.4.0)
- Changes:
  - `src/kcp.rs` uses `web_time::SystemTime` instead of `std::time::SystemTime`.
    The standard library time APIs panic on `wasm32-unknown-unknown`;
    `web-time` re-exports `std::time` on other targets.
  - `Cargo.toml` adds the `web-time` dependency.

Re-fetch and re-apply with:

```console
$ ./scripts/fetch-auto-artifactarium.ps1 -Force
```

or, on other platforms:

```console
$ ./scripts/fetch-auto-artifactarium.sh --force
```
