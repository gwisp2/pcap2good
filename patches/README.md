This directory holds patches applied by `scripts/fetch-auto-artifactarium.*`
to the downloaded copy of `auto-artifactarium`. The patched source lives in
`vendor/auto-artifactarium` and is gitignored.

Both patches are applied in the order listed below. The base revision is
`abbbf7a3f58846512250a789a76be2d3cdb115c1` (v1.4.0) from
<https://github.com/konkers/auto-artifactarium>.

## auto-artifactarium-web-time.patch

- `src/kcp.rs` uses `web_time::SystemTime` instead of `std::time::SystemTime`.
  The standard library time APIs panic on `wasm32-unknown-unknown`; `web-time`
  re-exports `std::time` on other targets.
- `Cargo.toml` adds the `web-time` dependency.

## auto-artifactarium-mora.patch

Taken from <https://github.com/konkers/auto-artifactarium/pull/2> (not merged
upstream at the time of writing).

- Adds the `PropMapEntry` protobuf message.
- Adds `matches_player_prop_map` / `matches_player_data_packet`, which locate
  the player property map by content rather than by command id or field number.
  The map includes `PROP_PLAYER_SCOIN` (Mora).

Re-fetch and re-apply with:

```console
$ ./scripts/fetch-auto-artifactarium.ps1 -Force
```

or, on other platforms:

```console
$ ./scripts/fetch-auto-artifactarium.sh --force
```
