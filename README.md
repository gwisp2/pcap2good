# pcap2good

Offline counterpart to [Irminsul](https://github.com/konkers/irminsul): instead of
sniffing live game traffic, it reads a packet capture from disk and prints the
player's characters, weapons and artifacts as [GOOD](https://frzyc.github.io/genshin-optimizer/#/doc)
v3 data, on stdout or in a file.

```console
$ pcap2good decode path/to/capture.pcap
{
  "format": "GOOD",
  "version": 3,
  "source": "pcap2good",
  "characters": [ ... ],
  "artifacts": [ ... ],
  "weapons": [ ... ],
  "materials": { ... }
}
```

Unless `--out` is used, only the JSON document is written to stdout. Progress,
warnings and errors go to stderr, so the output can be piped or redirected:

```console
$ pcap2good decode capture.pcap --out good.json
$ pcap2good decode capture.pcap > good.json
$ pcap2good decode capture.pcap | jq '.artifacts | length'
```

When the capture contains a player property update, the player's Mora balance is
exported in `materials` as `Mora`.

## Capturing

The capture must contain the connection handshake with the game server, since
the encryption key for the rest of the session is negotiated there. In practice
that means starting the capture **before** launching Genshin Impact, or before
logging in.

Genshin communicates over **UDP ports 22101 and 22102**.

```console
# Linux
$ sudo tcpdump -i any -w capture.pcap 'udp portrange 22101-22102'

# Windows (Npcap must be installed)
$ tshark -i "Ethernet" -f "udp portrange 22101-22102" -w capture.pcap
```

Captures taken with Wireshark's "any" interface or `tcpdump -i any` use the
Linux "cooked" link type; that is supported, as are ordinary Ethernet captures,
pcapng files, raw IP and BSD loopback captures.

Decryption starts from a table of dispatch keys. Those keys live in
[`keys/gi.json`](keys/gi.json) and are the same table Irminsul ships. If a
capture cannot be decrypted (for example after the game rotates its keys),
update that file from upstream Irminsul and rebuild.

## Options

| Option | Description |
| --- | --- |
| `-o`, `--out <FILE>` | Write the GOOD data to `<FILE>` instead of stdout |
| `--fake-initialize-4th-line` | Pretend unactivated fourth substats have already rolled |
| `--compact` | Single-line JSON instead of indented JSON |
| `--dump-commands <DIR>` | Write every decoded command to a directory as `<NNNN>-<id>.bin` and `<NNNN>-<id>.json` (for debugging) |
| `-v`, `-vv`, `-vvv` | Info, debug and trace logging on stderr |

Every character, artifact, weapon and material in the capture is exported.

With `--dump-commands`, every command produces two files: the raw payload as
`<NNNN>-<id>.bin` and a schema-less JSON rendering as `<NNNN>-<id>.json`.
Because the game's protobuf schemas are not available to this tool, the JSON
mirrors the wire format: object keys are field numbers, fields that occur more
than once become arrays, and length-delimited fields are decoded as nested
messages when possible, otherwise as text or base64. The header and body are
decoded separately:

```json
{
  "header": { "3": 1, "6": 1793150966255 },
  "body": { "7": { "1": 10000061, "2": 100 } }
}
```

If the capture does not contain any character or inventory packets, the command
still prints a valid (empty) GOOD document and writes a warning to stderr. This
usually means the capture started too late to see the handshake.

## Known limitations

The packet pipeline itself is implemented in this crate. Only a few low-level
pieces are partially embedded from [`auto-artifactarium`], the decoder Irminsul
uses, so limitations of that decoder still apply where those pieces are used.

After the login exchange the game encrypts its traffic with a session key, which
the decoder derives from the login response. Some Genshin Impact 7.1 sessions get
that response compressed with Oodle Network TCP, which the decoder does not
decompress, so the session key is never derived and only the handful of login
commands that use the dispatch key can be read. The CLI reports this as:

```
warning: the game compressed its login response (Oodle Network TCP), which this decoder cannot decompress
         the session key could not be derived; re-capture the session (the login response is not always compressed)
```

The compression is not deterministic: in a working session the same login
response arrives as a plain 25 576-byte protobuf body (25 585 bytes including
its 9-byte header), while a failing session carries the same message compressed
to 20 071 bytes with the decompressed size in header field 8. Re-capturing
usually produces the uncompressed variant.

This affects Irminsul itself as well; it is tracked upstream in
[konkers/irminsul#160](https://github.com/konkers/irminsul/issues/160) and
[konkers/irminsul#163](https://github.com/konkers/irminsul/issues/163). Nothing
is wrong with the capture file when this happens — and captures whose login
response is not compressed decode normally.

[`auto-artifactarium`]: https://github.com/konkers/auto-artifactarium

## Packet pipeline

The packet pipeline lives in [`src/pipeline`](src/pipeline). It splits the
capture into link-layer, UDP, KCP, decryption, command-framing and consumer
stages, and keeps separate state for every game flow found in a capture.

The upstream [`auto-artifactarium`] crate is not used as a dependency. Some of
its low-level pieces are partially embedded in the
[`auto_artifactarium`](src/auto_artifactarium) module instead: the generated
protobuf types and a few cryptographic/seed helpers adapted from upstream
revision `abbbf7a3f58846512250a789a76be2d3cdb115c1` (v1.4.0). The pipeline,
KCP handling and command framing are implemented here; player-data matching uses
those embedded helpers.

The protobuf definitions live in
[`src/auto_artifactarium/protos.proto`](src/auto_artifactarium/protos.proto).
`build.rs` regenerates the Rust bindings into `OUT_DIR` whenever that file
changes, so `cargo build` / `cargo check` is all that is needed after editing it.

## Building

Rust 1.88 or newer is required.

The build needs one local dependency, which is not committed:
[Dimbreath's AnimeGameData][anime-game-data] dump under `3rdparty/AnimeGameData`
(a symlink or junction to an existing checkout works).

```console
$ ./scripts/fetch-game-data.ps1              # or .sh on other platforms
$ cargo build --release
```

The script downloads only the 12 files the build reads (about 25 MB); a full
AnimeGameData checkout moved or linked to `3rdparty/AnimeGameData` works too.

The build reads names, artifact sets, affixes and related tables from the data
directory and embeds them in the binary, so decoding itself works fully
offline. The directory is gitignored; update it and rebuild when the game data
changes.

```console
$ cargo test
```

[anime-game-data]: https://gitlab.com/Dimbreath/animegamedata2

## Web wrapper

A static browser front end lives in [`web/`](web). It runs the decoder in a Web
Worker via WebAssembly, so the capture never leaves the machine and the page can
be served from any static file host. The **How to make a capture?** button under
the drop zone opens `web/guide.png` in a pan and zoom viewer.

```console
# The CLI version must match the wasm-bindgen crate in Cargo.lock.
$ cargo install wasm-bindgen-cli --version 0.2.129
$ ./web/build.ps1
$ python -m http.server 8000 -d web
```

Open <http://localhost:8000>. On other platforms the build is:

```console
$ ./scripts/fetch-game-data.sh
$ cargo build --release --target wasm32-unknown-unknown --lib
$ wasm-bindgen target/wasm32-unknown-unknown/release/pcap2good.wasm \
      --target web --out-dir web/pkg --out-name pcap2good
```

`web/pkg` is generated and gitignored. The page needs a real HTTP server (ES
modules and `fetch` do not work from `file://`).

## Deploying to GitHub Pages

GitHub Pages only serves static files, so the wasm package is built in CI. The
[`pages` workflow](.github/workflows/pages.yml) does this on every push:

1. Push the repository to GitHub.
2. Open **Settings → Pages → Build and deployment** and set **Source** to
   **GitHub Actions**.
3. Push to `main` or `master`, or run **Deploy web wrapper** from the Actions
   tab.

The site is served at `https://<user>.github.io/<repo>/`. The workflow fetches
the pinned game data, installs the matching `wasm-bindgen-cli`, builds
`web/pkg`, and deploys `web/`.

Nothing generated or machine-specific is committed: `3rdparty/`, `target/` and
`web/pkg/` are gitignored. If your default branch is neither `main` nor
`master`, update the `on.push.branches` list in the workflow.

## Differences from Irminsul

- Reads a capture file instead of capturing live traffic; no admin/root rights
  and no Npcap/pktmon dependency to decode.
- Command line plus a static in-browser (WASM) front end; no live capture,
  update checker, achievements or wish history.
- Handles `.pcap` and `.pcapng` files with legacy pcap and pcapng sections.

## License

MIT. Much of the decoding and GOOD export logic is adapted from
[Irminsul](https://github.com/konkers/irminsul), Copyright (c) 2025 Erik Gilling,
which is also MIT licensed. See [LICENSE](LICENSE).
