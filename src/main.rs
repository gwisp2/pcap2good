//! Offline counterpart to Irminsul: reads a Genshin Impact packet capture and
//! writes the player's characters, weapons and artifacts to stdout as GOOD
//! data.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{ArgAction, Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use post_irminsul::decode_capture_file;
use post_irminsul::player_data::ExportSettings;

#[derive(Debug, Parser)]
#[command(
    name = "postirminsul",
    version,
    about = "Extract Genshin Impact player data from a packet capture",
    long_about = "Extract Genshin Impact characters, weapons and artifacts from a .pcap or \
                  .pcapng capture and write them to stdout as GOOD data.\n\n\
                  The capture must include the game's connection handshake, so start capturing \
                  before Genshin Impact is launched or before logging in."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Decode a packet capture and write GOOD data to stdout
    Decode(DecodeArgs),
}

#[derive(Debug, Args)]
struct DecodeArgs {
    /// Path to the .pcap or .pcapng file to decode
    path: PathBuf,

    /// Write every decoded command to this directory as .bin and .json
    #[arg(long, value_name = "DIR")]
    dump_commands: Option<PathBuf>,

    #[command(flatten)]
    export: ExportArgs,
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// Pretend that unactivated fourth substats have already rolled
    #[arg(long)]
    fake_initialize_4th_line: bool,

    /// Write compact JSON instead of indented JSON
    #[arg(long)]
    compact: bool,
}

impl ExportArgs {
    fn settings(&self) -> ExportSettings {
        ExportSettings {
            fake_initialize_4th_line: self.fake_initialize_4th_line,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Decode(args) => decode(args),
    }
}

fn decode(args: DecodeArgs) -> Result<()> {
    let compact = args.export.compact;
    let settings = args.export.settings();
    let outcome = decode_capture_file(&args.path, &settings, args.dump_commands)?;

    let json = if compact {
        serde_json::to_string(&outcome.good)?
    } else {
        serde_json::to_string_pretty(&outcome.good)?
    };

    match write_output(&json) {
        // The reader closed the pipe (e.g. `| head`); nothing left to do.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
        result => result?,
    }

    eprintln!(
        "Read {} packets ({} on game ports), decoded {} commands",
        outcome.capture.packets, outcome.capture.game_packets, outcome.decode.commands
    );
    eprintln!(
        "Exported {} characters, {} artifacts, {} weapons",
        outcome.good.characters.len(),
        outcome.good.artifacts.len(),
        outcome.good.weapons.len()
    );

    for warning in &outcome.warnings {
        eprintln!("warning: {}", warning.message);
        if let Some(hint) = &warning.hint {
            eprintln!("         {hint}");
        }
    }

    Ok(())
}

/// Writes the export to stdout, ending with a newline.
fn write_output(json: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(json.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn init_tracing(verbosity: u8) {
    // Keep the default output clean: the packet sniffer logs internal errors
    // for every packet it cannot decrypt, which is expected when a capture
    // contains traffic from before the handshake.
    let default_filter = match verbosity {
        0 => "warn,auto_artifactarium=off,post_irminsul=info",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_target(false)
        .without_time()
        .init();
}
