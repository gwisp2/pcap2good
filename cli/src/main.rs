//! Offline counterpart to Irminsul: reads a Genshin Impact packet capture and
//! writes the player's characters, weapons and artifacts to stdout or a file as
//! GOOD data.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use pcap2good_core::decode_capture_file;

#[derive(Debug, Parser)]
#[command(
    name = "pcap2good",
    version,
    about = "Extract Genshin Impact player data from a packet capture",
    long_about = "Extract Genshin Impact characters, weapons and artifacts from a .pcap or \
                  .pcapng capture and write them to stdout or to a file as GOOD data.\n\n\
                  Completed achievements are extracted separately with --achievements.\n\n\
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
    /// Decode a packet capture and write GOOD data to stdout or a file
    Decode(DecodeArgs),
}

#[derive(Debug, Args)]
struct DecodeArgs {
    /// Path to the .pcap or .pcapng file to decode
    path: PathBuf,

    /// Write the GOOD data to this file instead of stdout
    #[arg(short, long, value_name = "FILE")]
    out: Option<PathBuf>,

    /// Write completed achievements to this JSON file
    #[arg(long, value_name = "FILE")]
    achievements: Option<PathBuf>,

    /// Write every decoded command to this directory as .bin and .json
    #[arg(long, value_name = "DIR")]
    dump_commands: Option<PathBuf>,

    #[command(flatten)]
    export: ExportArgs,
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// Write compact JSON instead of indented JSON
    #[arg(long)]
    compact: bool,
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
    let outcome = decode_capture_file(&args.path, args.dump_commands)?;

    if let Some(path) = &args.achievements {
        let achievements = if compact {
            serde_json::to_string(&outcome.achievements)?
        } else {
            serde_json::to_string_pretty(&outcome.achievements)?
        };
        write_file(path, &achievements)?;
    }

    let json = if compact {
        serde_json::to_string(&outcome.good)?
    } else {
        serde_json::to_string_pretty(&outcome.good)?
    };

    if let Some(path) = &args.out {
        write_file(path, &json)?;
    } else {
        match write_json(&mut io::stdout().lock(), &json) {
            // The reader closed the pipe (e.g. `| head`); nothing left to do.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
            result => result?,
        }
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
    eprintln!(
        "Achievements: {} completed",
        outcome.achievements.gi_achievements.len()
    );

    for warning in &outcome.warnings {
        eprintln!("warning: {}", warning.message);
        if let Some(hint) = &warning.hint {
            eprintln!("         {hint}");
        }
    }

    Ok(())
}

/// Writes the export to a file, ending with a newline.
fn write_file(path: &Path, json: &str) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create output file {}", path.display()))?;
    let mut writer = BufWriter::new(file);

    write_json(&mut writer, json)
        .with_context(|| format!("Failed to write output file {}", path.display()))
}

/// Writes the export to `writer`, ending with a newline.
fn write_json(writer: &mut impl Write, json: &str) -> io::Result<()> {
    writeln!(writer, "{json}")?;
    writer.flush()
}

fn init_tracing(verbosity: u8) {
    // Keep the default output clean: the packet sniffer logs internal errors
    // for every packet it cannot decrypt, which is expected when a capture
    // contains traffic from before the handshake.
    let default_filter = match verbosity {
        0 => "warn,pcap2good_core::auto_artifactarium=off,pcap2good_core=info",
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
