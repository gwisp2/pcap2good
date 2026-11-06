//! Native egui front end for the pcap2good decoder.
//!
//! The UI handles capture selection, file decoding, live PktMon capture, export
//! options and presentation. Decoding runs on a worker thread in both modes;
//! live capture publishes statistics and decoded data while it is running.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
#[cfg(windows)]
use pcap2good_core::decode::Decoder;
#[cfg(windows)]
use pcap2good_core::pipeline::{CapturedFrame, LinkType, Timestamp};
#[cfg(windows)]
use pcap2good_core::snapshot_outcome;
use pcap2good_core::{DecodeOutcome, WarningCode, decode_capture_file};

const OK: egui::Color32 = egui::Color32::from_rgb(0x6f, 0xd6, 0x8f);
const ERROR: egui::Color32 = egui::Color32::from_rgb(0xf2, 0x8b, 0x82);
const MUTED: egui::Color32 = egui::Color32::from_rgb(0x9a, 0xa4, 0xb2);
const TEXT: egui::Color32 = egui::Color32::from_rgb(0xe7, 0xe9, 0xee);
const WARN: egui::Color32 = egui::Color32::from_rgb(0xf0, 0xc8, 0x7a);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0xd3, 0xa7, 0x5f);
const ON_ACCENT: egui::Color32 = egui::Color32::from_rgb(0x14, 0x17, 0x1c);
const SECONDARY: egui::Color32 = egui::Color32::from_rgb(0x3a, 0x41, 0x4b);
const CARD_BG: egui::Color32 = egui::Color32::from_rgb(0x1b, 0x20, 0x27);
const OK_BORDER: egui::Color32 = egui::Color32::from_rgb(0x3b, 0x6d, 0x49);
const ERROR_BORDER: egui::Color32 = egui::Color32::from_rgb(0x6d, 0x3f, 0x3a);

enum Status {
    Idle,
    Decoding,
    Decoded(Duration),
    LiveDecoded(Duration),
    Error(String),
    Saved,
    SavedAchievements,
}

struct LiveUpdate {
    elapsed: Duration,
    outcome: DecodeOutcome,
}

enum LiveMessage {
    Finished(Box<LiveUpdate>),
    Failed(String),
}

struct LiveSession {
    stop: Arc<AtomicBool>,
    /// The newest update, replaced by the worker. A plain channel would queue
    /// every update when the window is not repainting.
    shared_latest: Arc<Mutex<Option<LiveUpdate>>>,
    rx: mpsc::Receiver<LiveMessage>,
    handle: Option<std::thread::JoinHandle<()>>,
    started: Instant,
    latest: Option<LiveUpdate>,
    stopping: bool,
    show_debug: bool,
}

impl Drop for LiveSession {
    fn drop(&mut self) {
        // Stop the worker and wait for it to finish so PktMon's driver and
        // session are released even when the window is closed mid-capture.
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct Pcap2GoodApp {
    selected: Option<PathBuf>,
    selected_size: u64,
    outcome: Option<DecodeOutcome>,
    json: String,
    status: Status,
    decode_rx: Option<mpsc::Receiver<Result<DecodeOutcome, String>>>,
    started: Option<Instant>,
    live: Option<LiveSession>,
    live_elapsed: Option<Duration>,
}

impl Pcap2GoodApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);

        let mut app = Self {
            selected: None,
            selected_size: 0,
            outcome: None,
            json: String::new(),
            status: Status::Idle,
            decode_rx: None,
            started: None,
            live: None,
            live_elapsed: None,
        };

        if let Some(arg) = std::env::args_os().nth(1) {
            if arg.to_str() == Some("--live") {
                app.start_live(&cc.egui_ctx);
            } else {
                app.open_capture(PathBuf::from(arg), &cc.egui_ctx);
            }
        }

        app
    }

    fn is_decoding(&self) -> bool {
        self.decode_rx.is_some()
    }

    fn is_capturing(&self) -> bool {
        self.live.is_some()
    }

    fn is_busy(&self) -> bool {
        self.is_decoding() || self.is_capturing()
    }

    fn select_capture(&mut self, path: PathBuf) -> bool {
        if self.is_busy() {
            return false;
        }

        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default();
        if !extension.eq_ignore_ascii_case("pcap") && !extension.eq_ignore_ascii_case("pcapng") {
            self.status = Status::Error(format!(
                "{} is not a .pcap or .pcapng capture",
                path.display()
            ));
            return false;
        }

        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                self.selected_size = metadata.len();
                self.selected = Some(path);
                self.outcome = None;
                self.json.clear();
                self.status = Status::Idle;
                self.live_elapsed = None;
                true
            }
            Ok(_) => {
                self.status = Status::Error(format!("{} is not a file", path.display()));
                false
            }
            Err(error) => {
                self.status = Status::Error(format!("Failed to read {}: {error}", path.display()));
                false
            }
        }
    }

    fn open_capture(&mut self, path: PathBuf, ctx: &egui::Context) {
        if self.select_capture(path) {
            self.start_decode(ctx);
        }
    }

    fn open_capture_dialog(&mut self, ctx: &egui::Context) {
        if self.is_busy() {
            return;
        }

        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open a packet capture")
            .add_filter("Packet captures", &["pcap", "pcapng"])
            .pick_file()
        {
            self.open_capture(path, ctx);
        }
    }

    fn save_dialog(&mut self) {
        if self.json.is_empty() {
            return;
        }

        let suggested = self
            .selected
            .as_ref()
            .and_then(|path| path.file_stem())
            .map(|stem| format!("{}.good.json", stem.to_string_lossy()))
            .unwrap_or_else(|| {
                if self.live_elapsed.is_some() {
                    "live-capture.good.json".to_owned()
                } else {
                    "good.json".to_owned()
                }
            });

        if let Some(path) = rfd::FileDialog::new()
            .set_title("Save GOOD data")
            .add_filter("GOOD JSON", &["json"])
            .set_file_name(suggested)
            .save_file()
        {
            let contents = format!("{}\n", self.json);
            match std::fs::write(&path, contents) {
                Ok(()) => self.status = Status::Saved,
                Err(error) => {
                    self.status =
                        Status::Error(format!("Failed to write {}: {error}", path.display()));
                }
            }
        }
    }

    fn save_achievements_dialog(&mut self) {
        let Some(outcome) = &self.outcome else {
            return;
        };
        if outcome.achievements.gi_achievements.is_empty() {
            return;
        }

        let suggested = self
            .selected
            .as_ref()
            .and_then(|path| path.file_stem())
            .map(|stem| format!("{}.achievements.json", stem.to_string_lossy()))
            .unwrap_or_else(|| {
                if self.live_elapsed.is_some() {
                    "live-capture.achievements.json".to_owned()
                } else {
                    "achievements.json".to_owned()
                }
            });
        let contents = match serde_json::to_string_pretty(&outcome.achievements) {
            Ok(contents) => format!("{contents}\n"),
            Err(error) => {
                self.status = Status::Error(format!("Failed to encode achievements: {error}"));
                return;
            }
        };

        if let Some(path) = rfd::FileDialog::new()
            .set_title("Save achievements")
            .add_filter("Achievements JSON", &["json"])
            .set_file_name(suggested)
            .save_file()
        {
            match std::fs::write(&path, contents) {
                Ok(()) => self.status = Status::SavedAchievements,
                Err(error) => {
                    self.status =
                        Status::Error(format!("Failed to write {}: {error}", path.display()));
                }
            }
        }
    }

    fn start_decode(&mut self, ctx: &egui::Context) {
        if self.is_busy() {
            return;
        }
        let Some(path) = self.selected.clone() else {
            return;
        };

        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();

        self.outcome = None;
        self.json.clear();
        self.status = Status::Decoding;
        self.started = Some(Instant::now());
        self.decode_rx = Some(rx);

        std::thread::spawn(move || {
            let result = decode_capture_file(&path, None).map_err(|error| format!("{error:#}"));
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }

    fn poll_decode(&mut self, ctx: &egui::Context) {
        let received = self.decode_rx.as_ref().map(|rx| rx.try_recv());

        match received {
            None | Some(Err(TryRecvError::Empty)) => {}
            Some(Err(TryRecvError::Disconnected)) => {
                self.decode_rx = None;
                self.started = None;
                self.status = Status::Error("The decoder thread stopped unexpectedly.".to_owned());
            }
            Some(Ok(Err(message))) => {
                self.decode_rx = None;
                self.started = None;
                self.status = Status::Error(message);
            }
            Some(Ok(Ok(outcome))) => {
                self.decode_rx = None;
                let elapsed = self
                    .started
                    .take()
                    .map(|started| started.elapsed())
                    .unwrap_or_default();
                self.json = serde_json::to_string_pretty(&outcome.good).unwrap_or_default();
                self.outcome = Some(outcome);
                self.status = Status::Decoded(elapsed);
            }
        }

        if self.is_decoding() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn start_live(&mut self, ctx: &egui::Context) {
        if self.is_busy() {
            return;
        }

        #[cfg(not(windows))]
        {
            let _ = ctx;
            self.status = Status::Error("Live capture is only available on Windows.".to_owned());
        }

        #[cfg(windows)]
        {
            if !is_elevated() {
                match relaunch_as_admin() {
                    Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                    Err(error) => self.status = Status::Error(error),
                }
                return;
            }

            let (tx, rx) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let shared_latest = Arc::new(Mutex::new(None));
            let started = Instant::now();

            self.selected = None;
            self.selected_size = 0;
            self.outcome = None;
            self.json.clear();
            self.status = Status::Idle;
            self.live_elapsed = None;

            let ctx = ctx.clone();
            let stop_clone = stop.clone();
            let latest_clone = shared_latest.clone();
            let handle = std::thread::spawn(move || {
                if let Err(error) =
                    capture_live(ctx.clone(), tx.clone(), stop, latest_clone, started)
                {
                    let _ = tx.send(LiveMessage::Failed(error));
                    ctx.request_repaint();
                }
            });

            self.live = Some(LiveSession {
                stop: stop_clone,
                shared_latest,
                rx,
                handle: Some(handle),
                started,
                latest: None,
                stopping: false,
                show_debug: false,
            });
        }
    }

    fn stop_live(&mut self) {
        if let Some(session) = &mut self.live {
            session.stop.store(true, Ordering::Relaxed);
            session.stopping = true;
        }
    }

    fn poll_live(&mut self, ctx: &egui::Context) {
        let mut finished = None;
        let mut disconnected = false;

        if let Some(session) = &mut self.live {
            if let Ok(mut slot) = session.shared_latest.lock()
                && let Some(update) = slot.take()
            {
                session.latest = Some(update);
            }

            match session.rx.try_recv() {
                Ok(LiveMessage::Finished(update)) => finished = Some(Ok(*update)),
                Ok(LiveMessage::Failed(error)) => finished = Some(Err(error)),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => disconnected = true,
            }
        }

        if let Some(result) = finished {
            self.live = None;
            match result {
                Ok(update) => {
                    self.json =
                        serde_json::to_string_pretty(&update.outcome.good).unwrap_or_default();
                    self.outcome = Some(update.outcome);
                    self.live_elapsed = Some(update.elapsed);
                    self.status = Status::LiveDecoded(update.elapsed);
                }
                Err(error) => self.status = Status::Error(error),
            }
        } else if disconnected {
            self.live = None;
            self.status = Status::Error("The live capture thread stopped unexpectedly.".to_owned());
        }

        if self.is_capturing() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|input| input.raw.dropped_files.clone());
        if let Some(file) = dropped.into_iter().next() {
            if let Some(path) = file.path {
                self.open_capture(path, ctx);
            } else {
                self.status =
                    Status::Error("Could not read the path of the dropped file.".to_owned());
            }
        }
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let (open, save) = ctx.input_mut(|input| {
            (
                input.consume_key(egui::Modifiers::COMMAND, egui::Key::O),
                input.consume_key(egui::Modifiers::COMMAND, egui::Key::S),
            )
        });

        if open {
            self.open_capture_dialog(ctx);
        }
        if save {
            self.save_dialog();
        }
    }

    fn status_info(&self) -> (String, egui::Color32) {
        match &self.status {
            Status::Idle => ("Ready to decode.".to_owned(), MUTED),
            Status::Decoding => ("Decoding...".to_owned(), TEXT),
            Status::Decoded(elapsed) => {
                let mut text = format!("Decoded in {:.1}s.", elapsed.as_secs_f32());
                if let Some(outcome) = &self.outcome {
                    text.push_str(&format!(
                        "  {} · {} · {} · {}",
                        plural(outcome.capture.packets, "packet", "packets"),
                        plural(outcome.capture.game_packets, "game packet", "game packets"),
                        plural(outcome.decode.commands, "command", "commands"),
                        plural(outcome.flows.len() as u64, "flow", "flows")
                    ));
                }
                (text, OK)
            }
            Status::LiveDecoded(elapsed) => {
                let mut text = format!("Captured live for {:.1}s.", elapsed.as_secs_f32());
                if let Some(outcome) = &self.outcome {
                    text.push_str(&format!(
                        "  {} · {} · {}",
                        plural(outcome.capture.packets, "packet", "packets"),
                        plural(outcome.decode.commands, "command", "commands"),
                        plural(outcome.flows.len() as u64, "flow", "flows")
                    ));
                }
                (text, OK)
            }
            Status::Error(message) => (message.clone(), ERROR),
            Status::Saved => ("Saved GOOD JSON.".to_owned(), OK),
            Status::SavedAchievements => ("Saved achievements.".to_owned(), OK),
        }
    }

    fn render_start(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(24.0);
                ui.heading("pcap2good");
                ui.label(egui::RichText::new("GOOD extractor for packet captures").weak());
                ui.add_space(24.0);

                let live = egui::Button::new(
                    egui::RichText::new("Live capture")
                        .size(20.0)
                        .color(ON_ACCENT),
                )
                .fill(ACCENT)
                .min_size(egui::vec2(340.0, 56.0));

                #[cfg(windows)]
                {
                    let response = ui.add(live).on_hover_text(
                        "Capture Genshin Impact traffic through the Windows PktMon service. \
                         Administrator rights are requested if needed.",
                    );
                    if response.clicked() {
                        self.start_live(ctx);
                    }
                }

                #[cfg(not(windows))]
                {
                    let _ = ui
                        .add_enabled(false, live)
                        .on_disabled_hover_text("Live capture is only available on Windows.");
                }

                ui.add_space(10.0);
                let load = egui::Button::new(
                    egui::RichText::new("Load capture file")
                        .size(18.0)
                        .color(TEXT),
                )
                .fill(SECONDARY)
                .min_size(egui::vec2(340.0, 50.0));
                if ui.add(load).clicked() {
                    self.open_capture_dialog(ctx);
                }

                if let Status::Error(message) = &self.status {
                    ui.add_space(10.0);
                    ui.add(egui::Label::new(egui::RichText::new(message).color(ERROR)).wrap());
                }

                ui.add_space(14.0);
                ui.label(
                    egui::RichText::new(
                        "The capture must include the login handshake; for live capture, start \
                         before launching Genshin Impact.",
                    )
                    .small()
                    .weak(),
                );
                ui.label(
                    egui::RichText::new(
                        "Everything is decoded locally; the capture is never uploaded.",
                    )
                    .small()
                    .weak(),
                );
            });
        });
    }

    fn reset_to_start(&mut self) {
        if self.is_busy() {
            return;
        }

        self.selected = None;
        self.selected_size = 0;
        self.outcome = None;
        self.json.clear();
        self.live_elapsed = None;
        self.status = Status::Idle;
    }

    fn render_results(&self, ui: &mut egui::Ui, outcome: &DecodeOutcome) -> (bool, bool) {
        let mut open_another = false;
        let mut start_over = false;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let title = if self.live_elapsed.is_some() {
                "Live capture complete"
            } else {
                "Decoding complete"
            };
            ui.heading(title);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Open another capture").clicked() {
                    open_another = true;
                }
                if ui.small_button("Start over").clicked() {
                    start_over = true;
                }
            });
        });

        if let Some(path) = &self.selected {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());
            ui.horizontal(|ui| {
                let response = ui.label(egui::RichText::new(name).strong());
                let _ = response.on_hover_text(path.display().to_string());
                ui.label(egui::RichText::new(format_bytes(self.selected_size)).weak());
            });
        } else if let Some(elapsed) = self.live_elapsed {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Live capture").strong());
                ui.label(
                    egui::RichText::new(format!("captured for {:.1}s", elapsed.as_secs_f32()))
                        .weak(),
                );
            });
        }

        ui.add_space(4.0);
        summary_grid(ui, outcome);

        if !outcome.warnings.is_empty() {
            ui.add_space(8.0);
            for warning in &outcome.warnings {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(WARN, "⚠");
                        ui.add(egui::Label::new(warning.message.as_str()).wrap());
                    });
                    if let Some(hint) = &warning.hint {
                        ui.label(egui::RichText::new(hint).small().weak());
                    }
                });
            }
        }

        (open_another, start_over)
    }
}

impl eframe::App for Pcap2GoodApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_live(ctx);
        self.poll_decode(ctx);
        self.handle_dropped_files(ctx);
        self.handle_shortcuts(ctx);

        if self.is_capturing() {
            let mut stop = false;

            egui::TopBottomPanel::bottom("live-controls").show(ctx, |ui| {
                ui.add_space(8.0);

                if let Some(session) = &self.live {
                    let label = if session.stopping {
                        "Stopping..."
                    } else {
                        "Stop live capture"
                    };
                    let button =
                        egui::Button::new(egui::RichText::new(label).size(18.0).color(ON_ACCENT))
                            .fill(ACCENT)
                            .min_size(egui::vec2(ui.available_width(), 46.0));
                    if ui.add_enabled(!session.stopping, button).clicked() {
                        stop = true;
                    }

                    ui.add_space(4.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new(
                                "Capturing UDP 22101-22102 through PktMon; data stays local.",
                            )
                            .small()
                            .weak(),
                        );
                    });
                }

                ui.add_space(6.0);
            });

            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if let Some(session) = &mut self.live {
                            stop |= render_live(ui, session);
                        }
                    });
            });

            if stop {
                self.stop_live();
            }
            return;
        }

        if self.is_decoding() {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(egui::RichText::new("Decoding...").size(22.0));
                });
            });
            return;
        }

        if self.outcome.is_some() {
            let mut open_another = false;
            let mut start_over = false;
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if let Some(outcome) = &self.outcome {
                            let (open, restart) = self.render_results(ui, outcome);
                            open_another |= open;
                            start_over |= restart;
                        }
                    });
            });

            egui::TopBottomPanel::bottom("export").show(ctx, |ui| {
                ui.add_space(8.0);

                let export = egui::Button::new(
                    egui::RichText::new("Export GOOD")
                        .size(18.0)
                        .color(ON_ACCENT),
                )
                .fill(ACCENT)
                .min_size(egui::vec2(ui.available_width(), 46.0));
                if ui.add_enabled(!self.json.is_empty(), export).clicked() {
                    self.save_dialog();
                }

                let achievement_count = self
                    .outcome
                    .as_ref()
                    .map(|outcome| outcome.achievements.gi_achievements.len())
                    .unwrap_or_default();
                if achievement_count > 0 {
                    ui.add_space(4.0);
                    ui.vertical_centered(|ui| {
                        let achievements =
                            egui::Button::new(format!("Export achievements ({achievement_count})"))
                                .small();
                        if ui.add(achievements).clicked() {
                            self.save_achievements_dialog();
                        }
                    });
                }

                let (text, color) = self.status_info();
                let hint = text.clone();
                ui.add_space(4.0);
                ui.vertical_centered(|ui| {
                    let response = ui.add(
                        egui::Label::new(egui::RichText::new(text).small().color(color)).truncate(),
                    );
                    let _ = response.on_hover_text(hint);
                });
                ui.add_space(6.0);
            });

            if start_over {
                self.reset_to_start();
            } else if open_another {
                self.open_capture_dialog(ctx);
            }
            return;
        }

        self.render_start(ctx);
    }
}

fn render_live(ui: &mut egui::Ui, session: &mut LiveSession) -> bool {
    let mut stop = false;

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.heading("Live capture");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if session.stopping {
                ui.add_enabled(false, egui::Button::new("Stopping..."));
            } else if ui.button("Stop capture").clicked() {
                stop = true;
            }
        });
    });

    ui.horizontal(|ui| {
        let (color, label) = if session.stopping {
            (WARN, "Stopping")
        } else {
            (OK, "Capturing")
        };
        ui.colored_label(color, "●");
        ui.label(egui::RichText::new(label).color(TEXT));
        ui.label(
            egui::RichText::new(format!("{:.1}s", session.started.elapsed().as_secs_f32())).weak(),
        );

        if session.show_debug
            && let Some(update) = &session.latest
        {
            let seconds = update.elapsed.as_secs_f32().max(0.001);
            let rate = update.outcome.capture.packets as f32 / seconds;
            ui.label(egui::RichText::new(format!("· {rate:.0} packets/s")).weak());
        }
    });

    ui.add_space(4.0);

    match &session.latest {
        Some(update) => {
            decoded_stats_row(ui, &update.outcome);
            ui.add_space(6.0);
            ui.toggle_value(&mut session.show_debug, "Show debug data");

            if session.show_debug {
                ui.add_space(8.0);
                live_stats_grid(ui, &update.outcome);
            }

            let warnings: Vec<_> = update
                .outcome
                .warnings
                .iter()
                .filter(|warning| {
                    !matches!(
                        warning.code,
                        WarningCode::NoHandshake | WarningCode::NoPlayerData
                    )
                })
                .collect();
            if !warnings.is_empty() {
                ui.add_space(8.0);
                for warning in warnings {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(WARN, "⚠");
                            ui.add(egui::Label::new(warning.message.as_str()).wrap());
                        });
                        if let Some(hint) = &warning.hint {
                            ui.label(egui::RichText::new(hint).small().weak());
                        }
                    });
                }
            }
        }
        None => {
            ui.add_space(16.0);
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("Waiting for game traffic...").size(18.0));
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Start Genshin Impact or log in now; the login handshake is needed to \
                         decrypt the session.",
                    )
                    .small()
                    .weak(),
                );
            });
        }
    }

    stop
}

fn live_stats_grid(ui: &mut egui::Ui, outcome: &DecodeOutcome) {
    let stats = &outcome.decode;
    let entries = [
        ("Packets", outcome.capture.packets.to_string()),
        ("Game packets", outcome.capture.game_packets.to_string()),
        ("Commands", stats.commands.to_string()),
        ("Flows", stats.flows.to_string()),
        ("KCP messages", stats.kcp_messages.to_string()),
        ("Decrypt failures", stats.decryption_failures.to_string()),
        ("Item packets", stats.item_packets.to_string()),
        ("Avatar packets", stats.avatar_packets.to_string()),
        ("Handshakes", stats.handshakes.to_string()),
    ];

    egui::Grid::new("live-stats-grid")
        .num_columns(5)
        .spacing([12.0, 8.0])
        .show(ui, |ui| {
            for (index, (label, value)) in entries.iter().enumerate() {
                packet_stat(ui, label, value);
                if index % 5 == 4 {
                    ui.end_row();
                }
            }
        });
}

fn packet_stat(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.set_min_width(78.0);
        ui.label(egui::RichText::new(label).small().weak());
        ui.label(egui::RichText::new(value).size(16.0).strong());
    });
}

fn decoded_stats_row(ui: &mut egui::Ui, outcome: &DecodeOutcome) {
    let entries = decoded_entries(outcome);
    let width = ((ui.available_width() - 70.0) / 3.0).max(110.0);

    egui::Grid::new("live-decoded-stats")
        .num_columns(3)
        .spacing([8.0, 6.0])
        .show(ui, |ui| {
            for (index, (label, value, found)) in entries.iter().enumerate() {
                extracted_card(ui, label, value, *found, width);
                if index % 3 == 2 {
                    ui.end_row();
                }
            }
        });
}

#[cfg(windows)]
fn capture_live(
    ctx: egui::Context,
    tx: mpsc::Sender<LiveMessage>,
    stop: Arc<AtomicBool>,
    shared_latest: Arc<Mutex<Option<LiveUpdate>>>,
    started: Instant,
) -> Result<(), String> {
    use std::sync::mpsc::RecvTimeoutError;

    use pktmon::filter::{PktMonFilter, TransportProtocol};
    use pktmon::{Capture, PacketPayload};

    let mut capture = Capture::new().map_err(live_error)?;
    for port in [22101u16, 22102u16] {
        capture
            .add_filter(PktMonFilter {
                name: format!("Genshin UDP {port}"),
                port: port.into(),
                transport_protocol: Some(TransportProtocol::UDP),
                ..PktMonFilter::default()
            })
            .map_err(live_error)?;
    }
    capture.start().map_err(live_error)?;

    let mut decoder =
        Decoder::new().map_err(|error| format!("Failed to initialise the decoder: {error:#}"))?;

    let mut last_update = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        match capture.next_packet_timeout(Duration::from_millis(100)) {
            Ok(packet) => {
                let link_type = match &packet.payload {
                    PacketPayload::Ethernet(_) => Some(LinkType(1)),
                    PacketPayload::IP(_) => Some(LinkType(101)),
                    PacketPayload::Unknown(bytes) => {
                        // Some components report raw IP instead of Ethernet.
                        let raw_ip = bytes.first().is_some_and(|byte| matches!(byte >> 4, 4 | 6));
                        Some(LinkType(if raw_ip { 101 } else { 1 }))
                    }
                    // Other component layers (L4 payloads, Wi-Fi frames, ...) do
                    // not contain the Ethernet/IP headers this decoder needs.
                    _ => None,
                };

                if let Some(link_type) = link_type {
                    decoder.process_frame(CapturedFrame {
                        timestamp: Timestamp {
                            micros: u64::try_from(started.elapsed().as_micros())
                                .unwrap_or(u64::MAX),
                        },
                        link_type,
                        data: packet.payload.to_vec().clone(),
                    });
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        if last_update.elapsed() >= Duration::from_millis(250) {
            let update = LiveUpdate {
                elapsed: started.elapsed(),
                outcome: snapshot_outcome(decoder.snapshot()),
            };
            if let Ok(mut slot) = shared_latest.lock() {
                *slot = Some(update);
            }
            ctx.request_repaint();
            last_update = Instant::now();
        }
    }

    let _ = capture.stop();
    let _ = capture.unload();

    let update = LiveUpdate {
        elapsed: started.elapsed(),
        outcome: snapshot_outcome(decoder.snapshot()),
    };
    let _ = tx.send(LiveMessage::Finished(Box::new(update)));
    ctx.request_repaint();

    Ok(())
}

#[cfg(windows)]
fn live_error(error: std::io::Error) -> String {
    let mut message = format!("Failed to start live capture: {error}");
    if !is_elevated() {
        message.push_str(
            "\n\nLive capture uses the Windows PktMon service and needs administrator \
             privileges. Restart pcap2good as administrator.",
        );
    }
    message
}

#[cfg(windows)]
fn is_elevated() -> bool {
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn IsUserAnAdmin() -> i32;
    }

    // SAFETY: IsUserAnAdmin takes no arguments and only inspects the token of
    // the current process.
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(windows)]
fn relaunch_as_admin() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteW(
            hwnd: *mut core::ffi::c_void,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show_cmd: i32,
        ) -> *mut core::ffi::c_void;
    }

    const SW_SHOWNORMAL: i32 = 1;

    let exe =
        std::env::current_exe().map_err(|error| format!("Failed to locate pcap2good: {error}"))?;
    let file: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let operation: Vec<u16> = "runas\0".encode_utf16().collect();
    let parameters: Vec<u16> = "--live\0".encode_utf16().collect();

    // SAFETY: All strings are NUL-terminated and outlive the call. The window
    // handle and working directory are optional and may be null.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    let code = result as isize;
    if code > 32 {
        Ok(())
    } else if code as u32 == 1223 {
        Err("Administrator permission was cancelled.".to_owned())
    } else {
        Err(format!(
            "Failed to relaunch pcap2good as administrator (error {code})."
        ))
    }
}

fn apply_theme(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(0x14, 0x17, 0x1c);
    visuals.window_fill = egui::Color32::from_rgb(0x1c, 0x21, 0x29);
    visuals.extreme_bg_color = egui::Color32::from_rgb(0x1c, 0x21, 0x29);
    visuals.selection.bg_fill = egui::Color32::from_rgb(0xd3, 0xa7, 0x5f);
    visuals.hyperlink_color = egui::Color32::from_rgb(0xf0, 0xc8, 0x7a);
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    ctx.set_style(style);
}

fn summary_grid(ui: &mut egui::Ui, outcome: &DecodeOutcome) {
    let entries = decoded_entries(outcome);
    let width = ((ui.available_width() - 46.0) / 2.0).max(150.0);

    egui::Grid::new("summary-grid")
        .num_columns(2)
        .spacing([10.0, 8.0])
        .show(ui, |ui| {
            for (index, (label, value, found)) in entries.iter().enumerate() {
                extracted_card(ui, label, value, *found, width);
                if index % 2 == 1 {
                    ui.end_row();
                }
            }
        });
}

fn decoded_entries(outcome: &DecodeOutcome) -> [(&'static str, String, bool); 6] {
    let item_types = outcome
        .good
        .materials
        .keys()
        .filter(|name| name.as_str() != "Mora")
        .count();
    let mora = outcome.good.materials.get("Mora").copied().unwrap_or(0);
    let items = match item_types {
        0 => "none".to_owned(),
        1 => "1 type".to_owned(),
        count => format!("{count} types"),
    };
    let characters = outcome.good.characters.len();
    let artifacts = outcome.good.artifacts.len();
    let weapons = outcome.good.weapons.len();
    let achievements = outcome.achievements.gi_achievements.len();

    [
        ("Characters", characters.to_string(), characters > 0),
        ("Artifacts", artifacts.to_string(), artifacts > 0),
        ("Weapons", weapons.to_string(), weapons > 0),
        ("Items", items, item_types > 0),
        ("Mora", mora.to_string(), mora > 0),
        ("Achievements", achievements.to_string(), achievements > 0),
    ]
}

fn extracted_card(ui: &mut egui::Ui, label: &str, value: &str, found: bool, width: f32) {
    let border = if found { OK_BORDER } else { ERROR_BORDER };

    egui::Frame::new()
        .fill(CARD_BG)
        .stroke(egui::Stroke::new(1.0_f32, border))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                extracted_badge(ui, found);
                ui.label(egui::RichText::new(label).size(14.0).color(TEXT));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(value).strong().color(TEXT));
                });
            });
        });
}

fn extracted_badge(ui: &mut egui::Ui, found: bool) {
    let fill = if found { OK } else { ERROR };
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());

    ui.painter().circle_filled(rect.center(), 8.0, fill);

    // Draw the icon instead of relying on a tick/cross glyph being present in
    // the default egui fonts.
    let stroke = egui::Stroke::new(2.0_f32, ON_ACCENT);
    if found {
        let a = rect.lerp_inside(egui::vec2(0.27, 0.52));
        let b = rect.lerp_inside(egui::vec2(0.43, 0.68));
        let c = rect.lerp_inside(egui::vec2(0.73, 0.33));
        ui.painter().line_segment([a, b], stroke);
        ui.painter().line_segment([b, c], stroke);
    } else {
        let a = rect.lerp_inside(egui::vec2(0.32, 0.32));
        let b = rect.lerp_inside(egui::vec2(0.68, 0.68));
        let c = rect.lerp_inside(egui::vec2(0.68, 0.32));
        let d = rect.lerp_inside(egui::vec2(0.32, 0.68));
        ui.painter().line_segment([a, b], stroke);
        ui.painter().line_segment([c, d], stroke);
    }
}

fn plural(count: u64, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;

    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} B")
    } else if value >= 10.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("pcap2good")
        .with_inner_size([550.0, 410.0])
        .with_min_inner_size([480.0, 360.0]);

    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../icon.png")) {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "pcap2good",
        options,
        Box::new(|cc| Ok(Box::new(Pcap2GoodApp::new(cc)))),
    )
}
