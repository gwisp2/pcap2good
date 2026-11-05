//! Native egui front end for the pcap2good decoder.
//!
//! The UI only handles capture selection, export options and presentation; all
//! decoding goes through [`pcap2good::decode_capture_file`] on a worker thread.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;
use pcap2good::{DecodeOutcome, ExportSettings, decode_capture_file};

const OK: egui::Color32 = egui::Color32::from_rgb(0x6f, 0xd6, 0x8f);
const ERROR: egui::Color32 = egui::Color32::from_rgb(0xf2, 0x8b, 0x82);
const MUTED: egui::Color32 = egui::Color32::from_rgb(0x9a, 0xa4, 0xb2);
const TEXT: egui::Color32 = egui::Color32::from_rgb(0xe7, 0xe9, 0xee);
const WARN: egui::Color32 = egui::Color32::from_rgb(0xf0, 0xc8, 0x7a);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0xd3, 0xa7, 0x5f);
const ON_ACCENT: egui::Color32 = egui::Color32::from_rgb(0x14, 0x17, 0x1c);

enum Status {
    Idle,
    Decoding,
    Decoded(Duration),
    Error(String),
    Saved,
    SavedAchievements,
}

struct Pcap2GoodApp {
    selected: Option<PathBuf>,
    selected_size: u64,
    fake_4th_line: bool,
    outcome: Option<DecodeOutcome>,
    json: String,
    status: Status,
    decode_rx: Option<mpsc::Receiver<Result<DecodeOutcome, String>>>,
    started: Option<Instant>,
}

impl Pcap2GoodApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);

        let mut app = Self {
            selected: None,
            selected_size: 0,
            fake_4th_line: false,
            outcome: None,
            json: String::new(),
            status: Status::Idle,
            decode_rx: None,
            started: None,
        };

        if let Some(path) = std::env::args_os().nth(1) {
            app.open_capture(PathBuf::from(path), &cc.egui_ctx);
        }

        app
    }

    fn is_decoding(&self) -> bool {
        self.decode_rx.is_some()
    }

    fn select_capture(&mut self, path: PathBuf) -> bool {
        if self.is_decoding() {
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
        if self.is_decoding() {
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
            .unwrap_or_else(|| "good.json".to_owned());

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
            .unwrap_or_else(|| "achievements.json".to_owned());
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
        if self.is_decoding() {
            return;
        }
        let Some(path) = self.selected.clone() else {
            return;
        };

        let settings = ExportSettings {
            fake_initialize_4th_line: self.fake_4th_line,
        };
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();

        self.outcome = None;
        self.json.clear();
        self.status = Status::Decoding;
        self.started = Some(Instant::now());
        self.decode_rx = Some(rx);

        std::thread::spawn(move || {
            let result =
                decode_capture_file(&path, &settings, None).map_err(|error| format!("{error:#}"));
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
                ui.label(egui::RichText::new("Offline GOOD extractor").weak());
                ui.add_space(24.0);

                let open = egui::Button::new(
                    egui::RichText::new("Open capture file")
                        .size(20.0)
                        .color(ON_ACCENT),
                )
                .fill(ACCENT)
                .min_size(egui::vec2(340.0, 56.0));
                if ui.add(open).clicked() {
                    self.open_capture_dialog(ctx);
                }

                ui.add_space(12.0);
                let live = egui::Button::new(egui::RichText::new("Live capture").size(20.0))
                    .min_size(egui::vec2(340.0, 56.0));
                let _ = ui
                    .add_enabled(false, live)
                    .on_disabled_hover_text("Live capture is not available yet.");

                ui.add_space(14.0);
                ui.checkbox(
                    &mut self.fake_4th_line,
                    egui::RichText::new("Pretend unactivated fourth substats have already rolled")
                        .small(),
                );

                if let Status::Error(message) = &self.status {
                    ui.add_space(10.0);
                    ui.add(egui::Label::new(egui::RichText::new(message).color(ERROR)).wrap());
                }

                ui.add_space(14.0);
                ui.label(
                    egui::RichText::new("The capture must include the login handshake.")
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

    fn render_results(&self, ui: &mut egui::Ui, outcome: &DecodeOutcome) -> bool {
        let mut open_another = false;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Decoding complete");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Open another capture").clicked() {
                    open_another = true;
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

        open_another
    }
}

impl eframe::App for Pcap2GoodApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_decode(ctx);
        self.handle_dropped_files(ctx);
        self.handle_shortcuts(ctx);

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
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if let Some(outcome) = &self.outcome {
                            open_another = self.render_results(ui, outcome);
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

            if open_another {
                self.open_capture_dialog(ctx);
            }
            return;
        }

        self.render_start(ctx);
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

    let entries = [
        ("Characters", outcome.good.characters.len().to_string()),
        ("Artifacts", outcome.good.artifacts.len().to_string()),
        ("Weapons", outcome.good.weapons.len().to_string()),
        ("Items", items),
        ("Mora", mora.to_string()),
        (
            "Achievements",
            outcome.achievements.gi_achievements.len().to_string(),
        ),
    ];

    egui::Grid::new("summary-grid")
        .num_columns(2)
        .spacing([16.0, 8.0])
        .show(ui, |ui| {
            for (index, (label, value)) in entries.iter().enumerate() {
                summary_stat(ui, label, value);
                if index % 2 == 1 {
                    ui.end_row();
                }
            }
        });
}

fn summary_stat(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.set_min_width(100.0);
        ui.label(egui::RichText::new(label).small().weak());
        ui.label(egui::RichText::new(value).size(18.0).strong());
    });
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
