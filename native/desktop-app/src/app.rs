use crate::activation::{ActivationBatch, ActivationChannel};
use crate::model::{DesktopSnapshot, HandleSummary, RequestRecord};
use crate::runtime::{
    add_secret, approve_request, deny_request, fetch_snapshot, open_browser_backup, run_setup,
    validated_console_url, CliRuntime, DesktopSettings,
};
use egui::{
    self, Align, Color32, CornerRadius, Frame, Layout, Margin, RichText, ScrollArea, Stroke,
    TextEdit, Vec2,
};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const BG: Color32 = Color32::from_rgb(8, 14, 25);
const PANEL: Color32 = Color32::from_rgb(15, 24, 40);
const PANEL_SOFT: Color32 = Color32::from_rgb(20, 31, 50);
const BORDER: Color32 = Color32::from_rgb(43, 60, 82);
const TEXT: Color32 = Color32::from_rgb(235, 242, 250);
const MUTED: Color32 = Color32::from_rgb(145, 161, 181);
const CYAN: Color32 = Color32::from_rgb(48, 198, 219);
const GREEN: Color32 = Color32::from_rgb(65, 211, 137);
const AMBER: Color32 = Color32::from_rgb(250, 184, 64);
const RED: Color32 = Color32::from_rgb(247, 106, 114);

const TRAY_OPEN: &str = "s-gw-open";
const TRAY_BROWSER: &str = "s-gw-browser";
const TRAY_QUIT: &str = "s-gw-quit";
const TRAY_ID: &str = "s-gw-tray";
const DEFAULT_SECRET_KIND: &str = "api-token";
const SECRET_KINDS: [&str; 6] = [
    "api-token",
    "password",
    "access-key",
    "private-key",
    "ssh-key",
    "credential",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum View {
    Overview,
    Approvals,
    Credentials,
    Policies,
    Agents,
    Activity,
}

impl View {
    const ALL: [Self; 6] = [
        Self::Overview,
        Self::Approvals,
        Self::Credentials,
        Self::Policies,
        Self::Agents,
        Self::Activity,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Approvals => "Approvals",
            Self::Credentials => "Credentials",
            Self::Policies => "Policies",
            Self::Agents => "Agents",
            Self::Activity => "Activity",
        }
    }

    fn glyph(self) -> &'static str {
        match self {
            Self::Overview => "▦",
            Self::Approvals => "✓",
            Self::Credentials => "◆",
            Self::Policies => "◈",
            Self::Agents => "◎",
            Self::Activity => "↗",
        }
    }
}

enum Work {
    Refresh,
    Approve(String),
    Deny(String),
    AddSecret {
        name: String,
        kind: String,
        inject_env: String,
        value: Zeroizing<String>,
    },
    Setup,
    Browser,
    UpdateConsoleUrl(Url),
}

struct CredentialDialog {
    open: bool,
    name: String,
    kind: String,
    inject_env: String,
    value: Zeroizing<String>,
}

impl Default for CredentialDialog {
    fn default() -> Self {
        Self {
            open: false,
            name: String::new(),
            kind: DEFAULT_SECRET_KIND.into(),
            inject_env: String::new(),
            value: Zeroizing::new(String::new()),
        }
    }
}

impl CredentialDialog {
    fn open(&mut self) {
        self.reset();
        self.open = true;
    }

    fn close(&mut self) {
        self.reset();
        self.open = false;
    }

    fn take_work(&mut self) -> Work {
        self.open = false;
        Work::AddSecret {
            name: std::mem::take(&mut self.name),
            kind: std::mem::replace(&mut self.kind, DEFAULT_SECRET_KIND.into()),
            inject_env: std::mem::take(&mut self.inject_env),
            value: std::mem::take(&mut self.value),
        }
    }

    fn reset(&mut self) {
        self.value.zeroize();
        self.name.clear();
        self.kind.clear();
        self.kind.push_str(DEFAULT_SECRET_KIND);
        self.inject_env.clear();
    }
}

impl Drop for CredentialDialog {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

enum WorkResult {
    Snapshot(Box<Result<DesktopSnapshot, String>>),
    Action(Result<String, String>),
}

pub struct SgwApp {
    work_tx: Sender<Work>,
    result_rx: Receiver<WorkResult>,
    snapshot: Option<DesktopSnapshot>,
    view: View,
    refresh_in_flight: bool,
    last_refresh: Instant,
    error: Option<String>,
    notice: Option<String>,
    tray: Option<TrayIcon>,
    allow_close: bool,
    activation: ActivationChannel,
    initial_activation: Option<ActivationBatch>,
    credential_dialog: CredentialDialog,
}

impl SgwApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        runtime: CliRuntime,
        settings: DesktopSettings,
        activation: ActivationChannel,
        initial_activation: Option<ActivationBatch>,
    ) -> Self {
        configure_style(&cc.egui_ctx);
        let (tray, tray_error) = match build_tray() {
            Ok(tray) => (Some(tray), None),
            Err(error) => (None, Some(error)),
        };
        if settings.background && tray.is_none() {
            cc.egui_ctx
                .send_viewport_cmd(egui::ViewportCommand::Visible(true));
        }
        let (work_tx, result_rx) = start_worker(runtime, settings);
        let mut app = Self {
            work_tx,
            result_rx,
            snapshot: None,
            view: View::Overview,
            refresh_in_flight: false,
            last_refresh: Instant::now(),
            error: None,
            notice: tray_error,
            tray,
            allow_close: false,
            activation,
            initial_activation,
            credential_dialog: CredentialDialog::default(),
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        if self.refresh_in_flight {
            return;
        }
        if self.work_tx.send(Work::Refresh).is_ok() {
            self.refresh_in_flight = true;
            self.last_refresh = Instant::now();
        }
    }

    fn send_action(&mut self, work: Work) -> bool {
        self.error = None;
        self.notice = None;
        if self.work_tx.send(work).is_err() {
            self.error = Some("The desktop worker stopped unexpectedly.".into());
            return false;
        }
        true
    }

    fn drain_results(&mut self) {
        while let Ok(result) = self.result_rx.try_recv() {
            match result {
                WorkResult::Snapshot(result) => match *result {
                    Ok(snapshot) => {
                        self.snapshot = Some(snapshot);
                        self.refresh_in_flight = false;
                        self.error = None;
                    }
                    Err(error) => {
                        self.refresh_in_flight = false;
                        self.error = Some(error);
                    }
                },
                WorkResult::Action(Ok(message)) => {
                    self.notice = Some(message);
                    self.refresh();
                }
                WorkResult::Action(Err(error)) => self.error = Some(error),
            }
        }
    }

    fn process_tray(&mut self, ctx: &egui::Context) {
        pump_linux_tray_events();
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            match event.id.as_ref() {
                TRAY_OPEN => show_window(ctx),
                TRAY_BROWSER => {
                    self.send_action(Work::Browser);
                }
                TRAY_QUIT => {
                    self.close_credential_dialog(ctx);
                    self.allow_close = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                _ => {}
            }
        }
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            let opens = matches!(
                &event,
                TrayIconEvent::Click {
                    id,
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } if id == TRAY_ID
            ) || matches!(&event, TrayIconEvent::DoubleClick { id, .. } if id == TRAY_ID);
            if opens {
                show_window(ctx);
            }
        }
    }

    fn process_activation(&mut self, ctx: &egui::Context) {
        match self.activation.poll() {
            Ok(Some(batch)) => {
                let request = batch.request();
                let should_show = request.should_show_window();
                let accepted = match validated_console_url(request.console_url()) {
                    Ok(url) => self.send_action(Work::UpdateConsoleUrl(url)),
                    Err(error) => {
                        self.error = Some(error);
                        false
                    }
                };
                if should_show {
                    show_window(ctx);
                }
                if accepted {
                    if let Err(error) = batch.acknowledge() {
                        self.error = Some(error);
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                self.error = Some(error);
            }
        }
    }

    fn render(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("navigation")
            .default_size(210.0)
            .min_size(210.0)
            .max_size(210.0)
            .resizable(false)
            .frame(
                Frame::new()
                    .fill(Color32::from_rgb(10, 18, 31))
                    .inner_margin(Margin::symmetric(14, 18)),
            )
            .show(ui, |ui| self.sidebar(ui));
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(BG)
                    .inner_margin(Margin::symmetric(24, 20)),
            )
            .show(ui, |ui| self.main_content(ui));
        self.add_secret_dialog(ui.ctx());
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("S")
                    .size(21.0)
                    .strong()
                    .color(BG)
                    .background_color(CYAN),
            );
            ui.add_space(6.0);
            ui.label(RichText::new("s-gw").size(22.0).strong().color(TEXT));
        });
        ui.label(RichText::new("Credential control").small().color(MUTED));
        ui.add_space(24.0);
        for view in View::ALL {
            let selected = self.view == view;
            let text = format!("{}   {}", view.glyph(), view.label());
            let button = egui::Button::new(
                RichText::new(text)
                    .color(if selected { TEXT } else { MUTED })
                    .size(14.0),
            )
            .fill(if selected {
                PANEL_SOFT
            } else {
                Color32::TRANSPARENT
            })
            .stroke(Stroke::NONE)
            .corner_radius(8.0)
            .min_size(Vec2::new(174.0, 38.0));
            if ui.add(button).clicked() {
                self.view = view;
            }
        }
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.label(
                RichText::new("Browser access is an explicit fallback.")
                    .small()
                    .color(MUTED),
            );
            if ui.button("Open browser backup").clicked() {
                self.send_action(Work::Browser);
            }
            ui.add_space(8.0);
            ui.separator();
        });
    }

    fn main_content(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading(RichText::new(self.view.label()).size(28.0).color(TEXT));
                ui.label(RichText::new(view_subtitle(self.view)).color(MUTED));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Refresh").clicked() {
                    self.refresh();
                }
                if self.refresh_in_flight {
                    ui.spinner();
                }
            });
        });
        ui.add_space(12.0);
        if let Some(message) = self.notice.clone() {
            banner(ui, &message, GREEN);
        }
        if let Some(error) = self.error.clone() {
            banner(ui, &error, RED);
            if self.snapshot.is_none() {
                ui.add_space(10.0);
                if ui.button("Set up local credential storage").clicked() {
                    self.send_action(Work::Setup);
                }
                return;
            }
        }
        ui.add_space(8.0);

        let snapshot = self.snapshot.clone();
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let Some(snapshot) = snapshot.as_ref() else {
                    ui.add_space(80.0);
                    ui.vertical_centered(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Loading local s-gw state…").color(MUTED));
                    });
                    return;
                };
                match self.view {
                    View::Overview => render_overview(ui, snapshot),
                    View::Approvals => self.render_approvals(ui, snapshot),
                    View::Credentials => self.render_credentials(ui, snapshot),
                    View::Policies => render_policies(ui, snapshot),
                    View::Agents => render_agents(ui, snapshot),
                    View::Activity => render_activity(ui, snapshot),
                }
            });
    }

    fn render_approvals(&mut self, ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
        let pending: Vec<_> = snapshot.pending_requests().cloned().collect();
        if pending.is_empty() {
            empty_state(
                ui,
                "No pending approvals",
                "New agent requests will appear here.",
            );
            return;
        }
        for request in pending {
            request_card(ui, &request, |decision| match decision {
                ApprovalDecision::Approve => {
                    self.send_action(Work::Approve(request.id.clone()));
                }
                ApprovalDecision::Deny => {
                    self.send_action(Work::Deny(request.id.clone()));
                }
            });
            ui.add_space(10.0);
        }
    }

    fn render_credentials(&mut self, ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{} local credentials", snapshot.handles.len())).color(MUTED),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Add credential").clicked() {
                    self.open_credential_dialog(ui.ctx());
                }
            });
        });
        ui.add_space(10.0);
        if snapshot.handles.is_empty() {
            empty_state(
                ui,
                "No credentials yet",
                "Add a credential without exposing its value to the UI after save.",
            );
            return;
        }
        for handle in &snapshot.handles {
            credential_card(ui, handle);
            ui.add_space(8.0);
        }
    }

    fn add_secret_dialog(&mut self, ctx: &egui::Context) {
        if !self.credential_dialog.open {
            return;
        }
        let mut open = self.credential_dialog.open;
        let mut should_close = false;
        egui::Window::new("Add credential")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(430.0)
            .show(ctx, |ui| {
                ui.label(RichText::new("Name").color(MUTED));
                ui.text_edit_singleline(&mut self.credential_dialog.name);
                ui.add_space(8.0);
                ui.label(RichText::new("Type").color(MUTED));
                egui::ComboBox::from_id_salt("secret-type")
                    .selected_text(&self.credential_dialog.kind)
                    .show_ui(ui, |ui| {
                        for kind in SECRET_KINDS {
                            ui.selectable_value(
                                &mut self.credential_dialog.kind,
                                kind.into(),
                                kind,
                            );
                        }
                    });
                ui.add_space(8.0);
                ui.label(RichText::new("Environment variable (optional)").color(MUTED));
                ui.text_edit_singleline(&mut self.credential_dialog.inject_env);
                ui.add_space(8.0);
                ui.label(RichText::new("Value").color(MUTED));
                let value = &mut *self.credential_dialog.value;
                if kind_uses_multiline_input(&self.credential_dialog.kind) {
                    ui.add(
                        TextEdit::multiline(value)
                            .id(secret_value_widget_id())
                            .desired_rows(8)
                            .password(true),
                    );
                } else {
                    ui.add(
                        TextEdit::singleline(value)
                            .id(secret_value_widget_id())
                            .password(true),
                    );
                }
                ui.label(
                    RichText::new("The value is sent to the local CLI through stdin.")
                        .small()
                        .color(MUTED),
                );
                ui.add_space(14.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Save credential").clicked() {
                        let work = self.credential_dialog.take_work();
                        self.send_action(work);
                        should_close = true;
                    }
                    if ui.button("Cancel").clicked() {
                        should_close = true;
                    }
                });
            });
        if !open || should_close {
            self.close_credential_dialog(ctx);
            return;
        }
        self.credential_dialog.open = true;
    }

    fn open_credential_dialog(&mut self, ctx: &egui::Context) {
        clear_secret_widget_state(ctx);
        self.credential_dialog.open();
    }

    fn close_credential_dialog(&mut self, ctx: &egui::Context) {
        self.credential_dialog.close();
        clear_secret_widget_state(ctx);
    }
}

impl eframe::App for SgwApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_results();
        self.process_tray(ctx);
        if ctx.input(|input| input.viewport().close_requested()) {
            self.close_credential_dialog(ctx);
            if !self.allow_close && self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else {
                self.allow_close = true;
            }
        }
        if !self.allow_close {
            if let Some(batch) = self.initial_activation.take() {
                if let Err(error) = batch.acknowledge() {
                    self.error = Some(error);
                }
            }
            self.process_activation(ctx);
            if self.last_refresh.elapsed() >= Duration::from_secs(4) {
                self.refresh();
            }
        }
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render(ui);
    }
}

fn start_worker(
    runtime: CliRuntime,
    mut settings: DesktopSettings,
) -> (Sender<Work>, Receiver<WorkResult>) {
    let (work_tx, work_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    thread::spawn(move || {
        while let Ok(work) = work_rx.recv() {
            let result = match work {
                Work::Refresh => {
                    let _ = result_tx.send(WorkResult::Snapshot(Box::new(fetch_snapshot(
                        &runtime, &settings,
                    ))));
                    continue;
                }
                Work::Approve(id) => approve_request(&runtime, &id),
                Work::Deny(id) => deny_request(&runtime, &id),
                Work::AddSecret {
                    name,
                    kind,
                    inject_env,
                    value,
                } => add_secret(&runtime, &name, &kind, &inject_env, value.as_str()),
                Work::Setup => run_setup(&runtime),
                Work::Browser => open_browser_backup(&runtime, &settings),
                Work::UpdateConsoleUrl(url) => Ok(update_console_url(&mut settings, url)),
            };
            if result_tx.send(WorkResult::Action(result)).is_err() {
                break;
            }
        }
    });
    (work_tx, result_rx)
}

fn update_console_url(settings: &mut DesktopSettings, url: Url) -> String {
    settings.console_url = url;
    format!("Browser backup now uses {}.", settings.console_url)
}

fn secret_value_widget_id() -> egui::Id {
    egui::Id::new("credential-secret-value")
}

fn clear_secret_widget_state(ctx: &egui::Context) {
    let id = secret_value_widget_id();
    ctx.memory_mut(|memory| memory.surrender_focus(id));
    ctx.data_mut(|data| data.remove::<egui::text_edit::TextEditState>(id));
}

fn kind_uses_multiline_input(kind: &str) -> bool {
    matches!(kind, "private-key" | "ssh-key")
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = PANEL;
    visuals.extreme_bg_color = Color32::from_rgb(7, 12, 21);
    visuals.widgets.inactive.bg_fill = PANEL_SOFT;
    visuals.widgets.inactive.fg_stroke.color = TEXT;
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(30, 47, 69);
    visuals.widgets.active.bg_fill = Color32::from_rgb(32, 63, 78);
    visuals.selection.bg_fill = Color32::from_rgb(29, 94, 108);
    ctx.set_visuals(visuals);
}

fn build_tray() -> Result<TrayIcon, String> {
    #[cfg(target_os = "linux")]
    gtk::init().map_err(|error| format!("Could not initialize the Linux tray: {error}"))?;

    let open = MenuItem::with_id(TRAY_OPEN, "Open s-gw", true, None);
    let browser = MenuItem::with_id(TRAY_BROWSER, "Open browser backup", true, None);
    let separator = PredefinedMenuItem::separator();
    let quit = MenuItem::with_id(TRAY_QUIT, "Quit", true, None);
    let menu = Menu::with_items(&[&open, &browser, &separator, &quit])
        .map_err(|error| format!("Could not create tray menu: {error}"))?;
    let icon = app_icon()?;
    TrayIconBuilder::new()
        .with_id(TRAY_ID)
        .with_tooltip("s-gw credential control")
        .with_icon(icon)
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .build()
        .map_err(|error| format!("Could not create tray icon: {error}"))
}

#[cfg(target_os = "linux")]
fn pump_linux_tray_events() {
    for _ in 0..32 {
        if !gtk::events_pending() {
            break;
        }
        gtk::main_iteration_do(false);
    }
}

#[cfg(not(target_os = "linux"))]
fn pump_linux_tray_events() {}

fn app_icon() -> Result<tray_icon::Icon, String> {
    let image = image::load_from_memory(include_bytes!("../icons/32x32.png"))
        .map_err(|error| format!("Could not load the app icon: {error}"))?
        .into_rgba8();
    let (width, height) = image.dimensions();
    tray_icon::Icon::from_rgba(image.into_raw(), width, height)
        .map_err(|error| format!("Could not decode the app icon: {error}"))
}

fn show_window(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
}

fn view_subtitle(view: View) -> &'static str {
    match view {
        View::Overview => "Local credential readiness at a glance",
        View::Approvals => "Review agent access before anything runs",
        View::Credentials => "Handles and policies; secret values remain hidden",
        View::Policies => "Ordered rules for recurring agent requests",
        View::Agents => "Local agent integration status",
        View::Activity => "Recent credential requests and outcomes",
    }
}

fn render_overview(ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
    ui.columns(4, |columns| {
        metric(
            &mut columns[0],
            "Credentials",
            snapshot.handles.len().to_string(),
            CYAN,
        );
        metric(
            &mut columns[1],
            "Pending",
            snapshot.pending_count().to_string(),
            AMBER,
        );
        metric(
            &mut columns[2],
            "Agents",
            snapshot.agents.len().to_string(),
            GREEN,
        );
        metric(
            &mut columns[3],
            "High risk",
            snapshot.high_risk_count().to_string(),
            RED,
        );
    });
    ui.add_space(14.0);
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(18))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let ready = snapshot.status.is_ready();
                ui.label(RichText::new("●").color(if ready { GREEN } else { AMBER }));
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(if ready {
                            "Operational readiness"
                        } else {
                            "Setup required"
                        })
                        .strong()
                        .color(TEXT),
                    );
                    let summary = if snapshot.status.readiness.summary.is_empty() {
                        if ready {
                            "Credential storage is ready."
                        } else {
                            "Complete local setup before enrolling credentials."
                        }
                    } else {
                        &snapshot.status.readiness.summary
                    };
                    ui.label(RichText::new(summary).color(MUTED));
                });
            });
            ui.add_space(12.0);
            status_row(
                ui,
                "Credential store",
                if snapshot.status.unlock_active() {
                    "Unlocked"
                } else {
                    "Locked or not configured"
                },
                snapshot.status.unlock_active(),
            );
            status_row(
                ui,
                "Local daemon",
                if snapshot.daemon_running {
                    "Running"
                } else {
                    "Not running (native app does not require it)"
                },
                snapshot.daemon_running,
            );
            status_row(
                ui,
                "Browser console",
                if snapshot.daemon_running {
                    "Available as backup"
                } else {
                    "Starts only when requested"
                },
                true,
            );
        });
    ui.add_space(14.0);
    ui.columns(2, |columns| {
        section(&mut columns[0], "Pending approvals", |ui| {
            let pending: Vec<_> = snapshot.pending_requests().take(4).collect();
            if pending.is_empty() {
                ui.label(RichText::new("No requests waiting for review.").color(MUTED));
            }
            for request in pending {
                ui.label(RichText::new(request.agent_label()).strong().color(TEXT));
                ui.label(RichText::new(request.action_label()).small().color(MUTED));
                ui.add_space(8.0);
            }
        });
        section(&mut columns[1], "Recent credentials", |ui| {
            if snapshot.handles.is_empty() {
                ui.label(RichText::new("No credentials enrolled yet.").color(MUTED));
            }
            for handle in snapshot.handles.iter().take(4) {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&handle.name).strong().color(TEXT));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new(handle.provider_label()).small().color(CYAN));
                    });
                });
                ui.label(RichText::new(&handle.handle).small().color(MUTED));
                ui.add_space(8.0);
            }
        });
    });
}

fn render_policies(ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
    if snapshot.policies.is_empty() {
        empty_state(
            ui,
            "No approval policies",
            "Requests will ask for approval unless a rule decides otherwise.",
        );
        return;
    }
    for rule in &snapshot.policies {
        section(ui, &rule.name, |ui| {
            ui.horizontal(|ui| {
                tag(
                    ui,
                    if rule.enabled { "Enabled" } else { "Disabled" },
                    if rule.enabled { GREEN } else { MUTED },
                );
                tag(
                    ui,
                    &rule.decision.to_ascii_uppercase(),
                    match rule.decision.as_str() {
                        "allow" => GREEN,
                        "deny" => RED,
                        _ => AMBER,
                    },
                );
                ui.label(
                    RichText::new(format!("Priority {}", rule.priority))
                        .small()
                        .color(MUTED),
                );
            });
        });
        ui.add_space(8.0);
    }
}

fn render_agents(ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
    if snapshot.agents.is_empty() {
        empty_state(
            ui,
            "No supported agents found",
            "Agent integration status will appear after setup.",
        );
        return;
    }
    ui.columns(2, |columns| {
        for (index, agent) in snapshot.agents.iter().enumerate() {
            section(&mut columns[index % 2], &agent.display_name, |ui| {
                tag(
                    ui,
                    agent.status_label(),
                    if matches!(agent.status_label(), "installed" | "existing") {
                        GREEN
                    } else {
                        MUTED
                    },
                );
                ui.label(RichText::new(&agent.id).small().color(MUTED));
            });
            columns[index % 2].add_space(8.0);
        }
    });
}

fn render_activity(ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
    if snapshot.requests.is_empty() {
        empty_state(
            ui,
            "No activity yet",
            "Agent credential requests and results will be listed here.",
        );
        return;
    }
    for request in snapshot.requests.iter().take(100) {
        section(ui, &request.action_label(), |ui| {
            ui.horizontal(|ui| {
                tag(ui, request.agent_label(), CYAN);
                tag(ui, &request.state, state_color(&request.state));
            });
            ui.label(RichText::new(&request.reason).color(MUTED));
            if let Some(error) = request.error.as_deref() {
                ui.label(RichText::new(error).small().color(RED));
            }
        });
        ui.add_space(8.0);
    }
}

enum ApprovalDecision {
    Approve,
    Deny,
}

fn request_card(
    ui: &mut egui::Ui,
    request: &RequestRecord,
    mut on_decision: impl FnMut(ApprovalDecision),
) {
    section(ui, &request.action_label(), |ui| {
        ui.horizontal(|ui| {
            tag(ui, request.agent_label(), CYAN);
            tag(ui, "PENDING", AMBER);
        });
        ui.label(RichText::new(&request.reason).color(MUTED));
        ui.label(
            RichText::new(format!("Credential: {}", request.handle))
                .small()
                .color(MUTED),
        );
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Approve once").clicked() {
                on_decision(ApprovalDecision::Approve);
            }
            if ui.button("Deny").clicked() {
                on_decision(ApprovalDecision::Deny);
            }
        });
    });
}

fn credential_card(ui: &mut egui::Ui, handle: &HandleSummary) {
    section(ui, &handle.name, |ui| {
        ui.horizontal(|ui| {
            tag(ui, &handle.provider_label(), CYAN);
            tag(
                ui,
                handle.severity_label(),
                if handle.high_risk() { RED } else { GREEN },
            );
        });
        ui.label(RichText::new(&handle.handle).small().color(MUTED));
        if let Some(env) = handle.policy.inject_env.as_deref() {
            ui.label(
                RichText::new(format!("Injects as {env}"))
                    .small()
                    .color(MUTED),
            );
        }
    });
}

fn metric(ui: &mut egui::Ui, label: &str, value: String, color: Color32) {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_min_height(72.0);
            ui.label(RichText::new(label).small().color(MUTED));
            ui.label(RichText::new(value).size(26.0).strong().color(color));
        });
}

fn section(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 2.0).max(220.0));
            ui.label(RichText::new(title).strong().color(TEXT));
            ui.add_space(6.0);
            body(ui);
        });
}

fn status_row(ui: &mut egui::Ui, label: &str, value: &str, positive: bool) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value).color(if positive { GREEN } else { AMBER }));
        });
    });
}

fn banner(ui: &mut egui::Ui, message: &str, color: Color32) {
    Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.65)))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.label(RichText::new(message).color(color));
        });
}

fn tag(ui: &mut egui::Ui, text: &str, color: Color32) {
    Frame::new()
        .fill(color.gamma_multiply(0.12))
        .corner_radius(CornerRadius::same(5))
        .inner_margin(Margin::symmetric(7, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).small().color(color));
        });
}

fn empty_state(ui: &mut egui::Ui, title: &str, detail: &str) {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(28))
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(title).size(18.0).strong().color(TEXT));
                ui.label(RichText::new(detail).color(MUTED));
            });
        });
}

fn state_color(state: &str) -> Color32 {
    match state {
        "executed" | "approved" => GREEN,
        "pending" | "executing" => AMBER,
        "denied" | "failed" => RED,
        _ => MUTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AgentProfile, Readiness, StatusSnapshot, UnlockStatus};
    use egui_kittest::{kittest::Queryable, Harness};

    fn fixture() -> DesktopSnapshot {
        DesktopSnapshot {
            status: StatusSnapshot {
                version: Some("0.1.19".into()),
                ready: Some(true),
                readiness: Readiness {
                    summary: "Ready for local credential requests.".into(),
                    blockers: vec![],
                },
                unlock: UnlockStatus {
                    active_source: "keychain".into(),
                },
                ..Default::default()
            },
            daemon_running: false,
            agents: vec![AgentProfile {
                id: "codex".into(),
                display_name: "Codex".into(),
                mcp_status: Some("supported".into()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn overview_is_a_native_widget_tree() {
        let snapshot = fixture();
        let harness = Harness::new_ui(|ui| render_overview(ui, &snapshot));
        harness.get_by_label("Operational readiness");
        harness.get_by_label("Credential store");
        harness.get_by_label("Local daemon");
        harness.get_by_label("Browser console");
    }

    #[test]
    fn native_navigation_names_are_present() {
        let labels: Vec<_> = View::ALL.into_iter().map(View::label).collect();
        assert_eq!(
            labels,
            [
                "Overview",
                "Approvals",
                "Credentials",
                "Policies",
                "Agents",
                "Activity"
            ]
        );
    }

    fn test_secret() -> String {
        (0..48)
            .map(|index| char::from(b'a' + (index % 26) as u8))
            .collect()
    }

    #[test]
    fn closing_and_reopening_credential_dialog_forgets_plaintext() {
        let mut dialog = CredentialDialog::default();
        dialog.open();
        dialog.value.push_str(&test_secret());
        assert!(!dialog.value.is_empty());

        dialog.close();
        assert!(!dialog.open);
        assert!(dialog.value.is_empty());

        dialog.open();
        assert!(dialog.value.is_empty());
    }

    #[test]
    fn credential_dispatch_leaves_no_plaintext_in_dialog_state() {
        let mut dialog = CredentialDialog::default();
        dialog.open();
        dialog.name.push_str("test credential");
        dialog.value.push_str(&test_secret());

        let work = dialog.take_work();

        assert!(!dialog.open);
        assert!(dialog.value.is_empty());
        match work {
            Work::AddSecret { value, .. } => {
                let _: &Zeroizing<String> = &value;
                assert!(!value.is_empty());
            }
            _ => panic!("credential dialog returned the wrong work type"),
        }
    }

    #[test]
    fn private_key_kinds_use_multiline_secret_entry() {
        assert!(SECRET_KINDS.contains(&"private-key"));
        assert!(SECRET_KINDS.contains(&"ssh-key"));
        assert!(kind_uses_multiline_input("private-key"));
        assert!(kind_uses_multiline_input("ssh-key"));
        assert!(!kind_uses_multiline_input("api-token"));
    }

    #[test]
    fn closing_credential_dialog_discards_text_edit_history() {
        let ctx = egui::Context::default();
        let id = secret_value_widget_id();
        egui::text_edit::TextEditState::default().store(&ctx, id);
        assert!(egui::text_edit::TextEditState::load(&ctx, id).is_some());

        clear_secret_widget_state(&ctx);

        assert!(egui::text_edit::TextEditState::load(&ctx, id).is_none());
    }

    #[test]
    fn activation_updates_the_worker_console_url() {
        let mut settings = DesktopSettings::from_args([
            "--authority-args".into(),
            "--console-url".into(),
            "http://127.0.0.1:8718/".into(),
        ])
        .expect("settings");
        let url = validated_console_url("http://127.0.0.1:9812/").expect("console URL");

        let message = update_console_url(&mut settings, url);

        assert_eq!(settings.console_url.as_str(), "http://127.0.0.1:9812/");
        assert_eq!(message, "Browser backup now uses http://127.0.0.1:9812/.");
    }
}
