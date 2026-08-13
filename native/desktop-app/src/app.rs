use crate::activation::{ActivationBatch, ActivationChannel};
use crate::model::{DesktopSnapshot, HandleSummary, RequestRecord};
use crate::runtime::{
    add_secret, approve_request, deny_request, fetch_snapshot, open_browser_backup, run_setup,
    validated_console_url, CliRuntime, DesktopSettings,
};
use egui::{
    self, Align, Color32, CornerRadius, Frame, Layout, Margin, RichText, ScrollArea, Sense, Stroke,
    TextEdit, Vec2,
};
use std::collections::HashSet;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const BG: Color32 = Color32::from_rgb(5, 8, 13);
const PANEL: Color32 = Color32::from_rgb(11, 17, 25);
const PANEL_SOFT: Color32 = Color32::from_rgb(17, 26, 38);
const SIDEBAR_BG: Color32 = Color32::from_rgb(5, 9, 16);
const BORDER: Color32 = Color32::from_rgb(32, 43, 56);
const TEXT: Color32 = Color32::from_rgb(247, 251, 255);
const MUTED: Color32 = Color32::from_rgb(149, 163, 183);
const CYAN: Color32 = Color32::from_rgb(62, 183, 255);
const GREEN: Color32 = Color32::from_rgb(86, 230, 173);
const AMBER: Color32 = Color32::from_rgb(240, 194, 67);
const RED: Color32 = Color32::from_rgb(255, 95, 109);

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
    UsageFlow,
    Activity,
    RequestHistory,
    Policies,
    Agents,
    Settings,
}

impl View {
    #[cfg(test)]
    const ALL: [Self; 9] = [
        Self::Overview,
        Self::Approvals,
        Self::Credentials,
        Self::UsageFlow,
        Self::Activity,
        Self::RequestHistory,
        Self::Policies,
        Self::Agents,
        Self::Settings,
    ];

    const OPERATE: [Self; 6] = [
        Self::Overview,
        Self::Approvals,
        Self::Credentials,
        Self::UsageFlow,
        Self::Activity,
        Self::RequestHistory,
    ];

    const CONFIGURE: [Self; 3] = [Self::Policies, Self::Agents, Self::Settings];

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Approvals => "Approvals",
            Self::Credentials => "Credentials",
            Self::UsageFlow => "Usage Flow",
            Self::Activity => "Activity",
            Self::RequestHistory => "Request History",
            Self::Policies => "Policies",
            Self::Agents => "Agents",
            Self::Settings => "Settings",
        }
    }

    fn detail(self) -> &'static str {
        match self {
            Self::Overview => "System posture",
            Self::Approvals => "Requests waiting",
            Self::Credentials => "Local handles",
            Self::UsageFlow => "Recent credential paths",
            Self::Activity => "Agent operations",
            Self::RequestHistory => "Local request ledger",
            Self::Policies => "Reusable rules",
            Self::Agents => "Integration profiles",
            Self::Settings => "Native application",
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
    brand_icon: Option<egui::TextureHandle>,
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
            brand_icon: load_brand_texture(&cc.egui_ctx),
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
            .default_size(244.0)
            .min_size(244.0)
            .max_size(244.0)
            .resizable(false)
            .frame(
                Frame::new()
                    .fill(SIDEBAR_BG)
                    .inner_margin(Margin::symmetric(12, 14)),
            )
            .show(ui, |ui| self.sidebar(ui));
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(BG)
                    .inner_margin(Margin::symmetric(20, 18)),
            )
            .show(ui, |ui| self.main_content(ui));
        self.add_secret_dialog(ui.ctx());
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if let Some(icon) = self.brand_icon.as_ref() {
                ui.add(egui::Image::new(icon).fit_to_exact_size(Vec2::splat(34.0)));
            } else {
                ui.label(
                    RichText::new("S")
                        .size(21.0)
                        .strong()
                        .color(BG)
                        .background_color(GREEN),
                );
            }
            ui.add_space(7.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("s-gw").size(20.0).strong().color(TEXT));
                ui.label(RichText::new("Credential control").small().color(MUTED));
            });
        });
        ui.add_space(18.0);

        let nav_height = (ui.available_height() - 120.0).max(180.0);
        ScrollArea::vertical()
            .id_salt("sidebar-navigation")
            .max_height(nav_height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                sidebar_group(
                    ui,
                    "OPERATE",
                    View::OPERATE,
                    self.snapshot.as_ref(),
                    &mut self.view,
                );
                ui.add_space(14.0);
                sidebar_group(
                    ui,
                    "CONFIGURE",
                    View::CONFIGURE,
                    self.snapshot.as_ref(),
                    &mut self.view,
                );
            });
        ui.add_space(8.0);
        if sidebar_footer(ui, self.snapshot.as_ref()) {
            self.send_action(Work::Browser);
        }
    }

    fn main_content(&mut self, ui: &mut egui::Ui) {
        paint_console_background(ui);
        self.topbar(ui);
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading(
                    RichText::new(self.view.label())
                        .size(27.0)
                        .strong()
                        .color(TEXT),
                );
                ui.label(RichText::new(self.view.detail()).color(MUTED));
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
                    View::UsageFlow => render_usage_flow(ui, snapshot),
                    View::Activity => render_activity(ui, snapshot),
                    View::RequestHistory => render_request_history(ui, snapshot),
                    View::Policies => render_policies(ui, snapshot),
                    View::Agents => render_agents(ui, snapshot),
                    View::Settings => self.render_settings(ui),
                }
            });
    }

    fn topbar(&mut self, ui: &mut egui::Ui) {
        Frame::new()
            .fill(SIDEBAR_BG)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(8)
            .inner_margin(Margin::symmetric(10, 8))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let snapshot = self.snapshot.as_ref();
                    let daemon_running = snapshot.is_some_and(|value| value.daemon_running);
                    let unlocked = snapshot.is_some_and(|value| value.status.unlock_active());
                    status_pill(
                        ui,
                        if daemon_running {
                            "Local daemon running"
                        } else {
                            "Local daemon stopped"
                        },
                        daemon_running,
                    );
                    status_pill(
                        ui,
                        if unlocked {
                            "Credential store unlocked"
                        } else {
                            "Credential store locked"
                        },
                        unlocked,
                    );
                    if ui.button("Approve Queue").clicked() {
                        self.view = View::Approvals;
                    }
                    let add_credential =
                        egui::Button::new(RichText::new("Add credential").strong().color(BG))
                            .fill(GREEN)
                            .stroke(Stroke::NONE)
                            .corner_radius(7);
                    if ui.add(add_credential).clicked() {
                        self.open_credential_dialog(ui.ctx());
                    }
                    if ui.button("Refresh").clicked() {
                        self.refresh();
                    }
                    if self.refresh_in_flight {
                        ui.spinner();
                    }
                });
            });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        section(ui, "Native application", |ui| {
            ui.label(
                RichText::new(
                    "The desktop app uses the bundled CLI and keeps browser access as an explicit backup.",
                )
                .color(MUTED),
            );
            ui.add_space(10.0);
            if ui.button("Open browser backup").clicked() {
                self.send_action(Work::Browser);
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

fn sidebar_group<const N: usize>(
    ui: &mut egui::Ui,
    label: &str,
    views: [View; N],
    snapshot: Option<&DesktopSnapshot>,
    current: &mut View,
) {
    ui.label(RichText::new(label).size(10.0).strong().color(MUTED));
    ui.add_space(5.0);
    for view in views {
        sidebar_item(ui, view, snapshot, current);
        ui.add_space(3.0);
    }
}

fn sidebar_item(
    ui: &mut egui::Ui,
    view: View,
    snapshot: Option<&DesktopSnapshot>,
    current: &mut View,
) {
    let selected = *current == view;
    let response = Frame::new()
        .fill(if selected {
            PANEL_SOFT
        } else {
            Color32::TRANSPARENT
        })
        .stroke(Stroke::new(
            1.0,
            if selected {
                BORDER
            } else {
                Color32::TRANSPARENT
            },
        ))
        .corner_radius(8)
        .inner_margin(Margin::symmetric(11, 7))
        .show(ui, |ui| {
            ui.set_width(194.0);
            ui.horizontal(|ui| {
                nav_icon(ui, view, selected);
                ui.add_space(3.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(view.label())
                                .size(14.0)
                                .strong()
                                .color(if selected { TEXT } else { MUTED }),
                        );
                        if let Some(count) = nav_count(view, snapshot) {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(count.to_string()).small().color(MUTED));
                            });
                        }
                    });
                    ui.label(RichText::new(view.detail()).size(10.5).color(MUTED));
                });
            });
        })
        .response
        .interact(Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::Button,
            ui.is_enabled(),
            selected,
            view.label(),
        )
    });
    if response.clicked() {
        *current = view;
    }
    if selected {
        let rail = egui::Rect::from_min_size(
            response.rect.left_top() + egui::vec2(-1.0, 8.0),
            egui::vec2(3.0, response.rect.height() - 16.0),
        );
        ui.painter().rect_filled(rail, 2.0, CYAN);
    }
}

fn nav_icon(ui: &mut egui::Ui, view: View, selected: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(20.0), Sense::hover());
    let color = if selected { CYAN } else { MUTED };
    ui.painter()
        .rect_filled(rect, 5.0, color.gamma_multiply(0.12));
    let center = rect.center();
    let stroke = Stroke::new(1.4, color);

    match view {
        View::Overview => {
            for offset in [
                egui::vec2(-3.0, -3.0),
                egui::vec2(3.0, -3.0),
                egui::vec2(-3.0, 3.0),
                egui::vec2(3.0, 3.0),
            ] {
                ui.painter().circle_filled(center + offset, 1.4, color);
            }
        }
        View::Approvals => {
            ui.painter().line_segment(
                [
                    center + egui::vec2(-4.0, 0.0),
                    center + egui::vec2(-1.0, 3.0),
                ],
                stroke,
            );
            ui.painter().line_segment(
                [
                    center + egui::vec2(-1.0, 3.0),
                    center + egui::vec2(4.0, -4.0),
                ],
                stroke,
            );
        }
        View::Credentials => {
            ui.painter()
                .circle_stroke(center + egui::vec2(-2.5, -1.5), 3.0, stroke);
            ui.painter()
                .line_segment([center, center + egui::vec2(5.0, 5.0)], stroke);
        }
        View::UsageFlow => {
            ui.painter().line_segment(
                [
                    center + egui::vec2(-5.0, 0.0),
                    center + egui::vec2(5.0, 0.0),
                ],
                stroke,
            );
            for x in [-5.0, 0.0, 5.0] {
                ui.painter()
                    .circle_filled(center + egui::vec2(x, 0.0), 1.8, color);
            }
        }
        View::Activity => {
            for (x, height) in [(-4.0, 4.0), (0.0, 7.0), (4.0, 10.0)] {
                ui.painter().line_segment(
                    [
                        center + egui::vec2(x, 5.0),
                        center + egui::vec2(x, 5.0 - height),
                    ],
                    stroke,
                );
            }
        }
        View::RequestHistory => {
            for y in [-4.0, 0.0, 4.0] {
                ui.painter().line_segment(
                    [center + egui::vec2(-4.0, y), center + egui::vec2(4.0, y)],
                    stroke,
                );
            }
        }
        View::Policies => {
            for (y, knob) in [(-4.0, -1.5), (0.0, 2.5), (4.0, 0.0)] {
                ui.painter().line_segment(
                    [center + egui::vec2(-5.0, y), center + egui::vec2(5.0, y)],
                    stroke,
                );
                ui.painter()
                    .circle_filled(center + egui::vec2(knob, y), 1.6, color);
            }
        }
        View::Agents => {
            ui.painter()
                .circle_stroke(center + egui::vec2(-3.0, -2.0), 2.2, stroke);
            ui.painter()
                .circle_stroke(center + egui::vec2(3.0, -2.0), 2.2, stroke);
            ui.painter().line_segment(
                [
                    center + egui::vec2(-5.0, 4.0),
                    center + egui::vec2(5.0, 4.0),
                ],
                stroke,
            );
        }
        View::Settings => {
            ui.painter().circle_stroke(center, 4.5, stroke);
            ui.painter().circle_filled(center, 1.5, color);
        }
    }
}

fn nav_count(view: View, snapshot: Option<&DesktopSnapshot>) -> Option<usize> {
    let snapshot = snapshot?;
    let count = match view {
        View::Approvals => Some(snapshot.pending_count()),
        View::Credentials => Some(snapshot.handles.len()),
        View::Agents => Some(
            snapshot
                .agents
                .iter()
                .filter(|agent| matches!(agent.status_label(), "installed" | "existing"))
                .count(),
        ),
        View::Overview
        | View::UsageFlow
        | View::Activity
        | View::RequestHistory
        | View::Policies
        | View::Settings => None,
    };
    count.filter(|value| *value > 0)
}

fn sidebar_footer(ui: &mut egui::Ui, snapshot: Option<&DesktopSnapshot>) -> bool {
    let ready = snapshot.is_some_and(|value| value.status.is_ready());
    Frame::new()
        .fill(PANEL_SOFT)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(8)
        .inner_margin(Margin::same(11))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                status_dot(ui, if ready { GREEN } else { AMBER });
                ui.label(RichText::new("Local profile").strong().color(TEXT));
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("s-gw").strong().color(TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!(
                            "QUEUE  {}",
                            snapshot.map_or(0, DesktopSnapshot::pending_count)
                        ))
                        .small()
                        .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format!(
                            "v{}",
                            snapshot
                                .and_then(|value| value.status.version.as_deref())
                                .unwrap_or(env!("CARGO_PKG_VERSION"))
                        ))
                        .small()
                        .color(MUTED),
                    );
                });
            });
        });
    ui.add_space(8.0);
    ui.label(
        RichText::new("Browser access is an explicit fallback.")
            .small()
            .color(MUTED),
    );
    ui.button("Open browser backup").clicked()
}

fn status_pill(ui: &mut egui::Ui, text: &str, positive: bool) {
    Frame::new()
        .fill(PANEL_SOFT)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(18)
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                status_dot(ui, if positive { GREEN } else { AMBER });
                ui.label(RichText::new(text).size(12.0).color(TEXT));
            });
        });
}

fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 3.5, color);
}

fn paint_console_background(ui: &egui::Ui) {
    let rect = ui.max_rect();
    let painter = ui.painter();
    let grid = Stroke::new(0.5, BORDER.gamma_multiply(0.14));
    let step = 48.0;

    let mut x = rect.left();
    while x <= rect.right() {
        painter.line_segment(
            [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
            grid,
        );
        x += step;
    }
    let mut y = rect.top();
    while y <= rect.bottom() {
        painter.line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            grid,
        );
        y += step;
    }

    paint_glow(
        painter,
        rect.right_top() + egui::vec2(-120.0, 10.0),
        210.0,
        CYAN,
    );
    paint_glow(
        painter,
        rect.left_bottom() + egui::vec2(180.0, -20.0),
        170.0,
        GREEN,
    );
}

fn paint_glow(painter: &egui::Painter, center: egui::Pos2, radius: f32, color: Color32) {
    for (scale, opacity) in [
        (1.0, 0.003),
        (0.82, 0.005),
        (0.64, 0.008),
        (0.46, 0.012),
        (0.28, 0.018),
    ] {
        painter.circle_filled(center, radius * scale, color.gamma_multiply(opacity));
    }
}

fn configure_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = PANEL;
    visuals.extreme_bg_color = Color32::from_rgb(7, 12, 21);
    visuals.widgets.inactive.bg_fill = PANEL_SOFT;
    visuals.widgets.inactive.fg_stroke.color = TEXT;
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(22, 35, 49);
    visuals.widgets.active.bg_fill = Color32::from_rgb(22, 64, 67);
    visuals.selection.bg_fill = Color32::from_rgb(14, 86, 68);
    visuals.window_corner_radius = CornerRadius::same(8);
    ctx.set_visuals(visuals);

    ctx.global_style_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.visuals.widgets.inactive.corner_radius = CornerRadius::same(7);
        style.visuals.widgets.hovered.corner_radius = CornerRadius::same(7);
        style.visuals.widgets.active.corner_radius = CornerRadius::same(7);
    });
}

fn load_brand_texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let image = image::load_from_memory(include_bytes!("../icons/128x128.png"))
        .ok()?
        .into_rgba8();
    let size = [image.width() as usize, image.height() as usize];
    let pixels = image.into_raw();
    Some(ctx.load_texture(
        "s-gw-brand",
        egui::ColorImage::from_rgba_unmultiplied(size, &pixels),
        egui::TextureOptions::LINEAR,
    ))
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

fn render_overview(ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
    const READINESS_ROW_HEIGHT: f32 = 108.0;
    const INVENTORY_ROW_HEIGHT: f32 = 205.0;
    const ACTIVITY_ROW_HEIGHT: f32 = 188.0;

    ui.columns(2, |columns| {
        section_at_least(
            &mut columns[0],
            "Operational readiness",
            READINESS_ROW_HEIGHT,
            |ui| {
                let ready = snapshot.status.is_ready();
                status_row(
                    ui,
                    "Protection readiness",
                    if ready { "Ready" } else { "Needs attention" },
                    ready,
                );
                status_row(
                    ui,
                    "Local daemon",
                    if snapshot.daemon_running {
                        "Running"
                    } else {
                        "Stopped"
                    },
                    snapshot.daemon_running,
                );
                status_row(
                    ui,
                    "Credential store",
                    if snapshot.status.unlock_active() {
                        "Unlocked"
                    } else {
                        "Locked"
                    },
                    snapshot.status.unlock_active(),
                );
                status_row(
                    ui,
                    "Request history",
                    &format!("{} local records", snapshot.requests.len()),
                    true,
                );
            },
        );
        section_at_least(
            &mut columns[1],
            "Pending approvals",
            READINESS_ROW_HEIGHT,
            |ui| {
                ui.label(
                    RichText::new(snapshot.pending_count().to_string())
                        .size(32.0)
                        .strong()
                        .color(TEXT),
                );
                ui.label(
                    RichText::new(if snapshot.pending_count() == 0 {
                        "No pending approvals"
                    } else {
                        "Approval needed"
                    })
                    .color(AMBER),
                );
            },
        );
    });
    ui.add_space(12.0);
    ui.columns(2, |columns| {
        section_at_least(
            &mut columns[0],
            "Credential handles",
            INVENTORY_ROW_HEIGHT,
            |ui| {
                if snapshot.handles.is_empty() {
                    ui.label(RichText::new("No credentials yet").color(MUTED));
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
            },
        );
        section_at_least(
            &mut columns[1],
            "Policy coverage",
            INVENTORY_ROW_HEIGHT,
            |ui| {
                policy_coverage_bar(ui, snapshot);
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let enabled = snapshot.policies.iter().filter(|rule| rule.enabled).count();
                    ui.label(
                        RichText::new(enabled.to_string())
                            .size(32.0)
                            .strong()
                            .color(GREEN),
                    );
                    ui.label(RichText::new("Enabled rules").color(MUTED));
                });
                let (allow, ask, deny) = policy_decision_counts(snapshot);
                ui.label(
                    RichText::new(format!("{allow} allow · {ask} ask · {deny} deny"))
                        .small()
                        .color(MUTED),
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new(format!(
                        "{} total policies · {} high-risk credentials",
                        snapshot.policies.len(),
                        snapshot.high_risk_count()
                    ))
                    .color(MUTED),
                );
            },
        );
    });
    ui.add_space(12.0);
    ui.columns(2, |columns| {
        section_at_least(
            &mut columns[0],
            "Recent activity",
            ACTIVITY_ROW_HEIGHT,
            |ui| {
                if snapshot.requests.is_empty() {
                    ui.label(RichText::new("No activity yet").color(MUTED));
                }
                for request in snapshot.requests.iter().take(5) {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(request.agent_label()).strong().color(TEXT));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            tag(ui, &request.state, state_color(&request.state));
                        });
                    });
                    ui.label(RichText::new(request.action_label()).small().color(MUTED));
                    ui.add_space(7.0);
                }
            },
        );
        section_at_least(&mut columns[1], "Usage Flow", ACTIVITY_ROW_HEIGHT, |ui| {
            usage_flow_summary(ui, snapshot)
        });
    });
}

fn usage_flow_summary(ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
    let (agents, credentials, requests) = usage_flow_counts(snapshot);
    let metrics = [
        ("Agents", agents, CYAN),
        ("Credentials", credentials, GREEN),
        ("Requests", requests, AMBER),
    ];
    if ui.available_width() >= 390.0 {
        ui.horizontal(|ui| {
            for (index, (label, value, color)) in metrics.into_iter().enumerate() {
                if index > 0 {
                    flow_connector(ui);
                }
                flow_metric(ui, label, value, color, 90.0);
            }
        });
    } else {
        ui.columns(3, |columns| {
            for (column, (label, value, color)) in columns.iter_mut().zip(metrics) {
                let width = (column.available_width() - 2.0).max(58.0);
                flow_metric(column, label, value, color, width);
            }
        });
    }
    ui.add_space(10.0);
    ui.label(
        RichText::new("Local agents request credential handles; s-gw applies policy before use.")
            .color(MUTED),
    );
}

fn usage_flow_counts(snapshot: &DesktopSnapshot) -> (usize, usize, usize) {
    let agents = snapshot
        .requests
        .iter()
        .map(RequestRecord::agent_label)
        .collect::<HashSet<_>>()
        .len();
    let credentials = snapshot
        .requests
        .iter()
        .map(|request| request.handle.as_str())
        .collect::<HashSet<_>>()
        .len();
    (agents, credentials, snapshot.requests.len())
}

fn flow_metric(ui: &mut egui::Ui, label: &str, value: usize, color: Color32, width: f32) {
    Frame::new()
        .fill(PANEL_SOFT)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(7)
        .inner_margin(Margin::symmetric(9, 7))
        .show(ui, |ui| {
            ui.set_width(width);
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new(value.to_string())
                        .size(20.0)
                        .strong()
                        .color(color),
                );
                ui.label(RichText::new(label).small().color(MUTED));
            });
        });
}

fn flow_connector(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 36.0), Sense::hover());
    let center = rect.center();
    let stroke = Stroke::new(1.0, BORDER);
    ui.painter().line_segment(
        [
            center + egui::vec2(-7.0, 0.0),
            center + egui::vec2(6.0, 0.0),
        ],
        stroke,
    );
    ui.painter().line_segment(
        [
            center + egui::vec2(2.0, -3.0),
            center + egui::vec2(6.0, 0.0),
        ],
        stroke,
    );
    ui.painter().line_segment(
        [center + egui::vec2(2.0, 3.0), center + egui::vec2(6.0, 0.0)],
        stroke,
    );
}

fn policy_coverage_bar(ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
    let available = ui.available_width().max(80.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(available, 8.0), Sense::hover());
    ui.painter().rect_filled(rect, 4.0, PANEL_SOFT);

    let (allow, ask, deny) = policy_decision_counts(snapshot);
    let enabled = allow + ask + deny;
    if enabled == 0 {
        return;
    }
    let mut left = rect.left();
    for (count, color) in [(allow, GREEN), (ask, AMBER), (deny, RED)] {
        if count == 0 {
            continue;
        }
        let width = rect.width() * count as f32 / enabled as f32;
        let segment = egui::Rect::from_min_max(
            egui::pos2(left, rect.top()),
            egui::pos2((left + width).min(rect.right()), rect.bottom()),
        );
        ui.painter().rect_filled(segment, 2.0, color);
        left += width;
    }
}

fn policy_decision_counts(snapshot: &DesktopSnapshot) -> (usize, usize, usize) {
    let mut allow = 0;
    let mut ask = 0;
    let mut deny = 0;
    for policy in snapshot.policies.iter().filter(|rule| rule.enabled) {
        match policy.decision.as_str() {
            "allow" => allow += 1,
            "deny" => deny += 1,
            _ => ask += 1,
        }
    }
    (allow, ask, deny)
}

fn render_usage_flow(ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
    section(ui, "Usage Flow", |ui| {
        ui.label(
            RichText::new("Agent  →  Authentication type  →  Target type")
                .size(18.0)
                .strong()
                .color(TEXT),
        );
        ui.add_space(12.0);
        if snapshot.requests.is_empty() {
            ui.label(
                RichText::new("Credential-use routes appear here after local credential requests.")
                    .color(MUTED),
            );
            return;
        }
        for request in snapshot.requests.iter().take(40) {
            let handle = snapshot
                .handles
                .iter()
                .find(|handle| handle.handle == request.handle);
            ui.horizontal(|ui| {
                tag(ui, request.agent_label(), CYAN);
                ui.label(RichText::new("→").color(MUTED));
                tag(ui, &auth_type_label(handle), GREEN);
                ui.label(RichText::new("→").color(MUTED));
                ui.label(RichText::new(target_type_label(request)).color(TEXT));
            });
            ui.add_space(7.0);
        }
    });
}

fn auth_type_label(handle: Option<&HandleSummary>) -> String {
    let Some(handle) = handle else {
        return "Unknown credential".into();
    };
    let provider = handle
        .provider
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let haystack = format!(
        "{} {} {} {}",
        provider,
        handle.name.to_ascii_lowercase(),
        handle.kind.to_ascii_lowercase(),
        handle
            .policy
            .inject_env
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
    );

    if provider == "aws" || handle.kind == "access-key" || haystack.contains("aws") {
        return "AWS access key".into();
    }
    if provider == "github" || haystack.contains("github") {
        return "GitHub token".into();
    }
    if provider == "openai" || haystack.contains("openai") {
        return "OpenAI API key".into();
    }
    if provider == "ssh" || haystack.contains("ssh") {
        return if handle.kind == "password" {
            "SSH password".into()
        } else {
            "SSH private key".into()
        };
    }
    match handle.kind.as_str() {
        "private-key" | "ssh-key" => "Private key".into(),
        "password" => "Password".into(),
        "api-token" => "API token".into(),
        "credential" => "Credential pair".into(),
        _ => "Unknown credential".into(),
    }
}

fn target_type_label(request: &RequestRecord) -> &'static str {
    if request.action.kind == "ssh_session" || request.action.ssh.is_some() {
        return "SSH server";
    }
    let command = request
        .action
        .command
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let haystack = format!(
        "{} {} {} {}",
        command,
        request.action.args.join(" ").to_ascii_lowercase(),
        request
            .action
            .working_dir
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        request.action.inject_env.to_ascii_lowercase()
    );

    if command == "aws" || haystack.contains(" amazon ") || haystack.contains(" s3 ") {
        "AWS API"
    } else if command == "gh" || command == "github" || haystack.contains("github") {
        "GitHub repository"
    } else if command == "kubectl" || haystack.contains("kubernetes") {
        "Kubernetes cluster"
    } else if matches!(command.as_str(), "docker" | "podman") {
        "Container runtime"
    } else if matches!(command.as_str(), "curl" | "wget")
        || haystack.contains("http://")
        || haystack.contains("https://")
    {
        "Web API"
    } else if matches!(command.as_str(), "psql" | "mysql" | "redis-cli") {
        "Database"
    } else if request.action.kind == "env_command" {
        "Local command"
    } else {
        "Other target"
    }
}

fn render_request_history(ui: &mut egui::Ui, snapshot: &DesktopSnapshot) {
    section(ui, "Recent request records", |ui| {
        ui.label(
            RichText::new("Recent credential request records from the local request ledger.")
                .color(MUTED),
        );
        ui.add_space(10.0);
        if snapshot.requests.is_empty() {
            ui.label(RichText::new("No request records yet").color(MUTED));
        }
        for request in snapshot.requests.iter().take(100) {
            ui.horizontal(|ui| {
                ui.label(RichText::new(request.agent_label()).strong().color(TEXT));
                ui.label(RichText::new(request.action_label()).color(MUTED));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    tag(ui, &request.state, state_color(&request.state));
                });
            });
            ui.separator();
        }
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
                    agent_status_color(agent.status_label()),
                );
                ui.label(RichText::new(&agent.id).small().color(MUTED));
            });
            columns[index % 2].add_space(8.0);
        }
    });
}

fn agent_status_color(status: &str) -> Color32 {
    if matches!(status, "installed" | "existing") {
        GREEN
    } else {
        MUTED
    }
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
    section(ui, "Credential activity", |ui| {
        ScrollArea::horizontal().show(ui, |ui| {
            let table_width = ui.available_width().max(680.0);
            ui.set_min_width(table_width);
            let column_width = ((table_width - 72.0) / 5.0).max(96.0);
            egui::Grid::new("credential-activity-table")
                .num_columns(5)
                .min_col_width(column_width)
                .striped(true)
                .spacing(egui::vec2(18.0, 9.0))
                .show(ui, |ui| {
                    for heading in ["Agent", "Credential", "Action", "State", "Updated"] {
                        ui.label(RichText::new(heading).small().strong().color(MUTED));
                    }
                    ui.end_row();

                    for request in snapshot.requests.iter().take(40) {
                        ui.label(RichText::new(request.agent_label()).strong().color(TEXT));
                        let compact_handle = compact_text(&request.handle, 24);
                        ui.label(RichText::new(compact_handle).small().color(GREEN))
                            .on_hover_text(&request.handle);
                        let action = request.action_label();
                        let compact_action = compact_text(&action, 38);
                        let action_text = if request.error.is_some() {
                            RichText::new(compact_action).color(RED)
                        } else {
                            RichText::new(compact_action).color(TEXT)
                        };
                        let action_response = ui.label(action_text);
                        if let Some(error) = request.error.as_deref() {
                            action_response.on_hover_text(error);
                        } else {
                            action_response.on_hover_text(&action);
                        }
                        tag(ui, &request.state, state_color(&request.state));
                        let updated = compact_text(request.sort_key(), 19);
                        ui.label(RichText::new(updated).small().color(MUTED))
                            .on_hover_text(request.sort_key());
                        ui.end_row();
                    }
                });
        });
    });
}

fn compact_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.into();
    }
    let mut result: String = value.chars().take(max_chars.saturating_sub(1)).collect();
    result.push('…');
    result
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

fn section(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    section_at_least(ui, title, 0.0, body);
}

fn section_at_least(
    ui: &mut egui::Ui,
    title: &str,
    min_height: f32,
    body: impl FnOnce(&mut egui::Ui),
) {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 2.0).max(220.0));
            ui.set_min_height(min_height);
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
        .corner_radius(CornerRadius::same(8))
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
    use crate::model::{AgentProfile, PolicyRule, Readiness, StatusSnapshot, UnlockStatus};
    use egui_kittest::{kittest::Queryable, Harness};

    fn fixture() -> DesktopSnapshot {
        DesktopSnapshot {
            status: StatusSnapshot {
                version: Some("0.1.21".into()),
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
        harness.get_by_label("Protection readiness");
        harness.get_by_label("Credential store");
        harness.get_by_label("Local daemon");
        harness.get_by_label("Request history");
    }

    #[test]
    fn native_navigation_matches_the_established_desktop_information_architecture() {
        let labels: Vec<_> = View::ALL.into_iter().map(View::label).collect();
        assert_eq!(
            labels,
            [
                "Overview",
                "Approvals",
                "Credentials",
                "Usage Flow",
                "Activity",
                "Request History",
                "Policies",
                "Agents",
                "Settings"
            ]
        );
    }

    #[test]
    fn overview_uses_the_established_desktop_dashboard_panels() {
        let snapshot = fixture();
        let harness = Harness::new_ui(|ui| render_overview(ui, &snapshot));

        for label in [
            "Operational readiness",
            "Pending approvals",
            "Credential handles",
            "Policy coverage",
            "Recent activity",
            "Usage Flow",
        ] {
            harness.get_by_label(label);
        }
    }

    #[test]
    fn desktop_dark_palette_matches_the_existing_console() {
        assert_eq!(BG, Color32::from_rgb(5, 8, 13));
        assert_eq!(PANEL, Color32::from_rgb(11, 17, 25));
        assert_eq!(TEXT, Color32::from_rgb(247, 251, 255));
        assert_eq!(MUTED, Color32::from_rgb(149, 163, 183));
        assert_eq!(GREEN, Color32::from_rgb(86, 230, 173));
    }

    #[test]
    fn overview_widget_tree_is_stable_across_common_windows_scales() {
        for scale in [1.0, 1.25, 1.5, 2.0] {
            let snapshot = fixture();
            let harness = Harness::builder()
                .with_size(Vec2::new(736.0, 540.0))
                .with_pixels_per_point(scale)
                .build_ui(move |ui| {
                    configure_style(ui.ctx());
                    render_overview(ui, &snapshot);
                });

            harness.get_by_label("Operational readiness");
            harness.get_by_label("Recent activity");
        }
    }

    #[test]
    fn dashboard_summaries_are_derived_from_real_request_and_policy_records() {
        let mut snapshot = fixture();
        snapshot.requests = vec![
            RequestRecord {
                agent_name: Some("Codex".into()),
                handle: "op://Dev/Webex".into(),
                ..Default::default()
            },
            RequestRecord {
                agent_name: Some("Codex".into()),
                handle: "op://Dev/GitHub".into(),
                ..Default::default()
            },
            RequestRecord {
                agent_name: Some("Claude".into()),
                handle: "op://Dev/Webex".into(),
                ..Default::default()
            },
        ];
        snapshot.policies = vec![
            PolicyRule {
                enabled: true,
                decision: "allow".into(),
                ..Default::default()
            },
            PolicyRule {
                enabled: true,
                decision: "ask".into(),
                ..Default::default()
            },
            PolicyRule {
                enabled: true,
                decision: "deny".into(),
                ..Default::default()
            },
            PolicyRule {
                enabled: false,
                decision: "allow".into(),
                ..Default::default()
            },
        ];

        assert_eq!(usage_flow_counts(&snapshot), (2, 2, 3));
        assert_eq!(policy_decision_counts(&snapshot), (1, 1, 1));
    }

    #[test]
    fn usage_flow_uses_authentication_and_target_categories() {
        let github = HandleSummary {
            handle: "s-gw:api-token:test".into(),
            name: "GitHub publisher".into(),
            kind: "api-token".into(),
            provider: Some("github".into()),
            ..Default::default()
        };
        let request = RequestRecord {
            handle: github.handle.clone(),
            action: crate::model::CommandAction {
                kind: "env_command".into(),
                command: "gh".into(),
                args: vec!["repo".into(), "view".into()],
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(auth_type_label(Some(&github)), "GitHub token");
        assert_eq!(target_type_label(&request), "GitHub repository");
    }

    #[test]
    fn navigation_hides_empty_badges() {
        let mut snapshot = fixture();
        assert_eq!(nav_count(View::Approvals, Some(&snapshot)), None);
        assert_eq!(nav_count(View::Credentials, Some(&snapshot)), None);
        assert_eq!(nav_count(View::Agents, Some(&snapshot)), None);

        snapshot.agents[0].mcp_status = Some("installed".into());
        assert_eq!(nav_count(View::Agents, Some(&snapshot)), Some(1));
    }

    #[test]
    fn custom_navigation_items_keep_button_accessibility() {
        let mut current = View::Overview;
        let harness = Harness::new_ui(|ui| {
            sidebar_item(ui, View::Overview, None, &mut current);
        });

        harness.get_by_role_and_label(egui::accesskit::Role::Button, "Overview");
    }

    #[test]
    fn activity_table_compacts_long_values_without_splitting_unicode() {
        assert_eq!(compact_text("short", 10), "short");
        assert_eq!(compact_text("credential-🔐-handle", 12), "credential-…");
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
