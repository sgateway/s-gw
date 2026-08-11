#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Deserialize;
use std::env;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::webview::{DownloadEvent, NewWindowResponse, PageLoadEvent, WebviewWindowBuilder};
use tauri::{AppHandle, Manager, Url, WebviewUrl, WebviewWindow, WindowEvent};
use tauri_plugin_opener::OpenerExt;

const DEFAULT_CONSOLE_URL: &str = "http://127.0.0.1:8718/";
const MAIN_WINDOW: &str = "main";
static LOADING_STATUS: Mutex<LoadingStatusState> = Mutex::new(LoadingStatusState {
    generation: 0,
    current: None,
});

#[derive(Clone, Debug, PartialEq, Eq)]
struct LoadingStatus {
    generation: u64,
    title: String,
    detail: String,
}

#[derive(Debug, Default)]
struct LoadingStatusState {
    generation: u64,
    current: Option<LoadingStatus>,
}

impl LoadingStatusState {
    fn set(&mut self, title: &str, detail: &str) -> LoadingStatus {
        self.generation += 1;
        let status = LoadingStatus {
            generation: self.generation,
            title: title.into(),
            detail: detail.into(),
        };
        self.current = Some(status.clone());
        status
    }

    fn clear(&mut self) {
        self.generation += 1;
        self.current = None;
    }
}

#[derive(Clone, Debug)]
struct DesktopSettings {
    authority_env: Vec<(String, String)>,
    background: bool,
    cli_path: Option<PathBuf>,
    console_url: Url,
    expected_instance_key: Option<String>,
    node_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    #[serde(rename = "instanceKey")]
    instance_key: String,
    name: String,
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    #[serde(rename = "instanceKey")]
    instance_key: Option<String>,
}

#[derive(Clone, Debug)]
enum CliRuntime {
    Node { node: PathBuf, cli: PathBuf },
    PathCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsoleState {
    Matching,
    Unavailable,
    Foreign,
    WrongInstance,
}

fn main() {
    let settings = match DesktopSettings::from_args(env::args().skip(1)) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("s-gw desktop: {error}");
            std::process::exit(2);
        }
    };

    let second_launch_settings = settings.clone();
    let app_settings = settings.clone();
    apply_authority_environment(&settings.authority_env);
    clear_sensitive_environment();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(
            move |app, args, _cwd| {
                let requested = settings_from_second_launch(&args);
                if requested.as_ref().is_some_and(|value| {
                    value.console_url != second_launch_settings.console_url
                        || value.authority_env != second_launch_settings.authority_env
                        || instance_keys_conflict(
                            value.expected_instance_key.as_deref(),
                            second_launch_settings.expected_instance_key.as_deref(),
                        )
                }) {
                    show_main_window(app);
                    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                        show_loading_error(
                            &window,
                            "A different s-gw desktop session is already open",
                            "Close it before opening another credential home or console port.",
                        );
                    }
                    return;
                }

                let background = requested
                    .as_ref()
                    .map(|value| value.background)
                    .unwrap_or_else(|| args.iter().any(|arg| arg == "--background"));
                if !background {
                    show_main_window(app);
                }

                if args.iter().any(|arg| arg == "--browser") {
                    open_console_in_browser(
                        app.clone(),
                        requested.unwrap_or_else(|| second_launch_settings.clone()),
                    );
                }
            },
        ))
        .plugin(
            tauri_plugin_opener::Builder::new()
                .open_js_links_on_click(false)
                .build(),
        )
        .setup(move |app| {
            let window = build_main_window(app, &app_settings)?;
            build_tray(app, &app_settings)?;

            if app_settings.background {
                let _ = window.hide();
            }

            start_console_task(app.handle().clone(), window, app_settings.clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != MAIN_WINDOW {
                return;
            }

            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("s-gw desktop could not start");
}

impl DesktopSettings {
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut authority_env = Vec::new();
        let mut authority_args = false;
        let mut background = false;
        let mut cli_path = None;
        let mut console_url = None;
        let mut expected_instance_key = None;
        let mut node_path = None;
        let mut items = args.into_iter();

        while let Some(arg) = items.next() {
            match arg.as_str() {
                "--authority" => {
                    authority_args = true;
                    let value = require_arg(&mut items, &arg)?;
                    authority_env.push(validate_authority_arg(&value)?);
                }
                "--authority-args" => authority_args = true,
                "--background" => background = true,
                "--browser" => {}
                "--cli-path" => cli_path = Some(PathBuf::from(require_arg(&mut items, &arg)?)),
                "--console-url" => console_url = Some(require_arg(&mut items, &arg)?),
                "--instance-key" => expected_instance_key = Some(require_arg(&mut items, &arg)?),
                "--node-path" => node_path = Some(PathBuf::from(require_arg(&mut items, &arg)?)),
                _ => return Err(format!("unknown argument: {arg}")),
            }
        }

        if cli_path.is_some() != node_path.is_some() {
            return Err("--cli-path and --node-path must be supplied together".into());
        }

        let console_url =
            validated_console_url(console_url.as_deref().unwrap_or(DEFAULT_CONSOLE_URL))?;
        let expected_instance_key = expected_instance_key
            .map(|value| validate_instance_key(&value))
            .transpose()?;
        if !authority_args {
            authority_env = current_authority_environment()?;
        }
        authority_env.sort_by(|left, right| left.0.cmp(&right.0));
        authority_env.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
        if authority_env.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err("desktop authority settings cannot redefine the same name".into());
        }

        Ok(Self {
            authority_env,
            background,
            cli_path,
            console_url,
            expected_instance_key,
            node_path,
        })
    }
}

fn settings_from_second_launch(args: &[String]) -> Option<DesktopSettings> {
    let start = usize::from(args.first().is_some_and(|value| !value.starts_with('-')));
    DesktopSettings::from_args(args[start..].iter().cloned()).ok()
}

fn instance_keys_conflict(left: Option<&str>, right: Option<&str>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if left != right)
}

const AUTHORITY_ENV_NAMES: [&str; 7] = [
    "SGW_EXECUTION_ENGINE",
    "SGW_HOME",
    "SGW_KEYCHAIN_ACCOUNT",
    "SGW_KEYCHAIN_SERVICE",
    "SGW_RECOVERY_HOME",
    "SGW_SECRET_BACKEND",
    "SGW_SECRET_KEYCHAIN_SERVICE",
];

fn validate_authority_arg(value: &str) -> Result<(String, String), String> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| "--authority must use NAME=VALUE".to_string())?;
    if !AUTHORITY_ENV_NAMES.contains(&name) {
        return Err(format!("unsupported desktop authority setting: {name}"));
    }
    if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err(format!("invalid desktop authority setting: {name}"));
    }
    Ok((name.into(), value.into()))
}

fn current_authority_environment() -> Result<Vec<(String, String)>, String> {
    let mut values = Vec::new();
    for name in AUTHORITY_ENV_NAMES {
        if let Ok(value) = env::var(name) {
            values.push(validate_authority_arg(&format!("{name}={value}"))?);
        }
    }
    Ok(values)
}

fn apply_authority_environment(values: &[(String, String)]) {
    for name in AUTHORITY_ENV_NAMES {
        env::remove_var(name);
    }
    for (name, value) in values {
        env::set_var(name, value);
    }
}

fn clear_sensitive_environment() {
    for name in [
        "SGW_MASTER_PASSPHRASE",
        "SGW_DISABLE_KEYCHAIN",
        "SGW_KEYCHAIN_HELPER",
        "SGW_SECRET_TOOL",
        "SGW_WINDOWS_CREDENTIAL_HELPER",
    ] {
        env::remove_var(name);
    }
}

fn require_arg(items: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    items
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn validated_console_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "--console-url must be an absolute URL")?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.username() != ""
        || url.password().is_some()
        || url.port().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("--console-url must use http://127.0.0.1:<port>/".into());
    }
    Ok(url)
}

fn validate_instance_key(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("--instance-key must be a 64-character hexadecimal value".into());
    }
    Ok(normalized)
}

fn build_main_window(
    app: &mut tauri::App,
    settings: &DesktopSettings,
) -> tauri::Result<WebviewWindow> {
    let allowed_origin = console_origin(&settings.console_url);
    let navigation_app = app.handle().clone();
    let new_window_app = app.handle().clone();

    WebviewWindowBuilder::new(app, MAIN_WINDOW, WebviewUrl::App("index.html".into()))
        .title("s-gw")
        .inner_size(1280.0, 840.0)
        .min_inner_size(900.0, 620.0)
        .center()
        .incognito(true)
        .browser_extensions_enabled(false)
        .devtools(cfg!(debug_assertions))
        .on_navigation(move |url| {
            if is_bundled_page(url) || is_console_navigation(url, &allowed_origin) {
                return true;
            }

            if is_safe_external_url(url) {
                open_browser(&navigation_app, url);
            }
            false
        })
        .on_new_window(move |url, _features| {
            if is_safe_external_url(&url) {
                open_browser(&new_window_app, &url);
            }
            NewWindowResponse::Deny
        })
        .on_page_load(|window, payload| {
            if matches!(payload.event(), PageLoadEvent::Finished) && is_bundled_page(payload.url())
            {
                replay_loading_status(&window);
            }
        })
        .on_download(|_webview, event| !matches!(event, DownloadEvent::Requested { .. }))
        .build()
}

fn is_bundled_page(url: &Url) -> bool {
    url.scheme() == "tauri" || url.host_str() == Some("tauri.localhost")
}

fn console_origin(url: &Url) -> String {
    format!(
        "{}://{}:{}/",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or(8718)
    )
}

fn is_console_navigation(url: &Url, allowed_origin: &str) -> bool {
    url.as_str().starts_with(allowed_origin)
}

fn is_safe_external_url(url: &Url) -> bool {
    matches!(url.scheme(), "https" | "mailto")
}

fn build_tray(app: &mut tauri::App, settings: &DesktopSettings) -> tauri::Result<()> {
    let open_item = MenuItem::with_id(app, "open", "Open s-gw", true, None::<&str>)?;
    let browser_item =
        MenuItem::with_id(app, "browser", "Open browser backup", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit s-gw", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open_item, &browser_item, &separator, &quit_item])?;

    let browser_settings = settings.clone();
    let mut tray = TrayIconBuilder::with_id("s-gw")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("s-gw credential protection")
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
            "browser" => open_console_in_browser(app.clone(), browser_settings.clone()),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn open_browser(app: &AppHandle, url: &Url) -> bool {
    app.opener().open_url(url.as_str(), None::<&str>).is_ok()
}

fn open_console_in_browser(app: AppHandle, settings: DesktopSettings) {
    thread::spawn(move || {
        let runtime = match resolve_runtime(&app, &settings) {
            Some(value) => value,
            None => {
                show_runtime_error(&app);
                return;
            }
        };
        let expected_key = match settings
            .expected_instance_key
            .clone()
            .or_else(|| runtime_instance_key(&runtime))
        {
            Some(value) => value,
            None => {
                show_runtime_error(&app);
                return;
            }
        };

        let mut state = probe_console(&settings.console_url, &expected_key);
        if state == ConsoleState::Unavailable {
            run_lifecycle(&runtime, "start", &settings.console_url);
            state = wait_for_console(&settings.console_url, &expected_key, Duration::from_secs(8));
        }
        if state == ConsoleState::Matching {
            if open_browser(&app, &settings.console_url) {
                return;
            }
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                show_loading_error(
                    &window,
                    "The browser backup could not open",
                    "Open the verified loopback address from the s-gw status output.",
                );
            }
            return;
        }

        if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
            if matches!(state, ConsoleState::Foreign | ConsoleState::WrongInstance) {
                show_authority_conflict(&window);
            } else {
                show_loading_error(
                    &window,
                    "The browser backup is not ready",
                    "Run `s-gw setup`, then try the browser backup again.",
                );
            }
        }
    });
}

fn show_runtime_error(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        show_loading_error(
            &window,
            "s-gw runtime is missing",
            "Reinstall s-gw, then reopen this app.",
        );
    }
}

fn start_console_task(app: AppHandle, window: WebviewWindow, settings: DesktopSettings) {
    thread::spawn(move || {
        let runtime = match resolve_runtime(&app, &settings) {
            Some(value) => value,
            None => {
                show_loading_error(
                    &window,
                    "s-gw runtime is missing",
                    "Reinstall s-gw or run `s-gw setup`, then reopen this app.",
                );
                return;
            }
        };

        let expected_key = match settings
            .expected_instance_key
            .clone()
            .or_else(|| runtime_instance_key(&runtime))
        {
            Some(value) => value,
            None => {
                show_loading_error(
                    &window,
                    "s-gw could not verify the local service",
                    "Use the browser backup after running `s-gw setup`.",
                );
                return;
            }
        };

        match probe_console(&settings.console_url, &expected_key) {
            ConsoleState::Matching => {
                navigate_to_console(&app, &window, &settings.console_url);
                return;
            }
            ConsoleState::Foreign | ConsoleState::WrongInstance => {
                show_authority_conflict(&window);
                return;
            }
            ConsoleState::Unavailable => run_lifecycle(&runtime, "start", &settings.console_url),
        }

        match wait_for_console(&settings.console_url, &expected_key, Duration::from_secs(6)) {
            ConsoleState::Matching => {
                navigate_to_console(&app, &window, &settings.console_url);
                return;
            }
            ConsoleState::Foreign | ConsoleState::WrongInstance => {
                show_authority_conflict(&window);
                return;
            }
            ConsoleState::Unavailable => run_lifecycle(&runtime, "setup", &settings.console_url),
        }

        match wait_for_console(
            &settings.console_url,
            &expected_key,
            Duration::from_secs(18),
        ) {
            ConsoleState::Matching => {
                navigate_to_console(&app, &window, &settings.console_url);
                return;
            }
            ConsoleState::Foreign | ConsoleState::WrongInstance => {
                show_authority_conflict(&window);
                return;
            }
            ConsoleState::Unavailable => {}
        }

        show_loading_error(
            &window,
            "s-gw needs attention",
            "Unlock the operating-system credential store, run `s-gw setup`, then reopen this app.",
        );

        loop {
            thread::sleep(Duration::from_secs(3));
            match probe_console(&settings.console_url, &expected_key) {
                ConsoleState::Matching => {
                    navigate_to_console(&app, &window, &settings.console_url);
                    return;
                }
                ConsoleState::Foreign | ConsoleState::WrongInstance => {
                    show_authority_conflict(&window);
                    return;
                }
                ConsoleState::Unavailable => {}
            }
        }
    });
}

fn navigate_to_console(app: &AppHandle, window: &WebviewWindow, console_url: &Url) {
    clear_loading_status();
    if window.navigate(console_url.clone()).is_ok() {
        return;
    }

    let opened = open_browser(app, console_url);
    let detail = if opened {
        "The verified browser backup has been opened instead."
    } else {
        "Use `s-gw app open --browser` to open the verified browser backup."
    };
    show_loading_error(window, "The native window could not open", detail);
}

fn show_authority_conflict(window: &WebviewWindow) {
    show_loading_error(
        window,
        "Another service is using the s-gw port",
        "s-gw left it untouched. Stop the other service or choose a different port.",
    );
}

fn resolve_runtime(app: &AppHandle, settings: &DesktopSettings) -> Option<CliRuntime> {
    if let Ok(resource_dir) = app.path().resource_dir() {
        let node = packaged_node_path(&resource_dir);
        let cli = resource_dir.join("runtime/package/dist/cli.js");
        if node.is_file() && cli.is_file() {
            return Some(CliRuntime::Node { node, cli });
        }
    }

    if !cfg!(debug_assertions) {
        return None;
    }

    if let (Some(node), Some(cli)) = (&settings.node_path, &settings.cli_path) {
        if node.is_file() && cli.is_file() {
            return Some(CliRuntime::Node {
                node: node.clone(),
                cli: cli.clone(),
            });
        }
    }

    command_exists("s-gw").then_some(CliRuntime::PathCommand)
}

#[cfg(target_os = "windows")]
fn packaged_node_path(resource_dir: &Path) -> PathBuf {
    resource_dir.join("runtime/node/node.exe")
}

#[cfg(not(target_os = "windows"))]
fn packaged_node_path(resource_dir: &Path) -> PathBuf {
    resource_dir.join("runtime/node/bin/node")
}

fn command_exists(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn runtime_instance_key(runtime: &CliRuntime) -> Option<String> {
    let output = cli_command(runtime)
        .arg("__desktop-instance-key")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let status: StatusResponse = serde_json::from_slice(&output.stdout).ok()?;
    status
        .instance_key
        .and_then(|value| validate_instance_key(&value).ok())
}

fn run_lifecycle(runtime: &CliRuntime, action: &str, console_url: &Url) {
    let mut command = cli_command(runtime);
    let port = console_url
        .port_or_known_default()
        .unwrap_or(8718)
        .to_string();
    command
        .arg(action)
        .args(["--port", &port, "--no-open-app", "--no-menubar"]);
    if action == "setup" {
        command.arg("--no-agents");
    }

    let _ = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn cli_command(runtime: &CliRuntime) -> Command {
    let mut command = match runtime {
        CliRuntime::Node { node, cli } => {
            let mut command = Command::new(node);
            command.arg(cli);
            command
        }
        CliRuntime::PathCommand => Command::new("s-gw"),
    };
    for name in [
        "SGW_MASTER_PASSPHRASE",
        "SGW_DISABLE_KEYCHAIN",
        "SGW_KEYCHAIN_HELPER",
        "SGW_SECRET_TOOL",
        "SGW_WINDOWS_CREDENTIAL_HELPER",
    ] {
        command.env_remove(name);
    }
    command
}

fn wait_for_console(url: &Url, expected_key: &str, timeout: Duration) -> ConsoleState {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let state = probe_console(url, expected_key);
        if state != ConsoleState::Unavailable {
            return state;
        }
        thread::sleep(Duration::from_millis(250));
    }
    ConsoleState::Unavailable
}

fn probe_console(url: &Url, expected_key: &str) -> ConsoleState {
    let port = match url.port_or_known_default() {
        Some(value) => value,
        None => return ConsoleState::Foreign,
    };
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut stream = match TcpStream::connect_timeout(&address.into(), Duration::from_millis(700)) {
        Ok(value) => value,
        Err(_) => return ConsoleState::Unavailable,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(700)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(700)));

    let request =
        format!("GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return ConsoleState::Foreign;
    }

    let mut response = Vec::new();
    if stream.take(65_536).read_to_end(&mut response).is_err() {
        return ConsoleState::Foreign;
    }
    parse_health_response(&response, expected_key)
}

fn parse_health_response(response: &[u8], expected_key: &str) -> ConsoleState {
    let split = match response.windows(4).position(|part| part == b"\r\n\r\n") {
        Some(value) => value,
        None => return ConsoleState::Foreign,
    };
    let headers = &response[..split];
    if !headers.starts_with(b"HTTP/1.1 200 ") && !headers.starts_with(b"HTTP/1.0 200 ") {
        return ConsoleState::Foreign;
    }

    let body = match response_body(&response[..split], &response[split + 4..]) {
        Some(value) => value,
        None => return ConsoleState::Foreign,
    };
    let health: HealthResponse = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return ConsoleState::Foreign,
    };
    if !health.ok || health.name != "s-gw" {
        return ConsoleState::Foreign;
    }
    if health.instance_key != expected_key {
        return ConsoleState::WrongInstance;
    }
    ConsoleState::Matching
}

fn response_body(headers: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    let headers = String::from_utf8_lossy(headers).to_ascii_lowercase();
    if !headers.contains("transfer-encoding: chunked") {
        return Some(body.to_vec());
    }

    decode_chunked_body(body)
}

fn decode_chunked_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = 0;
    let mut decoded = Vec::new();

    loop {
        let remaining = body.get(cursor..)?;
        let line_end = remaining.windows(2).position(|part| part == b"\r\n")? + cursor;
        let size_text = std::str::from_utf8(&body[cursor..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        cursor = line_end + 2;

        if size == 0 {
            return Some(decoded);
        }
        let chunk_end = cursor.checked_add(size)?;
        let trailer_end = chunk_end.checked_add(2)?;
        if body.len() < trailer_end || &body[chunk_end..trailer_end] != b"\r\n" {
            return None;
        }

        decoded.extend_from_slice(&body[cursor..chunk_end]);
        cursor = trailer_end;
    }
}

fn loading_error_script(status: &LoadingStatus) -> String {
    let title =
        serde_json::to_string(&status.title).unwrap_or_else(|_| "\"s-gw needs attention\"".into());
    let detail = serde_json::to_string(&status.detail)
        .unwrap_or_else(|_| "\"Open the browser backup.\"".into());
    let generation = status.generation;
    format!(
        "(() => {{const next={{generation:{generation},title:{title},detail:{detail}}};const current=window.__sgwDesktopStatus;if(!current||Number(current.generation)<=next.generation){{window.__sgwDesktopStatus=next;}}const status=window.__sgwDesktopStatus;const titleNode=document.getElementById('status-title');const detailNode=document.getElementById('status-detail');if(status&&titleNode&&detailNode){{titleNode.textContent=status.title;detailNode.textContent=status.detail;}}}})();"
    )
}

fn show_loading_error(window: &WebviewWindow, title: &str, detail: &str) {
    let status = LOADING_STATUS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .set(title, detail);
    let _ = window.eval(loading_error_script(&status));
}

fn replay_loading_status(window: &WebviewWindow) {
    let status = LOADING_STATUS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .current
        .clone();
    if let Some(status) = status {
        let _ = window.eval(loading_error_script(&status));
    }
}

fn clear_loading_status() {
    LOADING_STATUS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_explicit_ipv4_loopback_console_urls() {
        assert!(validated_console_url("http://127.0.0.1:8718/").is_ok());
        assert!(validated_console_url("http://localhost:8718/").is_err());
        assert!(validated_console_url("https://127.0.0.1:8718/").is_err());
        assert!(validated_console_url("http://127.0.0.2:8718/").is_err());
        assert!(validated_console_url("http://example.com:8718/").is_err());
        assert!(validated_console_url("http://127.0.0.1/").is_err());
        assert!(validated_console_url("http://127.0.0.1:8718/other").is_err());
        assert!(validated_console_url("http://127.0.0.1:8718/?token=nope").is_err());
    }

    #[test]
    fn validates_instance_key_shape() {
        assert!(validate_instance_key(&"a".repeat(64)).is_ok());
        assert!(validate_instance_key(&"g".repeat(64)).is_err());
        assert!(validate_instance_key(&"a".repeat(63)).is_err());
    }

    #[test]
    fn loading_status_keeps_only_the_latest_update() {
        let mut state = LoadingStatusState::default();
        let first = state.set("First", "Old detail");
        let second = state.set("Second", "New detail");

        assert!(second.generation > first.generation);
        assert_eq!(state.current, Some(second.clone()));

        state.clear();
        assert!(state.current.is_none());

        let third = state.set("Third", "After navigation");
        assert!(third.generation > second.generation);
    }

    #[test]
    fn loading_error_script_escapes_status_content() {
        let title = "Needs \"attention\"";
        let detail = "Retry after startup\nwithout widening access.";
        let script = loading_error_script(&LoadingStatus {
            generation: 17,
            title: title.into(),
            detail: detail.into(),
        });

        let title_json = serde_json::to_string(title).unwrap();
        let detail_json = serde_json::to_string(detail).unwrap();
        assert!(script.contains(&format!(
            "generation:17,title:{title_json},detail:{detail_json}"
        )));
        assert!(script.contains("Number(current.generation)<=next.generation"));
        assert!(script.contains("if(status&&titleNode&&detailNode)"));
        assert!(!script.contains("Retry after startup\nwithout"));
    }

    #[test]
    fn distinguishes_explicit_authority_from_default_launches() {
        let settings = DesktopSettings::from_args([
            "--authority".into(),
            "SGW_HOME=/tmp/sgw-primary".into(),
            "--authority".into(),
            "SGW_RECOVERY_HOME=/tmp/sgw-recovery".into(),
            "--console-url".into(),
            "http://127.0.0.1:9123/".into(),
            "--instance-key".into(),
            "a".repeat(64),
        ])
        .unwrap();
        assert!(settings
            .authority_env
            .contains(&("SGW_HOME".into(), "/tmp/sgw-primary".into())));
        assert!(settings
            .authority_env
            .contains(&("SGW_RECOVERY_HOME".into(), "/tmp/sgw-recovery".into())));
        assert!(!instance_keys_conflict(Some(&"a".repeat(64)), None));

        let defaults = DesktopSettings::from_args(["--authority-args".into()]).unwrap();
        assert!(defaults.authority_env.is_empty());
    }

    #[test]
    fn requires_matching_health_identity() {
        let key = "a".repeat(64);
        let body = format!(r#"{{"ok":true,"name":"s-gw","instanceKey":"{key}"}}"#);
        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}");
        assert_eq!(
            parse_health_response(response.as_bytes(), &key),
            ConsoleState::Matching
        );
        assert_eq!(
            parse_health_response(response.as_bytes(), &"b".repeat(64)),
            ConsoleState::WrongInstance
        );
    }

    #[test]
    fn rejects_non_success_health_responses() {
        let key = "a".repeat(64);
        let response = format!(
            "HTTP/1.1 503 Service Unavailable\r\n\r\n{{\"ok\":true,\"name\":\"s-gw\",\"instanceKey\":\"{key}\"}}"
        );
        assert_eq!(
            parse_health_response(response.as_bytes(), &key),
            ConsoleState::Foreign
        );
    }

    #[test]
    fn accepts_chunked_health_responses() {
        let key = "a".repeat(64);
        let body = format!(r#"{{"ok":true,"name":"s-gw","instanceKey":"{key}"}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            body.len(),
            body
        );
        assert_eq!(
            parse_health_response(response.as_bytes(), &key),
            ConsoleState::Matching
        );
    }

    #[test]
    fn rejects_overflowing_chunk_sizes() {
        let key = "a".repeat(64);
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n";
        assert_eq!(parse_health_response(response, &key), ConsoleState::Foreign);
    }
}
