use crate::model::{
    AgentProfile, DesktopSnapshot, HandleSummary, PolicyRule, RequestRecord, StatusSnapshot,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
#[cfg(any(target_os = "windows", test))]
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::env;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::TOKEN_QUERY;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;

const DEFAULT_CONSOLE_URL: &str = "http://127.0.0.1:8718/";
const MAX_CLI_OUTPUT: usize = 8 * 1024 * 1024;

const AUTHORITY_ENV_NAMES: [&str; 7] = [
    "SGW_EXECUTION_ENGINE",
    "SGW_HOME",
    "SGW_KEYCHAIN_ACCOUNT",
    "SGW_KEYCHAIN_SERVICE",
    "SGW_RECOVERY_HOME",
    "SGW_SECRET_BACKEND",
    "SGW_SECRET_KEYCHAIN_SERVICE",
];

#[derive(Clone, Debug)]
pub struct DesktopSettings {
    pub authority_env: Vec<(String, String)>,
    pub background: bool,
    pub browser: bool,
    pub cli_path: Option<PathBuf>,
    pub console_url: Url,
    pub expected_instance_key: Option<String>,
    pub node_path: Option<PathBuf>,
}

impl DesktopSettings {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut authority_env = Vec::new();
        let mut authority_args = false;
        let mut background = false;
        let mut browser = false;
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
                "--browser" => browser = true,
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
            browser,
            cli_path,
            console_url,
            expected_instance_key,
            node_path,
        })
    }

    pub fn single_instance_name(&self, runtime_key: Option<&str>) -> String {
        if let Some(key) = runtime_key.or(self.expected_instance_key.as_deref()) {
            return format!("com.s-gw.desktop.{key}");
        }

        let mut identity = String::new();
        for (name, value) in &self.authority_env {
            identity.push_str(name);
            identity.push('=');
            identity.push_str(value);
            identity.push('\n');
        }
        let digest = Sha256::digest(identity.as_bytes());
        format!("com.s-gw.desktop.{digest:x}")
    }
}

#[derive(Clone, Debug)]
pub enum CliRuntime {
    Node { node: PathBuf, cli: PathBuf },
    PathCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleState {
    Matching,
    Unavailable,
    Foreign,
    WrongInstance,
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    #[serde(rename = "instanceKey")]
    instance_key: String,
    name: String,
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct InstanceKeyResponse {
    #[serde(rename = "instanceKey")]
    instance_key: Option<String>,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WindowsInstanceIdentity {
    platform: &'static str,
    user: WindowsInstanceUser,
    home: String,
    recovery_home: String,
    keychain_service: &'static str,
    keychain_account: String,
    secret_backend: &'static str,
    secret_keychain_service: &'static str,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Serialize)]
struct WindowsInstanceUser {
    username: String,
    home: String,
    uid: i32,
    gid: i32,
}

pub fn apply_runtime_environment(settings: &DesktopSettings) {
    for name in AUTHORITY_ENV_NAMES {
        env::remove_var(name);
    }
    for (name, value) in &settings.authority_env {
        env::set_var(name, value);
    }
    clear_sensitive_environment();
}

pub fn resolve_runtime(settings: &DesktopSettings) -> Result<CliRuntime, String> {
    if let (Some(node), Some(cli)) = (&settings.node_path, &settings.cli_path) {
        if node.is_file() && cli.is_file() {
            return Ok(CliRuntime::Node {
                node: node.clone(),
                cli: cli.clone(),
            });
        }
        return Err("The configured s-gw runtime is incomplete.".into());
    }

    for root in packaged_runtime_roots() {
        let node = packaged_node_path(&root);
        let cli = root.join("package/dist/cli.js");
        if node.is_file() && cli.is_file() {
            return Ok(CliRuntime::Node { node, cli });
        }
    }

    if cfg!(debug_assertions) && command_exists("s-gw") {
        return Ok(CliRuntime::PathCommand);
    }

    Err("s-gw runtime is missing. Reinstall the desktop application.".into())
}

fn packaged_runtime_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(executable) = env::current_exe() {
        if let Some(parent) = executable.parent() {
            roots.push(parent.join("runtime"));
            roots.push(parent.join("s-gw/runtime"));
        }
    }
    if cfg!(target_os = "linux") {
        roots.push(PathBuf::from("/usr/lib/s-gw/runtime"));
    }
    if cfg!(debug_assertions) {
        roots.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("runtime"));
    }
    roots
}

#[cfg(target_os = "windows")]
fn packaged_node_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("node/node.exe")
}

#[cfg(not(target_os = "windows"))]
fn packaged_node_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join("node/bin/node")
}

pub fn fetch_snapshot(
    runtime: &CliRuntime,
    settings: &DesktopSettings,
) -> Result<DesktopSnapshot, String> {
    let status: StatusSnapshot = run_json(runtime, &["status"])?;
    let expected_key = settings
        .expected_instance_key
        .clone()
        .or_else(|| runtime_instance_key(runtime));
    if let (Some(expected), Some(actual)) =
        (expected_key.as_deref(), status.instance_key.as_deref())
    {
        if actual != expected {
            return Err("The packaged runtime belongs to a different s-gw credential home.".into());
        }
    }

    let mut handles: Vec<HandleSummary> = run_json(runtime, &["secret", "list"])?;
    let mut requests: Vec<RequestRecord> = run_json(runtime, &["requests"])?;
    let mut policies: Vec<PolicyRule> = run_json(runtime, &["approval", "policy", "list"])?;
    let mut agents: Vec<AgentProfile> = run_json(runtime, &["agent", "list"])?;
    handles.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    requests.sort_by(|left, right| right.sort_key().cmp(left.sort_key()));
    policies.sort_by_key(|value| value.priority);
    agents.sort_by(|left, right| left.display_name.cmp(&right.display_name));

    let daemon_running = expected_key
        .as_deref()
        .is_some_and(|key| probe_console(&settings.console_url, key) == ConsoleState::Matching);
    Ok(DesktopSnapshot {
        status,
        handles,
        requests,
        policies,
        agents,
        daemon_running,
    })
}

pub fn approve_request(runtime: &CliRuntime, request_id: &str) -> Result<String, String> {
    require_identifier(request_id)?;
    run_cli(
        runtime,
        &[
            "approve",
            request_id,
            "--mode",
            "per-transaction",
            "--agent-scope",
            "same-agent",
        ],
        None,
    )?;
    Ok("Request approved once.".into())
}

pub fn deny_request(runtime: &CliRuntime, request_id: &str) -> Result<String, String> {
    require_identifier(request_id)?;
    run_cli(runtime, &["deny", request_id], None)?;
    Ok("Request denied.".into())
}

pub fn add_secret(
    runtime: &CliRuntime,
    name: &str,
    kind: &str,
    inject_env: &str,
    value: &str,
) -> Result<String, String> {
    let name = require_text(name, "Credential name")?;
    let kind = require_text(kind, "Credential type")?;
    if value.is_empty() {
        return Err("Credential value is required.".into());
    }
    let mut args = vec![
        "secret",
        "add",
        "--name",
        name,
        "--type",
        kind,
        "--value-stdin",
    ];
    let inject_env = inject_env.trim();
    if !inject_env.is_empty() {
        if inject_env.len() > 256
            || !inject_env
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(
                "Environment name must use uppercase letters, numbers, and underscores.".into(),
            );
        }
        args.extend(["--inject-env", inject_env]);
    }
    run_cli(runtime, &args, Some(value.as_bytes()))?;
    Ok(format!("Added {name}."))
}

pub fn run_setup(runtime: &CliRuntime) -> Result<String, String> {
    run_cli(
        runtime,
        &[
            "setup",
            "--no-open-app",
            "--no-service",
            "--no-menubar",
            "--no-agents",
        ],
        None,
    )?;
    Ok("Local credential storage is ready.".into())
}

pub fn open_browser_backup(
    runtime: &CliRuntime,
    settings: &DesktopSettings,
) -> Result<String, String> {
    let expected_key = settings
        .expected_instance_key
        .clone()
        .or_else(|| runtime_instance_key(runtime))
        .ok_or_else(|| "s-gw could not verify the local credential home.".to_string())?;

    let mut state = probe_console(&settings.console_url, &expected_key);
    if state == ConsoleState::Unavailable {
        run_lifecycle(runtime, "start", &settings.console_url)?;
        state = wait_for_console(&settings.console_url, &expected_key, Duration::from_secs(8));
    }
    match state {
        ConsoleState::Matching => {
            open::that(settings.console_url.as_str())
                .map_err(|error| format!("Could not open the browser backup: {error}"))?;
            Ok("Opened the verified browser backup.".into())
        }
        ConsoleState::WrongInstance | ConsoleState::Foreign => {
            Err("Another service is using the s-gw port. It was left untouched.".into())
        }
        ConsoleState::Unavailable => {
            Err("The browser backup is not ready. Run setup, then try again.".into())
        }
    }
}

fn run_lifecycle(runtime: &CliRuntime, action: &str, console_url: &Url) -> Result<(), String> {
    let port = console_url
        .port_or_known_default()
        .unwrap_or(8718)
        .to_string();
    run_cli(
        runtime,
        &[action, "--port", &port, "--no-open-app", "--no-menubar"],
        None,
    )?;
    Ok(())
}

pub fn runtime_instance_key(runtime: &CliRuntime) -> Option<String> {
    let child_key = run_json::<InstanceKeyResponse>(runtime, &["__desktop-instance-key"])
        .ok()
        .and_then(|status| status.instance_key)
        .and_then(|value| validate_instance_key(&value).ok());
    if child_key.is_some() {
        return child_key;
    }

    #[cfg(target_os = "windows")]
    {
        current_windows_default_instance_key()
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

fn run_json<T: DeserializeOwned>(runtime: &CliRuntime, args: &[&str]) -> Result<T, String> {
    let raw = run_cli(runtime, args, None)?;
    serde_json::from_str(&raw)
        .map_err(|_| format!("s-gw returned invalid data for `{}`.", args.join(" ")))
}

fn run_cli(runtime: &CliRuntime, args: &[&str], input: Option<&[u8]>) -> Result<String, String> {
    let mut command = cli_command(runtime);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command
        .spawn()
        .map_err(|error| format!("Could not start the packaged s-gw runtime: {error}"))?;
    if let Some(bytes) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "Could not open secure input.".to_string())?;
        stdin
            .write_all(bytes)
            .map_err(|_| "Could not send the credential through secure input.".to_string())?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("Could not read the packaged s-gw runtime: {error}"))?;
    if output.stdout.len() > MAX_CLI_OUTPUT || output.stderr.len() > MAX_CLI_OUTPUT {
        return Err("The packaged s-gw runtime returned too much data.".into());
    }
    if output.status.success() {
        return String::from_utf8(output.stdout)
            .map_err(|_| "The packaged s-gw runtime returned invalid text.".into());
    }

    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.trim();
    if detail.is_empty() {
        Err(format!("s-gw `{}` failed.", args.join(" ")))
    } else {
        Err(detail.chars().take(1_000).collect())
    }
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
    command.env("NO_COLOR", "1");
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

pub fn probe_console(url: &Url, expected_key: &str) -> ConsoleState {
    let port = match url.port_or_known_default() {
        Some(value) => value,
        None => return ConsoleState::Foreign,
    };
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut stream = match TcpStream::connect_timeout(&address.into(), Duration::from_millis(500)) {
        Ok(value) => value,
        Err(_) => return ConsoleState::Unavailable,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
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
    let body = match response_body(headers, &response[split + 4..]) {
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

fn require_arg(items: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    items
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn require_identifier(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("Invalid request identifier.".into());
    }
    Ok(())
}

fn require_text<'a>(value: &'a str, label: &str) -> Result<&'a str, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(format!("{label} is invalid."));
    }
    Ok(value)
}

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

pub(crate) fn validated_console_url(value: &str) -> Result<Url, String> {
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

#[cfg(target_os = "windows")]
fn current_windows_default_instance_key() -> Option<String> {
    const IDENTITY_ENV_NAMES: [&str; 6] = [
        "SGW_HOME",
        "SGW_RECOVERY_HOME",
        "SGW_KEYCHAIN_SERVICE",
        "SGW_KEYCHAIN_ACCOUNT",
        "SGW_SECRET_BACKEND",
        "SGW_SECRET_KEYCHAIN_SERVICE",
    ];
    if env::var("SGW_TEST_MODE").ok().as_deref() == Some("1")
        || IDENTITY_ENV_NAMES
            .iter()
            .any(|name| env::var_os(name).is_some())
    {
        return None;
    }
    let username = current_windows_username()?;
    let token_profile = current_windows_profile()?;
    if let Some(value) = env::var_os("USERPROFILE") {
        if value.into_string().ok()?.as_str() != token_profile {
            return None;
        }
    }
    windows_default_instance_key(&username, &token_profile)
}

#[cfg(target_os = "windows")]
fn current_windows_username() -> Option<String> {
    let mut buffer = [0_u16; 257];
    let mut size = buffer.len() as u32;
    if unsafe { GetUserNameW(buffer.as_mut_ptr(), &mut size) } == 0 {
        return None;
    }
    windows_string_from_buffer(&buffer, size)
}

#[cfg(target_os = "windows")]
pub(crate) fn current_windows_profile() -> Option<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let profile = windows_profile_for_token(token);
    unsafe {
        CloseHandle(token);
    }
    profile
}

#[cfg(target_os = "windows")]
fn windows_profile_for_token(token: HANDLE) -> Option<String> {
    let mut size = 0_u32;
    unsafe {
        GetUserProfileDirectoryW(token, std::ptr::null_mut(), &mut size);
    }
    let mut buffer = windows_wide_buffer(size)?;
    if unsafe { GetUserProfileDirectoryW(token, buffer.as_mut_ptr(), &mut size) } == 0 {
        return None;
    }
    windows_string_from_buffer(&buffer, size)
}

#[cfg(target_os = "windows")]
fn windows_wide_buffer(size: u32) -> Option<Vec<u16>> {
    let len = usize::try_from(size).ok()?;
    if !(2..=32_768).contains(&len) {
        return None;
    }
    Some(vec![0_u16; len])
}

#[cfg(target_os = "windows")]
fn windows_string_from_buffer(buffer: &[u16], size: u32) -> Option<String> {
    let len = usize::try_from(size).ok()?;
    if len == 0 || len > buffer.len() {
        return None;
    }
    let content = if buffer[len - 1] == 0 {
        &buffer[..len - 1]
    } else {
        &buffer[..len]
    };
    let value = String::from_utf16(content).ok()?;
    (!value.is_empty()).then_some(value)
}

#[cfg(any(target_os = "windows", test))]
fn windows_default_instance_key(username: &str, profile: &str) -> Option<String> {
    if username.is_empty() || username.chars().any(char::is_control) {
        return None;
    }
    let bytes = profile.as_bytes();
    let drive_path =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    let unc_path = profile.starts_with("\\\\") && profile[2..].contains('\\');
    if profile.ends_with('\\')
        || profile.chars().any(char::is_control)
        || (!drive_path && !unc_path)
    {
        return None;
    }

    let home = format!("{profile}\\.s-gw");
    let identity = WindowsInstanceIdentity {
        platform: "win32",
        user: WindowsInstanceUser {
            username: username.into(),
            home: profile.into(),
            uid: -1,
            gid: -1,
        },
        recovery_home: format!("{home}-recovery"),
        home,
        keychain_service: "com.s-gw.sgw.master-passphrase",
        keychain_account: username.into(),
        secret_backend: "",
        secret_keychain_service: "com.s-gw.sgw.secret",
    };
    let encoded = serde_json::to_vec(&identity).ok()?;
    Some(format!("{:x}", Sha256::digest(encoded)))
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
        assert!(validated_console_url("http://127.0.0.1/").is_err());
        assert!(validated_console_url("http://127.0.0.1:8718/other").is_err());
    }

    #[test]
    fn matches_the_default_windows_instance_identity() {
        assert_eq!(
            windows_default_instance_key("barrydemo", "C:\\Users\\barrydemo").as_deref(),
            Some("6a77cb4cb1690e58dae1e5d7325685dd54dbaac69c0871042f9c1aef368f7a79")
        );
        assert_eq!(
            windows_default_instance_key("Zoë", "D:\\Users\\Zoë Example").as_deref(),
            Some("d09b1ad5b3cc7846d18466cb78bfa6d807c73d4c90efe1c5a55fa24fbb55d7de")
        );
        assert!(windows_default_instance_key("bad\nuser", "C:\\Users\\bad").is_none());
        assert!(windows_default_instance_key("barrydemo", "relative\\profile").is_none());
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
    fn desktop_arguments_do_not_start_the_console() {
        let settings = DesktopSettings::from_args(["--authority-args".into()]).unwrap();
        assert!(!settings.browser);
        assert_eq!(settings.console_url.as_str(), DEFAULT_CONSOLE_URL);
    }
}
