use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::io::{self, Read};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_TRUNCATED: &str = "\n<<SGW_OUTPUT_TRUNCATED>>";
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SECRET_BYTES: usize = 1024 * 1024;

const CHILD_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LOGNAME",
    "NO_COLOR",
    "PATH",
    "SHELL",
    "TERM",
    "TMPDIR",
    "USER",
    "USERPROFILE",
    "SYSTEMROOT",
    "WINDIR",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteRequest {
    pub version: u8,
    pub request_id: String,
    pub handle: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub inject_env: String,
    pub secret_value: String,
    #[serde(default)]
    pub env: Vec<EnvSecret>,
    pub working_dir: Option<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvSecret {
    pub handle: String,
    pub inject_env: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionSummary {
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub proof: String,
    pub duration_ms: u64,
    pub timeout_ms: u64,
    pub timed_out: bool,
    pub sanitized: bool,
}

pub fn execute(request: ExecuteRequest) -> Result<ExecutionSummary, String> {
    validate_request(&request)?;

    let started = Instant::now();
    let mut command = Command::new(&request.command);
    command
        .args(&request.args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for name in CHILD_ENV_ALLOWLIST {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    if env::var_os("PATH").is_none() {
        command.env("PATH", default_path());
    }

    command.env(&request.inject_env, &request.secret_value);
    for item in &request.env {
        command.env(&item.inject_env, &item.value);
    }
    if let Some(working_dir) = request.working_dir.as_deref() {
        command.current_dir(working_dir);
    }

    let mut child = command
        .spawn()
        .map_err(|error| format!("Unable to start approved command: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or("Approved command stdout was unavailable.")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Approved command stderr was unavailable.")?;

    let longest_secret = request
        .env
        .iter()
        .map(|item| item.value.len())
        .chain(std::iter::once(request.secret_value.len()))
        .max()
        .unwrap_or(0);
    let capture_cap = request.max_output_bytes.saturating_add(longest_secret);
    let stdout_reader = thread::spawn(move || read_bounded(stdout, capture_cap));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, capture_cap));

    let (status, timed_out) = wait_for_child(&mut child, request.timeout_ms)?;
    let stdout_bytes = join_reader(stdout_reader, "stdout")?;
    let stderr_bytes = join_reader(stderr_reader, "stderr")?;
    let raw_stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let raw_stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

    let mut secrets = Vec::with_capacity(request.env.len() + 1);
    secrets.push((&request.handle, &request.secret_value));
    for item in &request.env {
        secrets.push((&item.handle, &item.value));
    }
    secrets.sort_by_key(|item| std::cmp::Reverse(item.1.len()));

    let sanitized_stdout = sanitize_known_secrets(&raw_stdout, &secrets);
    let sanitized_stderr = sanitize_known_secrets(&raw_stderr, &secrets);
    let clean_stdout = cap_utf8_bytes(&sanitized_stdout, request.max_output_bytes);
    let clean_stderr = cap_utf8_bytes(&sanitized_stderr, request.max_output_bytes);
    let sanitized = sanitized_stdout != raw_stdout || sanitized_stderr != raw_stderr;

    Ok(ExecutionSummary {
        exit_code: if timed_out { Some(124) } else { status.code() },
        signal: signal_name(&status),
        proof: proof_for(
            &request.request_id,
            &request.handle,
            &clean_stdout,
            &clean_stderr,
        ),
        stdout: clean_stdout,
        stderr: clean_stderr,
        duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        timeout_ms: request.timeout_ms,
        timed_out,
        sanitized,
    })
}

fn validate_request(request: &ExecuteRequest) -> Result<(), String> {
    if request.version != 1 {
        return Err("Unsupported s-gw core protocol version.".into());
    }
    if request.request_id.is_empty() || request.handle.is_empty() || request.command.is_empty() {
        return Err("Execution request is missing required fields.".into());
    }
    validate_env_name(&request.inject_env)?;
    if request.secret_value.is_empty() || request.secret_value.len() > MAX_SECRET_BYTES {
        return Err("Primary credential has an unsupported size.".into());
    }
    if request.max_output_bytes == 0 || request.max_output_bytes > MAX_OUTPUT_BYTES {
        return Err("Output limit is outside the supported range.".into());
    }
    for item in &request.env {
        if item.handle.is_empty() || item.value.is_empty() || item.value.len() > MAX_SECRET_BYTES {
            return Err("Additional credential has invalid metadata or size.".into());
        }
        validate_env_name(&item.inject_env)?;
    }
    Ok(())
}

fn validate_env_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err("Credential environment name is empty.".into());
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|value| value == '_' || value.is_ascii_alphanumeric())
    {
        return Err("Credential environment name is invalid.".into());
    }
    Ok(())
}

fn wait_for_child(
    child: &mut std::process::Child,
    timeout_ms: u64,
) -> Result<(ExitStatus, bool), String> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("Unable to read approved command status: {error}"))?
        {
            return Ok((status, false));
        }

        if timeout_ms > 0 && started.elapsed() >= Duration::from_millis(timeout_ms) {
            child
                .kill()
                .map_err(|error| format!("Unable to stop timed-out approved command: {error}"))?;
            let status = child
                .wait()
                .map_err(|error| format!("Unable to reap timed-out approved command: {error}"))?;
            return Ok((status, true));
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn read_bounded<R: Read>(mut reader: R, limit: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if output.len() < limit {
            let keep = read.min(limit - output.len());
            output.extend_from_slice(&chunk[..keep]);
        }
    }
    Ok(output)
}

fn join_reader(
    reader: thread::JoinHandle<io::Result<Vec<u8>>>,
    stream: &str,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| format!("Approved command {stream} reader stopped unexpectedly."))?
        .map_err(|error| format!("Unable to read approved command {stream}: {error}"))
}

pub fn sanitize_known_secrets(text: &str, pairs: &[(&String, &String)]) -> String {
    let mut output = text.to_owned();
    for (handle, value) in pairs {
        if value.is_empty() {
            continue;
        }
        output = output.replace(value.as_str(), &token_for_handle(handle));
    }
    output
}

fn token_for_handle(handle: &str) -> String {
    format!("<<SGW_SECRET:{handle}>>")
}

fn cap_utf8_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }

    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &text[..end], OUTPUT_TRUNCATED)
}

pub fn proof_for(request_id: &str, handle: &str, stdout: &str, stderr: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request_id.as_bytes());
    hasher.update(handle.as_bytes());
    hasher.update(stdout.as_bytes());
    hasher.update(stderr.as_bytes());
    let digest = URL_SAFE_NO_PAD.encode(hasher.finalize());
    format!("s-gw-proof:{request_id}:{}", &digest[..24])
}

fn default_path() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\System32;C:\Windows"
    } else {
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
    }
}

#[cfg(unix)]
fn signal_name(status: &ExitStatus) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map(|signal| match signal {
        1 => "SIGHUP".to_owned(),
        2 => "SIGINT".to_owned(),
        3 => "SIGQUIT".to_owned(),
        6 => "SIGABRT".to_owned(),
        9 => "SIGKILL".to_owned(),
        11 => "SIGSEGV".to_owned(),
        13 => "SIGPIPE".to_owned(),
        14 => "SIGALRM".to_owned(),
        15 => "SIGTERM".to_owned(),
        value => format!("SIG{value}"),
    })
}

#[cfg(not(unix))]
fn signal_name(_status: &ExitStatus) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_matches_the_existing_protocol() {
        assert_eq!(
            proof_for("req_123", "s-gw:api-token:abc", "hello\n", ""),
            "s-gw-proof:req_123:MQqJU0gJIRILpu2hqA8F2MEZ"
        );
    }

    #[test]
    fn longest_secret_is_sanitized_first() {
        let short_handle = "s-gw:credential:short".to_owned();
        let short = "secret".to_owned();
        let long_handle = "s-gw:credential:long".to_owned();
        let long = "secret-value".to_owned();
        let pairs = vec![(&long_handle, &long), (&short_handle, &short)];

        assert_eq!(
            sanitize_known_secrets("secret-value secret", &pairs),
            "<<SGW_SECRET:s-gw:credential:long>> <<SGW_SECRET:s-gw:credential:short>>"
        );
    }

    #[test]
    fn byte_cap_preserves_utf8_boundaries() {
        assert_eq!(cap_utf8_bytes("abcéz", 4), format!("abc{OUTPUT_TRUNCATED}"));
    }
}
