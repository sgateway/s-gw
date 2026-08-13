#[cfg(target_os = "windows")]
use crate::runtime::current_windows_profile;
use crate::runtime::validated_console_url;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MARKER_PREFIX: &str = "activate-";
const MAX_MARKER_BYTES: u64 = 1_024;
const MAX_REQUEST_AGE: Duration = Duration::from_secs(30);
const MAX_REQUEST_CLOCK_SKEW: Duration = Duration::from_secs(5);
const PENDING_PREFIX: &str = ".pending-";
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const REQUEST_VERSION: u8 = 1;

static NEXT_MARKER_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRequest {
    version: u8,
    created_unix_millis: u64,
    console_url: String,
    show_window: bool,
}

impl ActivationRequest {
    pub fn new(console_url: &str, show_window: bool) -> Result<Self, String> {
        validated_console_url(console_url)?;
        let created_unix_millis = current_unix_millis()?;
        Ok(Self {
            version: REQUEST_VERSION,
            created_unix_millis,
            console_url: console_url.into(),
            show_window,
        })
    }

    pub fn console_url(&self) -> &str {
        &self.console_url
    }

    pub fn should_show_window(&self) -> bool {
        self.show_window
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != REQUEST_VERSION {
            return Err("The desktop activation request version is unsupported.".into());
        }
        validated_console_url(&self.console_url)?;
        Ok(())
    }

    fn is_expired(&self) -> Result<bool, String> {
        let now = current_unix_millis()?;
        let max_age = MAX_REQUEST_AGE.as_millis() as u64;
        let max_skew = MAX_REQUEST_CLOCK_SKEW.as_millis() as u64;
        Ok(now.saturating_sub(self.created_unix_millis) > max_age
            || self.created_unix_millis > now.saturating_add(max_skew))
    }
}

#[derive(Debug)]
pub struct ActivationBatch {
    request: ActivationRequest,
    markers: Vec<PathBuf>,
}

impl ActivationBatch {
    pub fn request(&self) -> &ActivationRequest {
        &self.request
    }

    pub fn acknowledge(self) -> Result<(), String> {
        for marker in self.markers {
            remove_validated_marker(&marker)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ActivationTicket {
    marker: PathBuf,
}

impl ActivationTicket {
    pub fn is_acknowledged(&self) -> Result<bool, String> {
        match fs::symlink_metadata(&self.marker) {
            Ok(metadata) => {
                validate_marker(&self.marker, &metadata)?;
                Ok(false)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
            Err(error) => Err(format!(
                "Could not inspect desktop activation acknowledgement: {error}"
            )),
        }
    }

    pub fn cancel(self) -> Result<(), String> {
        remove_validated_marker(&self.marker)
    }
}

#[derive(Clone, Debug)]
pub struct ActivationChannel {
    dir: PathBuf,
    next_poll: Instant,
}

impl ActivationChannel {
    pub fn new(instance_name: &str) -> Result<Self, String> {
        Self::from_base(&activation_base_dir()?, instance_name)
    }

    fn from_base(base: &Path, instance_name: &str) -> Result<Self, String> {
        if instance_name.is_empty()
            || instance_name.len() > 160
            || !instance_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err("The desktop instance name is invalid.".into());
        }

        ensure_private_directory(base)?;
        let dir = base.join(instance_name);
        ensure_private_directory(&dir)?;
        Ok(Self {
            dir,
            next_poll: Instant::now(),
        })
    }

    pub fn signal(&self, request: &ActivationRequest) -> Result<ActivationTicket, String> {
        request.validate()?;
        let encoded = serde_json::to_vec(request)
            .map_err(|error| format!("Could not encode desktop activation request: {error}"))?;
        if encoded.len() as u64 > MAX_MARKER_BYTES {
            return Err("The desktop activation request is too large.".into());
        }

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "System clock is unavailable.".to_string())?
            .as_nanos();
        let sequence = NEXT_MARKER_ID.fetch_add(1, Ordering::Relaxed);
        let marker_id = format!("{stamp:039}-{:010}-{sequence:020}", std::process::id());
        let pending = self.dir.join(format!("{PENDING_PREFIX}{marker_id}"));
        let marker = self.dir.join(format!("{MARKER_PREFIX}{marker_id}"));
        write_new_marker(&pending, &encoded)?;
        if let Err(error) = fs::rename(&pending, &marker) {
            let _ = fs::remove_file(&pending);
            return Err(format!(
                "Could not publish desktop activation request: {error}"
            ));
        }
        Ok(ActivationTicket { marker })
    }

    pub fn poll(&mut self) -> Result<Option<ActivationBatch>, String> {
        let now = Instant::now();
        if now < self.next_poll {
            return Ok(None);
        }
        self.next_poll = now + POLL_INTERVAL;
        self.take_pending()
    }

    pub fn drain_pending(&self) -> Result<Option<ActivationBatch>, String> {
        self.take_pending()
    }

    #[cfg(target_os = "macos")]
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("instance.lock")
    }

    fn take_pending(&self) -> Result<Option<ActivationBatch>, String> {
        let mut latest = None;
        let mut accepted_markers = Vec::new();
        let mut show_window = false;
        let mut first_error = None;

        for (_, path) in finalized_markers(&self.dir)? {
            match consume_request_marker(&path) {
                Ok(Some(request)) => {
                    show_window |= request.show_window;
                    latest = Some(request);
                    accepted_markers.push(path);
                }
                Ok(None) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }

        if let Some(mut request) = latest {
            request.show_window = show_window;
            return Ok(Some(ActivationBatch {
                request,
                markers: accepted_markers,
            }));
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(None)
    }
}

fn current_unix_millis() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System clock is unavailable.".to_string())?
        .as_millis();
    u64::try_from(millis).map_err(|_| "System clock is unavailable.".to_string())
}

fn activation_base_dir() -> Result<PathBuf, String> {
    #[cfg(unix)]
    {
        Ok(std::env::temp_dir().join(format!("s-gw-desktop-activation-{}", current_euid())))
    }
    #[cfg(target_os = "windows")]
    {
        let profile = current_windows_profile()
            .ok_or_else(|| "Could not resolve the current Windows profile.".to_string())?;
        Ok(PathBuf::from(profile)
            .join("AppData")
            .join("Local")
            .join("s-gw-desktop-activation"))
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        Ok(std::env::temp_dir().join("s-gw-desktop-activation"))
    }
}

fn finalized_markers(dir: &Path) -> Result<Vec<(OsString, PathBuf)>, String> {
    let entries = fs::read_dir(dir)
        .map_err(|error| format!("Could not read desktop activation state: {error}"))?;
    let mut markers = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("Could not inspect desktop activation state: {error}"))?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|value| value.starts_with(MARKER_PREFIX))
        {
            markers.push((name, entry.path()));
        }
    }
    markers.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(markers)
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => return prepare_private_directory(path, &metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Could not inspect desktop activation directory: {error}"
            ));
        }
    }

    create_private_directory(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect desktop activation directory: {error}"))?;
    prepare_private_directory(path, &metadata)
}

fn prepare_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    validate_private_directory(path, metadata)?;
    #[cfg(target_os = "windows")]
    harden_windows_directory(path)?;
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "Could not create desktop activation directory: {error}"
        )),
    }
}

#[cfg(target_os = "windows")]
fn create_private_directory(path: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let wide = windows_path(path)?;
    let attributes_len = u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
        .map_err(|_| "The Windows security attributes are invalid.".to_string())?;
    let sid = current_windows_user_sid_string()?;
    let sddl = windows_string(&format!(
        "O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    ))?;
    let mut descriptor = std::ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 || descriptor.is_null() {
        let error = unsafe { GetLastError() };
        if !descriptor.is_null() {
            unsafe {
                LocalFree(descriptor);
            }
        }
        return Err(format!(
            "Could not build desktop activation directory permissions: {error}"
        ));
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: attributes_len,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
    let error = if created == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    unsafe {
        LocalFree(descriptor);
    }

    if created != 0 || error == ERROR_ALREADY_EXISTS {
        return Ok(());
    }
    Err(format!(
        "Could not create desktop activation directory: {error}"
    ))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn create_private_directory(path: &Path) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "Could not create desktop activation directory: {error}"
        )),
    }
}

#[cfg(target_os = "windows")]
fn current_windows_user_sid_string() -> Result<String, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!(
            "Could not inspect the current Windows user token: {}",
            unsafe { GetLastError() }
        ));
    }

    let result = (|| {
        let mut required = 0_u32;
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
        }
        let word = std::mem::size_of::<usize>();
        let words = usize::try_from(required)
            .ok()
            .and_then(|size| size.checked_add(word - 1))
            .map(|size| size / word)
            .filter(|size| *size > 0)
            .ok_or_else(|| "The current Windows user token is invalid.".to_string())?;
        let mut buffer = vec![0_usize; words];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(format!(
                "Could not read the current Windows user token: {}",
                unsafe { GetLastError() }
            ));
        }
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        windows_sid_string(token_user.User.Sid)
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}

#[cfg(target_os = "windows")]
fn windows_sid_string(sid: windows_sys::Win32::Security::PSID) -> Result<String, String> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut value = std::ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut value) };
    if converted == 0 || value.is_null() {
        let error = unsafe { GetLastError() };
        if !value.is_null() {
            unsafe {
                LocalFree(value.cast());
            }
        }
        return Err(format!(
            "Could not encode the current Windows user SID: {error}"
        ));
    }
    let result = (|| {
        let length = (0..256_usize)
            .find(|offset| unsafe { *value.add(*offset) } == 0)
            .ok_or_else(|| "The current Windows user SID is invalid.".to_string())?;
        String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
            .map_err(|_| "The current Windows user SID is invalid.".to_string())
    })();
    unsafe {
        LocalFree(value.cast());
    }
    result
}

#[cfg(unix)]
fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "Desktop activation directory is not a private directory: {}",
            path.display()
        ));
    }
    if metadata.uid() != current_euid() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "Desktop activation directory has unsafe ownership or permissions: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "Desktop activation directory is not a private directory: {}",
            path.display()
        ));
    }
    validate_windows_directory_owner(path)
}

#[cfg(target_os = "windows")]
fn validate_windows_directory_owner(path: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let wide = windows_path(path)?;
    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || owner.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe {
                LocalFree(descriptor);
            }
        }
        return Err(format!(
            "Could not inspect desktop activation directory ownership: {status}"
        ));
    }

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        let error = unsafe { GetLastError() };
        unsafe {
            LocalFree(descriptor);
        }
        return Err(format!(
            "Could not inspect the current Windows user token: {error}"
        ));
    }

    let mut required = 0_u32;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
    }
    let word = std::mem::size_of::<usize>();
    let words = usize::try_from(required)
        .ok()
        .and_then(|size| size.checked_add(word - 1))
        .map(|size| size / word)
        .filter(|size| *size > 0)
        .ok_or_else(|| "The current Windows user token is invalid.".to_string());
    let same_owner = match words {
        Ok(words) => {
            let mut buffer = vec![0_usize; words];
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    required,
                    &mut required,
                )
            } == 0
            {
                Err(format!(
                    "Could not read the current Windows user token: {}",
                    unsafe { GetLastError() }
                ))
            } else {
                let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
                Ok(unsafe { EqualSid(token_user.User.Sid, owner) } != 0)
            }
        }
        Err(error) => Err(error),
    };

    unsafe {
        CloseHandle(token);
        LocalFree(descriptor);
    }
    match same_owner {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "Desktop activation directory belongs to a different Windows user: {}",
            path.display()
        )),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "windows")]
fn harden_windows_directory(path: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let mut wide = windows_path(path)?;
    let sddl = windows_string("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(format!(
            "Could not build desktop activation directory permissions: {}",
            unsafe { GetLastError() }
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    let dacl_ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } != 0
        && dacl_present != 0
        && !dacl.is_null();
    if !dacl_ok {
        let error = unsafe { GetLastError() };
        unsafe {
            LocalFree(descriptor);
        }
        return Err(format!(
            "Could not read desktop activation directory permissions: {error}"
        ));
    }

    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "Could not secure desktop activation directory: {status}"
        ));
    }
    validate_windows_directory_acl(path)
}

#[cfg(target_os = "windows")]
fn validate_windows_directory_acl(path: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    };

    let wide = windows_path(path)?;
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe {
                LocalFree(descriptor);
            }
        }
        return Err(format!(
            "Could not verify desktop activation directory permissions: {status}"
        ));
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    let control_ok =
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0;
    let ace_count = unsafe { (*dacl).AceCount };
    unsafe {
        LocalFree(descriptor);
    }
    if !control_ok || control & SE_DACL_PROTECTED == 0 || ace_count != 3 {
        return Err(format!(
            "Desktop activation directory permissions are unsafe: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_path(path: &Path) -> Result<Vec<u16>, String> {
    use std::os::windows::ffi::OsStrExt;

    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.is_empty() || value.contains(&0) {
        return Err("The desktop activation directory path is invalid.".into());
    }
    value.push(0);
    Ok(value)
}

#[cfg(target_os = "windows")]
fn windows_string(value: &str) -> Result<Vec<u16>, String> {
    if value.is_empty() || value.encode_utf16().any(|part| part == 0) {
        return Err("The Windows security descriptor is invalid.".into());
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "Desktop activation directory is not a private directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn write_new_marker(path: &Path, content: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut marker = options
        .open(path)
        .map_err(|error| format!("Could not create desktop activation marker: {error}"))?;
    marker
        .write_all(content)
        .and_then(|_| marker.flush())
        .map_err(|error| format!("Could not write desktop activation marker: {error}"))
}

fn consume_request_marker(path: &Path) -> Result<Option<ActivationRequest>, String> {
    let content = match read_validated_marker(path) {
        Ok(content) => content,
        Err(error) => {
            remove_marker(path)?;
            return Err(error);
        }
    };
    let request: ActivationRequest = match serde_json::from_slice(&content) {
        Ok(request) => request,
        Err(_) => {
            remove_marker(path)?;
            return Err("The desktop activation request is malformed.".into());
        }
    };
    if let Err(error) = request.validate() {
        remove_marker(path)?;
        return Err(error);
    }
    match request.is_expired() {
        Ok(true) => {
            remove_marker(path)?;
            return Ok(None);
        }
        Ok(false) => {}
        Err(error) => {
            remove_marker(path)?;
            return Err(error);
        }
    }
    Ok(Some(request))
}

fn read_validated_marker(path: &Path) -> Result<Vec<u8>, String> {
    let expected = marker_metadata(path)?;
    validate_marker(path, &expected)?;
    if expected.len() > MAX_MARKER_BYTES {
        return Err("The desktop activation request is too large.".into());
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("Could not open desktop activation marker: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("Could not inspect desktop activation marker: {error}"))?;
    validate_marker(path, &opened)?;
    validate_same_marker(path, &expected, &opened)?;

    let mut content = Vec::with_capacity(opened.len().min(MAX_MARKER_BYTES) as usize);
    file.take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|error| format!("Could not read desktop activation marker: {error}"))?;
    if content.len() as u64 > MAX_MARKER_BYTES {
        return Err("The desktop activation request is too large.".into());
    }
    Ok(content)
}

fn marker_metadata(path: &Path) -> Result<fs::Metadata, String> {
    fs::symlink_metadata(path)
        .map_err(|error| format!("Could not inspect desktop activation marker: {error}"))
}

fn remove_validated_marker(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "Could not inspect desktop activation marker: {error}"
            ));
        }
    };
    validate_marker(path, &metadata)?;
    remove_marker(path)
}

fn remove_marker(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "Could not consume desktop activation marker: {error}"
        )),
    }
}

#[cfg(unix)]
fn validate_same_marker(
    path: &Path,
    expected: &fs::Metadata,
    opened: &fs::Metadata,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if expected.dev() != opened.dev() || expected.ino() != opened.ino() {
        return Err(format!(
            "Desktop activation marker changed while opening: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_marker(
    _path: &Path,
    _expected: &fs::Metadata,
    _opened: &fs::Metadata,
) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn validate_marker(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !metadata.is_file()
        || metadata.uid() != current_euid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "Desktop activation marker is unsafe: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn validate_marker(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "Desktop activation marker is unsafe: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn validate_marker(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    if !metadata.is_file() {
        return Err(format!(
            "Desktop activation marker is unsafe: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn current_euid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "s-gw-activation-{label}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn request(port: u16, show_window: bool) -> ActivationRequest {
        ActivationRequest::new(&format!("http://127.0.0.1:{port}/"), show_window)
            .expect("valid request")
    }

    fn remove_test_root(channel: &ActivationChannel, root: &Path) {
        fs::remove_dir(&channel.dir).expect("remove test instance");
        fs::remove_dir(root).expect("remove test root");
    }

    #[test]
    fn request_is_consumed_once() {
        let root = test_root("round-trip");
        let channel = ActivationChannel::from_base(&root, "instance").expect("create channel");
        let sent = request(8718, true);
        let ticket = channel.signal(&sent).expect("signal channel");

        let batch = channel
            .take_pending()
            .expect("consume marker")
            .expect("activation request");
        assert_eq!(batch.request(), &sent);
        assert!(!ticket.is_acknowledged().expect("pending acknowledgement"));
        batch.acknowledge().expect("acknowledge request");
        assert!(ticket.is_acknowledged().expect("request acknowledged"));
        assert!(channel.take_pending().expect("marker is gone").is_none());
        remove_test_root(&channel, &root);
    }

    #[test]
    fn rapid_requests_keep_the_latest_url_and_any_show_request() {
        let root = test_root("rapid");
        let channel = ActivationChannel::from_base(&root, "instance").expect("create channel");
        channel.signal(&request(9812, true)).expect("first signal");
        channel
            .signal(&request(9813, false))
            .expect("second signal");

        let batch = channel
            .take_pending()
            .expect("consume markers")
            .expect("activation request");
        let received = batch.request();
        assert_eq!(received.console_url(), "http://127.0.0.1:9813/");
        assert!(received.should_show_window());
        batch.acknowledge().expect("acknowledge requests");
        remove_test_root(&channel, &root);
    }

    #[test]
    fn fresh_requests_survive_channel_recreation() {
        let root = test_root("recreated");
        let old = ActivationChannel::from_base(&root, "instance").expect("old channel");
        let ticket = old.signal(&request(8718, true)).expect("old signal");

        let current = ActivationChannel::from_base(&root, "instance").expect("current channel");
        let batch = current
            .take_pending()
            .expect("read pending marker")
            .expect("activation request");
        assert_eq!(batch.request().console_url(), "http://127.0.0.1:8718/");
        batch.acknowledge().expect("acknowledge request");
        assert!(ticket.is_acknowledged().expect("request acknowledged"));
        remove_test_root(&current, &root);
    }

    #[test]
    fn one_promoted_secondary_acknowledges_all_fresh_requests() {
        let root = test_root("multiple-secondaries");
        let first = ActivationChannel::from_base(&root, "instance").expect("first channel");
        let second = ActivationChannel::from_base(&root, "instance").expect("second channel");
        let first_ticket = first.signal(&request(9812, true)).expect("first request");
        let second_ticket = second
            .signal(&request(9813, false))
            .expect("second request");

        let batch = second
            .take_pending()
            .expect("read requests")
            .expect("activation batch");
        assert_eq!(batch.request().console_url(), "http://127.0.0.1:9813/");
        assert!(batch.request().should_show_window());
        batch.acknowledge().expect("acknowledge requests");
        assert!(first_ticket.is_acknowledged().expect("first acknowledged"));
        assert!(second_ticket
            .is_acknowledged()
            .expect("second acknowledged"));
        remove_test_root(&second, &root);
    }

    #[test]
    fn pending_files_are_ignored_until_published() {
        let root = test_root("pending");
        let channel = ActivationChannel::from_base(&root, "instance").expect("create channel");
        let pending = channel.dir.join(".pending-test");
        let marker = channel.dir.join("activate-test");
        let encoded = serde_json::to_vec(&request(8718, true)).expect("encode request");
        write_new_marker(&pending, &encoded).expect("write pending marker");

        assert!(channel.take_pending().expect("ignore pending").is_none());
        fs::rename(&pending, &marker).expect("publish marker");
        channel
            .take_pending()
            .expect("consume marker")
            .expect("activation request")
            .acknowledge()
            .expect("acknowledge request");
        remove_test_root(&channel, &root);
    }

    #[test]
    fn malformed_marker_does_not_block_a_later_request() {
        let root = test_root("malformed");
        let channel = ActivationChannel::from_base(&root, "instance").expect("create channel");
        let marker = channel.dir.join("activate-malformed");
        let mut invalid = request(8718, true);
        invalid.console_url = "http://example.com/".into();
        write_new_marker(
            &marker,
            &serde_json::to_vec(&invalid).expect("encode invalid request"),
        )
        .expect("write invalid request");

        assert!(channel.take_pending().is_err());
        channel.signal(&request(9812, true)).expect("valid signal");
        let batch = channel
            .take_pending()
            .expect("consume valid marker")
            .expect("valid request");
        assert_eq!(batch.request().console_url(), "http://127.0.0.1:9812/");
        batch.acknowledge().expect("acknowledge request");
        remove_test_root(&channel, &root);
    }

    #[test]
    fn expired_request_is_removed_without_activation() {
        let root = test_root("expired");
        let channel = ActivationChannel::from_base(&root, "instance").expect("create channel");
        let marker = channel.dir.join("activate-expired");
        let mut expired = request(8718, true);
        expired.created_unix_millis = 0;
        write_new_marker(
            &marker,
            &serde_json::to_vec(&expired).expect("encode expired request"),
        )
        .expect("write expired request");

        assert!(channel.take_pending().expect("consume expired").is_none());
        assert!(!marker.exists());
        remove_test_root(&channel, &root);
    }

    #[test]
    fn oversized_marker_is_consumed_without_blocking_later_requests() {
        let root = test_root("oversized");
        let channel = ActivationChannel::from_base(&root, "instance").expect("create channel");
        let marker = channel.dir.join("activate-oversized");
        write_new_marker(&marker, &vec![b'x'; MAX_MARKER_BYTES as usize + 1])
            .expect("write oversized request");

        assert!(channel.take_pending().is_err());
        assert!(!marker.exists());
        channel.signal(&request(9812, false)).expect("valid signal");
        channel
            .take_pending()
            .expect("consume valid marker")
            .expect("valid request")
            .acknowledge()
            .expect("acknowledge request");
        remove_test_root(&channel, &root);
    }

    #[test]
    fn shutdown_handoff_keeps_an_unacknowledged_request_for_the_next_primary() {
        let root = test_root("shutdown-handoff");
        let primary = ActivationChannel::from_base(&root, "instance").expect("primary channel");
        let secondary = ActivationChannel::from_base(&root, "instance").expect("secondary channel");
        let ticket = secondary
            .signal(&request(9812, true))
            .expect("activation request");

        drop(primary);
        assert!(!ticket.is_acknowledged().expect("request still pending"));
        let batch = secondary
            .take_pending()
            .expect("read handoff request")
            .expect("handoff request");
        assert_eq!(batch.request().console_url(), "http://127.0.0.1:9812/");
        batch.acknowledge().expect("acknowledge handoff");
        assert!(ticket.is_acknowledged().expect("handoff acknowledged"));
        remove_test_root(&secondary, &root);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_activation_directories_have_protected_current_user_acls() {
        let root = test_root("windows-acl");
        let channel = ActivationChannel::from_base(&root, "instance").expect("create channel");

        validate_windows_directory_owner(&root).expect("root owner");
        validate_windows_directory_acl(&root).expect("root ACL");
        validate_windows_directory_owner(&channel.dir).expect("instance owner");
        validate_windows_directory_acl(&channel.dir).expect("instance ACL");

        remove_test_root(&channel, &root);
    }

    #[cfg(unix)]
    #[test]
    fn marker_creation_never_follows_a_symlink() {
        use std::os::unix::fs::{symlink, DirBuilderExt};

        let root = test_root("marker-symlink");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("create root");
        let victim = root.join("victim");
        let marker = root.join("marker");
        fs::write(&victim, "unchanged").expect("write victim");
        symlink(&victim, &marker).expect("create symlink");

        let result = write_new_marker(&marker, b"replacement");
        let content = fs::read_to_string(&victim).expect("read victim");
        fs::remove_file(marker).expect("remove marker");
        fs::remove_file(victim).expect("remove victim");
        fs::remove_dir(root).expect("remove root");

        assert!(result.is_err());
        assert_eq!(content, "unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn marker_reader_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let root = test_root("read-symlink");
        let channel = ActivationChannel::from_base(&root, "instance").expect("create channel");
        let victim = channel.dir.join("victim");
        let marker = channel.dir.join("activate-symlink");
        fs::write(&victim, serde_json::to_vec(&request(8718, true)).unwrap())
            .expect("write victim");
        symlink(&victim, &marker).expect("create symlink");

        assert!(channel.take_pending().is_err());
        assert!(!marker.exists());
        fs::remove_file(victim).expect("remove victim");
        remove_test_root(&channel, &root);
    }

    #[cfg(unix)]
    #[test]
    fn activation_directory_rejects_symlinks_and_open_permissions() {
        use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};

        let open_root = test_root("open-mode");
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&open_root)
            .expect("create open root");
        fs::set_permissions(&open_root, fs::Permissions::from_mode(0o755))
            .expect("set open permissions");
        let open_result = ActivationChannel::from_base(&open_root, "instance");

        let symlink_root = test_root("dir-symlink");
        let real_root = test_root("dir-real");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&real_root)
            .expect("create real root");
        symlink(&real_root, &symlink_root).expect("create root symlink");
        let symlink_result = ActivationChannel::from_base(&symlink_root, "instance");

        fs::remove_dir(open_root).expect("remove open root");
        fs::remove_file(symlink_root).expect("remove root symlink");
        fs::remove_dir(real_root).expect("remove real root");

        assert!(open_result.is_err());
        assert!(symlink_result.is_err());
    }
}
