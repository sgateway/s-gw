use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeMetadata {
    kind: String,
    node_version: String,
    package: String,
    target: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeConfig {
    node_version: String,
}

#[derive(Deserialize)]
struct PackageInfo {
    name: String,
    version: String,
}

fn main() {
    validate_release_runtime();
    tauri_build::build()
}

fn validate_release_runtime() {
    if env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }
    let target = desktop_target();

    let app_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing app root"));
    let runtime_root = app_root.join("runtime");
    let metadata: RuntimeMetadata = read_json(&runtime_root.join("metadata.json"));
    let runtime_config: RuntimeConfig = read_json(&app_root.join("runtime.json"));
    let package_info: PackageInfo = read_json(&runtime_root.join("package/package.json"));

    require(
        metadata.kind == "s-gw-desktop-runtime",
        "invalid desktop runtime kind",
    );
    require(
        metadata.target == target,
        "desktop runtime target does not match the Rust target",
    );
    require(
        metadata.package == "@s-gw/s-gw",
        "invalid embedded package name",
    );
    require(
        metadata.package == package_info.name,
        "runtime metadata package mismatch",
    );
    require(
        metadata.version == package_info.version,
        "runtime metadata version mismatch",
    );
    require(
        metadata.version == env::var("CARGO_PKG_VERSION").unwrap_or_default(),
        "embedded package version does not match the desktop app",
    );
    require(
        metadata.node_version == runtime_config.node_version,
        "embedded Node version does not match runtime.json",
    );

    require_file(&runtime_root.join("package/dist/cli.js"), None);
    require_file(&runtime_root.join("package/dist/mcp-server.js"), None);
    require_file(
        &runtime_root.join("package/dist/console-ui/index.html"),
        None,
    );
    require_dir(&runtime_root.join("package/node_modules"));
    require_file(&runtime_root.join("node/LICENSE"), None);
    if target.starts_with("win32-") {
        require_file(&runtime_root.join("node/node.exe"), Some(b"MZ"));
    } else {
        require_file(&runtime_root.join("node/bin/node"), Some(b"\x7fELF"));
    }
    for relative in [
        "metadata.json",
        "node",
        "package",
        "package/dist/cli.js",
        "package/dist/mcp-server.js",
        "package/dist/console-ui/index.html",
        "package/node_modules",
    ] {
        require_contained(&runtime_root, &runtime_root.join(relative));
    }
}

fn desktop_target() -> String {
    let os = env::var("CARGO_CFG_TARGET_OS").expect("missing Rust target OS");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("missing Rust target architecture");
    let os = match os.as_str() {
        "windows" => "win32",
        "linux" => "linux",
        _ => panic!("desktop release builds support only Windows and Linux"),
    };
    let arch = match arch.as_str() {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => panic!("unsupported desktop target architecture: {arch}"),
    };
    format!("{os}-{arch}")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    println!("cargo:rerun-if-changed={}", path.display());
    let raw = fs::read(path).unwrap_or_else(|error| {
        panic!("missing desktop runtime input {}: {error}", path.display())
    });
    serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("invalid desktop runtime input {}: {error}", path.display()))
}

fn require_file(path: &Path, magic: Option<&[u8]>) {
    println!("cargo:rerun-if-changed={}", path.display());
    let metadata = fs::symlink_metadata(path).unwrap_or_else(|error| {
        panic!("missing desktop runtime input {}: {error}", path.display())
    });
    require(
        metadata.file_type().is_file(),
        &format!(
            "desktop runtime input is not a regular file: {}",
            path.display()
        ),
    );
    let contents = fs::read(path).unwrap_or_else(|error| {
        panic!("missing desktop runtime input {}: {error}", path.display())
    });
    require(
        !contents.is_empty(),
        &format!("empty desktop runtime input: {}", path.display()),
    );
    if let Some(expected) = magic {
        require(
            contents.starts_with(expected),
            &format!("wrong executable format in {}", path.display()),
        );
    }
}

fn require_dir(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
    let metadata = fs::symlink_metadata(path).unwrap_or_else(|error| {
        panic!(
            "missing desktop runtime directory {}: {error}",
            path.display()
        )
    });
    require(
        metadata.file_type().is_dir(),
        &format!(
            "desktop runtime input is not a directory: {}",
            path.display()
        ),
    );
}

fn require_contained(root: &Path, path: &Path) {
    let root = fs::canonicalize(root)
        .unwrap_or_else(|error| panic!("invalid desktop runtime root {}: {error}", root.display()));
    let path = fs::canonicalize(path)
        .unwrap_or_else(|error| panic!("invalid desktop runtime path {}: {error}", path.display()));
    require(
        path.starts_with(&root),
        &format!(
            "desktop runtime path escapes the bundle: {}",
            path.display()
        ),
    );
}

fn require(condition: bool, message: &str) {
    assert!(condition, "{message}");
}
