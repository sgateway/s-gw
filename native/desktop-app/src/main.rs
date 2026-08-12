#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod activation;
mod app;
mod model;
mod runtime;

use activation::{ActivationChannel, ActivationRequest};
use app::SgwApp;
use runtime::{
    apply_runtime_environment, open_browser_backup, resolve_runtime, runtime_instance_key,
    validated_console_url, DesktopSettings,
};
use single_instance::SingleInstance;
use std::env;
use std::thread;
use std::time::{Duration, Instant};

const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);

fn main() {
    if let Err(error) = run() {
        eprintln!("s-gw desktop: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut settings = DesktopSettings::from_args(env::args().skip(1))?;
    apply_runtime_environment(&settings);
    let runtime = resolve_runtime(&settings)?;
    let runtime_key = runtime_instance_key(&runtime);
    let instance_name = settings.single_instance_name(runtime_key.as_deref());
    let activation = ActivationChannel::new(&instance_name)?;
    let lock_name = instance_lock_name(&instance_name, &activation);
    let mut instance = open_instance_lock(&lock_name)?;

    if !instance.is_single() {
        if settings.browser {
            open_browser_backup(&runtime, &settings)?;
            return Ok(());
        }

        let request = ActivationRequest::new(settings.console_url.as_str(), !settings.background)?;
        let ticket = activation.signal(&request)?;
        let deadline = Instant::now() + ACTIVATION_TIMEOUT;
        loop {
            if ticket.is_acknowledged()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                ticket.cancel()?;
                return Err(
                    "The running desktop application did not accept the activation request.".into(),
                );
            }

            thread::sleep(LOCK_RETRY_INTERVAL);
            drop(instance);
            instance = open_instance_lock(&lock_name)?;
            if instance.is_single() {
                break;
            }
        }
    }

    if settings.browser {
        open_browser_backup(&runtime, &settings)?;
        return Ok(());
    }

    let initial_activation = activation.drain_pending()?;
    let show_from_activation = if let Some(batch) = initial_activation.as_ref() {
        apply_initial_activation(&mut settings, batch.request())?
    } else {
        false
    };
    let icon = window_icon()?;
    let viewport = desktop_viewport()
        .with_title("s-gw")
        .with_app_id("com.s-gw.sgw.desktop")
        .with_visible(!settings.background || show_from_activation)
        .with_icon(icon);
    let options = native_options(viewport);
    let settings_for_app = settings.clone();
    let activation_for_app = activation.clone();
    let result = eframe::run_native(
        "s-gw",
        options,
        Box::new(move |cc| {
            Ok(Box::new(SgwApp::new(
                cc,
                runtime,
                settings_for_app,
                activation_for_app,
                initial_activation,
            )))
        }),
    )
    .map_err(|error| format!("The native window could not start: {error}"));
    drop(instance);
    result
}

#[cfg(not(target_os = "macos"))]
fn desktop_viewport() -> egui::ViewportBuilder {
    egui::ViewportBuilder::default()
        .with_inner_size([1280.0, 840.0])
        .with_min_inner_size([980.0, 640.0])
}

#[cfg(target_os = "macos")]
fn desktop_viewport() -> egui::ViewportBuilder {
    egui::ViewportBuilder::default()
        .with_inner_size([1280.0, 840.0])
        .with_min_inner_size([900.0, 620.0])
}

#[cfg(windows)]
fn native_options(viewport: egui::ViewportBuilder) -> eframe::NativeOptions {
    let mut wgpu_options = eframe::WgpuConfiguration::default();
    let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) = &mut wgpu_options.wgpu_setup else {
        unreachable!("the default wgpu configuration creates a new instance")
    };
    setup.instance_descriptor.backends = eframe::wgpu::Backends::DX12;

    eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Wgpu,
        wgpu_options,
        ..Default::default()
    }
}

#[cfg(unix)]
fn native_options(viewport: egui::ViewportBuilder) -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    }
}

fn open_instance_lock(lock_name: &str) -> Result<SingleInstance, String> {
    SingleInstance::new(lock_name)
        .map_err(|error| format!("Could not create the desktop instance lock: {error}"))
}

fn apply_initial_activation(
    settings: &mut DesktopSettings,
    request: &ActivationRequest,
) -> Result<bool, String> {
    settings.console_url = validated_console_url(request.console_url())?;
    Ok(request.should_show_window())
}

#[cfg(target_os = "macos")]
fn instance_lock_name(_instance_name: &str, activation: &ActivationChannel) -> String {
    activation.lock_path().to_string_lossy().into_owned()
}

#[cfg(not(target_os = "macos"))]
fn instance_lock_name(instance_name: &str, _activation: &ActivationChannel) -> String {
    instance_name.into()
}

fn window_icon() -> Result<egui::IconData, String> {
    let image = image::load_from_memory(include_bytes!("../icons/128x128.png"))
        .map_err(|error| format!("Could not load the window icon: {error}"))?
        .into_rgba8();
    let (width, height) = image.dimensions();
    Ok(egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_activation_applies_the_requested_backup_url_and_visibility() {
        let mut settings = DesktopSettings::from_args([
            "--authority-args".into(),
            "--background".into(),
            "--console-url".into(),
            "http://127.0.0.1:8718/".into(),
        ])
        .expect("settings");
        let request =
            ActivationRequest::new("http://127.0.0.1:9812/", true).expect("activation request");

        let should_show =
            apply_initial_activation(&mut settings, &request).expect("apply activation");

        assert!(should_show);
        assert_eq!(settings.console_url.as_str(), "http://127.0.0.1:9812/");
    }
}
