//! ProxyGuard 0.4.0 — background guard for Codex / Claude.
//!
//! The monitor loop checks the machine's public egress country. When the country is
//! not in the allowed list (typically: the VPN dropped), Windows Firewall outbound
//! block rules are written for the target executables and the window pops up.
//! The process runs elevated (scheduled task created by the installer), so no UAC
//! prompt is needed at runtime.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(windows)]
use std::{os::windows::process::CommandExt, process::Command};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    App, AppHandle, Emitter, Manager, State, WindowEvent,
};
use tokio::sync::Notify;

const TARGET_EXES: [&str; 2] = ["codex.exe", "claude.exe"];
const RULE_PREFIX: &str = "ProxyGuard-Block-";
/// Consecutive failed checks before the guard fails closed (blocks targets).
const FAIL_CLOSED_AFTER: u32 = 2;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

// ---------- persisted configuration ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Config {
    allowed_country: String,
    interval_seconds: u64,
    /// Full paths of target executables ever seen, so their rules can be removed later
    /// even when the program is not running.
    known_paths: BTreeSet<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allowed_country: "US".into(),
            interval_seconds: 5,
            known_paths: BTreeSet::new(),
        }
    }
}

fn load_config(path: &Path) -> Config {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_config(path: &Path, config: &Config) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let raw = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    fs::write(path, raw).map_err(|e| e.to_string())
}

// ---------- runtime state shared with the UI ----------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetProcess {
    name: String,
    path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogEntry {
    time: u64,
    level: String,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GuardStatus {
    /// "starting" | "protected" | "blocked" | "unknown"
    state: String,
    message: String,
    public_ip: Option<String>,
    country_code: Option<String>,
    country: Option<String>,
    allowed_country: String,
    blocked: bool,
    block_error: Option<String>,
    known_paths: Vec<String>,
    running: Vec<TargetProcess>,
    checked_at: u64,
    interval_seconds: u64,
    logs: Vec<LogEntry>,
}

struct Runtime {
    config: Config,
    state: String,
    message: String,
    public_ip: Option<String>,
    country_code: Option<String>,
    country: Option<String>,
    checked_at: u64,
    /// None = unknown (just started), Some(true) = targets blocked, Some(false) = allowed.
    blocked: Option<bool>,
    /// Paths for which a block rule was successfully written in this blocked period.
    applied: BTreeSet<String>,
    block_error: Option<String>,
    running: Vec<TargetProcess>,
    logs: Vec<LogEntry>,
    last_ip: Option<String>,
    last_geo: Option<(String, String)>,
    fail_streak: u32,
}

impl Runtime {
    fn new(config: Config) -> Self {
        Self {
            config,
            state: "starting".into(),
            message: "正在进行首次出口检测…".into(),
            public_ip: None,
            country_code: None,
            country: None,
            checked_at: 0,
            blocked: None,
            applied: BTreeSet::new(),
            block_error: None,
            running: Vec::new(),
            logs: Vec::new(),
            last_ip: None,
            last_geo: None,
            fail_streak: 0,
        }
    }
}

struct Shared {
    runtime: Mutex<Runtime>,
    wake: Notify,
    config_path: PathBuf,
}

fn lock(shared: &Shared) -> MutexGuard<'_, Runtime> {
    shared.runtime.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn push_log(rt: &mut Runtime, level: &str, message: String) {
    rt.logs.insert(
        0,
        LogEntry {
            time: now_secs(),
            level: level.to_string(),
            message,
        },
    );
    rt.logs.truncate(100);
}

fn snapshot(rt: &Runtime) -> GuardStatus {
    GuardStatus {
        state: rt.state.clone(),
        message: rt.message.clone(),
        public_ip: rt.public_ip.clone(),
        country_code: rt.country_code.clone(),
        country: rt.country.clone(),
        allowed_country: rt.config.allowed_country.clone(),
        blocked: rt.blocked == Some(true),
        block_error: rt.block_error.clone(),
        known_paths: rt.config.known_paths.iter().cloned().collect(),
        running: rt.running.clone(),
        checked_at: rt.checked_at,
        interval_seconds: rt.config.interval_seconds,
        logs: rt.logs.clone(),
    }
}

// ---------- egress country detection ----------

enum Verdict {
    Allowed {
        ip: String,
        code: String,
        country: String,
    },
    Denied {
        ip: String,
        code: String,
        country: String,
    },
    Unknown(String),
}

#[derive(Deserialize)]
struct GeoResponse {
    success: bool,
    country_code: Option<String>,
    country: Option<String>,
}

async fn fetch_public_ip(client: &reqwest::Client) -> Result<String, String> {
    let value: serde_json::Value = client
        .get("https://api.ipify.org?format=json")
        .send()
        .await
        .map_err(|e| format!("出口 IP 查询失败：{e}"))?
        .error_for_status()
        .map_err(|e| format!("出口 IP 服务返回错误：{e}"))?
        .json()
        .await
        .map_err(|e| format!("出口 IP 响应解析失败：{e}"))?;
    let ip = value
        .get("ip")
        .and_then(|v| v.as_str())
        .ok_or("出口 IP 响应缺少 ip 字段")?
        .to_string();
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| "出口 IP 格式无效".to_string())?;
    Ok(ip)
}

async fn lookup_country(client: &reqwest::Client, ip: &str) -> Result<(String, String), String> {
    let url = format!("https://ipwho.is/{ip}?fields=success,country_code,country");
    let data: GeoResponse = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GeoIP 请求失败：{e}"))?
        .error_for_status()
        .map_err(|e| format!("GeoIP 服务返回错误：{e}"))?
        .json()
        .await
        .map_err(|e| format!("GeoIP 响应解析失败：{e}"))?;
    if !data.success {
        return Err("GeoIP 无法识别该 IP".into());
    }
    let code = data
        .country_code
        .ok_or("GeoIP 未返回国家代码")?
        .to_ascii_uppercase();
    Ok((code, data.country.unwrap_or_default()))
}

async fn evaluate(client: &reqwest::Client, shared: &Shared, allowed: &str) -> Verdict {
    let ip = match fetch_public_ip(client).await {
        Ok(ip) => ip,
        Err(e) => return Verdict::Unknown(e),
    };
    // Only ask GeoIP again when the public IP actually changes.
    let cached = {
        let rt = lock(shared);
        match (&rt.last_ip, &rt.last_geo) {
            (Some(last), Some(geo)) if *last == ip => Some(geo.clone()),
            _ => None,
        }
    };
    let (code, country) = match cached {
        Some(geo) => geo,
        None => match lookup_country(client, &ip).await {
            Ok(geo) => {
                let mut rt = lock(shared);
                rt.last_ip = Some(ip.clone());
                rt.last_geo = Some(geo.clone());
                geo
            }
            Err(e) => return Verdict::Unknown(e),
        },
    };
    if code.eq_ignore_ascii_case(allowed) {
        Verdict::Allowed { ip, code, country }
    } else {
        Verdict::Denied { ip, code, country }
    }
}

// ---------- target discovery ----------

#[cfg(windows)]
fn run_quiet(program: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

fn is_target_exe(path: &str) -> bool {
    let p = Path::new(path);
    let file = p
        .file_name()
        .map(|f| f.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    p.is_absolute() && TARGET_EXES.contains(&file.as_str())
}

fn push_target(found: &mut Vec<TargetProcess>, name: &str, path: &str) {
    if is_target_exe(path) {
        found.push(TargetProcess {
            name: name.to_string(),
            path: path.to_string(),
        });
    }
}

/// Running codex.exe / claude.exe processes plus copies found on PATH.
#[cfg(windows)]
fn discover_targets() -> Vec<TargetProcess> {
    let mut found = Vec::new();
    let script = "Get-Process -Name codex,claude -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName + '|' + $_.Path }";
    if let Ok(out) = run_quiet(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    ) {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some((name, path)) = line.split_once('|') {
                push_target(&mut found, name.trim(), path.trim());
            }
        }
    }
    for exe in TARGET_EXES {
        if let Ok(out) = run_quiet("where.exe", &[exe]) {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                push_target(&mut found, exe.trim_end_matches(".exe"), line.trim());
            }
        }
    }
    found.sort_by_key(|t| t.path.to_ascii_lowercase());
    found.dedup_by(|a, b| a.path.eq_ignore_ascii_case(&b.path));
    found
}

#[cfg(not(windows))]
fn discover_targets() -> Vec<TargetProcess> {
    Vec::new()
}

fn refresh_targets(shared: &Shared) {
    let found = discover_targets();
    let mut rt = lock(shared);
    let mut added = 0usize;
    for t in &found {
        if rt.config.known_paths.insert(t.path.clone()) {
            added += 1;
        }
    }
    rt.running = found;
    if added > 0 {
        let _ = save_config(&shared.config_path, &rt.config);
        push_log(&mut rt, "ok", format!("已登记 {added} 个目标程序路径"));
    }
}

// ---------- Windows Firewall block rules ----------

fn rule_name(path: &str) -> String {
    // FNV-1a over the lowercase path: stable, and safe as a rule name.
    let mut h: u32 = 2_166_136_261;
    for b in path.to_ascii_lowercase().bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(16_777_619);
    }
    format!("{RULE_PREFIX}{h:08x}")
}

#[cfg(windows)]
fn netsh(args: &[&str]) -> Result<(), String> {
    let out = run_quiet("netsh", args).map_err(|e| format!("无法执行 netsh：{e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "netsh 退出码 {:?}（需要管理员权限）",
            out.status.code()
        ))
    }
}

#[cfg(windows)]
fn add_block_rule(path: &str) -> Result<(), String> {
    let name = rule_name(path);
    let name_arg = format!("name={name}");
    let program_arg = format!("program=\"{path}\"");
    // Remove any leftover rule with the same name first so rules never duplicate.
    let _ = netsh(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        name_arg.as_str(),
    ]);
    netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        name_arg.as_str(),
        "dir=out",
        "action=block",
        program_arg.as_str(),
        "enable=yes",
        "profile=any",
    ])
}

#[cfg(windows)]
fn remove_block_rule(path: &str) -> Result<(), String> {
    let name_arg = format!("name={}", rule_name(path));
    netsh(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        name_arg.as_str(),
    ])
}

#[cfg(not(windows))]
fn add_block_rule(_path: &str) -> Result<(), String> {
    Err("防火墙阻断仅支持 Windows".into())
}

#[cfg(not(windows))]
fn remove_block_rule(_path: &str) -> Result<(), String> {
    Err("防火墙阻断仅支持 Windows".into())
}

/// Make sure the logon task may start on battery and has no time limit.
/// Runs only from the elevated background instance; failures are ignored.
#[cfg(windows)]
fn ensure_task_settings() {
    let script = "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero); Set-ScheduledTask -TaskName ProxyGuard -Settings $s | Out-Null";
    let _ = run_quiet(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    );
}

#[cfg(not(windows))]
fn ensure_task_settings() {}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

/// Write block rules for every known target path not yet covered.
/// Called on every denied cycle so newly discovered paths are picked up.
fn enforce_block(rt: &mut Runtime) {
    let paths: Vec<String> = rt.config.known_paths.iter().cloned().collect();
    let mut errors = Vec::new();
    for p in &paths {
        if rt.applied.contains(p) {
            continue;
        }
        match add_block_rule(p) {
            Ok(()) => {
                rt.applied.insert(p.clone());
            }
            Err(e) => errors.push(format!("{}：{}", file_name(p), e)),
        }
    }
    rt.blocked = Some(true);
    rt.block_error = if paths.is_empty() {
        Some("尚未发现 Codex / Claude 程序路径，请先在本机启动一次它们".into())
    } else if errors.is_empty() {
        None
    } else {
        Some(format!("部分阻断规则写入失败：{}", errors.join("；")))
    };
}

// ---------- decision making ----------

/// Applies a check result. Returns true when the window should pop up (new block).
fn apply_verdict(shared: &Shared, verdict: Verdict) -> bool {
    let mut rt = lock(shared);
    rt.checked_at = now_secs();
    match verdict {
        Verdict::Allowed { ip, code, country } => {
            rt.fail_streak = 0;
            rt.public_ip = Some(ip);
            rt.country_code = Some(code.clone());
            rt.country = Some(country.clone());
            if rt.blocked != Some(false) {
                let paths: Vec<String> = rt.config.known_paths.iter().cloned().collect();
                for p in &paths {
                    let _ = remove_block_rule(p);
                }
                rt.applied.clear();
                rt.blocked = Some(false);
                push_log(
                    &mut rt,
                    "ok",
                    format!("出口国家 {country}（{code}）符合允许范围，目标软件可以联网"),
                );
            }
            rt.block_error = None;
            rt.state = "protected".into();
            rt.message = format!("出口国家 {code} 符合允许范围，Codex / Claude 可以正常联网");
            false
        }
        Verdict::Denied { ip, code, country } => {
            rt.fail_streak = 0;
            rt.public_ip = Some(ip);
            rt.country_code = Some(code.clone());
            rt.country = Some(country.clone());
            let newly = rt.blocked != Some(true);
            enforce_block(&mut rt);
            let allowed = rt.config.allowed_country.clone();
            rt.state = "blocked".into();
            rt.message = format!(
                "当前 VPN 已断开或出口不在允许范围：实际出口 {country}（{code}），允许 {allowed}。已断开 Codex / Claude 联网"
            );
            if newly {
                let msg = rt.message.clone();
                push_log(&mut rt, "error", msg);
                return true;
            }
            false
        }
        Verdict::Unknown(err) => {
            rt.fail_streak = rt.fail_streak.saturating_add(1);
            if rt.fail_streak >= FAIL_CLOSED_AFTER {
                let newly = rt.blocked != Some(true);
                enforce_block(&mut rt);
                rt.state = "unknown".into();
                rt.message = format!(
                    "无法确认出口国家（已连续失败 {} 次），已断开 Codex / Claude 联网以防泄露：{err}",
                    rt.fail_streak
                );
                if newly {
                    let msg = rt.message.clone();
                    push_log(&mut rt, "error", msg);
                    return true;
                }
            } else {
                if rt.blocked != Some(true) {
                    rt.state = "unknown".into();
                }
                rt.message = format!(
                    "出口国家检测失败（{}/{}），再失败一次将断开目标软件：{err}",
                    rt.fail_streak, FAIL_CLOSED_AFTER
                );
            }
            false
        }
    }
}

// ---------- background loop ----------

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

async fn monitor_loop(app: AppHandle, shared: Arc<Shared>) {
    ensure_task_settings();
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let mut rt = lock(&shared);
            push_log(&mut rt, "error", format!("网络客户端初始化失败：{e}"));
            return;
        }
    };

    let mut cycle: u64 = 0;
    loop {
        let (allowed, interval) = {
            let rt = lock(&shared);
            (
                rt.config.allowed_country.clone(),
                rt.config.interval_seconds.clamp(3, 60),
            )
        };
        if cycle % 6 == 0 {
            refresh_targets(&shared);
        }
        cycle += 1;

        let verdict = evaluate(&client, &shared, &allowed).await;
        if apply_verdict(&shared, verdict) {
            show_main(&app);
        }
        let snap = snapshot(&lock(&shared));
        let _ = app.emit("guard-status", snap);

        // Wakes early when the user changes the country or presses "check now".
        let _ = tokio::time::timeout(Duration::from_secs(interval), shared.wake.notified()).await;
    }
}

// ---------- tauri commands ----------

#[tauri::command]
fn get_status(shared: State<'_, Arc<Shared>>) -> GuardStatus {
    snapshot(&lock(&shared))
}

#[tauri::command]
fn set_allowed_country(
    code: String,
    shared: State<'_, Arc<Shared>>,
) -> Result<GuardStatus, String> {
    let code = code.trim().to_ascii_uppercase();
    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err("请输入两位国家代码，例如 US".into());
    }
    {
        let mut rt = lock(&shared);
        rt.config.allowed_country = code.clone();
        save_config(&shared.config_path, &rt.config)?;
        push_log(&mut rt, "ok", format!("允许出口国家已设为 {code}"));
    }
    shared.wake.notify_one();
    Ok(snapshot(&lock(&shared)))
}

#[tauri::command]
fn check_now(shared: State<'_, Arc<Shared>>) {
    shared.wake.notify_one();
}

// ---------- tray and app setup ----------

fn setup_tray(app: &App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "打开 ProxyGuard", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出（停止守护）", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let mut builder = TrayIconBuilder::with_id("main-tray")
        .menu(&menu)
        .tooltip("ProxyGuard")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
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
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let background = args.iter().any(|a| a == "--background");
    let cleanup = args.iter().any(|a| a == "--cleanup");

    tauri::Builder::default()
        // A second launch (e.g. from the Start menu) just brings the existing window forward.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main(app)
        }))
        .on_window_event(|window, event| {
            // Closing the window hides it; the guard keeps running in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            set_allowed_country,
            check_now
        ])
        .setup(move |app| {
            let config_path = app.path().app_config_dir()?.join("guard.json");

            // Used by the uninstaller: remove every block rule we ever created, then exit.
            if cleanup {
                for p in load_config(&config_path).known_paths {
                    let _ = remove_block_rule(&p);
                }
                std::process::exit(0);
            }

            let shared = Arc::new(Shared {
                runtime: Mutex::new(Runtime::new(load_config(&config_path))),
                wake: Notify::new(),
                config_path,
            });
            app.manage(shared.clone());

            setup_tray(app)?;
            if !background {
                show_main(app.handle());
            }
            tauri::async_runtime::spawn(monitor_loop(app.handle().clone(), shared));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running ProxyGuard");
}
