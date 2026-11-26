//! ProxyGuard 0.5.0 — background guard for Codex / Claude and user-chosen programs.
//!
//! The monitor loop checks the machine's public egress country. When the country is
//! not in the allowed list (typically: the VPN dropped), Windows Firewall outbound
//! block rules are written for the target executables and the window pops up.
//! The process runs elevated (scheduled task created by the installer), so no UAC
//! prompt is needed at runtime.
//!
//! 0.5.0 adds user-selectable targets and a timezone-consistency launcher: once the
//! egress IP has been stable inside the allowed country, a target can be started
//! through ProxyGuard with `TZ` set to the timezone of the egress IP, so the
//! program's local timezone agrees with its IP. Only the child process environment
//! is touched; the real egress IP and the system timezone are never modified.

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
/// Consecutive allowed checks with the same egress IP before spoofed launches are enabled.
const STABLE_NEEDED: u32 = 3;
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
    /// Programs the user picked themselves (file picker / running process list).
    custom_targets: Vec<CustomTarget>,
}

/// A user-selected target program.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct CustomTarget {
    path: String,
    /// Write a firewall block rule for it when the egress is not allowed.
    guard: bool,
    /// Allow launching it through ProxyGuard with the egress timezone injected.
    spoof: bool,
}

impl Default for CustomTarget {
    fn default() -> Self {
        Self {
            path: String::new(),
            guard: true,
            spoof: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allowed_country: "US".into(),
            interval_seconds: 5,
            known_paths: BTreeSet::new(),
            custom_targets: Vec::new(),
        }
    }
}

/// Paths that get a firewall block rule while the egress is not allowed.
fn guard_paths(config: &Config) -> Vec<String> {
    let mut out: Vec<String> = config.known_paths.iter().cloned().collect();
    for c in config.custom_targets.iter().filter(|c| c.guard) {
        if !out.iter().any(|p| p.eq_ignore_ascii_case(&c.path)) {
            out.push(c.path.clone());
        }
    }
    out
}

/// Every path we may ever have written a rule for (used for cleanup).
fn all_rule_paths(config: &Config) -> Vec<String> {
    let mut out: Vec<String> = config.known_paths.iter().cloned().collect();
    for c in &config.custom_targets {
        if !out.iter().any(|p| p.eq_ignore_ascii_case(&c.path)) {
            out.push(c.path.clone());
        }
    }
    out
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

/// One row of the target list shown in the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetRow {
    path: String,
    name: String,
    /// Auto-registered codex / claude: always guarded, cannot be removed.
    builtin: bool,
    guard: bool,
    spoof: bool,
    running: bool,
}

/// A program started through ProxyGuard with a timezone injected.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchRecord {
    path: String,
    name: String,
    timezone: String,
    time: u64,
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
    targets: Vec<TargetRow>,
    /// Timezone (IANA id) of the current egress IP, used for spoofed launches.
    spoof_timezone: Option<String>,
    /// True once the egress IP is stable inside the allowed country.
    spoof_ready: bool,
    stable_streak: u32,
    stable_needed: u32,
    launches: Vec<LaunchRecord>,
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
    last_geo: Option<Geo>,
    fail_streak: u32,
    /// Consecutive allowed checks that saw `streak_ip`.
    stable_streak: u32,
    streak_ip: Option<String>,
    spoof_tz: Option<String>,
    launches: Vec<LaunchRecord>,
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
            stable_streak: 0,
            streak_ip: None,
            spoof_tz: None,
            launches: Vec::new(),
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

fn target_rows(rt: &Runtime) -> Vec<TargetRow> {
    let running: BTreeSet<String> = rt
        .running
        .iter()
        .map(|t| t.path.to_ascii_lowercase())
        .collect();
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for p in &rt.config.known_paths {
        if seen.insert(p.to_ascii_lowercase()) {
            rows.push(TargetRow {
                path: p.clone(),
                name: file_name(p),
                builtin: true,
                guard: true,
                spoof: true,
                running: running.contains(&p.to_ascii_lowercase()),
            });
        }
    }
    for c in &rt.config.custom_targets {
        if seen.insert(c.path.to_ascii_lowercase()) {
            rows.push(TargetRow {
                path: c.path.clone(),
                name: file_name(&c.path),
                builtin: false,
                guard: c.guard,
                spoof: c.spoof,
                running: running.contains(&c.path.to_ascii_lowercase()),
            });
        }
    }
    rows
}

fn spoof_ready(rt: &Runtime) -> bool {
    rt.blocked == Some(false) && rt.stable_streak >= STABLE_NEEDED && rt.spoof_tz.is_some()
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
        targets: target_rows(rt),
        spoof_timezone: rt.spoof_tz.clone(),
        spoof_ready: spoof_ready(rt),
        stable_streak: rt.stable_streak,
        stable_needed: STABLE_NEEDED,
        launches: rt.launches.clone(),
    }
}

// ---------- egress country detection ----------

#[derive(Debug, Clone)]
struct Geo {
    code: String,
    country: String,
    /// IANA timezone id of the egress IP, when the GeoIP service returned a valid one.
    timezone: Option<String>,
}

enum Verdict {
    Allowed { ip: String, geo: Geo },
    Denied { ip: String, geo: Geo },
    Unknown(String),
}

#[derive(Deserialize)]
struct GeoTimezone {
    id: Option<String>,
}

#[derive(Deserialize)]
struct GeoResponse {
    success: bool,
    country_code: Option<String>,
    country: Option<String>,
    timezone: Option<GeoTimezone>,
}

/// IANA ids only contain letters, digits and `_ + - /`. Anything else is rejected, because
/// the value ends up in a child process environment and a command line.
fn valid_timezone(tz: &str) -> bool {
    !tz.is_empty()
        && tz.len() <= 64
        && tz
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-' | '/'))
}

/// Fallback when the GeoIP service gives no timezone: the main zone of the country.
fn default_timezone(code: &str) -> Option<&'static str> {
    Some(match code {
        "US" => "America/New_York",
        "JP" => "Asia/Tokyo",
        "SG" => "Asia/Singapore",
        "MY" => "Asia/Kuala_Lumpur",
        "KR" => "Asia/Seoul",
        "GB" => "Europe/London",
        "DE" => "Europe/Berlin",
        "FR" => "Europe/Paris",
        "NL" => "Europe/Amsterdam",
        "CA" => "America/Toronto",
        "AU" => "Australia/Sydney",
        "CN" => "Asia/Shanghai",
        _ => return None,
    })
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

async fn lookup_country(client: &reqwest::Client, ip: &str) -> Result<Geo, String> {
    let url = format!("https://ipwho.is/{ip}?fields=success,country_code,country,timezone");
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
    let timezone = data
        .timezone
        .and_then(|t| t.id)
        .filter(|t| valid_timezone(t))
        .or_else(|| default_timezone(&code).map(String::from));
    Ok(Geo {
        code,
        country: data.country.unwrap_or_default(),
        timezone,
    })
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
    let geo = match cached {
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
    if geo.code.eq_ignore_ascii_case(allowed) {
        Verdict::Allowed { ip, geo }
    } else {
        Verdict::Denied { ip, geo }
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

/// PowerShell with UTF-8 output, so non-ASCII paths survive the pipe.
#[cfg(windows)]
fn run_ps(script: &str, sta: bool) -> std::io::Result<String> {
    let full = format!("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {script}");
    let mut args = vec!["-NoProfile", "-NonInteractive"];
    if sta {
        args.push("-STA");
    }
    args.extend(["-Command", full.as_str()]);
    let out = run_quiet("powershell.exe", &args)?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Every process that exposes an executable path (system folder and ProxyGuard itself skipped).
#[cfg(windows)]
fn all_processes() -> Vec<TargetProcess> {
    let script = "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | ForEach-Object { $_.ProcessName + '|' + $_.Path }";
    let mut found = Vec::new();
    if let Ok(text) = run_ps(script, false) {
        let windir = std::env::var("WINDIR")
            .unwrap_or_else(|_| "C:\\Windows".into())
            .to_ascii_lowercase();
        for line in text.lines() {
            if let Some((name, path)) = line.split_once('|') {
                let (name, path) = (name.trim(), path.trim());
                let lower = path.to_ascii_lowercase();
                if !Path::new(path).is_absolute()
                    || lower.starts_with(&windir)
                    || file_name(path).eq_ignore_ascii_case("proxyguard.exe")
                {
                    continue;
                }
                found.push(TargetProcess {
                    name: name.to_string(),
                    path: path.to_string(),
                });
            }
        }
    }
    found.sort_by_key(|t| (t.name.to_ascii_lowercase(), t.path.to_ascii_lowercase()));
    found.dedup_by(|a, b| a.path.eq_ignore_ascii_case(&b.path));
    found
}

#[cfg(not(windows))]
fn all_processes() -> Vec<TargetProcess> {
    Vec::new()
}

/// codex.exe / claude.exe copies found on PATH.
#[cfg(windows)]
fn path_copies() -> Vec<TargetProcess> {
    let mut found = Vec::new();
    for exe in TARGET_EXES {
        if let Ok(out) = run_quiet("where.exe", &[exe]) {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                push_target(&mut found, exe.trim_end_matches(".exe"), line.trim());
            }
        }
    }
    found
}

#[cfg(not(windows))]
fn path_copies() -> Vec<TargetProcess> {
    Vec::new()
}

fn same_path(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn refresh_targets(shared: &Shared) {
    let procs = all_processes();
    let customs: Vec<String> = lock(shared)
        .config
        .custom_targets
        .iter()
        .map(|c| c.path.clone())
        .collect();

    // Built-in targets: running codex / claude plus copies on PATH.
    let mut found = Vec::new();
    for p in &procs {
        push_target(&mut found, &p.name, &p.path);
    }
    found.extend(path_copies());
    found.sort_by_key(|t| t.path.to_ascii_lowercase());
    found.dedup_by(|a, b| same_path(&a.path, &b.path));

    // Running processes: built-ins plus any user-chosen program.
    let mut running = found.clone();
    for p in &procs {
        if customs.iter().any(|c| same_path(c, &p.path))
            && !running.iter().any(|r| same_path(&r.path, &p.path))
        {
            running.push(p.clone());
        }
    }

    let mut rt = lock(shared);
    let mut added = 0usize;
    for t in &found {
        if rt.config.known_paths.insert(t.path.clone()) {
            added += 1;
        }
    }
    rt.running = running;
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
    let paths = guard_paths(&rt.config);
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
        Some("尚未登记任何目标程序路径，请先启动一次 Codex / Claude，或在面板中添加程序".into())
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
        Verdict::Allowed { ip, geo } => {
            let Geo {
                code,
                country,
                timezone,
            } = geo;
            rt.fail_streak = 0;
            rt.public_ip = Some(ip.clone());
            rt.country_code = Some(code.clone());
            rt.country = Some(country.clone());
            if rt.blocked != Some(false) {
                for p in all_rule_paths(&rt.config) {
                    let _ = remove_block_rule(&p);
                }
                rt.applied.clear();
                rt.blocked = Some(false);
                push_log(
                    &mut rt,
                    "ok",
                    format!("出口国家 {country}（{code}）符合允许范围，目标软件可以联网"),
                );
            }

            // Egress stability: same IP, allowed country, consecutive checks.
            if rt.streak_ip.as_deref() == Some(ip.as_str()) {
                rt.stable_streak = rt.stable_streak.saturating_add(1);
                if rt.stable_streak == STABLE_NEEDED {
                    let tz = timezone.clone().unwrap_or_else(|| "未知".into());
                    push_log(
                        &mut rt,
                        "ok",
                        format!("出口 IP {ip} 已稳定，可通过 ProxyGuard 以时区 {tz} 启动目标程序"),
                    );
                }
            } else {
                let previous = rt.streak_ip.replace(ip.clone());
                rt.stable_streak = 1;
                if previous.is_some() && !rt.launches.is_empty() {
                    let tz = timezone.clone().unwrap_or_else(|| "未知".into());
                    push_log(
                        &mut rt,
                        "warn",
                        format!("出口 IP 已变化，伪装时区重新匹配为 {tz}；已启动的程序需重启才会采用新时区"),
                    );
                }
            }
            rt.spoof_tz = timezone;

            rt.block_error = None;
            rt.state = "protected".into();
            rt.message = format!("出口国家 {code} 符合允许范围，目标程序可以正常联网");
            false
        }
        Verdict::Denied { ip, geo } => {
            let Geo { code, country, .. } = geo;
            rt.fail_streak = 0;
            reset_stability(&mut rt);
            rt.public_ip = Some(ip);
            rt.country_code = Some(code.clone());
            rt.country = Some(country.clone());
            let newly = rt.blocked != Some(true);
            enforce_block(&mut rt);
            let allowed = rt.config.allowed_country.clone();
            rt.state = "blocked".into();
            rt.message = format!(
                "当前 VPN 已断开或出口不在允许范围：实际出口 {country}（{code}），允许 {allowed}。已断开目标程序联网"
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
            reset_stability(&mut rt);
            if rt.fail_streak >= FAIL_CLOSED_AFTER {
                let newly = rt.blocked != Some(true);
                enforce_block(&mut rt);
                rt.state = "unknown".into();
                rt.message = format!(
                    "无法确认出口国家（已连续失败 {} 次），已断开目标程序联网以防泄露：{err}",
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
                    "出口国家检测失败（{}/{}），再失败一次将断开目标程序：{err}",
                    rt.fail_streak, FAIL_CLOSED_AFTER
                );
            }
            false
        }
    }
}

/// Any non-allowed or failed check invalidates the "stable egress" condition.
fn reset_stability(rt: &mut Runtime) {
    rt.stable_streak = 0;
    rt.streak_ip = None;
    rt.spoof_tz = None;
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

/// Accepts only an absolute path to an existing `.exe`, without characters that could break
/// out of a firewall argument or a command line.
fn validate_exe_path(raw: &str) -> Result<String, String> {
    let path = raw.trim().trim_matches('"').trim().to_string();
    if path.is_empty() {
        return Err("请先选择程序".into());
    }
    if path.chars().any(|c| {
        matches!(
            c,
            '"' | '%' | '&' | '|' | '<' | '>' | '^' | '!' | '\n' | '\r'
        )
    }) {
        return Err("路径包含不支持的字符（\" % & | < > ^ !）".into());
    }
    let p = Path::new(&path);
    if !p.is_absolute() {
        return Err("需要完整的绝对路径".into());
    }
    let is_exe = p
        .extension()
        .map(|e| e.to_string_lossy().eq_ignore_ascii_case("exe"))
        .unwrap_or(false);
    if !is_exe {
        return Err("只支持 .exe 程序".into());
    }
    #[cfg(windows)]
    {
        if !p.is_file() {
            return Err("文件不存在".into());
        }
    }
    Ok(path)
}

#[tauri::command]
fn add_target(
    path: String,
    guard: bool,
    spoof: bool,
    shared: State<'_, Arc<Shared>>,
) -> Result<GuardStatus, String> {
    let path = validate_exe_path(&path)?;
    {
        let mut rt = lock(&shared);
        let exists = rt.config.known_paths.iter().any(|p| same_path(p, &path))
            || rt
                .config
                .custom_targets
                .iter()
                .any(|c| same_path(&c.path, &path));
        if exists {
            return Err("该程序已在目标列表中".into());
        }
        rt.config.custom_targets.push(CustomTarget {
            path: path.clone(),
            guard,
            spoof,
        });
        save_config(&shared.config_path, &rt.config)?;
        push_log(
            &mut rt,
            "ok",
            format!("已添加目标程序 {}", file_name(&path)),
        );
    }
    shared.wake.notify_one();
    Ok(snapshot(&lock(&shared)))
}

#[tauri::command]
fn remove_target(path: String, shared: State<'_, Arc<Shared>>) -> Result<GuardStatus, String> {
    {
        let mut rt = lock(&shared);
        let before = rt.config.custom_targets.len();
        rt.config
            .custom_targets
            .retain(|c| !same_path(&c.path, &path));
        if rt.config.custom_targets.len() == before {
            return Err("只能移除自己添加的程序".into());
        }
        let _ = remove_block_rule(&path);
        rt.applied.retain(|p| !same_path(p, &path));
        save_config(&shared.config_path, &rt.config)?;
        push_log(
            &mut rt,
            "ok",
            format!("已移除目标程序 {}", file_name(&path)),
        );
    }
    shared.wake.notify_one();
    Ok(snapshot(&lock(&shared)))
}

#[tauri::command]
fn set_target_flags(
    path: String,
    guard: bool,
    spoof: bool,
    shared: State<'_, Arc<Shared>>,
) -> Result<GuardStatus, String> {
    {
        let mut rt = lock(&shared);
        let Some(c) = rt
            .config
            .custom_targets
            .iter_mut()
            .find(|c| same_path(&c.path, &path))
        else {
            return Err("只能修改自己添加的程序".into());
        };
        let guard_was_on = c.guard;
        c.guard = guard;
        c.spoof = spoof;
        if guard_was_on && !guard {
            // Guard switched off: lift this program's block rule right away.
            let _ = remove_block_rule(&path);
            rt.applied.retain(|p| !same_path(p, &path));
        }
        save_config(&shared.config_path, &rt.config)?;
    }
    shared.wake.notify_one();
    Ok(snapshot(&lock(&shared)))
}

/// Opens the standard Windows "open file" dialog and returns the chosen .exe path.
#[tauri::command]
async fn pick_file() -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        #[cfg(windows)]
        {
            let script = "Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Filter = 'Programs (*.exe)|*.exe'; $d.Title = 'ProxyGuard'; if ($d.ShowDialog() -eq 'OK') { $d.FileName }";
            let text = run_ps(script, true).map_err(|e| format!("无法打开文件选择器：{e}"))?;
            let picked = text.lines().next().map(|l| l.trim().to_string()).unwrap_or_default();
            Ok(if picked.is_empty() { None } else { Some(picked) })
        }
        #[cfg(not(windows))]
        {
            Err("文件选择器仅支持 Windows".to_string())
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Running programs the user can choose from.
#[tauri::command]
async fn list_processes() -> Result<Vec<TargetProcess>, String> {
    tauri::async_runtime::spawn_blocking(all_processes)
        .await
        .map_err(|e| e.to_string())
}

/// Starts `path` with `TZ` set to the egress IP's timezone.
///
/// The guard runs elevated, so the program is started through `runas /trustlevel:0x20000`
/// (Basic User) — a user program must never inherit administrator rights from the guard.
/// There is deliberately no fallback to a plain elevated launch.
#[cfg(windows)]
fn launch_with_tz(path: &str, tz: &str) -> Result<(), String> {
    if !valid_timezone(tz) {
        return Err("时区格式无效".into());
    }
    let dir = Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .ok_or("无法确定程序所在目录")?;
    if dir.contains('"') {
        return Err("路径包含不支持的字符".into());
    }
    // `set TZ=…&&` has no space before `&&`, so the value carries no trailing blank.
    let inner = format!("cmd.exe /c set TZ={tz}&& start \\\"\\\" /d \\\"{dir}\\\" \\\"{path}\\\"");
    let arg = format!("/trustlevel:0x20000 \"{inner}\"");
    let out = Command::new("runas.exe")
        .raw_arg(arg)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("无法执行 runas：{e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Err(format!(
            "启动失败（runas 退出码 {:?}）{text}",
            out.status.code()
        ))
    }
}

#[cfg(not(windows))]
fn launch_with_tz(_path: &str, _tz: &str) -> Result<(), String> {
    Err("带时区启动仅支持 Windows".into())
}

#[tauri::command]
async fn launch_target(
    path: String,
    shared: State<'_, Arc<Shared>>,
) -> Result<GuardStatus, String> {
    let shared = shared.inner().clone();
    // Decide under the lock; run the process outside it.
    let tz = {
        let rt = lock(&shared);
        let registered = rt.config.known_paths.iter().any(|p| same_path(p, &path))
            || rt
                .config
                .custom_targets
                .iter()
                .any(|c| c.spoof && same_path(&c.path, &path));
        if !registered {
            return Err("该程序未登记，或已关闭“时区伪装”".into());
        }
        if !spoof_ready(&rt) {
            return Err(format!(
                "出口尚未稳定：需要在允许国家内连续 {STABLE_NEEDED} 次检测到同一 IP（当前 {}）。为避免时区与 IP 不一致，暂不启动",
                rt.stable_streak
            ));
        }
        rt.spoof_tz.clone().ok_or("尚无可用的出口时区")?
    };
    let validated = validate_exe_path(&path)?;
    let (p2, tz2) = (validated.clone(), tz.clone());
    tauri::async_runtime::spawn_blocking(move || launch_with_tz(&p2, &tz2))
        .await
        .map_err(|e| e.to_string())??;
    let mut rt = lock(&shared);
    rt.launches.retain(|l| !same_path(&l.path, &validated));
    rt.launches.insert(
        0,
        LaunchRecord {
            path: validated.clone(),
            name: file_name(&validated),
            timezone: tz.clone(),
            time: now_secs(),
        },
    );
    push_log(
        &mut rt,
        "ok",
        format!(
            "已以时区 {tz} 启动 {}（仅该进程生效）",
            file_name(&validated)
        ),
    );
    Ok(snapshot(&rt))
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
            check_now,
            add_target,
            remove_target,
            set_target_flags,
            pick_file,
            list_processes,
            launch_target
        ])
        .setup(move |app| {
            let config_path = app.path().app_config_dir()?.join("guard.json");

            // Used by the uninstaller: remove every block rule we ever created, then exit.
            if cleanup {
                for p in all_rule_paths(&load_config(&config_path)) {
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
