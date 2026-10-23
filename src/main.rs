use std::{
    collections::HashSet,
    io::Read,
    path::Path,
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use turbomcp::prelude::*;

// Compile-time check: MCP server version must match Cargo.toml
const _: () = {
    let cargo = env!("CARGO_PKG_VERSION").as_bytes();
    let mcp = b"1.0.2";
    assert!(cargo.len() == mcp.len(), "MCP server version does not match Cargo.toml — update #[server(version)] below");
    let mut i = 0;
    while i < cargo.len() {
        assert!(cargo[i] == mcp[i], "MCP server version does not match Cargo.toml — update #[server(version)] below");
        i += 1;
    }
};

/// The policy is fixed at startup from the operator-controlled environment. No MCP tool can
/// change it: the MCP client is the party the policy restricts. `approved` holds the unlisted
/// programs the user approved with a password during this server process; it only grows through
/// a successful password dialog.
#[derive(Clone)]
struct Sudo39 {
    policy: Arc<Policy>,
    approved: Arc<Mutex<HashSet<String>>>,
    /// Serializes elevation: the sudo credential reset, validation, and run of one call must not
    /// interleave with another call's.
    run_lock: Arc<Mutex<()>>,
}

#[server(
    name = "sudo39",
    version = "1.0.2",
    description = "Guarded privilege-elevation MCP server for AI agents."
)]
impl Sudo39 {
    fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(policy),
            approved: Arc::new(Mutex::new(HashSet::new())),
            run_lock: Arc::new(Mutex::new(())),
        }
    }

    #[tool("Run a program as root after the user approves it with their password in a native OS dialog that shows the exact command; a cancelled dialog fails the call. sudo39_policy lists the allowed programs and whether programs outside that list may be requested and whether one approval covers later calls.")]
    async fn sudo_run(
        &self,
        #[description(
            "Absolute path of the program, for example \"/usr/bin/id\". Pass arguments with the arguments parameter."
        )]
        command: String,
        #[description("Optional arguments passed to the program as separate argv entries, without a shell.")]
        arguments: Option<Vec<String>>,
        #[description("Elevation mode; omit for auto. Only modes listed by sudo39_policy are accepted.")]
        mode: Option<String>,
    ) -> McpResult<String> {
        let request = CommandRequest::new(command, arguments)?;
        let mode = ElevationMode::parse(mode.as_deref().unwrap_or("auto"))
            .map_err(McpError::invalid_params)?;

        let approved_now = lock(&self.approved)?.clone();
        let approval = match validate_request(&self.policy, &approved_now, mode, &request) {
            Ok(approval) => approval,
            Err(error) => {
                audit_request("deny", mode, &request, None);
                return Err(error);
            }
        };
        audit_request(approval.as_str(), mode, &request, None);

        let policy = self.policy.clone();
        let run_lock = self.run_lock.clone();
        let blocking_request = request.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let _guard = run_lock.lock().map_err(|_| "run lock poisoned".to_string())?;
            execute(&policy, mode, &blocking_request, approval)
        })
        .await;
        let (result, authenticated) = match outcome {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => {
                audit_request("error", mode, &request, None);
                return Err(McpError::internal(error));
            }
            Err(error) => {
                audit_request("error", mode, &request, None);
                return Err(McpError::internal(error.to_string()));
            }
        };
        if approval == Approval::Unlisted && authenticated {
            lock(&self.approved)?.insert(request.program.clone());
            audit_request("approved", mode, &request, None);
        }
        audit_request("finish", mode, &request, result.output.status.code());

        Ok(format_output(&request, mode, approval, &result))
    }

    #[tool("Show the active sudo39 policy: allowed programs, elevation modes, whether programs outside the list may be requested, and the programs approved during this server run. The policy is read-only.")]
    async fn sudo39_policy(&self) -> McpResult<String> {
        let mut approved = lock(&self.approved)?.iter().cloned().collect::<Vec<_>>();
        approved.sort();
        Ok(format!("{}\napproved_this_run: {approved:?}", self.policy.describe()))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> McpResult<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| McpError::internal("approved-program lock poisoned"))
}

/// How a request passed the policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Approval {
    /// In SUDO39_ALLOWED_PROGRAMS, or SUDO39_ALLOW_UNSAFE=1.
    Listed,
    /// Unlisted, approved by the user's password earlier in this server run.
    Approved,
    /// Unlisted and not yet approved: the dialog is forced and marked.
    Unlisted,
}

impl Approval {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Listed => "start",
            Self::Approved => "start_approved",
            Self::Unlisted => "start_unlisted",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Listed => "allowlist",
            Self::Approved => "approved earlier this run",
            Self::Unlisted => "not in allowlist; approved by this dialog",
        }
    }
}

#[derive(Debug)]
struct Policy {
    allowed_programs: HashSet<String>,
    allowed_modes: Vec<ElevationMode>,
    allow_unsafe: bool,
    /// SUDO39_PROMPT_UNLISTED=1: unlisted programs ask for the password instead of failing.
    prompt_unlisted: bool,
    /// SUDO39_REMEMBER=1: run through sudo with sudo39's askpass dialog, so sudo's credential
    /// cache, keyed to this server process, lets one password cover later calls.
    remember: bool,
}

impl Policy {
    /// Reads SUDO39_ALLOWED_PROGRAMS, SUDO39_ALLOWED_MODES, SUDO39_ALLOW_UNSAFE,
    /// SUDO39_PROMPT_UNLISTED and SUDO39_REMEMBER.
    ///
    /// # Errors
    /// Returns a description of the first invalid entry: a program that is not an absolute path
    /// of a root-owned file reachable only through root-owned, non-group/other-writable
    /// directories, an unknown mode, a flag other than 0/1, or a macOS-only flag elsewhere.
    fn from_env() -> Result<Self, String> {
        let prompt_unlisted = env_flag("SUDO39_PROMPT_UNLISTED")?;
        let remember = env_flag("SUDO39_REMEMBER")?;
        if (prompt_unlisted || remember) && !cfg!(target_os = "macos") {
            return Err(
                "SUDO39_PROMPT_UNLISTED and SUDO39_REMEMBER need the macOS password dialog"
                    .to_string(),
            );
        }
        let mut allowed_programs = HashSet::new();
        for entry in env_list("SUDO39_ALLOWED_PROGRAMS") {
            check_trusted_program(&entry)
                .map_err(|error| format!("SUDO39_ALLOWED_PROGRAMS entry {entry:?}: {error}"))?;
            allowed_programs.insert(entry);
        }

        let mut allowed_modes = Vec::new();
        let modes = env_list("SUDO39_ALLOWED_MODES");
        for entry in if modes.is_empty() { vec!["auto".to_string()] } else { modes } {
            let mode = ElevationMode::parse(&entry)
                .map_err(|error| format!("SUDO39_ALLOWED_MODES: {error}"))?;
            if !allowed_modes.contains(&mode) {
                allowed_modes.push(mode);
            }
        }

        Ok(Self {
            allowed_programs,
            allowed_modes,
            allow_unsafe: std::env::var("SUDO39_ALLOW_UNSAFE").ok().as_deref() == Some("1"),
            prompt_unlisted,
            remember,
        })
    }

    fn describe(&self) -> String {
        let mut allowed_programs = self.allowed_programs.iter().collect::<Vec<_>>();
        allowed_programs.sort();
        let allowed_modes = self
            .allowed_modes
            .iter()
            .map(|mode| mode.as_str())
            .collect::<Vec<_>>();

        format!(
            "allow_unsafe: {}\nallowed_programs: {:?}\nallowed_modes: {:?}\nprompt_unlisted: {}\nremember: {}",
            self.allow_unsafe, allowed_programs, allowed_modes, self.prompt_unlisted, self.remember
        )
    }
}

/// A 0/1 flag; unset is 0. Any other value fails, so a typo cannot silently disable a choice.
fn env_flag(name: &str) -> Result<bool, String> {
    match std::env::var(name).ok().as_deref().map(str::trim) {
        None | Some("") | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(format!("{name} must be 0 or 1, got {other:?}")),
    }
}

fn env_list(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[derive(Clone, Debug)]
struct CommandRequest {
    program: String,
    args: Vec<String>,
}

impl CommandRequest {
    fn new(command: String, args: Option<Vec<String>>) -> McpResult<Self> {
        let program = command.trim();
        if program.is_empty() {
            return Err(McpError::invalid_params("program must not be empty"));
        }
        if !Path::new(program).is_absolute() {
            return Err(McpError::invalid_params(
                "program must be an absolute path, for example /usr/bin/id",
            ));
        }
        Ok(Self {
            program: program.to_string(),
            args: args.unwrap_or_default(),
        })
    }
}

fn validate_request(
    policy: &Policy,
    approved: &HashSet<String>,
    mode: ElevationMode,
    request: &CommandRequest,
) -> McpResult<Approval> {
    if !policy.allowed_modes.contains(&mode) {
        return Err(McpError::permission_denied(format!(
            "mode {:?} is not allowed; see sudo39_policy",
            mode.as_str()
        )));
    }
    let approval = if policy.allow_unsafe || policy.allowed_programs.contains(&request.program) {
        Approval::Listed
    } else if approved.contains(&request.program) {
        Approval::Approved
    } else if policy.prompt_unlisted && mode == ElevationMode::Auto {
        Approval::Unlisted
    } else {
        return Err(McpError::permission_denied(
            "program is not in the allowlist; see sudo39_policy",
        ));
    };
    // Rechecked per call: the file or a parent may have changed since startup.
    check_trusted_program(&request.program).map_err(McpError::permission_denied)?;
    Ok(approval)
}

/// Runs one validated request. Returns the result and whether the user authenticated for this
/// call (a password was accepted or a cached sudo credential was valid).
fn execute(
    policy: &Policy,
    mode: ElevationMode,
    request: &CommandRequest,
    approval: Approval,
) -> Result<(RunResult, bool), String> {
    #[cfg(target_os = "macos")]
    if mode == ElevationMode::Auto {
        if policy.remember {
            return run_remembered(request, approval);
        }
        let result = run_macos_osascript_marked(request, approval == Approval::Unlisted)?;
        // AppleScript error -128 is "User canceled"; any other outcome passed the dialog.
        let cancelled = String::from_utf8_lossy(&result.output.stderr).contains("(-128)");
        return Ok((result, !cancelled));
    }
    let _ = (policy, approval);
    mode.run(request).map(|result| (result, true))
}

/// macOS remember mode. Authenticates with `sudo -A -v` through sudo39's own askpass dialog,
/// checks that the resulting credential is not usable from another process, then runs the
/// program with `sudo -n`. A first-time unlisted program resets this process's sudo credential
/// first, so its approval always takes a password.
#[cfg(target_os = "macos")]
fn run_remembered(request: &CommandRequest, approval: Approval) -> Result<(RunResult, bool), String> {
    let exe = std::env::current_exe().map_err(|error| format!("cannot locate sudo39: {error}"))?;
    if approval == Approval::Unlisted {
        let mut reset = Command::new(SUDO);
        reset.arg("-k");
        run_command(reset, "sudo").map_err(|error| format!("sudo -k failed: {error}"))?;
    }

    let mut validate = Command::new(SUDO);
    validate
        .env("SUDO_ASKPASS", &exe)
        .env(ASKPASS_MODE_ENV, "1")
        .env(ASKPASS_TEXT_ENV, askpass_text(request, approval))
        .args(["-A", "-v"]);
    let validated = run_command(validate, "sudo").map_err(|error| format!("sudo -v failed: {error}"))?;
    if !validated.output.status.success() {
        return Err(format!(
            "authentication was cancelled or failed: {}",
            String::from_utf8_lossy(&validated.output.stderr).trim()
        ));
    }

    let mut probe = Command::new(&exe);
    probe.arg(PROBE_ARG);
    let probed = run_command(probe, "probe").map_err(|error| format!("credential probe failed: {error}"))?;
    if probed.output.status.success() {
        let mut reset = Command::new(SUDO);
        reset.arg("-k");
        let _ = run_command(reset, "sudo");
        return Err("refusing remember mode: another process can use the sudo credential without a password (timestamp_type=global or a NOPASSWD rule in sudoers); the credential was reset".to_string());
    }

    let mut command = Command::new(SUDO);
    command.arg("-n").arg("--").arg(&request.program).args(&request.args);
    let result = run_command(command, "sudo").map_err(|error| format!("sudo failed: {error}"))?;
    Ok((result, true))
}

#[cfg(target_os = "macos")]
const SUDO: &str = "/usr/bin/sudo";
/// Set only on the `sudo -A -v` sudo39 spawns. sudo runs SUDO_ASKPASS as `<path> <sudo prompt>`
/// with its caller's environment, so the marker, not argv, selects the askpass entry point.
#[cfg(target_os = "macos")]
const ASKPASS_MODE_ENV: &str = "SUDO39_ASKPASS_MODE";
#[cfg(target_os = "macos")]
const PROBE_ARG: &str = "--probe-shared-sudo";
#[cfg(target_os = "macos")]
const ASKPASS_TEXT_ENV: &str = "SUDO39_ASKPASS_TEXT";

#[cfg(target_os = "macos")]
fn askpass_text(request: &CommandRequest, approval: Approval) -> String {
    let mut text = admin_prompt(&shell_join(request), approval == Approval::Unlisted);
    text.push_str("\n\nYour password unlocks sudo for this sudo39 server only, for sudo's timestamp_timeout (5 minutes unless sudoers changes it); allowlisted and approved programs then run without asking.");
    text
}

/// The SUDO_ASKPASS helper (SUDO39_ASKPASS_MODE=1). Shows a hidden-answer dialog with the text
/// sudo39 put in SUDO39_ASKPASS_TEXT and prints the password for sudo; Cancel exits non-zero.
/// The password goes from the dialog to sudo's pipe and never reaches the MCP process.
#[cfg(target_os = "macos")]
fn askpass_main() -> i32 {
    let text = std::env::var(ASKPASS_TEXT_ENV)
        .unwrap_or_else(|_| "An AI agent (sudo39 MCP) asks for your password to run a command as root.".to_string());
    let script = format!(
        "text returned of (display dialog {} default answer \"\" with hidden answer with title \"sudo39\" with icon caution buttons {{\"Cancel\", \"Allow\"}} default button \"Allow\" cancel button \"Cancel\")",
        apple_script_string(&text)
    );
    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(output) if output.status.success() => {
            use std::io::Write;
            let mut stdout = std::io::stdout();
            if stdout.write_all(&output.stdout).is_err() || stdout.flush().is_err() {
                return 1;
            }
            0
        }
        _ => 1,
    }
}

/// `sudo39 --probe-shared-sudo`: exits 0 when `sudo -n` succeeds from this process, whose parent
/// is the server rather than sudo's earlier caller; a per-process credential must not satisfy it.
#[cfg(target_os = "macos")]
fn probe_main() -> i32 {
    Command::new(SUDO)
        .args(["-n", "--", "/usr/bin/true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_or(1, |status| if status.success() { 0 } else { 1 })
}

/// Rejects a program that a non-root user could replace: the path must be absolute and free of
/// symlinks, name a regular file owned by root, and every directory on the way must be owned by
/// root and not writable by group or others.
#[cfg(unix)]
fn check_trusted_program(program: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let path = Path::new(program);
    if !path.is_absolute() {
        return Err("not an absolute path".to_string());
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot resolve: {error}"))?;
    if canonical != path {
        return Err(format!(
            "path contains a symlink or relative component; use {}",
            canonical.display()
        ));
    }
    let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("not a regular file".to_string());
    }
    let mut current = Some(path);
    while let Some(node) = current {
        let metadata = std::fs::metadata(node).map_err(|error| error.to_string())?;
        if metadata.uid() != 0 {
            return Err(format!("{} is not owned by root", node.display()));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(format!("{} is writable by group or others", node.display()));
        }
        current = node.parent();
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_trusted_program(program: &str) -> Result<(), String> {
    if Path::new(program).is_absolute() {
        Ok(())
    } else {
        Err("not an absolute path".to_string())
    }
}

struct RunResult {
    launcher: &'static str,
    output: Output,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ElevationMode {
    Auto,
    Sudo,
    Pkexec,
    MacosOsascript,
    WindowsUac,
}

impl ElevationMode {
    fn parse(mode: &str) -> Result<Self, String> {
        match mode {
            "auto" => Ok(Self::Auto),
            "sudo" => Ok(Self::Sudo),
            "pkexec" => Ok(Self::Pkexec),
            "macos_osascript" => Ok(Self::MacosOsascript),
            "windows_uac" => Ok(Self::WindowsUac),
            other => Err(format!(
                "unsupported elevation mode {other:?}; use auto, sudo, pkexec, macos_osascript, or windows_uac"
            )),
        }
    }

    fn run(self, request: &CommandRequest) -> Result<RunResult, String> {
        match self {
            Self::Auto => run_elevated_auto(request),
            Self::Sudo => run_sudo(request),
            Self::Pkexec => run_pkexec(request),
            Self::MacosOsascript => run_macos_osascript(request),
            Self::WindowsUac => run_windows_uac(request),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Sudo => "sudo",
            Self::Pkexec => "pkexec",
            Self::MacosOsascript => "macos_osascript",
            Self::WindowsUac => "windows_uac",
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_elevated_auto(request: &CommandRequest) -> Result<RunResult, String> {
    if cfg!(target_os = "macos") {
        return run_macos_osascript(request);
    }

    run_sudo(request).or_else(|sudo_error| {
        run_pkexec(request).map_err(|pkexec_error| {
            format!("sudo failed: {sudo_error}; pkexec failed: {pkexec_error}")
        })
    })
}

#[cfg(target_os = "windows")]
fn run_elevated_auto(request: &CommandRequest) -> Result<RunResult, String> {
    run_windows_uac(request)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_elevated_auto(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("auto elevation is only implemented for Linux, macOS, and Windows".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_sudo(request: &CommandRequest) -> Result<RunResult, String> {
    let mut command = Command::new("sudo");
    if let Some(askpass) = std::env::var_os("SUDO39_ASKPASS") {
        command.env("SUDO_ASKPASS", askpass);
        command.arg("-A");
    } else {
        command.arg("-n");
    }

    command.arg("--").arg(&request.program).args(&request.args);
    run_command(command, "sudo").map_err(|error| format!("sudo failed: {error}"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run_sudo(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("sudo mode is only available on Linux and macOS".to_string())
}

#[cfg(target_os = "linux")]
fn run_pkexec(request: &CommandRequest) -> Result<RunResult, String> {
    let mut command = Command::new("pkexec");
    command.arg(&request.program).args(&request.args);
    run_command(command, "pkexec").map_err(|error| format!("pkexec failed: {error}"))
}

#[cfg(not(target_os = "linux"))]
fn run_pkexec(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("pkexec mode is only available on Linux".to_string())
}

/// Longest command text shown in the administrator dialog; longer commands are cut with "…".
#[cfg(target_os = "macos")]
const PROMPT_COMMAND_LIMIT: usize = 600;

#[cfg(target_os = "macos")]
fn run_macos_osascript(request: &CommandRequest) -> Result<RunResult, String> {
    run_macos_osascript_marked(request, false)
}

#[cfg(target_os = "macos")]
fn run_macos_osascript_marked(request: &CommandRequest, unlisted: bool) -> Result<RunResult, String> {
    let shell_command = shell_join(request);
    let script = format!(
        "do shell script {} with prompt {} with administrator privileges",
        apple_script_string(&shell_command),
        apple_script_string(&admin_prompt(&shell_command, unlisted)),
    );

    let mut command = Command::new("/usr/bin/osascript");
    command.arg("-e").arg(script);
    run_command(command, "osascript").map_err(|error| format!("osascript failed: {error}"))
}

#[cfg(target_os = "macos")]
fn admin_prompt(shell_command: &str, unlisted: bool) -> String {
    let shown = if shell_command.chars().count() > PROMPT_COMMAND_LIMIT {
        let cut = shell_command.chars().take(PROMPT_COMMAND_LIMIT).collect::<String>();
        format!("{cut}…")
    } else {
        shell_command.to_string()
    };
    let marker = if unlisted {
        "⚠ NOT IN ALLOWLIST. Approving lets this server run this program as root again until it restarts.\n\n"
    } else {
        ""
    };
    format!("{marker}An AI agent (sudo39 MCP) asks to run as root:\n\n{shown}")
}

#[cfg(not(target_os = "macos"))]
fn run_macos_osascript(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("macos_osascript mode is only available on macOS".to_string())
}

#[cfg(target_os = "windows")]
fn run_windows_uac(request: &CommandRequest) -> Result<RunResult, String> {
    let arguments = request
        .args
        .iter()
        .map(|arg| format!("'{}'", powershell_single_quote(arg)))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        "Start-Process -FilePath '{}' -ArgumentList @({}) -Verb RunAs -Wait",
        powershell_single_quote(&request.program),
        arguments
    );

    let mut command = Command::new("powershell.exe");
    command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(script);

    run_command(command, "powershell_start_process")
        .map_err(|error| format!("powershell UAC failed: {error}"))
}

#[cfg(not(target_os = "windows"))]
fn run_windows_uac(_request: &CommandRequest) -> Result<RunResult, String> {
    Err("windows_uac mode is only available on Windows".to_string())
}

#[cfg(target_os = "macos")]
fn shell_join(request: &CommandRequest) -> String {
    std::iter::once(&request.program)
        .chain(request.args.iter())
        .map(|part| shell_single_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "macos")]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn apple_script_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "windows")]
fn powershell_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn run_command(mut command: Command, launcher: &'static str) -> Result<RunResult, String> {
    let timeout = env_u64("SUDO39_TIMEOUT_SECS", 30);
    let output_limit = env_u64("SUDO39_OUTPUT_LIMIT_BYTES", 4096) as usize;

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture stderr".to_string())?;

    let stdout_reader = thread::spawn(move || read_limited(stdout, output_limit));
    let stderr_reader = thread::spawn(move || read_limited(stderr, output_limit));
    let deadline = SystemTime::now() + Duration::from_secs(timeout);

    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }

        if SystemTime::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = stdout_reader
                .join()
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default();
            let stderr = stderr_reader
                .join()
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default();
            let mut msg = format!(
                "timed out after {timeout} seconds; the launcher was killed, an elevated child may still be running"
            );
            let stdout_text = String::from_utf8_lossy(&stdout.0);
            let stderr_text = String::from_utf8_lossy(&stderr.0);
            if !stdout_text.is_empty() {
                msg.push_str(&format!("\npartial stdout:\n{stdout_text}"));
            }
            if !stderr_text.is_empty() {
                msg.push_str(&format!("\npartial stderr:\n{stderr_text}"));
            }
            return Err(msg);
        }

        thread::sleep(Duration::from_millis(50));
    };

    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| "stdout reader panicked".to_string())??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| "stderr reader panicked".to_string())??;

    Ok(RunResult {
        launcher,
        stdout_truncated,
        stderr_truncated,
        output: Output {
            status,
            stdout,
            stderr,
        },
    })
}

fn read_limited(mut reader: impl Read, limit: usize) -> Result<(Vec<u8>, bool), String> {
    let mut output = Vec::new();
    let mut buffer = [0; 8192];

    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Ok((output, false));
        }

        let remaining = limit - output.len();
        if count > remaining {
            output.extend_from_slice(&buffer[..remaining]);
            // Dropping the reader closes the pipe, so the child gets SIGPIPE instead of
            // blocking on output that would be discarded.
            return Ok((output, true));
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn format_output(
    request: &CommandRequest,
    mode: ElevationMode,
    approval: Approval,
    result: &RunResult,
) -> String {
    let status = result.output.status.code().map_or_else(
        || "terminated by signal".to_string(),
        |code| code.to_string(),
    );
    let stdout = String::from_utf8_lossy(&result.output.stdout);
    let stderr = String::from_utf8_lossy(&result.output.stderr);
    let stdout_suffix = if result.stdout_truncated {
        "\n[truncated]"
    } else {
        ""
    };
    let stderr_suffix = if result.stderr_truncated {
        "\n[truncated]"
    } else {
        ""
    };

    format!(
        "program: {}\nargs: {:?}\nmode: {}\napproval: {}\nlauncher: {}\nlauncher_exit_status: {}\nstdout:\n{}{}\nstderr:\n{}{}",
        request.program,
        request.args,
        mode.as_str(),
        approval.label(),
        result.launcher,
        status,
        stdout,
        stdout_suffix,
        stderr,
        stderr_suffix,
    )
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn audit_request(event: &str, mode: ElevationMode, request: &CommandRequest, status: Option<i32>) {
    eprintln!(
        "sudo39_audit event={} unix_ts={} mode={} program={:?} args={:?} status={:?}",
        event,
        unix_ts(),
        mode.as_str(),
        request.program,
        request.args,
        status
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use turbomcp::prelude::*;

    // Helper entry points spawned by remember mode; they never start the MCP server.
    #[cfg(target_os = "macos")]
    {
        if std::env::var(ASKPASS_MODE_ENV).ok().as_deref() == Some("1") {
            std::process::exit(askpass_main());
        }
        if std::env::args().nth(1).as_deref() == Some(PROBE_ARG) {
            std::process::exit(probe_main());
        }
    }

    let policy = Policy::from_env().map_err(|error| format!("sudo39: invalid policy: {error}"))?;
    eprintln!("sudo39_audit event=policy unix_ts={} {:?}", unix_ts(), policy.describe());

    let mut protocol = ProtocolConfig::multi_version();
    protocol.allow_fallback = true;

    Sudo39::new(policy)
        .builder()
        .with_protocol(protocol)
        .serve()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(programs: &[&str], modes: &[ElevationMode]) -> Policy {
        Policy {
            allowed_programs: programs.iter().map(ToString::to_string).collect(),
            allowed_modes: modes.to_vec(),
            allow_unsafe: false,
            prompt_unlisted: false,
            remember: false,
        }
    }

    fn request(program: &str) -> CommandRequest {
        CommandRequest::new(program.to_string(), None).unwrap()
    }

    fn none() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn trims_program() {
        let request = CommandRequest::new(" /usr/bin/id ".to_string(), None).unwrap();
        assert_eq!(request.program, "/usr/bin/id");
        assert!(request.args.is_empty());
    }

    #[test]
    fn rejects_relative_program() {
        let error = CommandRequest::new("id".to_string(), None).unwrap_err();
        assert!(error.message.contains("absolute path"));
    }

    #[test]
    fn rejects_program_outside_allowlist() {
        let error = validate_request(
            &policy(&["/usr/bin/id"], &[ElevationMode::Auto]),
            &none(),
            ElevationMode::Auto,
            &request("/usr/bin/whoami"),
        )
        .unwrap_err();
        assert!(error.message.contains("allowlist"));
    }

    #[test]
    fn rejects_mode_outside_policy() {
        let error = validate_request(
            &policy(&["/usr/bin/id"], &[ElevationMode::Auto]),
            &none(),
            ElevationMode::Sudo,
            &request("/usr/bin/id"),
        )
        .unwrap_err();
        assert!(error.message.contains("mode"));
    }

    #[cfg(unix)]
    #[test]
    fn accepts_root_owned_system_program() {
        let approval = validate_request(
            &policy(&["/usr/bin/id"], &[ElevationMode::Auto]),
            &none(),
            ElevationMode::Auto,
            &request("/usr/bin/id"),
        )
        .unwrap();
        assert_eq!(approval, Approval::Listed);
    }

    #[cfg(unix)]
    #[test]
    fn unlisted_program_needs_prompt_unlisted() {
        let mut prompting = policy(&["/usr/bin/id"], &[ElevationMode::Auto, ElevationMode::Sudo]);
        prompting.prompt_unlisted = true;
        let unlisted = request("/usr/bin/whoami");
        assert_eq!(
            validate_request(&prompting, &none(), ElevationMode::Auto, &unlisted).unwrap(),
            Approval::Unlisted
        );
        // Only auto shows a dialog; an explicit sudo mode could pass on a cached credential.
        assert!(validate_request(&prompting, &none(), ElevationMode::Sudo, &unlisted).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn approved_program_skips_the_unlisted_marker() {
        let mut prompting = policy(&[], &[ElevationMode::Auto]);
        prompting.prompt_unlisted = true;
        let approved = HashSet::from(["/usr/bin/whoami".to_string()]);
        assert_eq!(
            validate_request(&prompting, &approved, ElevationMode::Auto, &request("/usr/bin/whoami"))
                .unwrap(),
            Approval::Approved
        );
    }

    #[cfg(unix)]
    #[test]
    fn unlisted_program_still_needs_a_trusted_path() {
        let mut prompting = policy(&[], &[ElevationMode::Auto]);
        prompting.prompt_unlisted = true;
        let error = validate_request(&prompting, &none(), ElevationMode::Auto, &request("/tmp"))
            .unwrap_err();
        assert!(error.message.contains("symlink"), "{}", error.message);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_user_owned_program_even_when_unsafe() {
        let dir = std::env::temp_dir().join(format!("sudo39-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("id");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        let fake = fake.canonicalize().unwrap().to_string_lossy().into_owned();

        let mut unsafe_policy = policy(&[], &[ElevationMode::Auto]);
        unsafe_policy.allow_unsafe = true;
        let error = validate_request(&unsafe_policy, &none(), ElevationMode::Auto, &request(&fake))
            .unwrap_err();
        assert!(error.message.contains("not owned by root"), "{}", error.message);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_path() {
        // /tmp is a symlink to /private/tmp on macOS; on Linux /proc/self/exe is a symlink.
        let candidate = if cfg!(target_os = "macos") { "/tmp" } else { "/proc/self/exe" };
        let error = check_trusted_program(candidate).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
    }

    #[test]
    fn truncation_is_reported_when_output_exceeds_limit() {
        let (output, truncated) = read_limited(&b"abcdef"[..], 4).unwrap();
        assert_eq!(output, b"abcd");
        assert!(truncated);
        let (output, truncated) = read_limited(&b"abcd"[..], 4).unwrap();
        assert_eq!(output, b"abcd");
        assert!(!truncated);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn admin_prompt_shows_quoted_command() {
        let request = CommandRequest::new(
            "/usr/bin/id".to_string(),
            Some(vec!["-u".to_string(), "it's".to_string()]),
        )
        .unwrap();
        let prompt = admin_prompt(&shell_join(&request), false);
        assert!(prompt.ends_with("'/usr/bin/id' '-u' 'it'\\''s'"), "{prompt}");
        assert!(!prompt.contains("NOT IN ALLOWLIST"));
        assert!(admin_prompt(&shell_join(&request), true).starts_with("⚠ NOT IN ALLOWLIST"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn askpass_text_names_command_and_scope() {
        let text = askpass_text(&request("/usr/bin/fs_usage"), Approval::Unlisted);
        assert!(text.starts_with("⚠ NOT IN ALLOWLIST"), "{text}");
        assert!(text.contains("'/usr/bin/fs_usage'"), "{text}");
        assert!(text.contains("this sudo39 server only"), "{text}");
    }

    #[test]
    fn env_flag_accepts_only_zero_and_one() {
        // SAFETY: tests touching this variable run only here.
        unsafe { std::env::set_var("SUDO39_TEST_FLAG", "yes") };
        assert!(env_flag("SUDO39_TEST_FLAG").is_err());
        unsafe { std::env::set_var("SUDO39_TEST_FLAG", "1") };
        assert!(env_flag("SUDO39_TEST_FLAG").unwrap());
        unsafe { std::env::remove_var("SUDO39_TEST_FLAG") };
        assert!(!env_flag("SUDO39_TEST_FLAG").unwrap());
    }

    #[test]
    fn policy_describe_sorts_allowed_programs() {
        let policy = policy(&["/usr/bin/whoami", "/usr/bin/id"], &[ElevationMode::Auto]);
        assert_eq!(
            policy.describe(),
            "allow_unsafe: false\nallowed_programs: [\"/usr/bin/id\", \"/usr/bin/whoami\"]\nallowed_modes: [\"auto\"]\nprompt_unlisted: false\nremember: false"
        );
    }
}
