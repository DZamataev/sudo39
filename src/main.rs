use std::{
    collections::HashSet,
    io::Read,
    path::Path,
    process::{Command, Output, Stdio},
    sync::Arc,
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
/// change it: the MCP client is the party the policy restricts.
#[derive(Clone)]
struct Sudo39 {
    policy: Arc<Policy>,
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
        }
    }

    #[tool("Run an allowlisted program as root. The user approves each call in a native OS dialog that shows the exact command; a denied dialog fails the call.")]
    async fn sudo_run(
        &self,
        #[description(
            "Absolute path of the program, for example \"/usr/bin/id\". It must exactly match an entry of the allowlist shown by sudo39_policy. Pass arguments with the arguments parameter."
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

        if let Err(error) = validate_request(&self.policy, mode, &request) {
            audit_request("deny", mode, &request, None);
            return Err(error);
        }
        audit_request("start", mode, &request, None);
        let blocking_request = request.clone();
        let result = match tokio::task::spawn_blocking(move || mode.run(&blocking_request)).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                audit_request("error", mode, &request, None);
                return Err(McpError::internal(error));
            }
            Err(error) => {
                audit_request("error", mode, &request, None);
                return Err(McpError::internal(error.to_string()));
            }
        };
        audit_request("finish", mode, &request, result.output.status.code());

        Ok(format_output(&request, mode, &result))
    }

    #[tool("Show the active sudo39 policy: allowed programs and elevation modes. The policy is read-only.")]
    async fn sudo39_policy(&self) -> McpResult<String> {
        Ok(self.policy.describe())
    }
}

#[derive(Debug)]
struct Policy {
    allowed_programs: HashSet<String>,
    allowed_modes: Vec<ElevationMode>,
    allow_unsafe: bool,
}

impl Policy {
    /// Reads SUDO39_ALLOWED_PROGRAMS, SUDO39_ALLOWED_MODES and SUDO39_ALLOW_UNSAFE.
    ///
    /// # Errors
    /// Returns a description of the first invalid entry: a program that is not an absolute path
    /// of a root-owned file reachable only through root-owned, non-group/other-writable
    /// directories, or an unknown mode.
    fn from_env() -> Result<Self, String> {
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
            "allow_unsafe: {}\nallowed_programs: {:?}\nallowed_modes: {:?}",
            self.allow_unsafe, allowed_programs, allowed_modes
        )
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
    mode: ElevationMode,
    request: &CommandRequest,
) -> McpResult<()> {
    if !policy.allowed_modes.contains(&mode) {
        return Err(McpError::permission_denied(format!(
            "mode {:?} is not allowed; see sudo39_policy",
            mode.as_str()
        )));
    }
    if !policy.allow_unsafe && !policy.allowed_programs.contains(&request.program) {
        return Err(McpError::permission_denied(
            "program is not in the allowlist; see sudo39_policy",
        ));
    }
    // Rechecked per call: the file or a parent may have changed since startup.
    check_trusted_program(&request.program).map_err(McpError::permission_denied)
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
    let shell_command = shell_join(request);
    let script = format!(
        "do shell script {} with prompt {} with administrator privileges",
        apple_script_string(&shell_command),
        apple_script_string(&admin_prompt(&shell_command)),
    );

    let mut command = Command::new("/usr/bin/osascript");
    command.arg("-e").arg(script);
    run_command(command, "osascript").map_err(|error| format!("osascript failed: {error}"))
}

#[cfg(target_os = "macos")]
fn admin_prompt(shell_command: &str) -> String {
    let shown = if shell_command.chars().count() > PROMPT_COMMAND_LIMIT {
        let cut = shell_command.chars().take(PROMPT_COMMAND_LIMIT).collect::<String>();
        format!("{cut}…")
    } else {
        shell_command.to_string()
    };
    format!("An AI agent (sudo39 MCP) asks to run as root:\n\n{shown}")
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

fn format_output(request: &CommandRequest, mode: ElevationMode, result: &RunResult) -> String {
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
        "program: {}\nargs: {:?}\nmode: {}\nlauncher: {}\nlauncher_exit_status: {}\nstdout:\n{}{}\nstderr:\n{}{}",
        request.program,
        request.args,
        mode.as_str(),
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
        }
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
        let request = CommandRequest::new("/usr/bin/whoami".to_string(), None).unwrap();
        let error = validate_request(
            &policy(&["/usr/bin/id"], &[ElevationMode::Auto]),
            ElevationMode::Auto,
            &request,
        )
        .unwrap_err();
        assert!(error.message.contains("allowlist"));
    }

    #[test]
    fn rejects_mode_outside_policy() {
        let request = CommandRequest::new("/usr/bin/id".to_string(), None).unwrap();
        let error = validate_request(
            &policy(&["/usr/bin/id"], &[ElevationMode::Auto]),
            ElevationMode::Sudo,
            &request,
        )
        .unwrap_err();
        assert!(error.message.contains("mode"));
    }

    #[cfg(unix)]
    #[test]
    fn accepts_root_owned_system_program() {
        let request = CommandRequest::new("/usr/bin/id".to_string(), None).unwrap();
        validate_request(
            &policy(&["/usr/bin/id"], &[ElevationMode::Auto]),
            ElevationMode::Auto,
            &request,
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_user_owned_program_even_when_unsafe() {
        let dir = std::env::temp_dir().join(format!("sudo39-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("id");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        let fake = fake.canonicalize().unwrap().to_string_lossy().into_owned();

        let request = CommandRequest::new(fake.clone(), None).unwrap();
        let mut unsafe_policy = policy(&[], &[ElevationMode::Auto]);
        unsafe_policy.allow_unsafe = true;
        let error = validate_request(&unsafe_policy, ElevationMode::Auto, &request).unwrap_err();
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
        let prompt = admin_prompt(&shell_join(&request));
        assert!(prompt.ends_with("'/usr/bin/id' '-u' 'it'\\''s'"), "{prompt}");
    }

    #[test]
    fn policy_describe_sorts_allowed_programs() {
        let policy = policy(&["/usr/bin/whoami", "/usr/bin/id"], &[ElevationMode::Auto]);
        assert_eq!(
            policy.describe(),
            "allow_unsafe: false\nallowed_programs: [\"/usr/bin/id\", \"/usr/bin/whoami\"]\nallowed_modes: [\"auto\"]"
        );
    }
}
