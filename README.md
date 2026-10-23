# sudo39

sudo39 is a small MCP server built with [TurboMCP](https://github.com/Epistates/turbomcp). Its primary tool is:

> **WARNING:** With great power comes great responsibility. This server grants elevated OS privileges to AI agents. Misconfiguration can allow arbitrary root-level execution. Read the full Elevation Model section before deploying.

```text
sudo_run(command, arguments?, mode?)
```

> **Hardened fork (dz/security-hardening).** The policy is read-only at runtime: the MCP admin tools and confirmation prompts are removed, programs are absolute paths of root-owned files, the elevation modes are allowlisted, and the macOS dialog shows the exact command. See "Security changes" below.

Example MCP tool arguments:

```json
{
  "command": "/usr/bin/id",
  "arguments": ["-u"]
}
```

## Elevation Model

`sudo39` intentionally does not accept a password parameter. Passwords sent through an MCP client can end up in model context, logs, traces, shell history, and transcripts. Configure elevation on the host instead:

- Linux: `sudo` in `auto` mode, or `pkexec` if `sudo` cannot run. Set `SUDO39_ASKPASS` to let `sudo -A` ask for credentials through an askpass helper.
- macOS: `auto` uses `osascript` with the native administrator prompt; the prompt text names the exact quoted command (cut after 600 characters).
- Windows: `auto` uses PowerShell `Start-Process -Verb RunAs` to trigger UAC.

The policy comes only from the server's startup environment, which the operator controls. No MCP tool changes it; `sudo39_policy()` shows it read-only. An invalid entry stops the server at startup.

```sh
# Absolute paths, exactly as the client must pass them in `command`.
export SUDO39_ALLOWED_PROGRAMS=/usr/bin/id,/usr/bin/whoami
# Elevation modes the client may request (default: auto).
export SUDO39_ALLOWED_MODES=auto
# Allow any program; the trusted-path check below still applies.
export SUDO39_ALLOW_UNSAFE=1
```

Every program, at startup and again on each call, must be an absolute path without symlinks that names a regular file owned by root, and the file and every parent directory must be owned by root and not writable by group or others. This rejects `/opt/homebrew/bin/*` (a user-owned symlink), `~/.local/bin/*`, and anything a non-root process could replace.

An allowlisted program that accepts arbitrary arguments, such as `sh`, `env`, `launchctl`, `cp`, `tee`, `dd`, or `systemctl`, gives the client full root. Allowlist only programs whose every argument combination you accept.

Runtime limits default to 30 seconds and 4 KiB (~1000 LLM tokens) per output stream:

```sh
export SUDO39_TIMEOUT_SECS=30
export SUDO39_OUTPUT_LIMIT_BYTES=4096
```

For `sudo` password prompts, set `SUDO39_ASKPASS` to an askpass helper controlled by the same trust boundary as the MCP server:

```sh
export SUDO39_ASKPASS=/absolute/path/to/askpass
```

Modes:

- `auto`
- `sudo`
- `pkexec`
- `macos_osascript`
- `windows_uac`

## Security changes

Compared with upstream `7e0d7fc`:

1. Removed `sudo39_add_allowed_program`, `sudo39_remove_allowed_program`, `sudo39_set_allow_unsafe`, `sudo39_reload_policy_from_env` and their `confirm_*` prompts. Their confirmation phrases were deterministic and were printed by the prompts and by the mismatch error, so the client could enable unsafe mode without a human.
2. Programs must be absolute and pass the trusted-path check. Upstream matched bare names such as `id`, which `sudo` resolves through the inherited `PATH`; a client able to write to a `PATH` directory could plant its own `id` and run it as root.
3. `SUDO39_ALLOWED_MODES` limits the requested elevation mechanism, so a client cannot switch to `sudo -n` to reuse a cached timestamp without a dialog.
4. The macOS administrator dialog shows the command; upstream showed only "osascript wants to make changes".
5. Output truncation is reported when a single read exceeds the limit.

A timeout kills the launcher (`osascript`, `sudo`, `pkexec`), not an already elevated child; the result says so.

## Install

```bash
cargo install sudo39
```

### Install for any AI CLI / IDE

Installs the binary and auto-configures it for every MCP client detected: **Claude Code**, **Claude Desktop**, **Codex**, **OpenCode**, **OpenClaw**.

```sh
curl -fsSL https://raw.githubusercontent.com/alejandroqh/marketplace/main/h39.sh | bash
```

## Build

```sh
cargo build --release
```

## MCP Client Config

For a stdio MCP client:

```json
{
  "mcpServers": {
    "sudo39": {
      "command": "/absolute/path/to/sudo39",
      "args": []
    }
  }
}
```

## Notes

Any MCP client granted access to this server can request elevated operations allowed by the policy; it cannot change the policy. Each request still needs the user's approval in the OS dialog (unless a cached `sudo` timestamp or a `NOPASSWD` rule skips it). Treat the server binary, its process environment, and the askpass helper as the administrative trust boundary: a process running as your user can replace a user-owned binary or call `osascript` itself.

`sudo` cannot safely prompt for a password on MCP stdio, because stdin/stdout are already the protocol transport. If no askpass helper is configured, `sudo39` runs `sudo -n`, which fails instead of prompting. This is deliberate.

Commands are executed without a shell on Linux and Windows. On macOS, the administrator prompt path uses AppleScript's `do shell script`; `sudo39` shell-quotes the program and argument vector before passing it to AppleScript. Pass arguments with the `arguments` array; `command` must be an absolute program path.

The returned `launcher_exit_status`, `stdout`, and `stderr` are captured from the elevation launcher and capped by `SUDO39_OUTPUT_LIMIT_BYTES`. On Linux this is normally the elevated command through `sudo` or `pkexec`. On macOS it is `osascript`. On Windows it is the PowerShell `Start-Process` launcher, not a reliable capture of the elevated child process output.

Server startup (with the effective policy) and each execution write a minimal audit event to stderr with timestamp and relevant policy or command fields. It does not log stdout or stderr.
