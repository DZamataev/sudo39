# sudo39

sudo39 is a small MCP server built with [TurboMCP](https://github.com/Epistates/turbomcp). Its primary tool is:

> **WARNING:** With great power comes great responsibility. This server grants elevated OS privileges to AI agents. Misconfiguration can allow arbitrary root-level execution. Read the full Elevation Model section before deploying.

```text
sudo_run(command, arguments?, mode?)
```

> **Hardened fork** of [alejandroqh/sudo39](https://github.com/alejandroqh/sudo39). The policy is read-only at runtime: the MCP admin tools and confirmation prompts are removed, programs are absolute paths of root-owned files, the elevation modes are allowlisted, and the macOS dialog shows the exact command. See [Security changes](#security-changes). Install it from this repository: `cargo install sudo39` and the upstream installer script fetch the unhardened upstream build.

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

### Asking for unlisted programs and remembering approval (macOS)

Two opt-in flags let the user approve programs at the moment the agent needs them, with the password as the only approval channel. Buttons alone would not do: an agent with computer-use tools can click a dialog, but it cannot type the user's password.

```sh
export SUDO39_PROMPT_UNLISTED=1   # unlisted programs ask for the password instead of failing
export SUDO39_REMEMBER=1          # one password covers later calls for sudo's timestamp_timeout
```

- `SUDO39_PROMPT_UNLISTED=1`: a program outside `SUDO39_ALLOWED_PROGRAMS` opens the password dialog marked "⚠ NOT IN ALLOWLIST". The password approves the program for the rest of this server run (`approved_this_run` in `sudo39_policy`); a restart forgets it. Only `auto` mode asks, and the trusted-path check still applies, so the agent cannot get its own binary approved.
- `SUDO39_REMEMBER=1`: `auto` runs `sudo -A -v` with sudo39's own askpass dialog, which names the command, then `sudo -n -- <program>`. Without a terminal, sudo keys its credential cache to the parent process, so the password unlocks sudo for this server process only, for `timestamp_timeout` (5 minutes unless sudoers changes it). A first-time unlisted program resets that cache first, so its approval always takes a password. The password travels from the dialog to sudo's askpass pipe and never reaches the MCP process.
- After each authentication sudo39 runs `sudo -n /usr/bin/true` from a separate child process. If that succeeds, the credential is shared (`Defaults timestamp_type=global` or a `NOPASSWD` rule), so sudo39 resets it and refuses the call.

Each flag accepts only `0` or `1`; any other value stops the server at startup. On other platforms both flags stop the server at startup.

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
6. Opt-in `SUDO39_PROMPT_UNLISTED` and `SUDO39_REMEMBER` restore approval on the fly through the password dialog, which the client cannot complete itself.
5. Output truncation is reported when a single read exceeds the limit.

A timeout kills the launcher (`osascript`, `sudo`, `pkexec`), not an already elevated child; the result says so.

## Install

Build from this repository; the crate on crates.io and the upstream `h39.sh` installer are the unhardened upstream version.

```sh
git clone https://github.com/DZamataev/sudo39.git
cd sudo39
cargo test --locked
cargo build --release --locked
install -m 0755 target/release/sudo39 ~/.local/bin/sudo39
```

or `cargo install --locked --git https://github.com/DZamataev/sudo39 --branch main`.

## MCP Client Config

The policy lives in the client's server entry, so the client process that launches sudo39 is where you widen or narrow it. For a stdio MCP client:

```json
{
  "mcpServers": {
    "sudo39": {
      "command": "/absolute/path/to/sudo39",
      "args": [],
      "env": {
        "SUDO39_ALLOWED_PROGRAMS": "/usr/bin/id,/usr/bin/whoami",
        "SUDO39_ALLOWED_MODES": "auto",
        "SUDO39_TIMEOUT_SECS": "120"
      }
    }
  }
}
```

On macOS the administrator dialog waits inside `SUDO39_TIMEOUT_SECS`; 30 seconds is often too short to read the command and type a password. Keep the client's own tool-call timeout above it.

DeepSeek Harness reads the same entry from `$DSH_HOME/cordis.patch.yml`:

```yaml
- insert:
    - id: mcp-sudo39
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: sudo39
        transport: stdio
        command: /Users/<you>/.local/bin/sudo39
        args: []
        cwd: !!js process.cwd()
        env:
          SUDO39_ALLOWED_PROGRAMS: /usr/bin/id,/usr/bin/whoami
          SUDO39_ALLOWED_MODES: auto
          SUDO39_ALLOW_UNSAFE: '0'
          SUDO39_PROMPT_UNLISTED: '1'   # optional, macOS
          SUDO39_REMEMBER: '1'          # optional, macOS
          SUDO39_TIMEOUT_SECS: '120'
        toolCallTimeoutMs: 150000
        failOnStartupError: true
```

Set `SUDO39_ALLOW_UNSAFE: '0'` explicitly when the client merges its ambient environment into the server's, so an inherited `SUDO39_ALLOW_UNSAFE=1` cannot turn the allowlist off.

## Notes

Any MCP client granted access to this server can request elevated operations allowed by the policy; it cannot change the policy. Each request still needs the user's approval in the OS dialog (unless a cached `sudo` timestamp or a `NOPASSWD` rule skips it). Treat the server binary, its process environment, and the askpass helper as the administrative trust boundary: a process running as your user can replace a user-owned binary or call `osascript` itself.

`sudo` cannot safely prompt for a password on MCP stdio, because stdin/stdout are already the protocol transport. If no askpass helper is configured, `sudo39` runs `sudo -n`, which fails instead of prompting. This is deliberate.

Commands are executed without a shell on Linux and Windows. On macOS, the administrator prompt path uses AppleScript's `do shell script`; `sudo39` shell-quotes the program and argument vector before passing it to AppleScript. Pass arguments with the `arguments` array; `command` must be an absolute program path.

The returned `launcher_exit_status`, `stdout`, and `stderr` are captured from the elevation launcher and capped by `SUDO39_OUTPUT_LIMIT_BYTES`. On Linux this is normally the elevated command through `sudo` or `pkexec`. On macOS it is `osascript`. On Windows it is the PowerShell `Start-Process` launcher, not a reliable capture of the elevated child process output.

Server startup (with the effective policy) and each execution write a minimal audit event to stderr with timestamp and relevant policy or command fields. It does not log stdout or stderr.
