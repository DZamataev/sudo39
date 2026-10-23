# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] - hardened fork

### Removed

- Runtime policy tools `sudo39_add_allowed_program`, `sudo39_remove_allowed_program`, `sudo39_set_allow_unsafe`, `sudo39_reload_policy_from_env` and the `confirm_*` prompts; the policy is read-only and comes from the startup environment.

### Changed

- `command` and `SUDO39_ALLOWED_PROGRAMS` entries must be absolute, symlink-free paths of root-owned files in root-owned, non-group/other-writable directories; checked at startup and on every call. Bare names such as `id` are rejected.
- The macOS administrator dialog shows the quoted command.

### Added

- `SUDO39_ALLOWED_MODES` (default `auto`).
- macOS `SUDO39_PROMPT_UNLISTED=1`: an unlisted program asks for the password in a dialog marked NOT IN ALLOWLIST and stays approved until the server restarts.
- macOS `SUDO39_REMEMBER=1`: `sudo -A` with sudo39's own askpass dialog; sudo's per-process credential cache lets one password cover later calls for `timestamp_timeout`. A shared credential (global timestamp or NOPASSWD) is detected, reset, and refused.
- `sudo_run` results carry an `approval` line.

### Fixed

- Truncation is reported when one read exceeds `SUDO39_OUTPUT_LIMIT_BYTES`.

### Known gaps

- `openclaw-plugin/` still proxies the removed policy tools; calls to them fail with "Tool not found".

## [v1.0.2] - 2026-04-16

### Added

- OpenClaw native plugin (`openclaw-plugin/`)
- Claude bundle plugin (`.claude-plugin/`)

### Changed

- Updated TurboMCP dependency to 3.0.14

## [v1.0.0] - 2026-04-10

### Added

- `sudo_run` tool for privilege-elevated command execution via MCP
- Platform-specific elevation: `sudo`, `pkexec`, `macos_osascript`, `windows_uac`, and `auto` mode
- Allowlist-based policy system via `SUDO39_ALLOWED_PROGRAMS` environment variable
- Unsafe mode toggle via `SUDO39_ALLOW_UNSAFE` for unrestricted program access
- Runtime policy management tools: `sudo39_policy`, `sudo39_add_allowed_program`, `sudo39_remove_allowed_program`, `sudo39_set_allow_unsafe`, `sudo39_reload_policy_from_env`
- Confirmation-phrase workflow for all mutating admin operations
- MCP prompts for generating confirmation phrases (`confirm_add_allowed_program`, `confirm_remove_allowed_program`, `confirm_set_allow_unsafe`, `confirm_reload_policy_from_env`)
- Configurable per-execution timeout (`SUDO39_TIMEOUT_SECS`, default 30s)
- Configurable output capture limit (`SUDO39_OUTPUT_LIMIT_BYTES`, default 4 KiB)
- Askpass helper support via `SUDO39_ASKPASS` for non-interactive `sudo -A`
- Structured audit logging to stderr for all executions and policy changes
- No-password-in-context design: credentials never flow through MCP
