## Logger Engine Reference

This document explains how `engine/logger-engine.lua` ingests ubus monitor traffic, classifies operations, enriches them with before/after data, and emits audit logs. Use it alongside `README.md` (repo root) and `engine/README_FILTERING.md` for a complete picture.

---

### 1. Bootstrapping & Configuration

1. **Package paths**  
   The script amends `package.path` to load bundled modules (`engine`, `engine-modules`, `formatter`). When deployed under `/usr/lib/lua/Audits-PGP`, no extra `LUA_PATH` is required.

2. **Config load**  
   ```lua
   local config = require("engine.config")
   config.setup_paths()
   local cfg = config.load()
   ```
   - `cfg.controls` / `cfg.logging` -> feature toggles (`LOGGING_CONTROLS`)  
   - `cfg.settings` -> rotation / batch timing (`LOG_SETTINGS`)  
   - `cfg.security` -> file-read whitelist, exec blacklist  
   - `cfg.filters` -> allowed ubus families & noise hints

3. **Outputs**  
   `build_output_specs(cfg)` maps `human`, `key_value`, `debug`, etc., to absolute file paths. Rotation defaults fall back to `cfg.outputs.rotation.max_file_size` (1 MiB).

4. **Modules**  
   - `formatter = require("formatter.init")` for human/KV lines  
   - `event_pipeline = require("engine.event_pipeline")` for fast filter + triage  
   - `before_after = require("engine-modules.before_after")` (optional)  
   - `uci_interface = require("engine-modules.uci_interface")`

Environment overrides (e.g., `ARGUS_LOG_DIR`, `ARGUS_DEBUG`) are handled inside `engine/config.lua`.

---

### 2. Filtering & Triage (High-Level)

Filtering happens in three layers (see `engine/README_FILTERING.md` for deep dive):

1. **Pre-parse noise:** `should_skip_before_parse` / `is_probably_noise` examine raw ubus monitor lines (family tokens, regex hints).
2. **Fast filter:** `event_pipeline.fast_filter` keeps `NEEDED_EVENTS` and drops `HARD_NOISE_EVENTS`.
3. **Triage + mode drops:**  
   - `process_invoke_event` calls `event_pipeline.triage` with `TRIAGE_MAP` + `should_filter_file_operation`.  
   - `event_pipeline.should_log` enforces `MODE_DROP_EVENTS` derived from `cfg.features.operation_mode`.

`filter_stats` tracks rejection/log counts and is periodically emitted via the unified `debug()` helper when `filter_stats_interval` is hit.

---

### 3. Runtime State Model

`state` centralizes all mutable context:

```lua
local state = {
    objects = {},     -- objid -> objpath
    callbacks = {},   -- callback_id -> pending operation or session link
    sessions = {},    -- session_id -> { user, saves = {}, changes = {} }
    auth_sessions = {}-- ubus_rpc_session -> { user, login_time, ip }
}
```

Helpers:

- `get_session(session_id)` creates/returns tracked session buckets.
- `state.callbacks` stores:
  - `{ type = "operation", op = classified_operation }`
  - `{ type = "uci_session_link", session_id = ... }`
- `state.auth_sessions` remembers successful `auth_login` events for later `auth_logout` correlation.

---

### 4. Handler Pipeline (`handle_*` functions)

`logger-engine.lua` treats every ubus monitor line as `(family, callback_id, payload)` and dispatches to focused handlers:

| Handler | Family | Responsibility |
|---------|--------|----------------|
| `handle_objpath_data` | `data` | Maintains `state.objects[objid] = objpath` for later lookups. |
| `handle_uci_changes_data` | `data` | Copies `parsed.data.changes` into the pending session referenced by `state.callbacks[callback_id]`. |
| `handle_exec_data` | `data` | Attaches stdout/stderr/exit data to pending `file.exec` operations. |
| `handle_invoke` | `invoke` | Builds canonical events via `event_pipeline.build_event`, runs filtering/triage, and stores `{type="operation"}` entries in `state.callbacks`. |
| `handle_status` | `status` | Finalizes successful callbacks: stages UCI operations, triggers before/after capture, builds auth/exec/firewall log entries, and invokes `create_log_entries_for_operation`. |

Flow summary:

1. `EVENT_PIPELINE.extract_and_build` (within `EVENT_PIPELINE.process`) parses each ubus monitor line into `parsed_data`, identifies the family, and calls the relevant handler.
2. `handle_invoke` + `process_invoke_event` classify operations (uci_change, exec, auth_*, service restarts, etc.).
3. `handle_status` inspects the stored operation and routes to:
   - `stage_uci_operation_for_session` for UCI commands (tracks before-state + session linkage).
   - `process_successful_uci_apply` after `uci.apply` succeeds (summaries + before/after analysis).
   - Inline branches for exec/auth/firewall/system commands to shape log metadata.

---

### 5. Logging & Output Generation

1. **Sanitization:** `sanitize_sensitive_information` redacts passwords, PSKs, keys unless `cfg.security.redact_sensitive_values == false`.
2. **File-read guard:** `create_log_entries_for_operation` re-checks `should_filter_file_operation` before logging `file_read` types.
3. **Formatter integration:**  
   - Builds `clean_operation` and calls `formatter.format`.  
   - Human-readable entries: `TIMESTAMP [user: foo] <message>` appended to `log_entry_batches.human_readable`.  
   - KV entries: `build_kv_line` + `convert_values_to_key_value_string`, queued in `log_entry_batches.key_value`.
4. **Batch flush:**  
   - `flush_log_batches(force)` rotates files (via `rotate_log_file_if_needed`), writes queued batches, and clears tables.  
   - Triggered on interval (`auto_flush_interval_seconds`), on batch size (`batch_size_for_immediate_flush`), and during shutdown/error paths.
5. **Debug output:** `debug(tag, fmt, …)` mirrors events to stderr and `debug.log` when `ARGUS_DEBUG=1` or `cfg.debug.enabled` is true. Tags such as `FLOW`, `SESSION`, `UCI`, and `CALLBACK` replace the old category-specific toggles.

---

### 6. Before/After Integration

When `cfg.features.before_after_tracking` is true and `engine-modules/before_after.lua` loads successfully:

1. `initialize_before_after_module` configures `uci_interface`, sets debug callbacks, and runs health checks.
2. `stage_uci_operation_for_session` captures before-state synchronously (`before_after.capture_before_state`) and stores it under `session_id` + section.
3. `handle_uci_changes_data` collects the raw `changes` array emitted after each operation.
4. `process_successful_uci_apply` merges staged saves and captured `changes`, invokes `before_after.analyze_changes`, and logs a synthesized `set_applied` entry that includes `analyzed_changes`.
5. `before_after.cleanup_session_state` runs after each session apply or when a session is deleted.

If initialization fails, `before_after_active` is set to `false`, and capture is silently skipped.

---

### 7. Execution Filters & Authentication Context

- `should_filter_exec_operation` builds a signature of `command + args` and compares it against `cfg.security.exec_command_blacklist` plus `DEFAULT_EXEC_COMMAND_BLACKLIST`. Matches are dropped before logging.
- `auth_login` updates `state.auth_sessions` with source IP + timestamp; `auth_logout` clears it, enabling downstream log correlation if needed.

---

### 8. Hot Reload & Maintenance

`check_reload()` is a no-op unless `engine/config.lua` exposes `should_reload`/`reload`. When present, it refreshes `cfg`, rebuilds output specs, reopens debug files, reapplies mode settings, and restarts before/after as needed.

The main loop (`while true do ...`) performs:

1. `check_reload()` per iteration.
2. Non-blocking `ubus_monitor_stream:read("*l")`.
3. Skip logic (`should_skip_before_parse`) for obvious noise.
4. `EVENT_PIPELINE.process` call to route handlers.
5. Periodic `flush_log_batches(false)` every 100 lines.

---

### 9. Testing & Diagnostics

- `lua tests/run_smoke.lua` covers formatter integration, before/after capture, and minimal config wiring.
- `lua tests/stress_event_filters.lua` exercises the fast-filter/triage path under load.
- `log-outputs/output.log` (or the configured log directory) reflects human-readable output; rotate/cleanup via `LOG_SETTINGS.max_file_size`.
- Enable `ARGUS_DEBUG=1` to mirror `debug.log` to stderr for quick validation on-device.

---

### 10. Quick Reference (Function Map)

| Area | Key Functions |
|------|---------------|
| Input filtering | `should_skip_before_parse`, `is_probably_noise`, `matches_noise_hint` |
| Event building | `event_pipeline.build_event`, `process_invoke_event`, `TRIAGE_MAP` |
| Session tracking | `stage_uci_operation_for_session`, `get_session`, `state.callbacks` |
| Logging | `create_log_entries_for_operation`, `flush_log_batches`, `rotate_log_file_if_needed` |
| Before/After | `initialize_before_after_module`, `before_after.capture_before_state`, `process_successful_uci_apply` |
| Exec/Auth extras | `should_filter_exec_operation`, `state.auth_sessions` |

Use this guide when exploring or modifying `logger-engine.lua` to maintain feature parity with the existing pipeline.
