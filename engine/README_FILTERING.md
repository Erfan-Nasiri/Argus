## Engine Filtering Guide

This document summarizes where and how Project Argus filters ubus events inside the runtime engine. It mirrors the current `engine/config.lua` defaults and the `engine/event_pipeline.lua` logic.

### 1. Configuration Inputs

Filtering toggles and lists come from:

- `engine/config.lua`
  - `cfg.features.file_read_filtering` enables file-read suppression.
  - `cfg.security.file_read_whitelist` contains default safe paths (system files, hotplug directories, etc.). Since overrides are ignored in this minimal build, only environment variables can adjust these paths.
  - `cfg.filters.mode_drop_events` determines per-mode drop rules (empty by default).

### 2. Filtering Stages

Filtering happens in three layers through `engine/event_pipeline.lua` and `engine/logger-engine.lua`:

1. **Fast Filter (`event_pipeline.fast_filter`)**
   - Drops hard-coded noise defined in `engine/event_profile.lua` (e.g., `session.access`, `network.interface.dump`).
   - Keeps essential events listed in `event_profile.NEEDED_EVENTS`.
   - Metrics update: `filter_stats.layer2_rejected`.

2. **Triage Filter (`event_pipeline.triage`)**
   - Looks up `object.method` in `TRIAGE_MAP`.
   - When the operation is `file_read`, calls `should_filter_file_operation`.
     - Uses whitelist entries from `cfg.security.file_read_whitelist`.
   - If no triage match or the helper decides to drop the file read, the event ends here.
   - Metrics update: `filter_stats.operations_triaged`.

3. **Mode Drop Filter (`event_pipeline.should_log`)**
   - Applies `MODE_DROP_EVENTS` selected by `cfg.features.operation_mode`.
   - `MODE_DROP_EVENTS` comes from `cfg.filters.mode_drop_events`.
   - Useful for site-specific suppression (e.g., ignoring `uci.show` bursts).

### 3. Arguments and Helpers

The following helpers participate in filtering:

- `should_skip_before_parse(ubus_line)` – drops obviously malformed or hotplug noise before JSON decode.
- `event_pipeline.fast_filter(event)` – uses `event_profile` to reject known-noise pairs.
- `event_pipeline.triage(event, TRIAGE_MAP, should_filter_file_operation, log_fn)` – core classification and file-read filtering.
- `event_pipeline.should_log(operation, event, MODE_DROP_EVENTS, MODE_PROFILE_NAME, log_fn)` – final decision to log the operation.

### 4. Extending Filters

Because `engine/config.lua` currently ignores override tables, extensions must happen in code:

- Update `event_profile.HARD_NOISE_EVENTS` for new hard-drop patterns.
- Modify the whitelist in `engine/config.lua` to affect file-read filtering.
- Adjust `TRIAGE_MAP` (in `logger-engine.lua`) when adding new handler types.
- Expand `MODE_DROP_EVENTS` in `logger-engine.lua` to suppress operations in specific modes.

### 5. Debugging

Enable debug flags via environment variables:

- `ARGUS_DEBUG=1` – enables `cfg.debug.enabled` and console logging.
- `ARGUS_LOG_DIR=/tmp/log/Audits` – points logs at a custom directory (applies to debug logs too).

Relevant debug output:

- `dop` (“debug operations”) output logs decisions at each filtering stage.
- `debug.log` file (when enabled) gets the same verbose messages.

### 6. References

- `engine/event_pipeline.lua`
- `engine/event_profile.lua`
- `engine/logger-engine.lua` (search for `process_invoke_event`, `should_skip_before_parse`, `MODE_DROP_EVENTS`)
- `engine/config.lua`

