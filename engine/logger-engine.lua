#!/usr/bin/env lua
-- ==============================================================================
-- Project Argus - OpenWrt Complete Audit Logger with Before/After Integration
-- ==============================================================================
-- Purpose: Monitors ubus operations and creates comprehensive audit trails
-- Enhanced: Integrated before/after state tracking with intelligent descriptions
-- Output: Clean descriptions without numbers, forensic-quality change tracking
-- Author :Erfan-Nasiri
-- ==============================================================================

-- OpenWrt Lua module paths
package.path = "/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua;" .. package.path

do
    local info = debug.getinfo(1, "S")
    local src = info and info.source or ""
    local root = src:match("@(.+)/engine/logger%-engine.lua$")
    if root then
        package.path = table.concat({
            root .. "/?.lua",
            root .. "/?/init.lua",
            root .. "/../?.lua",
            root .. "/../?/init.lua",
            root .. "/../engine-modules/?.lua",
            root .. "/../engine-modules/?/init.lua",
            package.path
        }, ";")
    end
end

local config = require("engine.config")
config.setup_paths()

local json_handler = require("cjson.safe")
local io           = require("io")
local os           = require("os")
local string_lib   = require("string")
local table_lib    = require("table")
local table_concat = table_lib.concat
local formatter    = require("formatter.init")
local event_pipeline = require("engine.event_pipeline")

local cfg    = config.load()

local function build_output_specs(current_cfg)
    if config.get_output_specs then
        return config.get_output_specs(current_cfg)
    end
    local paths = (current_cfg.paths and current_cfg.paths.logs) or current_cfg.paths or {}
    local alias_map = {
        human = "human_readable_log",
        key_value = "key_value_log",
    }
    local result = {}
    for name, alias in pairs(alias_map) do
        local path = (current_cfg.paths and current_cfg.paths[alias]) or paths[name]
        result[name] = { path = path }
    end
    return result
end

local LOG_SETTINGS      = cfg.settings or {}
local LOGGING_CONTROLS  = assert(cfg.controls or cfg.logging, "cfg.controls missing")
local SECURITY_SETTINGS = cfg.security or {}
local FILTER_SETTINGS   = cfg.filters or {}
local OUTPUT_SPECS      = build_output_specs(cfg)

-- Preserve rotation fallback (default 1 MiB) if not provided
local rotation_defaults = (cfg.outputs and cfg.outputs.rotation) or {}
LOG_SETTINGS.max_file_size = LOG_SETTINGS.max_file_size
  or rotation_defaults.max_file_size
  or (1024 * 1024)

local before_after = nil
do
    local ok, mod = pcall(require, "engine-modules.before_after")
    if ok then
        before_after = mod
    end
end
local uci_interface = require("engine-modules.uci_interface")

-- Removed State Queue Module

local before_after_active = false

local DEFAULT_FILE_READ_WHITELIST = {
    "/etc/board.json",
    "/proc/sys/net/netfilter/nf_conntrack_count",
    "/proc/sys/net/netfilter/nf_conntrack_max",
    "/proc/sys/net/netfilter/nf_conntrack_*",
}

local DEFAULT_EXEC_COMMAND_BLACKLIST = {
    "/usr/sbin/ipsec status",
}

local DEFAULT_FILTERS = {
    ubus_message_types = { "invoke", "status", "data" },
    noise_hints = {
        { include = "luci-rpc", also = "access" },
        { include = "session", also = "heartbeat" },
        "session.access",
        "getConntrackList",
        "system.board",
    }
}

local function normalize_list(value, fallback)
    local list = {}
    if type(value) == "table" then
        for _, v in ipairs(value) do
            if type(v) == "string" and v ~= "" then
                list[#list + 1] = v
            end
        end
        if #list == 0 then
            for k, v in pairs(value) do
                if type(k) == "string" and v == true then
                    list[#list + 1] = k
                elseif type(v) == "string" and v ~= "" then
                    list[#list + 1] = v
                end
            end
        end
    end
    if #list == 0 and type(fallback) == "table" then
        for _, v in ipairs(fallback) do
            if type(v) == "string" and v ~= "" then
                list[#list + 1] = v
            end
        end
    end
    return list
end

local function list_to_set(list)
    local set = {}
    for _, v in ipairs(list) do
        set[v] = true
    end
    return set
end

local function normalize_noise_hints(hints, fallback)
    local list = {}
    local source = hints
    if type(source) ~= "table" or #source == 0 then
        source = fallback
    end
    if type(source) ~= "table" then
        return list
    end
    for _, hint in ipairs(source) do
        if type(hint) == "table" and hint.include then
            list[#list + 1] = { include = hint.include, also = hint.also }
        elseif type(hint) == "string" then
            list[#list + 1] = { include = hint }
        end
    end
    return list
end

local FAST_ALLOWED_METHODS = list_to_set(
    normalize_list(FILTER_SETTINGS.ubus_message_types, DEFAULT_FILTERS.ubus_message_types)
)

local NOISE_HINTS = normalize_noise_hints(
    FILTER_SETTINGS.noise_hints,
    DEFAULT_FILTERS.noise_hints
)

local function get_output_spec(name)
    return OUTPUT_SPECS[name] or {}
end

local function get_output_path(name)
    local spec = get_output_spec(name)
    return spec and spec.path or nil
end

local function extract_file_operation_path(values)
    if type(values) ~= "table" then
        return nil
    end
    return values.path
        or values.file
        or values.filename
        or values.target
        or values.source
end

local function matches_whitelist_entry(path, entry)
    if not path or not entry or entry == "" then
        return false
    end
    if entry:sub(-1) == "*" then
        local prefix = entry:sub(1, -2)
        return prefix == "" or path:sub(1, #prefix) == prefix
    elseif entry:sub(-1) == "/" then
        return path:sub(1, #entry) == entry
    end
    return path == entry
end

local function list_contains_path(path, whitelist)
    if type(whitelist) ~= "table" then
        return false
    end
    for _, entry in ipairs(whitelist) do
        if matches_whitelist_entry(path, entry) then
            return true
        end
    end
    return false
end

local function should_filter_file_operation(values)
    if LOGGING_CONTROLS.file_read_filter_enabled == false then
        return false
    end
    local path = extract_file_operation_path(values)
    if not path then
        return false
    end

    if list_contains_path(path, SECURITY_SETTINGS and SECURITY_SETTINGS.file_read_whitelist)
        or list_contains_path(path, DEFAULT_FILE_READ_WHITELIST) then
        return true, path
    end

    return false, path
end

local function build_exec_signature(command, arguments)
    if not command or command == "" then
        return nil
    end
    if type(arguments) ~= "table" or #arguments == 0 then
        return command
    end
    local parts = {}
    for _, arg in ipairs(arguments) do
        parts[#parts + 1] = tostring(arg)
    end
    return command .. " " .. table_concat(parts, " ")
end

local function matches_exec_blacklist(signature, blacklist)
    if not signature or type(blacklist) ~= "table" then
        return false
    end
    for _, entry in ipairs(blacklist) do
        if type(entry) == "string" and entry ~= "" then
            if entry:sub(-1) == "*" then
                local prefix = entry:sub(1, -2)
                if prefix == "" or signature:sub(1, #prefix) == prefix then
                    return true
                end
            elseif signature == entry then
                return true
            end
        end
    end
    return false
end

local function should_filter_exec_operation(command, arguments)
    local signature = build_exec_signature(command, arguments)
    if not signature then
        return false
    end

    if matches_exec_blacklist(signature, SECURITY_SETTINGS and SECURITY_SETTINGS.exec_command_blacklist)
        or matches_exec_blacklist(signature, DEFAULT_EXEC_COMMAND_BLACKLIST) then
        return true, signature
    end

    return false, signature
end

-- Performance localizations
local json_decode   = json_handler.decode
local json_encode   = json_handler.encode
local current_time  = os.date
local string_format = string_lib.format
local string_find   = string_lib.find
local string_match  = string_lib.match
local string_sub    = string_lib.sub
local string_lower  = string_lib.lower
local table_insert  = table_lib.insert
local io_popen      = io.popen

local MODE_PROFILE_NAME
local MODE_DROP_EVENTS

local function refresh_mode_settings(current_cfg)
    MODE_PROFILE_NAME = (current_cfg._runtime and current_cfg._runtime.mode_profile_name)
        or (current_cfg.features and string_lower(tostring(current_cfg.features.operation_mode or "balanced")))
        or "balanced"
    MODE_DROP_EVENTS = (current_cfg.filters and current_cfg.filters.mode_drop_events) or {}
end

local function matches_noise_hint(line)
    if not NOISE_HINTS or #NOISE_HINTS == 0 then
        return false
    end
    for _, hint in ipairs(NOISE_HINTS) do
        local include = hint.include
        if include and string_find(line, include, 1, true) then
            local also = hint.also
            if not also or string_find(line, also, 1, true) then
                return true
            end
        end
    end
    return false
end

local function is_probably_noise(line, message_family)
    if not line or line == "" then
        return true
    end
    if next(FAST_ALLOWED_METHODS) and message_family and not FAST_ALLOWED_METHODS[message_family] then
        return true
    end
    if not string_find(line, "invoke:", 1, true)
        and not string_find(line, "status:", 1, true)
        and not string_find(line, "data:", 1, true) then
        return true
    end
    if matches_noise_hint(line) then
        return true
    end
    return false
end

local function write_debug_message(message, category)
    if not (message and LOGGING_CONTROLS.enable_debug_logging) then
        return
    end
    category = category or "INFO"
    io.stderr:write(string_format("[Argus:%s] %s\n", category, message))
end

local function before_after_enabled()
    return before_after_active and before_after ~= nil
end

local function debug_log(flag, category, fmt, ...)
    if not LOGGING_CONTROLS.enable_debug_logging then
        return
    end
    if flag and LOGGING_CONTROLS[flag] == false then
        return
    end
    write_debug_message(string_format(fmt, ...), category)
end

local function debug_operation(fmt, ...)
    debug_log("debug_operation_flow", "OPERATIONS", fmt, ...)
end

local function debug_session(fmt, ...)
    debug_log("debug_session_management", "SESSIONS", fmt, ...)
end

local function debug_changes(fmt, ...)
    debug_log("debug_uci_changes", "UCI_CHANGES", fmt, ...)
end

local function debug_callback(fmt, ...)
    debug_log("debug_callback_tracking", "CALLBACKS", fmt, ...)
end

-- ==============================================================================
-- STATE MANAGEMENT (UNIFIED)
-- ==============================================================================

local state = {
    objects = {},
    callbacks = {},
    sessions = {},
    auth_sessions = {},
}

local function get_session(session_id)
    if not session_id then return nil end
    local s = state.sessions[session_id]
    if not s then
        s = { user = nil, saves = {}, changes = {} }
        state.sessions[session_id] = s
    end
    return s
end

local TRIAGE_MAP = {
    ["uci.set"]    = "uci_change",
    ["uci.add"]    = "uci_change",
    ["uci.delete"] = "uci_change",
    ["uci.remove"] = "uci_change",
    ["uci.apply"]  = "uci_apply",

    ["luci.setPassword"] = "auth_password_change",
    ["luci.access"]      = "auth_password_change",
    ["luci.login"]       = "auth_login",
    ["luci.logout"]      = "auth_logout",
    ["luci.setLocaltime"] = "direct",
    ["luci.setInitAction"] = "direct",

    ["network.firewall.restart"] = "firewall_restart",
    ["network.firewall.reload"]  = "firewall_reload",
    ["network.firewall.info"]    = "firewall_info",
    ["system.upgrade"]           = "system_upgrade",
    ["system.validate_firmware"] = "firmware_validate",
    ["system.reboot"]            = "direct",
    ["system.setLocaltime"]      = "direct",
    ["system.setInitAction"]     = "direct",

    ["file.exec"]   = "exec",
    ["file.write"]  = "file_write",
    ["file.remove"] = "file_remove",
    ["file.read"]   = "file_read",
}

local function apply_config_triage_overrides()
    local tcfg = cfg.triage
    if not tcfg or not tcfg.extra_types then
        return
    end
    for key, op_type in pairs(tcfg.extra_types) do
        if type(key) == "string" and type(op_type) == "string" then
            TRIAGE_MAP[key] = op_type
        end
    end
end

apply_config_triage_overrides()

local function is_valid_user(user)
    return user and user ~= "" and user ~= "-"
end

local function process_invoke_event(event)
    debug_operation("INVOKE user=%s obj=%s method=%s callback=%s",
        event.user or "-",
        event.object_name or "unknown",
        event.method or "unknown",
        event.callback_id or "<none>")
    if not event_pipeline.fast_filter(event) then
        return nil
    end

    local classified_operation = event_pipeline.triage(
        event,
        TRIAGE_MAP,
        should_filter_file_operation
    )
    if not classified_operation then
        debug_operation("DROP invoke event %s.%s (triage)", event.object_name or "unknown", event.method or "unknown")
        return nil
    end

    if not event_pipeline.should_log(
        classified_operation,
        event,
        MODE_DROP_EVENTS,
        MODE_PROFILE_NAME
    ) then
        debug_operation("DROP %s.%s suppressed by mode %s",
            event.object_name or "unknown",
            event.method or "unknown",
            MODE_PROFILE_NAME or "balanced")
        return nil
    end

    debug_operation("TRIAGED %s.%s -> %s",
        event.object_name or "unknown",
        event.method or "unknown",
        classified_operation.type or "unknown")
    return classified_operation
end

-- ==============================================================================
-- UTILITY FUNCTIONS
-- ==============================================================================

-- NEW: Initialize before/after module integration with enhanced error handling
local function initialize_before_after_module()
    -- Validate before/after module availability
    if not before_after then
        write_debug_message("ERROR: Before/after module not available", "CRITICAL")
        return false
    end

    -- Configure native UCI interface preferences
    local uci_ok, uci_err = pcall(function()
        uci_interface.configure({
            enable_native_uci = cfg.features and cfg.features.enable_native_uci ~= false,
            cache_ttl = cfg.performance and cfg.performance.uci_cache_ttl,
            max_entries = cfg.performance and cfg.performance.uci_cache_size,
        })
    end)
    if not uci_ok then
        write_debug_message(string_format("WARNING: Failed to configure UCI interface: %s", tostring(uci_err)), "SYSTEM")
    end

    -- Configure the before/after module with error handling
    local config_success, config_error = pcall(function()
        before_after.configure({
            enable_detailed_logging = LOGGING_CONTROLS.debug_before_after_operations,
        })
    end)

    if not config_success then
        write_debug_message(string_format("ERROR: Failed to configure before/after module: %s", config_error), "CRITICAL")
        return false
    end

    -- Set debug callback to integrate with our debug system
    local debug_success, debug_error = pcall(function()
        before_after.set_debug_callback(function(message)
            if LOGGING_CONTROLS.debug_before_after_operations then
                write_debug_message(message, "BEFORE_AFTER_MODULE")
            end
        end)
    end)

    if not debug_success then
        write_debug_message(string_format("ERROR: Failed to set debug callback: %s", debug_error), "CRITICAL")
        return false
    end

    -- Perform health check
    local health_success, health_result = pcall(before_after.health_check)
    if health_success and health_result then
        write_debug_message(string_format(
            "Before/After module health: backend=%s (available=%s) sessions=%d processed=%d failures=%d",
            health_result.uci_backend or "unknown",
            health_result.uci_available and "yes" or "no",
            health_result.active_sessions or 0,
            health_result.total_processed or 0,
            health_result.analysis_failures or 0), "SYSTEM")
    end

    before_after_active = true
    write_debug_message("Before/After tracking module initialized successfully", "SYSTEM")
    return true
end

local function disable_before_after_module(reason)
    if not before_after_active or not before_after then
        before_after_active = false
        return
    end

    local message = string_format("Before/After module disabled (%s)", reason or "configuration")
    if before_after.cleanup then
        local cleanup_success, cleanup_error = pcall(before_after.cleanup)
        if not cleanup_success then
            write_debug_message(string_format("WARNING: Before/after cleanup failed: %s", cleanup_error), "SYSTEM")
        end
    end
    before_after_active = false
    write_debug_message(message, "SYSTEM")
end

-- Rotate log file if it's getting too large
local function rotate_log_file_if_needed(file_path)
    local file_handle = io.open(file_path, "rb")
    if not file_handle then return end
    
    local current_size = file_handle:seek("end") or 0
    file_handle:close()
    
    if current_size >= LOG_SETTINGS.max_file_size then 
        local backup_name = file_path .. "." .. current_time("%Y%m%d%H%M%S")
        os.rename(file_path, backup_name)
        write_debug_message("Rotated log file: " .. file_path .. " -> " .. backup_name, "SYSTEM")
    end
end

-- Extract JSON data from ubus monitor line
local function extract_json_from_ubus_line(ubus_line)
    local json_start_position = string_find(ubus_line, "{", 1, true)
    if not json_start_position then return nil end
    return string_sub(ubus_line, json_start_position)
end

-- Format a value for display (handles tables, strings, etc.)
local function format_value_for_display(value)
    if type(value) == 'string' then 
        return value:gsub("\\", "\\\\"):gsub("\n", "\\n")
    elseif type(value) == 'table' then
        local formatted_parts = {}
        if value[1] ~= nil then  -- Array-like table
            for i = 1, #value do 
                formatted_parts[#formatted_parts + 1] = format_value_for_display(value[i]) 
            end
            return "[" .. table_concat(formatted_parts, ",") .. "]"
        else  -- Key-value table
            for key, val in pairs(value) do 
                table.insert(formatted_parts, tostring(key) .. "=" .. format_value_for_display(val)) 
            end
            return "{" .. table_concat(formatted_parts, ",") .. "}"
        end
    end
    return tostring(value)
end

local function convert_values_to_key_value_string(values_table)
    if not values_table then return "-" end

    local key_value_pairs = {}

    -- Handle new format: array of change objects (from comprehensive_changes)
    if type(values_table) == "table" and values_table[1] and type(values_table[1]) == "table" then
        if values_table[1].method then
            for i, change in ipairs(values_table) do
                local method = change.method or "unknown"
                local config = change.config or "unknown"
                local section = change.section or "unknown"
                local field = change.field or "unknown"
                local value = change.value or "unknown"

                if method == "delete" then
                    field = field == "section" and "section" or field
                    value = value == "deleted" and "deleted" or value
                end

                table_insert(key_value_pairs, string_format("change_%d=%s.%s.%s=%s",
                    i, method, field, value, config))
            end
            return table_concat(key_value_pairs, ",")
        end
    end

    -- Handle old format: key-value table
    if next(values_table) == nil then return "-" end

    for key, value in pairs(values_table) do
        if key ~= "ubus_rpc_session" then
            table_insert(key_value_pairs, key .. "=" .. format_value_for_display(value))
        end
    end

    if #key_value_pairs == 0 then return "-" end
    return table_concat(key_value_pairs, ",")
end

local function ts_utc()
    return current_time("!%a %b %d %H:%M:%S %Y")
end

local function kv(key, value)
    if value == nil then return nil end
    return string_format("%s=%q", key, value)
end

local function build_kv_line(operation, ts)
    local fields = {
        kv("time", ts or ts_utc()),
        kv("user", operation.user or "-"),
        kv("action", operation.action),
        kv("category", operation.category),
        kv("type", operation.type),
        kv("config", operation.config),
    }
    local out = {}
    for i = 1, #fields do
        if fields[i] then
            out[#out + 1] = fields[i]
        end
    end
    return table_concat(out, " ")
end

-- Remove sensitive information from logged values
local function sanitize_sensitive_information(values_table, operation_method)
    if SECURITY_SETTINGS and SECURITY_SETTINGS.redact_sensitive_values == false then 
        return values_table or {}
    end
    local cleaned_values = {}
    for key, value in pairs(values_table or {}) do
        if operation_method == "setPassword" and (key == "password" or key == "passwd" or key == "new_password") then
            cleaned_values[key] = "[REDACTED]"
        elseif key == "key" or key == "psk" or key == "secret" then
            cleaned_values[key] = "[REDACTED]"
        else
            cleaned_values[key] = value
        end
    end
    return cleaned_values
end

-- ==============================================================================
-- BATCHING AND FLUSHING SYSTEM
-- ==============================================================================

-- Batched log entries waiting to be written
local log_entry_batches = {
    human_readable = {},
    key_value      = {},
}

local last_batch_flush_time = os.time()

-- rotate + append a batch safely
local function write_batch_if_any(path, batch_tbl)
    if not path or #batch_tbl == 0 then return end
    rotate_log_file_if_needed(path)
    local f = io.open(path, "a")
    if f then
        f:write(table_concat(batch_tbl, "\n"), "\n")
        f:close()
    end
end

local function flush_log_batches(force_flush)

    -- Skip if audit logging is completely disabled
    if not LOGGING_CONTROLS.enable_audit_logging then
        return
    end

    local now = os.time()
    local should_flush_now = force_flush
        or (now - last_batch_flush_time >= LOGGING_CONTROLS.auto_flush_interval_seconds)
        or (#log_entry_batches.key_value > LOGGING_CONTROLS.batch_size_for_immediate_flush)

    if not should_flush_now then return end

    -- Data-driven write of all outputs (minimal)
    local targets = {
        { LOGGING_CONTROLS.enable_human_readable,  get_output_path("human"),    log_entry_batches.human_readable },
        { LOGGING_CONTROLS.enable_key_value_pairs, get_output_path("key_value"), log_entry_batches.key_value },
    }

    for _, t in ipairs(targets) do
        local enabled, path, batch = t[1], t[2], t[3]
        if enabled then
            write_batch_if_any(path, batch)
            -- clear in place (preserve reference)
            for i = #batch, 1, -1 do batch[i] = nil end
        end
    end

    last_batch_flush_time = now
end

-- ==============================================================================
-- LOG ENTRY GENERATION
-- ==============================================================================

-- Generate and queue log entries for an operation
local function create_log_entries_for_operation(operation_data)
    -- Skip if audit logging is disabled
    if not LOGGING_CONTROLS.enable_audit_logging then
        return
    end
    
    local user = operation_data.user or "-"
    local action = operation_data.action or operation_data.method or "unknown"
    local category = operation_data.category or operation_data.obj_name or "-"
    local config = operation_data.config or category
    local section = operation_data.section
    local values = operation_data.values or {}
    
    -- Clean sensitive data before logging
    local sanitized_values = sanitize_sensitive_information(values, action)

    if action == "file_read" then
        local drop, requested_path = should_filter_file_operation(sanitized_values)
        if not drop then
            local fallback_drop, fallback_path = should_filter_file_operation(values)
            drop = fallback_drop
            requested_path = requested_path or fallback_path
        end
        if drop then
            debug_operation("FILE_READ filtered path=%s", requested_path or "<unknown>")
            return
        end
    end
    
    local timestamp = ts_utc()
    local is_service_op = (operation_data.obj_name == "service")
    local flattened_values = sanitized_values

    if is_service_op then
        flattened_values = {
            name = (operation_data.values and operation_data.values.name) or operation_data.config,
            action = operation_data.method,
        }
    end

    -- Prepare clean operation data for formatter
    local clean_operation = {
        type = operation_data.type,
        user = user,
        action = action,
        category = category,
        config = config,
        section = section,
        values = flattened_values,

        -- NEW: Include analyzed changes from before/after module
        analyzed_changes = operation_data.analyzed_changes
    }

    -- Validate formatter integration
    if not formatter or not formatter.format then
        return
    end
    
    -- Generate human-readable log entry with enhanced before/after integration
    if LOGGING_CONTROLS.enable_human_readable then
        local readable_message = "formatter unavailable"
        local format_success, format_error = pcall(function()
            readable_message = formatter.format(clean_operation)
        end)

        if not format_success then
            readable_message = string_format("ERROR: %s (user: %s, action: %s)", format_error, user, action)
        end

        local formatted_line = string_format("%s [user: %s] %s", timestamp, user, readable_message)
        log_entry_batches.human_readable[#log_entry_batches.human_readable + 1] = formatted_line
    end

    -- Generate key-value log entry
    if LOGGING_CONTROLS.enable_key_value_pairs then
        local kv_line = build_kv_line(clean_operation, timestamp)
        local values_field = kv("values", convert_values_to_key_value_string(flattened_values))
        if values_field and values_field ~= "" then
            if kv_line ~= "" then
                kv_line = kv_line .. " " .. values_field
            else
                kv_line = values_field
            end
        end
        if kv_line ~= "" then
            log_entry_batches.key_value[#log_entry_batches.key_value + 1] = kv_line
        end
    end

    -- JSON/authentication/security outputs removed in minimalist mode
    debug_operation("LOG ENTRY queued action=%s user=%s category=%s config=%s",
        action or "-", user or "-", category or "-", config or "-")
end

-- ==============================================================================
-- ENHANCED UCI OPERATION STATE MANAGEMENT (With Before/After Integration)
-- ==============================================================================

local function stage_uci_operation_for_session(operation_data, callback_id)
    local values = operation_data.values or {}
    local session_id = values.ubus_rpc_session
    if not session_id then return end

    -- Link callback → session
    state.callbacks[callback_id] = {
        type = "uci_session_link",
        session_id = session_id,
    }
    -- Synchronous before/after capture (queue removed)
    local before_state = nil
    if before_after_enabled() then
        before_state = before_after.capture_before_state(operation_data)
        before_after.store_session_state(session_id, values.section, before_state)
    end

    local save_data = {
        method = operation_data.method,
        config = values.config,
        section = values.section,
        section_type = values.type,
        original_values = values.values or {},
        before_state = before_state,
    }

    if operation_data.method == "delete" or operation_data.method == "remove" then
        save_data.deleted_section = values.section
    end

    local session = get_session(session_id)
    if not session.user then
        session.user = operation_data.user
    end
    table_insert(session.saves, save_data)
end

local function process_successful_uci_apply(session_id, user)
    local session_data = state.sessions[session_id]
    if not (session_id and session_data) then 
        return 
    end
    
    if #session_data.saves == 0 then 
        state.sessions[session_id] = nil
        return 
    end
    
    local before_after_active_now = before_after_enabled()
    local comprehensive_changes = {}
    local config_name = session_data.saves[1].config

    local function append_change(entry, source_label)
        local is_duplicate = false
        for _, existing in ipairs(comprehensive_changes) do
            if existing.method == entry.method
                and existing.config == entry.config
                and existing.section == entry.section
                and existing.field == entry.field
                and existing.value == entry.value
            then
                is_duplicate = true
                break
            end
        end

        if is_duplicate then
            return
        end

        table_insert(comprehensive_changes, entry)
    end
    
    if session_data.changes and next(session_data.changes) ~= nil then
        for config, change_list in pairs(session_data.changes) do
            for _, change in ipairs(change_list) do
                local change_entry = {
                    method = change[1],
                    config = config,
                    section = change[2],
                    field = change[3],
                    value = change[4]
                }

                if change_entry.method == "delete" or change_entry.method == "remove" then
                    change_entry.field = change_entry.field or "section"
                    change_entry.value = change_entry.value or "deleted"
                end

                if before_after_active_now then
                    local before_state = before_after.get_session_state(session_id, change[2])
                    if before_state then
                        change_entry.before_state = before_state
                    end
                end

                for _, staged_op in ipairs(session_data.saves) do
                    if staged_op.section == change[2] then
                        change_entry.section_type = staged_op.section_type
                        if not change_entry.before_state and staged_op.before_state then
                            change_entry.before_state = staged_op.before_state
                        end
                        break
                    end
                end

                append_change(change_entry, "Enhanced")
            end
        end

        session_data.changes = {}
    else
        for _, save_op in ipairs(session_data.saves) do
            local fallback_entry = {
                method = save_op.method,
                config = save_op.config,
                section = save_op.section,
                section_type = save_op.section_type,
                values = save_op.original_values,
                before_state = save_op.before_state
            }

            if save_op.method == "delete" or save_op.method == "remove" then
                fallback_entry.field = "section"
                fallback_entry.value = "deleted"
            end

            append_change(fallback_entry, "Fallback")
        end
    end
    
    local analyzed_changes = {}
    if before_after_active_now
        and LOGGING_CONTROLS.enable_intelligent_descriptions
        and #comprehensive_changes > 0 then
        analyzed_changes = before_after.analyze_changes(comprehensive_changes)
    end
    
    create_log_entries_for_operation({
        user = user,
        action = "set_applied",
        type = "set_applied",
        category = "uci",
        config = config_name,
        values = comprehensive_changes,
        section = nil,
        analyzed_changes = analyzed_changes
    })
    
    state.sessions[session_id] = nil

    if before_after_active_now and before_after and before_after.cleanup_session_state then
        pcall(before_after.cleanup_session_state, session_id)
    end
end

-- ==============================================================================
-- OPERATION CLASSIFICATION (THE TRIAGE BRAIN)
-- ==============================================================================

local function handle_objpath_data(parsed_data)
    if not (parsed_data.objpath and parsed_data.objid) then
        return false
    end

    if state.objects[parsed_data.objid] ~= parsed_data.objpath then
        state.objects[parsed_data.objid] = parsed_data.objpath
    end

    return true
end

local function handle_uci_changes_data(parsed_data, callback_id)
    if not (parsed_data.data and parsed_data.data.changes) then
        return false
    end

    if not callback_id then
        debug_changes("Changes without callback id")
        return true
    end

    local link = state.callbacks[callback_id]
    if link and link.type == "uci_session_link" and link.session_id then
        local session_id = link.session_id
        local session = get_session(session_id)

        for config, change_list in pairs(parsed_data.data.changes) do
            session.changes[config] = session.changes[config] or {}
            for _, change in ipairs(change_list) do
                table_insert(session.changes[config], change)
            end
        end

        state.callbacks[callback_id] = nil
        debug_changes("Stored %d change groups for session %s", #parsed_data.data.changes, session_id)
    else
        debug_changes("Unmapped change callback %s", callback_id or "<none>")
    end

    return true
end

local function handle_exec_data(parsed_data, callback_id)
    if not (parsed_data.data and callback_id) then
        return false
    end

    local entry = state.callbacks[callback_id]
    if not entry or entry.type ~= "operation" then
        return false
    end

    local op = entry.op
    if op and op.type == "exec" then
        op.output_data = parsed_data.data
        debug_operation("Captured exec output callback %s", callback_id)
    end

    return true
end

local function handle_invoke(parsed_data, callback_id)
    if not callback_id then
        return
    end

    local event = event_pipeline.build_event(parsed_data, callback_id, state.objects)
    if not event or not is_valid_user(event.user) then
        return
    end

    local classified_operation = process_invoke_event(event)
    if not classified_operation then
        return
    end

    state.callbacks[callback_id] = {
        type = "operation",
        op = classified_operation,
    }
    debug_callback("Queued operation %s for callback %s", classified_operation.type or "?", callback_id)
end

local function handle_status(parsed_data, callback_id)
    local cb_entry = state.callbacks[callback_id]
    local operation = (cb_entry and cb_entry.type == "operation") and cb_entry.op or nil

    if parsed_data.status == 0 and operation then
        state.callbacks[callback_id] = nil
        debug_callback("SUCCESS callback %s type=%s", callback_id, operation.type or "?")
        if operation.type == "uci_change" then
            stage_uci_operation_for_session(operation, callback_id)

        elseif operation.type == "uci_apply" then
            process_successful_uci_apply(operation.values.ubus_rpc_session, operation.user)

        else
            if operation.type == "exec" then
                local exec_arguments = operation.values.params or {}
                local drop_exec, signature = should_filter_exec_operation(operation.config, exec_arguments)
                if drop_exec then
                    debug_operation("EXEC filtered %s", signature or "<unknown>")
                    return
                end
                local exec_values = {
                    command = operation.config,
                    arguments = exec_arguments
                }
                if operation.output_data then
                    exec_values.code = operation.output_data.code
                    exec_values.stdout = operation.output_data.stdout
                    exec_values.stderr = operation.output_data.stderr
                end
                operation.values = exec_values
                operation.action = "exec"

            elseif operation.type == "auth_password_change" then
                operation.action = "setPassword"
                operation.category = "authentication"
                operation.config = "user_management"
                operation.result = "success"

            elseif operation.type == "auth_login" then
                operation.action = "login"
                operation.category = "authentication"
                operation.config = "session_management"
                operation.result = "success"
                local sid = operation.values.ubus_rpc_session or "unknown"
                state.auth_sessions[sid] = {
                    user = operation.user,
                    login_time = os.time(),
                    ip = operation.source_ip
                }

            elseif operation.type == "auth_logout" then
                operation.action = "logout"
                operation.category = "authentication"
                operation.config = "session_management"
                operation.result = "success"
                local sid = operation.values.ubus_rpc_session or "unknown"
                state.auth_sessions[sid] = nil

            elseif operation.type == "firewall_restart" then
                operation.action = "firewall_restart"
                operation.category = "network_security"
                operation.config = "firewall"

            elseif operation.type == "firewall_reload" then
                operation.action = "firewall_reload"
                operation.category = "network_security"
                operation.config = "firewall"

            elseif operation.type == "firewall_info" then
                operation.action = "firewall_info"
                operation.category = "network_security"
                operation.config = "firewall"

            elseif operation.type == "system_upgrade" then
                operation.action = "system_upgrade"
                operation.category = "system_security"
                operation.config = "firmware"

            elseif operation.type == "firmware_validate" then
                operation.action = "validate_firmware"
                operation.category = "system_security"
                operation.config = "firmware"

            elseif operation.type == "file_write" then
                operation.action = "file_write"
                operation.category = "file_system"
                operation.config = "file_operations"

            elseif operation.type == "file_remove" then
                operation.action = "file_remove"
                operation.category = "file_system"
                operation.config = "file_operations"

            elseif operation.type == "file_read" then
                operation.action = "file_read"
                operation.category = "file_system"
                operation.config = "file_operations"

            elseif operation.type == "backup_read" then
                operation.action = "read"
                operation.category = "backup"
                operation.config = "backup"

            else
                operation.action = operation.method
            end

            create_log_entries_for_operation(operation)
        end

    elseif parsed_data.status ~= 0 and operation then
        state.callbacks[callback_id] = nil
        debug_callback("FAIL callback %s type=%s status=%s", callback_id, operation.type or "?", tostring(parsed_data.status))
        if operation.type and string_find(operation.type, "^auth_", 1, true) then
            operation.result = string_format("failed(status:%d)", parsed_data.status)
            operation.action = string_match(operation.type, "^auth_(.+)") or operation.type
            operation.category = "authentication"
            create_log_entries_for_operation(operation)
        end
    end
end

local function process_ubus_monitor_line(ubus_line)
    local message_family = string_match(ubus_line, "^%s*([%a]+):")
    local line_contains_objpath = string_find(ubus_line, '"objpath"', 1, true) ~= nil
    local must_keep = (message_family == "status") or line_contains_objpath

    if not must_keep and is_probably_noise(ubus_line, message_family) then
        return
    end

    local json_data_string = extract_json_from_ubus_line(ubus_line)
    if not json_data_string then
        return
    end
    
    local parse_success, parsed_data = pcall(json_decode, json_data_string)
    if not parse_success or not parsed_data then
        return
    end

    if not message_family then
        if string_find(ubus_line, "data:", 1, true) then
            message_family = "data"
        elseif string_find(ubus_line, "invoke:", 1, true) then
            message_family = "invoke"
        elseif string_find(ubus_line, "status:", 1, true) then
            message_family = "status"
        end
    end

    local callback_id = string_match(ubus_line, "#([%da-f]+)")

    if message_family == "data" then
        if handle_objpath_data(parsed_data) then return end
        if handle_uci_changes_data(parsed_data, callback_id) then return end
        if handle_exec_data(parsed_data, callback_id) then return end
        return
    end

    if message_family == "invoke" then
        if callback_id then
            handle_invoke(parsed_data, callback_id)
        end
        return
    end

    if message_family == "status" then
        if callback_id then
            handle_status(parsed_data, callback_id)
        end
    end
end

-- ==============================================================================
-- MAIN PROGRAM EXECUTION (PROJECT ARGUS INITIALIZATION)
-- ==============================================================================

-- Initialize the logging system
config.ensure_paths(cfg) -- replaces initialize_logging_system()
if LOGGING_CONTROLS.enable_before_after_tracking then
    local initialized = initialize_before_after_module()
    if not initialized then
        before_after_active = false
        write_debug_message("Before/After tracking disabled due to initialization failure", "SYSTEM")
    end
else
    disable_before_after_module("configuration")
    write_debug_message("Before/After tracking disabled via configuration", "SYSTEM")
end

-- State capture queue removed: all before/after captures are synchronous now

local startup_mode = before_after_enabled() and "Enhanced with Before/After Module" or "Before/After Disabled"
write_debug_message("Starting Project Argus - " .. startup_mode, "SYSTEM")
write_debug_message(string_format("Logging Controls: audit=%s kv=%s debug=%s before_after=%s", 
    tostring(LOGGING_CONTROLS.enable_audit_logging),
    tostring(LOGGING_CONTROLS.enable_key_value_pairs),
    tostring(LOGGING_CONTROLS.enable_debug_logging),
    tostring(LOGGING_CONTROLS.enable_before_after_tracking)
), "SYSTEM")

-----------------------------------------------------------------------
-- == MAIN UBUS MONITOR LOOP (Optimized Pipeline Version) ==
-----------------------------------------------------------------------

collectgarbage("setpause", 110)
collectgarbage("setstepmul", 300)

local socket = require("socket")
local EVENT_PIPELINE = require("engine.event_pipeline")

local FAST_PREFILTER_PATTERNS = {
    '"user"',
    '"ubus_rpc_session"',
    '"objpath"',
    "invoke:",
    "status:",
    "data:"
}

local function should_skip_before_parse(line)
    if not line or line == "" then
        return true
    end
    for i = 1, #FAST_PREFILTER_PATTERNS do
        if string_find(line, FAST_PREFILTER_PATTERNS[i], 1, true) then
            return false
        end
    end
    return true
end

-- Backwards compatibility: fall back to legacy handler when pipeline helpers
-- are not present (older event_pipeline.lua revisions).
if not EVENT_PIPELINE.extract_and_build then
    function EVENT_PIPELINE.extract_and_build(ubus_line)
        return ubus_line
    end
end

if not EVENT_PIPELINE.process then
    function EVENT_PIPELINE.process(event)
        return process_ubus_monitor_line(event)
    end
end

local ubus_monitor_stream = io_popen(
    "ubus monitor -m invoke -m status -m data 2>/dev/null",
    "r"
)

if not ubus_monitor_stream then
    write_debug_message("CRITICAL: Failed to open ubus monitor stream", "CRITICAL")
    os.exit(1)
end

local monitoring_mode = before_after_enabled()
        and "with before/after tracking"
        or  "without before/after tracking"

write_debug_message("Beginning ubus monitoring loop " .. monitoring_mode, "SYSTEM")

local lines_processed = 0

while true do
    repeat
        local ubus_line = ubus_monitor_stream:read("*l")
        if not ubus_line then
            socket.sleep(0.001)
            break
        end

        if should_skip_before_parse(ubus_line) then
            break
        end

        lines_processed = lines_processed + 1

        local event = EVENT_PIPELINE.extract_and_build(ubus_line)
        if event then
            local ok, triaged = pcall(EVENT_PIPELINE.process, event)
            if not ok then
                write_debug_message(
                    "ERROR triaging event: " .. tostring(triaged),
                    "ERROR"
                )
            end
        end
    until true

    if lines_processed % 100 == 0 then
        flush_log_batches(false)
    end

    if before_after_enabled()
        and LOGGING_CONTROLS.debug_before_after_operations
        and before_after.get_stats
        and (lines_processed % 1000 == 0)
    then
        local stats = before_after.get_stats()
        write_debug_message(string.format(
            "Before/After Stats: %d states captured, %d processed, %.1f%% cache hit, %d sessions",
            stats.states_captured or 0,
            stats.states_processed or 0,
            stats.cache_hit_rate or 0,
            stats.active_sessions or 0
        ), "BEFORE_AFTER_STATS")
    end
end

-- ==============================================================================
-- GRACEFUL CLEANUP
-- ==============================================================================
ubus_monitor_stream:close()
flush_log_batches(true)  -- Final flush of all pending entries

-- Final module statistics
if before_after_enabled() and before_after.get_stats then
    local final_stats = before_after.get_stats()
    write_debug_message(string_format("Before/After Module Final Stats: %d states captured, %d processed, %d fields analyzed", 
        final_stats.states_captured or 0, final_stats.states_processed or 0, 
        final_stats.fields_captured or 0), "SYSTEM")
end

disable_before_after_module("shutdown")

-- Final statistics
write_debug_message(string_format("Project Argus stopped gracefully. Processed %d lines total", lines_processed), "SYSTEM")
local staged_count = 0
for _ in pairs(state.sessions) do staged_count = staged_count + 1 end
local pending_callbacks = 0
for _ in pairs(state.callbacks) do pending_callbacks = pending_callbacks + 1 end
write_debug_message(string_format("Final state: %d sessions, %d pending callbacks", 
    staged_count, pending_callbacks), "SYSTEM")

-- ==============================================================================
-- END OF PROJECT ARGUS - ENHANCED AUDIT LOGGER
-- ==============================================================================
