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

-- Core dependencies
local json_handler = require "cjson.safe"
local io = require "io"
local os = require "os"
local string = require "string"
local table = require "table"
local formatter = require "formatter.init"

-- Load centralized configuration
--local config = require "engine.config"()

-- =============================================================================-
-- DEBUGGING SYSTEM (Early definition for module loading)
-- ==============================================================================

local debug_message_batch = {}  -- Collect debug messages for batch writing

-- Early debug logging function for module loading
local function write_debug_message(message, category)
    category = category or "GENERAL"
    local formatted_message = "[DEBUG:" .. category .. "] " .. message

    -- Show immediately on console
    io.stderr:write(formatted_message .. "\n")

    -- Queue for file writing if possible
    if debug_message_batch then
        debug_message_batch[#debug_message_batch + 1] = formatted_message
    end
end

-- Load engine modules with OpenWrt compatibility
local engine_modules_path = "/usr/lib/lua/engine-modules/"
local before_after, uci_session
-- Optional lightweight in-process queue for before-state capture (declared, loaded later based on config)
local state_capture_queue

-- Try different ways to load the modules
local function load_engine_module(module_name)
    local paths_to_try = {
        "engine-modules." .. module_name,
        module_name,
        "/usr/lib/lua/engine-modules/" .. module_name,
        "/usr/lib/lua/engine-modules/" .. module_name .. ".lua"
    }

    for _, path in ipairs(paths_to_try) do
        local success, module = pcall(require, path)
        if success then
            return module
        end
    end

    return nil, "Module not found: " .. module_name
end

-- Load the before_after module (using original as requested)
before_after, uci_session = load_engine_module("before_after"), load_engine_module("uci_session")
-- Try to load the optional state_capture_queue module (may not exist on all branches)
state_capture_queue = load_engine_module("state_capture_queue")

-- Performance optimization: localize frequently used functions
local json_decode = json_handler.decode
local json_encode = json_handler.encode
local current_time = os.date
local string_format = string.format
local string_find = string.find
local string_match = string.match
local string_sub = string.sub
local table_concat = table.concat
local table_insert = table.insert
local io_popen = io.popen

-- ==============================================================================
-- CONFIGURATION SECTION
-- ==============================================================================

-- File paths for different log types
local LOG_PATHS = {
    base_directory = "/tmp/log/Audits",
    key_value_log = "/tmp/log/Audits/audit.log",
    human_readable_log = "/tmp/log/Audits/format.log", 
    json_log = "/tmp/log/Audits/audit.json",
    debug_log = "/tmp/log/Audits/debug.log",
    security_log = "/tmp/log/Audits/audit_security.log",
    authentication_log = "/tmp/log/Audits/audit_auth.log"
}

-- Log rotation settings
local LOG_SETTINGS = {
    max_file_size = 1024 * 1024,  -- 1MB before rotation
}

-- Comprehensive logging control panel with before/after integration
local LOGGING_CONTROLS = {
    -- Master controls
    enable_audit_logging = true,        -- Main switch for all audit logging
    
    -- Output format controls  
    enable_human_readable = true,       -- Easy-to-read format for operators
    enable_key_value_pairs = true,      -- Structured key=value format
    enable_json_output = true,          -- Machine-readable JSON format
    enable_authentication_log = true,   -- Dedicated auth event log
    enable_security_alerts = true,      -- High-priority security events
    
    -- NEW: Before/After Module Integration
    enable_before_after_tracking = true,     -- Master switch for forensic tracking
    enable_intelligent_descriptions = true,  -- Smart change descriptions
    enable_before_after_caching = true,      -- Cache UCI queries for performance
    
    -- Development and debugging controls
    enable_debug_logging = true,       -- Debug info to file
    show_debug_on_console = true,      -- Debug output to stderr
    debug_operation_flow = true,       -- Debug operation classification
    debug_session_management = true,   -- Debug UCI sessions and staging
    debug_uci_changes = true,          -- Debug UCI change data capture
    debug_callback_tracking = true,    -- Debug callback ID management
    debug_before_after_operations = true,  -- NEW: Debug before/after module
    
    -- Performance and batching settings
    auto_flush_interval_seconds = 3,    -- How often to write batched logs
    batch_size_for_immediate_flush = 30, -- Write immediately at this many entries
    -- Optional state capture queue toggle (set to false to force synchronous captures)
    enable_state_capture_queue = false,
}

-- ==============================================================================
-- DEBUGGING SYSTEM
-- ==============================================================================

local debug_message_batch = {}  -- Collect debug messages for batch writing

-- Main debug logging function with categories
local function write_debug_message(message, category)
    -- Skip entirely if debug is disabled everywhere
    if not (LOGGING_CONTROLS.enable_debug_logging or LOGGING_CONTROLS.show_debug_on_console) then 
        return 
    end
    
    category = category or "GENERAL"
    local formatted_message = string_format("[DEBUG:%s] %s", category, message)
    
    -- Show immediately on console if enabled
    if LOGGING_CONTROLS.show_debug_on_console then
        io.stderr:write(formatted_message .. "\n")
    end
    
    -- Queue for file writing if file debug is enabled
    if LOGGING_CONTROLS.enable_debug_logging then
        local timestamped_message = string_format("[%s] %s", 
            current_time("!%a %b %d %H:%M:%S %Y"), formatted_message)
        debug_message_batch[#debug_message_batch + 1] = timestamped_message
    end
end

-- Specialized debug functions for different areas
local function debug_operation_processing(message)
    if LOGGING_CONTROLS.debug_operation_flow then
        write_debug_message(message, "OPERATIONS")
    end
end

local function debug_session_state(message)
    if LOGGING_CONTROLS.debug_session_management then
        write_debug_message(message, "SESSIONS")
    end
end

local function debug_uci_change_capture(message)
    if LOGGING_CONTROLS.debug_uci_changes then
        write_debug_message(message, "UCI_CHANGES")
    end
end

local function debug_callback_tracking(message)
    if LOGGING_CONTROLS.debug_callback_tracking then
        write_debug_message(message, "CALLBACKS")
    end
end

-- ==============================================================================
-- STATE MANAGEMENT
-- ==============================================================================

-- Track object IDs to object paths (ubus mapping)
local ubus_object_mappings = {}

-- UCI operations staged by session (waiting for apply)
local staged_uci_operations_by_session = {}

-- CRITICAL: Track UCI changes data by session ID (the key correlation point)
local uci_changes_by_session = {}

-- CRITICAL: Track callback to session mapping for changes data correlation
local callback_to_session_mapping = {}

-- Pending operations waiting for completion
local operations_waiting_for_response = {}

-- Active authentication sessions
local active_user_sessions = {}

-- ==============================================================================
-- UTILITY FUNCTIONS
-- ==============================================================================

-- Create log directories and initialize empty log files
local function initialize_logging_system()
    os.execute("mkdir -p " .. LOG_PATHS.base_directory .. " >/dev/null 2>&1")
    
    -- Only create files for enabled log types
    local enabled_log_files = {}
    if LOGGING_CONTROLS.enable_human_readable then 
        table.insert(enabled_log_files, LOG_PATHS.human_readable_log) 
    end
    if LOGGING_CONTROLS.enable_key_value_pairs then 
        table.insert(enabled_log_files, LOG_PATHS.key_value_log) 
    end
    if LOGGING_CONTROLS.enable_json_output then 
        table.insert(enabled_log_files, LOG_PATHS.json_log) 
    end
    if LOGGING_CONTROLS.enable_debug_logging then 
        table.insert(enabled_log_files, LOG_PATHS.debug_log) 
    end
    if LOGGING_CONTROLS.enable_security_alerts then 
        table.insert(enabled_log_files, LOG_PATHS.security_log) 
    end
    if LOGGING_CONTROLS.enable_authentication_log then 
        table.insert(enabled_log_files, LOG_PATHS.authentication_log) 
    end
    
    -- Touch each enabled log file
    for _, log_file_path in ipairs(enabled_log_files) do
        local file_handle = io.open(log_file_path, "a")
        if file_handle then file_handle:close() end
    end
end

-- NEW: Initialize before/after module integration with enhanced error handling
local function initialize_before_after_module()
    -- Validate before/after module availability
    if not before_after then
        write_debug_message("ERROR: Before/after module not available", "CRITICAL")
        return false
    end

    -- Configure the before/after module with error handling
    local config_success, config_error = pcall(function()
        before_after.configure({
            enable_caching = LOGGING_CONTROLS.enable_before_after_caching,
            cache_ttl = 300,  -- 5 minutes cache
            enable_detailed_logging = LOGGING_CONTROLS.debug_before_after_operations,
            max_cache_entries = 100  -- Memory limit for embedded systems
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
        write_debug_message(string_format("Before/After module health: UCI=%s, Cache=%s, Sessions=%d",
            health_result.uci_available and "available" or "unavailable",
            health_result.cache_functional and "enabled" or "disabled",
            health_result.active_sessions or 0), "SYSTEM")
    end

    write_debug_message("Before/After tracking module initialized successfully", "SYSTEM")
    return true
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

-- Convert values table to key=value,key=value format
local function convert_values_to_key_value_string(values_table)
    if not values_table then return "-" end

    local key_value_pairs = {}

    -- Handle new format: array of change objects (from comprehensive_changes)
    if type(values_table) == "table" and values_table[1] and type(values_table[1]) == "table" then
        if values_table[1].method then
            -- This is an array of change objects
            for i, change in ipairs(values_table) do
                local method = change.method or "unknown"
                local config = change.config or "unknown"
                local section = change.section or "unknown"
                local field = change.field or "unknown"
                local value = change.value or "unknown"

                -- Handle delete operations properly
                if method == "delete" then
                    field = field == "section" and "section" or field
                    value = value == "deleted" and "deleted" or value
                end

                table.insert(key_value_pairs, string_format("change_%d=%s.%s.%s=%s",
                    i, method, field, value, config))
            end
            return table_concat(key_value_pairs, ",")
        end
    end

    -- Handle old format: key-value table
    if next(values_table) == nil then return "-" end

    for key, value in pairs(values_table) do
        -- Skip session IDs from display (too noisy)
        if key ~= 'ubus_rpc_session' then
            table.insert(key_value_pairs, key .. "=" .. format_value_for_display(value))
        end
    end

    if #key_value_pairs == 0 then return "-" end
    return table_concat(key_value_pairs, ",")
end

-- Remove sensitive information from logged values
local function sanitize_sensitive_information(values_table, operation_method)
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
    key_value = {}, 
    json = {}, 
    authentication = {} 
}

local last_batch_flush_time = os.time()

-- Write accumulated debug messages to file
local function flush_debug_messages()
    if LOGGING_CONTROLS.enable_debug_logging and #debug_message_batch > 0 then
        local debug_file = io.open(LOG_PATHS.debug_log, "a")
        if debug_file then 
            debug_file:write(table_concat(debug_message_batch, "\n") .. "\n")
            debug_file:close()
        end
        debug_message_batch = {}
    end
end

-- Write batched log entries to their respective files
local function flush_log_batches(force_flush)
    -- Always flush debug messages first
    flush_debug_messages()
    
    -- Skip if audit logging is completely disabled
    if not LOGGING_CONTROLS.enable_audit_logging then
        return
    end
    
    local now = os.time()
    local should_flush_now = force_flush or 
        (now - last_batch_flush_time >= LOGGING_CONTROLS.auto_flush_interval_seconds) or 
        (#log_entry_batches.key_value > LOGGING_CONTROLS.batch_size_for_immediate_flush)
    
    if not should_flush_now then return end
    
    -- Write human-readable log batch
    if LOGGING_CONTROLS.enable_human_readable and #log_entry_batches.human_readable > 0 then
        rotate_log_file_if_needed(LOG_PATHS.human_readable_log)
        local readable_file = io.open(LOG_PATHS.human_readable_log, "a")
        if readable_file then 
            readable_file:write(table_concat(log_entry_batches.human_readable, "\n") .. "\n")
            readable_file:close()
        end
        log_entry_batches.human_readable = {}
    end
    
    -- Write key-value log batch
    if LOGGING_CONTROLS.enable_key_value_pairs and #log_entry_batches.key_value > 0 then
        rotate_log_file_if_needed(LOG_PATHS.key_value_log)
        local kv_file = io.open(LOG_PATHS.key_value_log, "a")
        if kv_file then 
            kv_file:write(table_concat(log_entry_batches.key_value, "\n") .. "\n")
            kv_file:close() 
        end
        log_entry_batches.key_value = {}
    end
    
    -- Write JSON log batch
    if LOGGING_CONTROLS.enable_json_output and #log_entry_batches.json > 0 then
        rotate_log_file_if_needed(LOG_PATHS.json_log)
        local json_file = io.open(LOG_PATHS.json_log, "a")
        if json_file then 
            json_file:write(table_concat(log_entry_batches.json, "\n") .. "\n")
            json_file:close() 
        end
        log_entry_batches.json = {}
    end
    
    -- Write authentication log batch
    if LOGGING_CONTROLS.enable_authentication_log and #log_entry_batches.authentication > 0 then
        rotate_log_file_if_needed(LOG_PATHS.authentication_log)
        local auth_file = io.open(LOG_PATHS.authentication_log, "a")
        if auth_file then 
            auth_file:write(table_concat(log_entry_batches.authentication, "\n") .. "\n")
            auth_file:close() 
        end
        log_entry_batches.authentication = {}
    end
    
    last_batch_flush_time = now
end

-- ==============================================================================
-- LOG ENTRY GENERATION
-- ==============================================================================

-- Operations that contain sensitive information
local sensitive_operations = { 
    set_applied = true, exec = true, reboot = true, read = true, write = true, 
    setLocaltime = true, setInitAction = true,
    setPassword = true, login = true, logout = true,
    firewall_restart = true, firewall_reload = true,
    system_upgrade = true, validate_firmware = true,
    file_write = true, file_remove = true
}

-- Authentication-related operations  
local authentication_operations = { setPassword = true, login = true, logout = true }

-- Generate and queue log entries for an operation
local function create_log_entries_for_operation(operation_data)
    -- Skip if audit logging is disabled
    if not LOGGING_CONTROLS.enable_audit_logging then
        debug_operation_processing("Audit logging disabled - skipping log entry creation")
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
    
    local timestamp = current_time("!%a %b %d %H:%M:%S %Y")
    debug_operation_processing(string_format("CREATING LOG: user=%s action=%s category=%s config=%s", 
        user, action, category, config))
    
    -- Prepare clean operation data for formatter
    local clean_operation = {
        type = operation_data.type,
        user = user,
        action = action,
        category = category,
        config = config,
        section = section,
        values = sanitized_values,

        -- NEW: Include analyzed changes from before/after module
        analyzed_changes = operation_data.analyzed_changes
    }

    -- Validate formatter integration
    if not formatter or not formatter.format then
        debug_operation_processing("ERROR: Formatter module not properly loaded")
        return
    end
    
    -- Generate human-readable log entry with enhanced before/after integration
    if LOGGING_CONTROLS.enable_human_readable then
        local readable_message = "formatter unavailable"
        local format_success, format_error = pcall(function()
            readable_message = formatter.format(clean_operation)
        end)

        if not format_success then
            debug_operation_processing(string_format("ERROR: Formatter failed: %s", format_error))
            readable_message = string_format("ERROR: %s (user: %s, action: %s)", format_error, user, action)
        end

        local formatted_line = string_format("%s [user: %s] %s", timestamp, user, readable_message)
        log_entry_batches.human_readable[#log_entry_batches.human_readable + 1] = formatted_line
    end

    -- Generate key-value log entry
    if LOGGING_CONTROLS.enable_key_value_pairs then
        local kv_components = { "time=" .. timestamp, "user=" .. user, "action=" .. action }
        if category and category ~= "-" then 
            table.insert(kv_components, "category=" .. category) 
        end
        if config and config ~= "-" then 
            table.insert(kv_components, "config=" .. config) 
        end
        if section and section ~= "" and section ~= "-" then 
            table.insert(kv_components, "section=" .. section) 
        end
        table.insert(kv_components, "values=" .. convert_values_to_key_value_string(sanitized_values))
        log_entry_batches.key_value[#log_entry_batches.key_value + 1] = table_concat(kv_components, "  ")
    end

    -- Generate JSON log entry
    if LOGGING_CONTROLS.enable_json_output then
        clean_operation.time = timestamp
        log_entry_batches.json[#log_entry_batches.json + 1] = json_encode(clean_operation)
    end
    
    -- Authentication-specific logging
    if LOGGING_CONTROLS.enable_authentication_log and authentication_operations[action] then
        local auth_entry = string_format("[%s] AUTH: user=%s action=%s source_ip=%s result=%s", 
            timestamp, user, action, 
            operation_data.source_ip or "unknown", 
            operation_data.result or "unknown")
        log_entry_batches.authentication[#log_entry_batches.authentication + 1] = auth_entry
    end
    
    -- Security alert logging for sensitive operations
    if LOGGING_CONTROLS.enable_security_alerts and sensitive_operations[action] then
        rotate_log_file_if_needed(LOG_PATHS.security_log)
        local security_file = io.open(LOG_PATHS.security_log, "a")
        if security_file then 
            local readable_message = formatter.format(clean_operation)
            security_file:write(string_format("[%s] SENSITIVE: %s\n", timestamp, readable_message))
            security_file:close() 
        end
    end
end

-- ==============================================================================
-- ENHANCED UCI OPERATION STATE MANAGEMENT (With Before/After Integration)
-- ==============================================================================

-- ENHANCED: Stage a UCI operation with before/after state capture
local function stage_uci_operation_for_session(operation_data, callback_id)
    local session_id = operation_data.values.ubus_rpc_session
    if not session_id then return end

    -- CRITICAL: Map this callback ID to the session ID for changes data correlation
    callback_to_session_mapping[callback_id] = session_id
    debug_callback_tracking(string_format("MAPPED callback %s -> session %s", callback_id, session_id))

    -- NEW: Capture before-state using the before/after module (prefer async queue)
    local before_state = nil
    if LOGGING_CONTROLS.enable_before_after_tracking and before_after then
        -- If queue module available, enqueue a background capture handler
        if state_capture_queue and state_capture_queue.enqueue then
            local enqueue_ok, enqueue_err = pcall(function()
                state_capture_queue.enqueue({
                    session_id = session_id,
                    operation = operation_data,
                    handler = function(item)
                        -- Safely perform capture in background
                        local ok, captured = pcall(function()
                            return before_after.capture_before_state(item.operation, function(msg)
                                debug_session_state(msg)
                            end)
                        end)
                        if ok and captured then
                            -- store resolved state for later correlation
                            pcall(before_after.store_session_state, item.session_id, item.operation.values.section, captured)
                        else
                            debug_session_state("Queue handler: before_state capture failed or returned nil")
                        end
                    end
                })
            end)
            if not enqueue_ok then
                write_debug_message(string_format("ERROR: Failed to enqueue before-state capture: %s", tostring(enqueue_err)), "SYSTEM")
            end
            -- leave before_state nil — async capture will populate module cache
        else
            -- Synchronous fallback when queue not available
            before_state = before_after.capture_before_state(operation_data, function(msg)
                debug_session_state(msg)
            end)
            -- Store in module's session management for correlation
            before_after.store_session_state(session_id, operation_data.values.section, before_state)
        end
    end

    -- Store basic operation info with before-state data
    local save_data = {
        method = operation_data.method,
        config = operation_data.values.config,
        section = operation_data.values.section,
        section_type = operation_data.values.type,  -- For add operations
        original_values = operation_data.values.values or {},
        
        -- NEW: Include before-state data
        before_state = before_state
    }

    -- For delete and remove operations, preserve section info
    if operation_data.method == "delete" or operation_data.method == "remove" then
        save_data.deleted_section = operation_data.values.section
    end
    
    if not staged_uci_operations_by_session[session_id] then
        staged_uci_operations_by_session[session_id] = { saves = {}, user = operation_data.user }
    end
    table.insert(staged_uci_operations_by_session[session_id].saves, save_data)
    
    debug_session_state(string_format("Enhanced staging '%s' for session %s (callback %s). Total staged: %d", 
        operation_data.method, session_id, callback_id, #staged_uci_operations_by_session[session_id].saves))
end

-- ENHANCED: Process successful UCI apply operation with before/after correlation
local function process_successful_uci_apply(session_id, user)
    if not (session_id and staged_uci_operations_by_session[session_id]) then 
        debug_session_state(string_format("No staged operations found for session %s", session_id))
        return 
    end
    
    local session_data = staged_uci_operations_by_session[session_id]
    if #session_data.saves == 0 then 
        staged_uci_operations_by_session[session_id] = nil
        debug_session_state(string_format("Empty saves list for session %s", session_id))
        return 
    end
    
    -- Build comprehensive change data combining staged operations with clean changes
    local comprehensive_changes = {}
    local config_name = session_data.saves[1].config  -- All should be same config
    
    -- Check if we have clean changes data for this session
    if uci_changes_by_session[session_id] then
        debug_uci_change_capture(string_format("Using clean changes data for session %s", session_id))
        
        -- Process the clean changes data: {"dhcp":[["set","cfg0676c9","cname","2122q"]]}
        for config, change_list in pairs(uci_changes_by_session[session_id]) do
            for _, change in ipairs(change_list) do
                -- change format: ["set", "cfg0676c9", "cname", "2122q"]
                local change_entry = {
                    method = change[1],      -- "set", "add", "delete"
                    config = config,         -- "dhcp"
                    section = change[2],     -- "cfg0676c9"
                    field = change[3],       -- "cname" or nil for delete
                    value = change[4]        -- "2122q" or nil for delete
                }

                -- For delete and remove operations, field and value will be nil, but we need to handle this properly
                if change_entry.method == "delete" or change_entry.method == "remove" then
                    change_entry.field = change_entry.field or "section"
                    change_entry.value = change_entry.value or "deleted"
                end

                -- NEW: Get before-state from the module
                local before_state = before_after.get_session_state(session_id, change[2])
                if before_state then
                    change_entry.before_state = before_state
                end

                -- Find corresponding staged operation to get section type
                for _, staged_op in ipairs(session_data.saves) do
                    if staged_op.section == change[2] then
                        change_entry.section_type = staged_op.section_type
                        -- Merge additional before-state if available from staging
                        if not change_entry.before_state and staged_op.before_state then
                            change_entry.before_state = staged_op.before_state
                        end
                        break
                    end
                end

                -- Check for duplicates before adding
                local is_duplicate = false
                for _, existing_change in ipairs(comprehensive_changes) do
                    if existing_change.method == change_entry.method and
                       existing_change.config == change_entry.config and
                       existing_change.section == change_entry.section and
                       existing_change.field == change_entry.field and
                       existing_change.value == change_entry.value then
                        is_duplicate = true
                        break
                    end
                end

                if not is_duplicate then
                    table.insert(comprehensive_changes, change_entry)

                    debug_uci_change_capture(string_format("Enhanced change: %s.%s.%s = %s (before-state: %s)",
                        config, change[2], change[3] or "section", tostring(change[4]),
                        change_entry.before_state and "available" or "none"))
                else
                    debug_uci_change_capture(string_format("Skipped duplicate change: %s.%s.%s = %s",
                        config, change[2], change[3] or "section", tostring(change[4])))
                end
            end
        end
        
        -- Clean up the changes data for this session
        uci_changes_by_session[session_id] = nil
        
    else
        -- Fallback to original staging method for sessions without clean changes
        debug_uci_change_capture(string_format("No clean changes data for session %s, using fallback", session_id))

        for _, save_op in ipairs(session_data.saves) do
            local fallback_entry = {
                method = save_op.method,
                config = save_op.config,
                section = save_op.section,
                section_type = save_op.section_type,
                values = save_op.original_values,

                -- NEW: Include before-state from staging
                before_state = save_op.before_state
            }

            -- Handle delete and remove operations in fallback mode
            if save_op.method == "delete" or save_op.method == "remove" then
                fallback_entry.field = "section"
                fallback_entry.value = "deleted"
            end

            -- Check for duplicates before adding
            local is_duplicate = false
            for _, existing_change in ipairs(comprehensive_changes) do
                if existing_change.method == fallback_entry.method and
                   existing_change.config == fallback_entry.config and
                   existing_change.section == fallback_entry.section then
                    is_duplicate = true
                    break
                end
            end

            if not is_duplicate then
                table.insert(comprehensive_changes, fallback_entry)
                debug_uci_change_capture(string_format("Fallback change: %s.%s (method: %s)",
                    save_op.config, save_op.section, save_op.method))
            else
                debug_uci_change_capture(string_format("Skipped duplicate fallback change: %s.%s (method: %s)",
                    save_op.config, save_op.section, save_op.method))
            end
        end
    end
    
    -- NEW: Analyze changes using the before/after module
    local analyzed_changes = {}
    if LOGGING_CONTROLS.enable_intelligent_descriptions and #comprehensive_changes > 0 then
        analyzed_changes = before_after.analyze_changes(comprehensive_changes, function(msg)
            debug_uci_change_capture(msg)
        end)
    end
    
    -- Create the set_applied log entry with comprehensive change data and analysis
    create_log_entries_for_operation({
        user = user,
        action = "set_applied",
        type = "set_applied",
        category = "uci",
        config = config_name,
        values = comprehensive_changes,  -- Pass the rich change data
        section = nil,  -- No specific section for batch operations

        -- NEW: Include analyzed changes for intelligent formatting
        analyzed_changes = analyzed_changes
    })
    
    -- Cleanup
    staged_uci_operations_by_session[session_id] = nil

    -- NEW: Enhanced module cleanup with error handling
    if before_after and before_after.cleanup_session_state then
        local cleanup_success, cleanup_error = pcall(before_after.cleanup_session_state, session_id)
        if not cleanup_success then
            debug_session_state(string_format("WARNING: Before/after cleanup failed for session %s: %s",
                session_id, cleanup_error))
        end
    end

    debug_session_state(string_format("Applied %d changes for session %s with before/after analysis",
        #comprehensive_changes, session_id))
end

-- ==============================================================================
-- OPERATION CLASSIFICATION (THE TRIAGE BRAIN)
-- ==============================================================================

-- CRITICAL: The expert triage function - classifies operations for processing
local function triage_operation(user, object_name, method, message_data)
    local operation_type = nil
    
    -- UCI configuration operations (staged until apply)
    if object_name == "uci" and (method == "set" or method == "add" or method == "delete" or method == "remove") then
        operation_type = "uci_change"
    elseif object_name == "uci" and method == "apply" then
        operation_type = "uci_apply"
    
    -- Authentication operations (logged immediately)
    elseif object_name == "luci" and (method == "setPassword" or method == "access") then
        operation_type = "auth_password_change"
    elseif object_name == "luci" and method == "login" then
        operation_type = "auth_login"
    elseif object_name == "luci" and method == "logout" then  
        operation_type = "auth_logout"
    
    -- Firewall operations (logged immediately)
    elseif object_name == "network.firewall" and method == "restart" then
        operation_type = "firewall_restart"
    elseif object_name == "network.firewall" and method == "reload" then
        operation_type = "firewall_reload"
    elseif object_name == "network.firewall" and method == "info" then
        operation_type = "firewall_info"
    
    -- System security operations (logged immediately)
    elseif object_name == "system" and method == "upgrade" then
        operation_type = "system_upgrade"
    elseif object_name == "system" and method == "validate_firmware" then
        operation_type = "firmware_validate"
    
    -- File operations (logged immediately)
    elseif object_name == "file" and method == "exec" then
        operation_type = "exec"
    elseif object_name == "file" and method == "write" then
        operation_type = "file_write"
    elseif object_name == "file" and method == "remove" then
        operation_type = "file_remove"
    elseif object_name == "file" and method == "read" then
        operation_type = "file_read"
   
    -- Backup operations (logged immediately)
    elseif method == "access" and message_data.object == "backup" then
        operation_type = "backup_read"
    
    -- Direct system operations (logged immediately)
    elseif (object_name == "system" or object_name == "luci") and 
           (method == "setLocaltime" or method == "setInitAction" or method == "reboot") then
        operation_type = "direct"
    end
    
    if operation_type then
        debug_operation_processing(string_format("TRIAGED: method '%s' on object '%s' as type '%s'", 
            method, object_name, operation_type))
        return {
            type = operation_type, 
            user = user, 
            obj_name = object_name, 
            method = method,
            values = message_data, 
            config = message_data.command or message_data.name or message_data.config or object_name,
            source_ip = message_data.remote_addr or message_data.source_ip
        }
    end

    debug_operation_processing(string_format("FILTERED: Discarding noisy event: method='%s' on object='%s'", 
        method, object_name))
    return nil
end

-- ==============================================================================
-- UBUS MONITORING AND PROCESSING (THE MAIN ENGINE)
-- ==============================================================================

-- Process a single line from ubus monitor
local function process_ubus_monitor_line(ubus_line)
    local json_data_string = extract_json_from_ubus_line(ubus_line)
    if not json_data_string then return end
    
    local parse_success, parsed_data = pcall(json_decode, json_data_string)
    if not parse_success or not parsed_data then return end

    -- Handle object path mapping discovery
    if string_find(ubus_line, "data:", 1, true) and parsed_data.objpath and parsed_data.objid then
        if ubus_object_mappings[parsed_data.objid] ~= parsed_data.objpath then
            ubus_object_mappings[parsed_data.objid] = parsed_data.objpath
            debug_session_state(string_format("MAPPED: objid %s -> %s", 
                tostring(parsed_data.objid), parsed_data.objpath))
        end
        return
    end

    local callback_id = string_match(ubus_line, "#([%da-f]+)")
    if not callback_id then return end

    -- CRITICAL: Handle UCI changes data capture (the missing piece!)
    if string_find(ubus_line, "data:", 1, true) and parsed_data.data and parsed_data.data.changes then
        -- Find the session ID using our callback->session mapping
        local session_id = callback_to_session_mapping[callback_id]
        
        if session_id then
            -- Store changes data by session ID for later correlation during apply
            if not uci_changes_by_session[session_id] then
                uci_changes_by_session[session_id] = {}
            end
            
            -- Merge changes data (handle multiple operations in same session)
            for config, change_list in pairs(parsed_data.data.changes) do
                if not uci_changes_by_session[session_id][config] then
                    uci_changes_by_session[session_id][config] = {}
                end
                -- Append new changes to existing ones
                for _, change in ipairs(change_list) do
                    table.insert(uci_changes_by_session[session_id][config], change)
                end
            end
            
            debug_uci_change_capture(string_format("Stored changes for session %s (callback %s): %s", 
                session_id, callback_id, json_encode(parsed_data.data.changes)))
                
            -- Clean up callback mapping once we've captured the changes
            callback_to_session_mapping[callback_id] = nil
        else
            debug_uci_change_capture(string_format("Received changes data for unmapped callback %s", callback_id))
        end
        return
    end

    -- Handle command output capture for exec operations
    if string_find(ubus_line, "data:", 1, true) and parsed_data.data and 
       operations_waiting_for_response[callback_id] then
        
        local operation = operations_waiting_for_response[callback_id]
        
        if operation.type == "exec" then
            operation.output_data = parsed_data.data
            debug_operation_processing(string_format("Captured exec output for callback %s", callback_id))
        end
        return
    end
    
    -- Handle operation invocation (the entry point for all user actions)
    if string_find(ubus_line, "invoke:", 1, true) then
        -- CRITICAL FILTER: Only process lines with actual users (not system operations)
        if not (parsed_data.user and parsed_data.user ~= "" and parsed_data.user ~= "-") then 
            return 
        end
        
        local object_name = ubus_object_mappings[parsed_data.objid] or "unknown"
        local method = parsed_data.method
        local message_data = parsed_data.data or {}
        
        debug_callback_tracking(string_format("INVOKE: user=%s objid=%s->%s method=%s callback=%s", 
            parsed_data.user, tostring(parsed_data.objid), object_name, method, callback_id))
        
        -- Use the expert triage function to classify this operation
        local classified_operation = triage_operation(parsed_data.user, object_name, method, message_data)
        if classified_operation then 
            operations_waiting_for_response[callback_id] = classified_operation
            debug_callback_tracking(string_format("PENDING: Added operation type '%s' for callback %s", 
                classified_operation.type, callback_id))
        end

    -- Handle operation completion (the trigger point for logging)
    elseif string_find(ubus_line, "status:", 1, true) then        
        local operation = operations_waiting_for_response[callback_id]
        
        -- SINGLE POINT OF TRUTH: Only process successful operations exactly once
        if parsed_data.status == 0 and operation then
            operations_waiting_for_response[callback_id] = nil
            debug_callback_tracking(string_format("SUCCESS: Processing completed operation type '%s' for callback %s", 
                operation.type, callback_id))

            if operation.type == "uci_change" then
                -- STAGE FOR LATER: Don't log yet, wait for apply
                stage_uci_operation_for_session(operation, callback_id)

            elseif operation.type == "uci_apply" then
                -- TRIGGER: Process all staged changes for this session
                process_successful_uci_apply(operation.values.ubus_rpc_session, operation.user)

            else 
                -- IMMEDIATE LOGGING: Handle all non-UCI operations
                if operation.type == "exec" then
                    local exec_values = { 
                        command = operation.config,
                        arguments = operation.values.params or {} 
                    }
                    if operation.output_data then
                        exec_values.code = operation.output_data.code
                        exec_values.stdout = operation.output_data.stdout
                        exec_values.stderr = operation.output_data.stderr
                    end
                    operation.values = exec_values
                    operation.action = "exec"
                
                -- Authentication operations
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
                    -- Track successful login sessions
                    active_user_sessions[operation.values.ubus_rpc_session or "unknown"] = {
                        user = operation.user, 
                        login_time = os.time(), 
                        ip = operation.source_ip
                    }
                
                elseif operation.type == "auth_logout" then
                    operation.action = "logout"
                    operation.category = "authentication"
                    operation.config = "session_management" 
                    operation.result = "success"
                    -- Clean up session tracking
                    active_user_sessions[operation.values.ubus_rpc_session or "unknown"] = nil
                
                -- Firewall operations
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
                
                -- System security operations
                elseif operation.type == "system_upgrade" then
                    operation.action = "system_upgrade"
                    operation.category = "system_security"
                    operation.config = "firmware"
                
                elseif operation.type == "firmware_validate" then
                    operation.action = "validate_firmware"
                    operation.category = "system_security"
                    operation.config = "firmware"
                
                -- File operations
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
                
                else -- Direct operations (setLocaltime, setInitAction, reboot)
                    operation.action = operation.method
                end
                
                -- Log the operation immediately
                create_log_entries_for_operation(operation)
            end
            
        elseif parsed_data.status ~= 0 and operation then
            -- Handle failed operations (especially important for authentication)
            operations_waiting_for_response[callback_id] = nil
            debug_callback_tracking(string_format("FAILED: Operation type '%s' failed with status %d", 
                operation.type, parsed_data.status))
            
            if operation.type and string_find(operation.type, "^auth_", 1, true) then
                operation.result = string_format("failed(status:%d)", parsed_data.status)
                operation.action = string_match(operation.type, "^auth_(.+)") or operation.type
                operation.category = "authentication"
                create_log_entries_for_operation(operation)
            end
        end
    end
end

-- ==============================================================================
-- MAIN PROGRAM EXECUTION (PROJECT ARGUS INITIALIZATION)
-- ==============================================================================

-- Initialize the logging system
initialize_logging_system()
initialize_before_after_module()  -- NEW: Initialize before/after module

-- Conditionally enable the in-process state capture queue
if LOGGING_CONTROLS.enable_state_capture_queue then
    local ok, module_or_err = pcall(load_engine_module, "state_capture_queue")
    if ok and module_or_err then
        state_capture_queue = module_or_err
        write_debug_message("State capture queue loaded and enabled", "SYSTEM")
        if state_capture_queue.set_debug_callback then
            state_capture_queue.set_debug_callback(function(msg) debug_session_state(msg) end)
        end
    else
        state_capture_queue = nil
        write_debug_message("State capture queue not available; falling back to synchronous captures", "SYSTEM")
    end
else
    state_capture_queue = nil
    write_debug_message("State capture queue disabled via configuration; using synchronous captures", "SYSTEM")
end

write_debug_message("Starting Project Argus - Enhanced with Before/After Module", "SYSTEM")
write_debug_message(string_format("Logging Controls: audit=%s kv=%s json=%s debug=%s before_after=%s", 
    tostring(LOGGING_CONTROLS.enable_audit_logging),
    tostring(LOGGING_CONTROLS.enable_key_value_pairs),
    tostring(LOGGING_CONTROLS.enable_json_output),
    tostring(LOGGING_CONTROLS.enable_debug_logging),
    tostring(LOGGING_CONTROLS.enable_before_after_tracking)
), "SYSTEM")

-- Open ubus monitor stream
local ubus_monitor_stream = io_popen("ubus monitor 2>/dev/null", "r")
if not ubus_monitor_stream then 
    write_debug_message("CRITICAL: Failed to open ubus monitor stream", "CRITICAL")
    os.exit(1) 
end

-- Main monitoring loop - the heart of Project Argus
write_debug_message("Beginning ubus monitoring loop with enhanced before/after tracking", "SYSTEM")
local lines_processed = 0

while true do
    local ubus_line = ubus_monitor_stream:read("*l")
    if not ubus_line then 
        write_debug_message("ubus monitor stream ended", "SYSTEM")
        break 
    end
    
    lines_processed = lines_processed + 1
    
    -- Process the line safely with comprehensive error handling
    local processing_success, error_message = pcall(process_ubus_monitor_line, ubus_line)
    if not processing_success then 
        write_debug_message("ERROR processing ubus line " .. lines_processed .. ": " .. tostring(error_message), "ERROR") 
    end
    
    -- Flush log batches periodically (performance optimization)
    if lines_processed % 100 == 0 then  -- Check every 100 lines
        flush_log_batches(false)
    end
    
    -- Periodically process queued before-state captures (non-blocking)
    if state_capture_queue and lines_processed % 10 == 0 then
        local ok, processed = pcall(function() return state_capture_queue.process_once(8) end)
        if ok and processed and processed > 0 then
            debug_session_state(string_format("Processed %d queued capture tasks", processed))
        end
    end
    
    -- Report before/after module statistics periodically
    if lines_processed % 1000 == 0 then
        if LOGGING_CONTROLS.debug_before_after_operations and before_after.get_stats then
            local stats = before_after.get_stats()
            write_debug_message(string_format(
                "Before/After Stats: %d states captured, %d processed, %.1f%% cache hit rate, %d active sessions",
                stats.states_captured or 0, stats.states_processed or 0, 
                stats.cache_hit_rate or 0.0, stats.active_sessions or 0
            ), "BEFORE_AFTER_STATS")
        end
    end
end

-- Graceful cleanup
ubus_monitor_stream:close()
flush_log_batches(true)  -- Final flush of all pending entries

-- NEW: Enhanced before/after module cleanup with error handling
if before_after and before_after.cleanup then
    local cleanup_success, cleanup_error = pcall(before_after.cleanup)
    if not cleanup_success then
        write_debug_message(string_format("WARNING: Before/after module cleanup failed: %s", cleanup_error), "SYSTEM")
    else
        write_debug_message("Before/after module cleanup completed successfully", "SYSTEM")
    end
end

-- Final module statistics
if before_after.get_stats then
    local final_stats = before_after.get_stats()
    write_debug_message(string_format("Before/After Module Final Stats: %d states captured, %d processed, %d fields analyzed", 
        final_stats.states_captured or 0, final_stats.states_processed or 0, 
        final_stats.fields_captured or 0), "SYSTEM")
end

-- Final statistics
write_debug_message(string_format("Project Argus stopped gracefully. Processed %d lines total", lines_processed), "SYSTEM")
write_debug_message(string_format("Final state: %d staged sessions, %d pending operations", 
    #staged_uci_operations_by_session, #operations_waiting_for_response), "SYSTEM")

-- ==============================================================================
-- END OF PROJECT ARGUS - ENHANCED AUDIT LOGGER
-- ==============================================================================
