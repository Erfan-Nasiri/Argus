-- ==============================================================================
-- init.lua - Main Formatter Interface with Exact Original Functionality
-- ==============================================================================
-- Purpose: Modular UCI Change Processor preserving ALL original functionality
-- Features: Session-based UCI change correlation, intelligent section resolution,
--          comprehensive value translation, and robust error handling
-- ==============================================================================

local M = {}

-- Load sub-modules
local utils = require "formatter.utils"
local uci = require "formatter.uci"
local naming = require "formatter.naming"
local security = require "formatter.security"
local deduplication = require "formatter.deduplication"
local change_summary_factory = require "formatter.services.change_summary"
local analyzed_summary_factory = require "formatter.services.analyzed_summary"

-- ==============================================================================
-- FORMATTER CONFIGURATION
-- ==============================================================================

-- Feature switches
local FORMATTER_CONFIG = {
    enable_deduplication = false, -- Enable/disable deduplication feature
    enable_field_naming = true,   -- Enable/disable intelligent field naming
    enable_security_assessment = true,  -- Enable/disable security impact assessment
    show_change_counts = false    -- Show number of changes in summary
}

-- Performance: Pre-localize ALL standard library functions
local string_format, string_gsub, string_match, string_lower, string_find, string_sub =
      string.format, string.gsub, string.match, string.lower, string.find, string.sub
local table_insert, table_concat = table.insert, table.concat
local pairs, ipairs, next, type, tostring, tonumber =
      pairs, ipairs, next, type, tostring, tonumber
local os_time, os_date = os.time, os.date
local pcall = pcall

local change_summary = change_summary_factory.new({
    utils = utils,
    naming = naming,
    security = security,
    deduplication = deduplication,
    config = FORMATTER_CONFIG,
    table_insert = table_insert,
    table_concat = table_concat,
    ipairs = ipairs,
    pairs = pairs,
    string_find = string_find,
    string_sub = string_sub,
    string_match = string_match
})

local analyzed_summary = analyzed_summary_factory.new({
    utils = utils,
    table_insert = table_insert,
    table_concat = table_concat,
    ipairs = ipairs,
    impact_priority = { low = 1, medium = 2, high = 3 }
})

local function normalize_legacy_operations(operations)
    local normalized = {}
    for _, op in ipairs(operations or {}) do
        local method = utils.safe_get(op, "method", "unknown", "string")
        local config = utils.safe_get(op, "config", "unknown", "string")
        local section = utils.safe_get(op, "section", nil, "string")
        local section_type = utils.safe_get(op, "section_type", nil, "string")
        if method == "set" then
            local values = utils.safe_get(op, "values", {}, "table")
            for key, value in pairs(values) do
                if type(key) == "string" and key ~= "ubus_rpc_session" and not key:match("^%.") then
                    table_insert(normalized, {
                        method = "set",
                        config = config,
                        section = section,
                        section_type = section_type,
                        field = key,
                        value = value
                    })
                end
            end
        else
            table_insert(normalized, {
                method = method,
                config = config,
                section = section,
                section_type = section_type,
                values = utils.safe_get(op, "values", {}, "table")
            })
        end
    end
    return normalized
end

-- ==============================================================================
-- MAIN FORMATTER INTERFACE
-- ==============================================================================

function M.format(op)
    -- Ultimate defensive check - handle any input safely
    if type(op) ~= "table" then
        return "invalid-operation-data"
    end

    local action = utils.safe_get(op, "action", utils.safe_get(op, "method", "unknown"))
    local config = utils.safe_get(op, "config", "unknown", "string")
    local values = utils.safe_get(op, "values", {}, "table")
    local message = nil

    -- CRITICAL: Handle session-based UCI changes (the new intelligence)
    if action == "set_applied" and type(values) == "table" and #values > 0 then
        local analyzed_changes = utils.safe_get(op, "analyzed_changes", {}, "table")

        if analyzed_changes and #analyzed_changes > 0 then
            message = analyzed_summary(analyzed_changes, config)
        else
            local first_entry = values[1]
            if first_entry and first_entry.method then
                message = change_summary(values)
            else
                message = change_summary(normalize_legacy_operations(values))
            end
        end

    -- Handle exec operations
    elseif action == "exec" then
        local cmd = utils.safe_get(values, "command", utils.safe_get(op, "config", "unknown-command"))
        local args = utils.safe_get(values, "arguments", {}, "table")
        local exit_code = utils.safe_get(values, "code", nil, "number")

        -- Build full command with arguments
        local full_cmd = cmd
        if type(args) == "table" and #args > 0 then
            local safe_args = {}
            for _, arg in ipairs(args) do
                table_insert(safe_args, utils.safe_string(arg))
            end
            full_cmd = utils.safe_format("%s %s", cmd, table_concat(safe_args, " "))
        end

        if exit_code and exit_code ~= 0 then
            message = utils.safe_format("executed '%s' (failed: exit code %d)", full_cmd, exit_code)
        else
            message = utils.safe_format("executed '%s'", full_cmd)
        end

    -- Handle backup operations
    elseif action == "read" and config == "backup" then
        message = "accessed system backup"

    -- Handle system operations
    elseif action == "reboot" then
        message = "initiated system reboot"

    elseif action == "setLocaltime" then
        local time_value = utils.safe_get(values, "localtime", nil)
        if time_value then
            local timestamp = tonumber(time_value)
            if timestamp then
                local formatted_time = os_date("%Y-%m-%d %H:%M:%S", timestamp)
                message = utils.safe_format("set system time to %s", formatted_time)
            else
                message = utils.safe_format("set system time to %s", time_value)
            end
        else
            message = "modified system time"
        end

    elseif action == "setInitAction" then
        local service_name = utils.safe_get(op, "config", "unknown-service", "string")
        local init_action = utils.safe_get(values, "action", "unknown-action", "string")
        local service_display = utils.safe_get(values, "name", service_name, "string")

        local action_descriptions = {
            start = "started", stop = "stopped", restart = "restarted",
            reload = "reloaded", enable = "enabled", disable = "disabled"
        }

        local action_desc = action_descriptions[init_action] or init_action
        message = utils.safe_format("%s service '%s'", action_desc, service_display)

    -- Handle file operations
    elseif action == "file_write" or action == "write" then
        local filename = utils.safe_get(values, "path", "unknown_file", "string")
        local data_written = utils.safe_get(values, "data", nil, "string")

        if data_written and data_written ~= "" then
            local sanitized_data = string_gsub(data_written, "\n", "\\n")

            -- Intelligent truncation with context preservation
            if #sanitized_data > 200 then
                sanitized_data = string_sub(sanitized_data, 1, 150) .. "..." .. string_sub(sanitized_data, -47)
            end

            message = utils.safe_format("wrote content to file '%s': \"%s\"", filename, sanitized_data)
        else
            message = utils.safe_format("modified file '%s'", filename)
        end

    elseif action == "file_remove" then
        local filename = utils.safe_get(values, "path", "unknown_file", "string")
        message = utils.safe_format("removed file '%s'", filename)

    elseif action == "file_read" then
        local filename = utils.safe_get(values, "path", utils.safe_get(op, "config", "file"), "string")
        local size = utils.safe_get(values, "size", nil, "number")
        if size then
            message = utils.safe_format("read %d bytes from file '%s'", size, filename)
        else
            message = utils.safe_format("read file '%s'", filename)
        end

    -- Handle authentication operations
    elseif action == "login" then
        local username = utils.safe_get(values, "username", utils.safe_get(op, "user", "unknown"), "string")
        local result = utils.safe_get(op, "result", "success", "string")
        if result == "success" then
            message = utils.safe_format("user '%s' logged in successfully", username)
        else
            message = utils.safe_format("user '%s' login failed (%s)", username, result)
        end

    elseif action == "logout" then
        local username = utils.safe_get(values, "username", utils.safe_get(op, "user", "unknown"), "string")
        message = utils.safe_format("user '%s' logged out", username)

    elseif action == "setPassword" then
        local target_user = utils.safe_get(values, "username", "unknown", "string")
        message = utils.safe_format("changed password for user '%s'", target_user)

    -- Handle firewall operations
    elseif action == "firewall_restart" then
        message = "restarted firewall service"

    elseif action == "firewall_reload" then
        message = "reloaded firewall rules"

    elseif action == "firewall_info" then
        message = "queried firewall status"

    -- Handle system operations
    elseif action == "system_upgrade" then
        message = "initiated system firmware upgrade"

    elseif action == "validate_firmware" then
        message = "validated firmware image"

    -- Handle individual UCI operations (bypass normal staging)
    elseif action == "set" and config ~= "unknown" then
        local section = utils.safe_get(op, "section", nil, "string")
        local section_name = naming.resolve_section_name(config, section)

        local changes = {}
        for key, value in pairs(values) do
            if not string_match(key, "^%.") and key ~= "ubus_rpc_session" then
                local field_name = naming.translate_field_name(key)
                local translated_value = naming.translate_value(config, key, value, true)
                table_insert(changes, utils.safe_format("%s=%s", field_name, translated_value))
            end
        end

        if #changes > 0 then
            message = utils.safe_format("set %s: %s", section_name, table_concat(changes, ", "))
        else
            message = utils.safe_format("modified %s", section_name)
        end

    elseif action == "add" and config ~= "unknown" then
        local section_type = utils.safe_get(op, "type", "section", "string")
        local section_name = utils.safe_format("%s %s", config, section_type)

        local details = {}
        for key, value in pairs(values) do
            if not string_match(key, "^%.") and key ~= "ubus_rpc_session" and key ~= "type" then
                local field_name = naming.translate_field_name(key)
                local translated_value = naming.translate_value(config, key, value, true)
                table_insert(details, utils.safe_format("%s=%s", field_name, translated_value))
            end
        end

        if #details > 0 then
            message = utils.safe_format("added %s with %s", section_name, table_concat(details, ", "))
        else
            message = utils.safe_format("added %s", section_name)
        end

    elseif action == "delete" and config ~= "unknown" then
        local section = utils.safe_get(op, "section", nil, "string")
        local section_name = naming.resolve_section_name(config, section)
        message = utils.safe_format("deleted %s", section_name)

    -- Handle access operations
    elseif action == "access" then
        local object = utils.safe_get(values, "object", config, "string")
        local method = utils.safe_get(values, "method", "unknown", "string")
        message = utils.safe_format("accessed %s via %s", object, method)

    -- Handle file read operations with path information (moved before generic handler)
    elseif action == "read" and utils.safe_get(op, "category", "unknown", "string") == "file" then
        local file_path = utils.safe_get(values, "path", "unknown_file", "string")
        local size = utils.safe_get(values, "size", nil, "number")
        if size then
            message = utils.safe_format("read %d bytes from file '%s'", size, file_path)
        else
            -- Include file path explicitly in message for clarity
            message = utils.safe_format("read file '%s'", file_path)
        end

    else
        -- Prefer explicit file path when available for read operations (fallback)
        if action == "read" then
            local file_path = utils.safe_get(values, "path", utils.safe_get(op, "config", nil), "string")
            local size = utils.safe_get(values, "size", nil, "number")
            if file_path and file_path ~= "" then
                if size then
                    message = utils.safe_format("read %d bytes from file '%s'", size, file_path)
                else
                    message = utils.safe_format("read file '%s'", file_path)
                end
            end
        end

        -- Generic action handling (if no more specific message constructed)
        if not message then
            local category = utils.safe_get(op, "category", config, "string")
            if category ~= "unknown" and category ~= action then
                message = utils.safe_format("performed '%s' on %s", action, category)
            else
                message = utils.safe_format("performed '%s'", action)
            end
        end
    end

    -- Add severity tag for non-batch actions (simplified impact assessment)
    if message and action ~= "set_applied" and action ~= "delete_applied" then
        local severity = security.get_action_severity(action, config)
        message = message .. " [" .. severity .. "]"
    end

    return message or "unhandled-operation"
end

-- ==============================================================================
-- MODULE HEALTH AND MAINTENANCE
-- ==============================================================================
-- Graceful cleanup for embedded systems
function M.cleanup()
    if naming.clear_cache then
        naming.clear_cache()
    end
    if uci.cleanup then
        uci.cleanup()
    end
end

function M.health()
    local naming_stats = naming.get_cache_stats and naming.get_cache_stats() or {}
    local uci_stats = uci.health and uci.health() or {}
    return {
        cache_size = naming_stats.size or 0,
        last_cleanup = naming_stats.last_cleanup,
        uci_available = uci_stats.available ~= false,
        uci_backend = uci_stats.backend or "shell"
    }
end

function M.debug_info()
    local naming_stats = naming.get_cache_stats and naming.get_cache_stats() or {}
    local info = uci.debug_info and uci.debug_info() or {}
    return {
        cached_sections = naming_stats.size or 0,
        section_cache_ttl = naming_stats.ttl or 0,
        uci_backend = info.backend or "shell",
        uci_calls_native = info.calls_native or 0,
        uci_calls_shell = info.calls_shell or 0,
        uci_cache_hits = info.cache_hits or 0,
        uci_cache_misses = info.cache_misses or 0,
    }
end

return M
