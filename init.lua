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

-- ==============================================================================
-- ANALYZED CHANGES PROCESSOR (BEFORE/AFTER MODULE INTEGRATION)
-- ==============================================================================

-- Process analyzed changes from before/after module
local function process_analyzed_changes(analyzed_changes, config_name)
    local all_summaries = {}
    local total_changes = 0
    local highest_impact = "low"
    local avg_confidence = "low"

    -- Track impact levels for consolidation
    local impact_levels = {}
    local confidence_levels = {}

    for _, change_analysis in ipairs(analyzed_changes) do
        local description = utils.safe_get(change_analysis, "change_summary", "unknown change", "string")
        local impact = utils.safe_get(change_analysis, "impact_level", "medium", "string")
        local confidence = utils.safe_get(change_analysis, "confidence", "medium", "string")

        -- Store impact and confidence for later consolidation
        table_insert(impact_levels, impact)
        table_insert(confidence_levels, confidence)

        -- Format the change description WITHOUT impact information (clean format)
        local formatted_change = description
        table_insert(all_summaries, formatted_change)
        total_changes = total_changes + 1
    end

    -- Calculate consolidated impact and confidence
    local impact_priority = { low = 1, medium = 2, high = 3 }
    local confidence_priority = { low = 1, medium = 2, high = 3 }

    -- Find highest impact
    for _, impact in ipairs(impact_levels) do
        if impact_priority[impact] and impact_priority[impact] > impact_priority[highest_impact] then
            highest_impact = impact
        end
    end

    -- Calculate average confidence
    local total_confidence = 0
    for _, confidence in ipairs(confidence_levels) do
        total_confidence = total_confidence + confidence_priority[confidence]
    end
    local avg_confidence_score = total_confidence / #confidence_levels
    if avg_confidence_score >= 2.5 then
        avg_confidence = "high"
    elseif avg_confidence_score >= 1.5 then
        avg_confidence = "medium"
    else
        avg_confidence = "low"
    end

    -- Build final comprehensive message
    local changes_detail = table_concat(all_summaries, "; ")

    -- Skip deduplication for analyzed changes (they're already intelligently formatted)
    -- Deduplication is designed for raw UCI messages, not analyzed changes

    local summary_prefix = utils.safe_format("applied %s changes", config_name)

    if changes_detail == "" then
        changes_detail = "unknown changes"
    end

    -- Add consolidated impact and confidence at the end
    return utils.safe_format("%s | changes: %s [impact: %s, confidence: %s]",
        summary_prefix, changes_detail, highest_impact, avg_confidence)
end

-- ==============================================================================
-- SESSION-BASED UCI CHANGE PROCESSOR (THE CORE INTELLIGENCE)
-- ==============================================================================

-- Process clean UCI changes data from session-based tracking
local function process_session_based_changes(changes_list)
    local groups_by_section = {}
    local section_order = {}

    -- Group changes by section for intelligent summarization
    for _, change in ipairs(changes_list) do
        local section_key = utils.safe_get(change, "section", "global", "string")

        if not groups_by_section[section_key] then
            groups_by_section[section_key] = {
                section = change.section,
                config = utils.safe_get(change, "config", "unknown", "string"),
                section_type = utils.safe_get(change, "section_type", nil, "string"),
                changes = {}
            }
            table_insert(section_order, section_key)
        end

        table_insert(groups_by_section[section_key].changes, change)
    end

    -- Generate summaries for each section
    local all_summaries = {}
    local total_changes = 0
    local config_name = "unknown"

    for _, section_key in ipairs(section_order) do
        local section_group = groups_by_section[section_key]
        local changes = utils.safe_get(section_group, "changes", {}, "table")
        local section_config = utils.safe_get(section_group, "config", "unknown", "string")
        local section_id = utils.safe_get(section_group, "section", nil, "string")
        local section_type = utils.safe_get(section_group, "section_type", nil, "string")

        config_name = section_config  -- Update for return value

        -- Resolve section name using intelligence engine with operation data
        local section_name = naming.resolve_section_name(section_config, section_id, section_type, changes)

        -- Process changes for this section
        local section_summaries = {}
        local deletes = {}
        local adds = {}
        local sets = {}
        local removes = {}
        local list_adds = {}

        for _, change in ipairs(changes) do
            local method = utils.safe_get(change, "method", "unknown", "string")
            local field = utils.safe_get(change, "field", nil, "string")
            local value = utils.safe_get(change, "value", nil)
            total_changes = total_changes + 1

            if method == "delete" then
                table_insert(deletes, utils.safe_format("removed %s", section_name))

            elseif method == "remove" then
                if field then
                    local field_name = naming.translate_field_name(field)
                    table_insert(removes, utils.safe_format("removed %s field", field_name))
                else
                    table_insert(removes, utils.safe_format("removed %s", section_name))
                end

            elseif method == "add" then
                if field and value then
                    local field_name = naming.translate_field_name(field)
                    local translated_value = naming.translate_value(section_config, field, value, true)
                    table_insert(adds, utils.safe_format("created %s with %s=%s",
                        section_name, field_name, translated_value))
                else
                    table_insert(adds, utils.safe_format("created %s", section_name))
                end

            elseif method == "list-add" then
                if field and value then
                    local field_name = naming.translate_field_name(field)
                    local translated_value = naming.translate_value(section_config, field, value, true)
                    table_insert(list_adds, utils.safe_format("added %s to %s", translated_value, field_name))
                end

            elseif method == "set" then
                if field and value ~= nil then
                    local field_name = naming.translate_field_name(field)
                    local translated_value = naming.translate_value(section_config, field, value, true)
                    table_insert(sets, utils.safe_format("%s=%s", field_name, translated_value))
                end
            end
        end

        -- Combine operations for this section in logical order
        for _, desc in ipairs(deletes) do table_insert(section_summaries, desc) end
        for _, desc in ipairs(removes) do table_insert(section_summaries, desc) end
        for _, desc in ipairs(adds) do table_insert(section_summaries, desc) end
        for _, desc in ipairs(list_adds) do table_insert(section_summaries, desc) end

        -- Group sets for this section
        if #sets > 0 then
            -- Remove redundant config name from section name for cleaner display
            local display_name = section_name
            if string_find(section_name, section_config .. " ", 1, true) == 1 then
                display_name = string_sub(section_name, #section_config + 2)
            end

            table_insert(section_summaries, utils.safe_format("set %s: %s",
                display_name, table_concat(sets, ", ")))
        end

        -- Add all section summaries to master list
        for _, summary in ipairs(section_summaries) do
            table_insert(all_summaries, summary)
        end
    end

    -- Build final comprehensive message
    local changes_detail = table_concat(all_summaries, "; ")

    -- Deduplicate messages to reduce noise (if enabled)
    if FORMATTER_CONFIG.enable_deduplication then
        local deduped_summaries = deduplication.deduplicate_messages(all_summaries)
        changes_detail = table_concat(deduped_summaries, "; ")
    end

    local summary_prefix = utils.safe_format("applied %s changes", config_name)

    -- Calculate impact level (simplified)
    local impact_level = security.get_config_impact and security.get_config_impact(config_name) or "medium"

    if changes_detail == "" then
        changes_detail = "unknown changes"
    end

    return utils.safe_format("%s | changes: %s | [impact: %s]",
        summary_prefix, changes_detail, impact_level)
end

-- ==============================================================================
-- LEGACY UCI OPERATION PROCESSOR (FALLBACK SUPPORT)
-- ==============================================================================

-- Process legacy-style UCI operations (for backwards compatibility)
local function process_legacy_uci_operations(operations)
    local groups_by_section = {}
    local section_order = {}

    -- Group operations by section
    for _, op in ipairs(operations) do
        local section_key = utils.safe_get(op, "section", "global", "string")

        if not groups_by_section[section_key] then
            groups_by_section[section_key] = {
                section = op.section,
                config = utils.safe_get(op, "config", "unknown", "string"),
                section_type = utils.safe_get(op, "section_type", nil, "string"),
                operations = {}
            }
            table_insert(section_order, section_key)
        end

        table_insert(groups_by_section[section_key].operations, op)
    end

    -- Generate summaries
    local all_summaries = {}
    local operation_count = 0
    local config_name = "unknown"

    for _, section_key in ipairs(section_order) do
        local section_group = groups_by_section[section_key]
        local operations = utils.safe_get(section_group, "operations", {}, "table")
        local config = utils.safe_get(section_group, "config", "unknown", "string")
        local section_id = utils.safe_get(section_group, "section", nil, "string")
        local section_type = utils.safe_get(section_group, "section_type", nil, "string")

        config_name = config

        local section_name = naming.resolve_section_name(config, section_id, section_type, operations)

        -- Process operations for this section
        local deletes = {}
        local adds = {}
        local sets = {}

        for _, op in ipairs(operations) do
            local method = utils.safe_get(op, "method", "unknown", "string")
            local values = utils.safe_get(op, "values", {}, "table")
            operation_count = operation_count + 1

            if method == "delete" then
                table_insert(deletes, utils.safe_format("removed %s", section_name))

            elseif method == "add" then
                local details = {}
                for key, value in pairs(values) do
                    if not string_match(key, "^%.") and key ~= "ubus_rpc_session" and key ~= "type" then
                        local field_name = naming.translate_field_name(key)
                        local translated_value = naming.translate_value(config, key, value, true)
                        table_insert(details, utils.safe_format("%s=%s", field_name, translated_value))
                    end
                end

                if #details > 0 then
                    table_insert(adds, utils.safe_format("created %s with %s",
                        section_name, table_concat(details, ", ")))
                else
                    table_insert(adds, utils.safe_format("created %s", section_name))
                end

            elseif method == "set" then
                local field_changes = {}
                for key, value in pairs(values) do
                    if not string_match(key, "^%.") and key ~= "ubus_rpc_session" then
                        local field_name = naming.translate_field_name(key)
                        local translated_value = naming.translate_value(config, key, value, true)
                        table_insert(field_changes, utils.safe_format("%s=%s", field_name, translated_value))
                    end
                end

                if #field_changes > 0 then
                    table_insert(sets, table_concat(field_changes, ", "))
                end
            end
        end

        -- Combine operations for this section
        for _, desc in ipairs(deletes) do table_insert(all_summaries, desc) end
        for _, desc in ipairs(adds) do table_insert(all_summaries, desc) end

        if #sets > 0 then
            local display_name = section_name
            if string_find(section_name, config .. " ", 1, true) == 1 then
                display_name = string_sub(section_name, #config + 2)
            end
            table_insert(all_summaries, utils.safe_format("set %s: %s",
                display_name, table_concat(sets, ", ")))
        end
    end

    -- Build final message
    local changes_detail = table_concat(all_summaries, "; ")

    -- Deduplicate messages to reduce noise (if enabled)
    if FORMATTER_CONFIG.enable_deduplication then
        local deduped_summaries = deduplication.deduplicate_messages(all_summaries)
        changes_detail = table_concat(deduped_summaries, "; ")
    end

    local summary_prefix = utils.safe_format("applied %s changes", config_name)

    -- Calculate impact level (simplified)
    local impact_level = security.get_config_impact and security.get_config_impact(config_name) or "medium"

    if changes_detail == "" then
        changes_detail = "unknown changes"
    end

    return utils.safe_format("%s | changes: %s | [impact: %s]",
        summary_prefix, changes_detail, impact_level)
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
        -- NEW: Check if we have analyzed changes from before/after module
        local analyzed_changes = utils.safe_get(op, "analyzed_changes", {}, "table")

        if analyzed_changes and #analyzed_changes > 0 then
            -- Use the intelligent analysis from before/after module
            message = process_analyzed_changes(analyzed_changes, config)
        else
            -- Check if this is the new session-based format with clean changes
            local first_entry = values[1]
            if first_entry and first_entry.method and (first_entry.field or first_entry.config) then
                -- NEW FORMAT: Session-based clean changes
                message = process_session_based_changes(values)
            else
                -- LEGACY FORMAT: Fallback to old processing
                message = process_legacy_uci_operations(values)
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
    uci.uci_cache.data = {}
    uci.uci_cache.section_resolutions = {}
end

-- Health check for system monitoring
function M.health()
    local cache_entries = 0
    for _ in pairs(uci.uci_cache.data) do cache_entries = cache_entries + 1 end

    return {
        cache_size = cache_entries,
        last_cleanup = uci.uci_cache.last_cleanup,
        uci_available = uci.execute_uci_command("show system.@system[0]") ~= nil
    }
end

-- Debug information for troubleshooting
function M.debug_info()
    local cache_entries = {}
    for key, entry in pairs(uci.uci_cache.data) do
        table_insert(cache_entries, utils.safe_format("%s (age: %ds)", key, os_time() - entry.timestamp))
    end

    return {
        cached_configs = cache_entries,
        resolution_cache_size = 0, -- Simplified for compatibility
        available_configs = uci.execute_uci_command("show") and "available" or "unavailable"
    }
end

return M
