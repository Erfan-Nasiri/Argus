-- =============================================================================-
-- before_after.lua - Forensic UCI State Tracking Module for Project Argus
-- =============================================================================-
-- Purpose: Capture before/after states for UCI changes with intelligent analysis
-- Features: Session-based state correlation, intelligent change descriptions,
--          performance-optimized UCI caching, forensic-quality audit trails
-- Author: Standalone module for maximum reliability and portability
-- =============================================================================-

local M = {}

-- Load CFGID resolver for intelligent section naming
local cfgid_resolver = require "formatter.cfgid_resolver"

-- Performance: Localize standard functions
local io_popen = io.popen
local os_time = os.time
local string_format = string.format
local string_match = string.match
local string_gsub = string.gsub
local string_lower = string.lower
local string_find = string.find
local table_insert = table.insert
local table_concat = table.concat
local pairs, ipairs = pairs, ipairs
local type = type
local tostring = tostring
local tonumber = tonumber

-- =============================================================================-
-- MODULE CONFIGURATION AND STATE
-- =============================================================================-

local config = {
    enable_caching = true,
    cache_ttl = 300,  -- 5 minutes
    enable_detailed_logging = false,
    max_cache_entries = 100,  -- Memory limit for embedded systems
    debug_mode = false
}

-- Internal state
local uci_cache = {}
local session_states = {}
local stats = {
    states_captured = 0,
    states_processed = 0,
    fields_captured = 0,
    cache_hits = 0,
    cache_misses = 0,
    active_sessions = 0,
    analysis_failures = 0
}

local debug_callback = nil
local last_cleanup = os_time()

-- =============================================================================-
-- UTILITY FUNCTIONS
-- =============================================================================-

-- Safe debug logging
local function debug_log(message, force)
    if debug_callback and (config.enable_detailed_logging or config.debug_mode or force) then
        debug_callback("[BEFORE_AFTER] " .. message)
    end
end

-- Execute UCI command with error handling
local function execute_uci_command(cmd)
    local full_cmd = "uci " .. cmd .. " 2>/dev/null"
    local handle = io_popen(full_cmd, "r")
    if not handle then
        debug_log("Failed to execute: " .. full_cmd, true)
        return nil
    end

    local output = handle:read("*a")
    local success = handle:close()

    if success and output and output ~= "" then
        local clean_output = string_gsub(output, "\n$", "")  -- Remove trailing newline
        debug_log("UCI command success: " .. cmd .. " -> " .. (clean_output or ""), true)
        return clean_output
    end

    debug_log("UCI command failed or empty: " .. cmd, true)
    return nil
end

-- Cache management with TTL
local function get_from_cache(key)
    local cached = uci_cache[key]
    if not cached then
        stats.cache_misses = stats.cache_misses + 1
        return nil
    end

    if (os_time() - cached.timestamp) >= config.cache_ttl then
        uci_cache[key] = nil
        stats.cache_misses = stats.cache_misses + 1
        debug_log("Cache expired for: " .. key)
        return nil
    end

    stats.cache_hits = stats.cache_hits + 1
    debug_log("Cache hit for: " .. key)
    return cached.value
end

local function set_cache(key, value)
    if not config.enable_caching then return end

    uci_cache[key] = {
        value = value,
        timestamp = os_time()
    }

    -- Periodic cache cleanup
    if (os_time() - last_cleanup) > 300 then  -- Every 5 minutes
        local now = os_time()
        local removed = 0
        for cache_key, entry in pairs(uci_cache) do
            if (now - entry.timestamp) >= config.cache_ttl then
                uci_cache[cache_key] = nil
                removed = removed + 1
            end
        end
        last_cleanup = now
        if removed > 0 then
            debug_log(string_format("Cache cleanup: removed %d expired entries", removed))
        end
    end
end

-- =============================================================================-
-- UCI VALUE RETRIEVAL ENGINE
-- =============================================================================-

-- Get specific UCI value with caching
local function get_uci_value(config_name, section, option)
    local cache_key = config_name .. "." .. section .. (option and ("." .. option) or "")

    -- Check cache first
    local cached_value = get_from_cache(cache_key)
    if cached_value ~= nil then
        return cached_value
    end

    -- Execute UCI command
    local cmd = option and
        string_format("get %s.%s.%s", config_name, section, option) or
        string_format("get %s.%s", config_name, section)

    local value = execute_uci_command(cmd)

    -- Cache the result (including nil for failed lookups)
    set_cache(cache_key, value)

    return value
end

-- Get all options for a section with intelligent parsing
local function get_section_options(config_name, section)
    local cache_key = config_name .. "." .. section .. ".*"

    -- Check cache
    local cached_options = get_from_cache(cache_key)
    if cached_options then
        return cached_options
    end

    -- Execute uci show command
    local cmd = string_format("show %s.%s", config_name, section)
    local output = execute_uci_command(cmd)

    if not output then
        set_cache(cache_key, {})
        return {}
    end

    local options = {}
    for line in string.gmatch(output, "[^\n]+") do
        -- Parse lines like: dhcp.cfg0676c9.mac='00:11:22:33:44:55'
        local option, value = string_match(line, "^[^=]+%.([^=]+)=(.+)$")
        if option and value then
            -- Remove quotes from values
            local clean_value = string_match(value, "^'(.*)'$") or value
            options[option] = clean_value
            debug_log(string_format("Captured option %s.%s.%s = %s", config_name, section, option, clean_value))
        end
    end

    -- Cache the parsed options
    set_cache(cache_key, options)

    return options
end

-- Enhanced UCI data retrieval with fallback strategies
local function get_section_data(config_name, section)
    local options = get_section_options(config_name, section)

    -- Get section type
    local section_type = get_uci_value(config_name, section)

    -- Try to get section name if available
    local section_name = options.name or options.ssid or options.hostname or nil

    return {
        config = config_name,
        section = section,
        type = section_type,
        name = section_name,
        options = options
    }
end

-- =============================================================================-
-- BEFORE-STATE CAPTURE ENGINE
-- =============================================================================-

-- Capture before-state for UCI operation
function M.capture_before_state(operation_data, debug_fn)
    if not config.enable_caching and not M then return {} end

    if not operation_data or type(operation_data) ~= "table" then
        debug_log("Invalid operation_data passed to capture_before_state")
        return {}
    end

    local method = operation_data.method
    local values = operation_data.values

    if not values or type(values) ~= "table" then
        debug_log("Missing or invalid values table in operation_data for before-state capture")
        return {}
    end

    local config_name = values.config
    local section = values.section

    if not config_name or not section then
        debug_log("Missing config or section for before-state capture: " .. (config_name or "nil") .. ", " .. (section or "nil"))
        debug_log("Operation data: " .. (debug_fn and debug_fn or "no debug function"))
        return {}
    end

    local before_state = {}
    stats.states_captured = stats.states_captured + 1

    debug_log(string_format("Capturing before-state: %s %s.%s", method, config_name, section))

    -- Pre-resolve CFGID for intelligent naming BEFORE the operation completes
    if cfgid_resolver and config_name and section then
        local operation_data = {
            method = method,
            values = values
        }

        -- Try to get section data for pre-resolution
        local section_data = get_section_options(config_name, section)
        if next(section_data) then
            -- We have section data, pre-resolve with it
            local resolved_name = cfgid_resolver.pre_resolve_cfgid(config_name, section, nil, operation_data)
            if resolved_name then
                debug_log(string_format("Pre-resolved CFGID: %s.%s -> %s", config_name, section, resolved_name))
            end
        else
            -- No section data available yet, try with operation values
            local resolved_name = cfgid_resolver.pre_resolve_cfgid(config_name, section, nil, operation_data)
            if resolved_name then
                debug_log(string_format("Pre-resolved CFGID (no data): %s.%s -> %s", config_name, section, resolved_name))
            end
        end
    end

    if method == "set" then
        -- Capture current values for fields being changed
        local new_values = values.values or {}
        for field, new_value in pairs(new_values) do
            if field ~= "ubus_rpc_session" and field ~= ".type" then
                local current_value = get_uci_value(config_name, section, field)
                if current_value then
                    before_state[field] = {
                        old_value = current_value,
                        new_value = tostring(new_value),
                        operation = "set"
                    }
                    stats.fields_captured = stats.fields_captured + 1
                    debug_log(string_format("  Field change: %s '%s' -> '%s'",
                        field, current_value, tostring(new_value)))
                else
                    -- Field didn't exist before (new field)
                    before_state[field] = {
                        old_value = nil,
                        new_value = tostring(new_value),
                        operation = "add_field"
                    }
                    stats.fields_captured = stats.fields_captured + 1
                    debug_log(string_format("  New field: %s = '%s'", field, tostring(new_value)))
                end
            end
        end

    elseif method == "delete" then
        -- Capture entire section before deletion
        local all_options = get_section_options(config_name, section)
        if next(all_options) then
            before_state.entire_section = {
                options = all_options,
                operation = "delete_section"
            }
            stats.fields_captured = stats.fields_captured + #all_options
            debug_log(string_format("  Captured entire section with %d options", #all_options))
        else
            -- Even if no options, capture that the section exists
            before_state.entire_section = {
                options = {},
                operation = "delete_section"
            }
            debug_log("  Captured empty section (will be deleted)")
        end

    elseif method == "add" then
        -- For add operations, verify section doesn't already exist
        local section_type = get_uci_value(config_name, section)
        if section_type and section_type ~= "" then
            before_state.section_exists = {
                section_type = section_type,
                operation = "modify_existing"
            }
            debug_log(string_format("  Section already exists with type: %s", section_type))
        else
            before_state.section_exists = {
                section_type = nil,
                operation = "create_new"
            }
            debug_log("  Creating new section")
        end

    elseif method == "remove" then
        -- For remove operations, capture what will be removed
        local option = values.option
        if option then
            -- Removing a specific option
            local current_value = get_uci_value(config_name, section, option)
            if current_value then
                before_state[option] = {
                    old_value = current_value,
                    new_value = nil,
                    operation = "remove_option"
                }
                stats.fields_captured = stats.fields_captured + 1
                debug_log(string_format("  Will remove option: %s.%s.%s = '%s'",
                    config_name, section, option, current_value))
            else
                debug_log(string_format("  Option to remove not found: %s.%s.%s",
                    config_name, section, option))
            end
        else
            -- Removing entire section (options is null)
            local all_options = get_section_options(config_name, section)
            if next(all_options) then
                before_state.entire_section = {
                    options = all_options,
                    operation = "remove_section"
                }
                stats.fields_captured = stats.fields_captured + #all_options
                debug_log(string_format("  Will remove entire section with %d options", #all_options))
            else
                -- Even if no options, capture that the section exists
                before_state.entire_section = {
                    options = {},
                    operation = "remove_section"
                }
                debug_log("  Will remove empty section")
            end
        end
    end

    -- Count items in before_state (including entire_section as 1 item)
    local item_count = 0
    for _ in pairs(before_state) do
        item_count = item_count + 1
    end
    debug_log(string_format("Before-state capture complete: %d items captured", item_count))
    return before_state
end

-- =============================================================================-
-- SESSION STATE MANAGEMENT
-- =============================================================================-

-- Store session state for correlation
function M.store_session_state(session_id, section, before_state)
    if not session_states[session_id] then
        session_states[session_id] = {}
        stats.active_sessions = stats.active_sessions + 1
    end

    session_states[session_id][section] = before_state
    debug_log(string_format("Stored session state: %s -> %s (%d items)",
        session_id, section, #before_state))
end

-- Get session state
function M.get_session_state(session_id, section)
    local session_data = session_states[session_id]
    if not session_data then
        debug_log(string_format("No session data for: %s", session_id))
        return nil
    end

    local state = session_data[section]
    debug_log(string_format("Retrieved session state: %s.%s = %s",
        session_id, section, state and "available" or "none"))
    return state
end

-- Cleanup session state
function M.cleanup_session_state(session_id)
    if session_states[session_id] then
        session_states[session_id] = nil
        stats.active_sessions = math.max(0, stats.active_sessions - 1)
        debug_log(string_format("Cleaned up session: %s", session_id))
    end
end

-- =============================================================================-
-- CHANGE ENRICHMENT ENGINE
-- =============================================================================-

-- Enrich changes with before/after state information
function M.enrich_changes(changes_list)
    if not changes_list or #changes_list == 0 then
        debug_log("No changes to enrich")
        return {}
    end

    debug_log(string_format("Enriching %d changes with before/after state", #changes_list))

    local enriched_changes = {}

    for _, change in ipairs(changes_list) do
        local enriched_change = {
            config = change.config,
            section = change.section,
            method = change.method,
            field = change.field,
            value = change.value,
            section_type = change.section_type,
            values = change.values,
            user = change.user
        }

        -- Add before state if available
        local session_id = change.session_id or change.callback_id
        if session_id then
            local before_state = M.get_session_state(session_id, change.section)
            if before_state then
                enriched_change.before_state = before_state
                debug_log(string_format("  Added before_state for %s.%s", change.config, change.section))
            end
        end

        table_insert(enriched_changes, enriched_change)
    end

    debug_log(string_format("Enrichment complete: %d changes enriched", #enriched_changes))
    return enriched_changes
end

-- =============================================================================-
-- INTELLIGENT CHANGE ANALYSIS ENGINE
-- =============================================================================-

-- Resolve section name using CFGID resolver with fallback
local function resolve_section_name(config, section, session_id, operation_data, before_state)
    if not cfgid_resolver or not config or not section then
        return "section"
    end

    local operation_data_copy = {values = {name = "unknown"}}
    if operation_data then
        operation_data_copy = {values = operation_data.values or {name = "unknown"}}
        operation_data_copy.method = operation_data.method
    end

    -- If we have before_state, use it for better resolution
    if before_state then
        operation_data_copy.values = before_state
        if operation_data then
            operation_data_copy.method = operation_data.method
        end
    end

    local resolved_name = cfgid_resolver.resolve_cfgid(config, section, session_id, operation_data_copy)
    if resolved_name and not string_find(resolved_name, "unknown") and not string_find(resolved_name, "section") then
        return resolved_name
    end

    return "section"
end

-- Analyze set operation changes
local function analyze_set_change(change, before_state)
    local config = change.config
    local section = change.section
    local field = change.field
    local new_value = change.value
    local session_id = change.session_id or change.callback_id

    if not field then
        return {
            change_summary = "set operation without field",
            impact_level = "low",
            confidence = "low"
        }
    end

    local field_display = field:gsub("_", " ")  -- Make field names readable
    local section_name = resolve_section_name(config, section, session_id, change, before_state)

    -- Check if we have before_state for this field
    if before_state and before_state[field] and before_state[field].old_value then
        local old_value = before_state[field].old_value

        if old_value and old_value ~= new_value then
            local analysis = {
                change_summary = string_format("set %s %s from '%s' to '%s'",
                    section_name, field_display, old_value, new_value),
                impact_level = "medium",
                confidence = "high"
            }

            -- Specific field impact analysis
            if field == "enabled" or field == "disabled" then
                analysis.impact_level = "high"
            elseif string_find(field, "password") or string_find(field, "key") or string_find(field, "secret") then
                analysis.impact_level = "high"
            elseif string_find(field, "port") or string_find(field, "proto") then
                analysis.impact_level = "medium"
            end

            return analysis
        else
            return {
                change_summary = string_format("set %s %s to '%s'",
                    section_name, field_display, new_value),
                impact_level = "low",
                confidence = "medium"
            }
        end
    else
        -- No before_state available - create basic description
        return {
            change_summary = string_format("set %s %s to '%s'",
                section_name, field_display, new_value),
            impact_level = "low",
            confidence = "low"
        }
    end
end

-- Analyze delete operation changes
local function analyze_delete_change(change, before_state)
    local config = change.config
    local section = change.section
    local field = change.field
    local value = change.value
    local session_id = change.session_id or change.callback_id

    -- Handle delete operations properly
    if field == "section" and value == "deleted" then
        -- This is a section deletion
        local section_name = resolve_section_name(config, section, session_id, change, before_state)

        -- For delete operations, try to get section data from session state first
        local session_state = nil
        if session_id then
            session_state = M.get_session_state(session_id, section)
        end

        if session_state and session_state.entire_section then
            local num_options = #(session_state.entire_section.options or {})
            return {
                change_summary = string_format("removed %s with %d settings", section_name, num_options),
                impact_level = "high",
                confidence = "high",
                details = {options_count = num_options, source = "session_state"}
            }
        elseif before_state and before_state.entire_section then
            local num_options = #(before_state.entire_section.options or {})
            return {
                change_summary = string_format("removed %s with %d settings", section_name, num_options),
                impact_level = "high",
                confidence = "high",
                details = {options_count = num_options, source = "before_state"}
            }
        else
            -- Try to get current section data as fallback
            local current_options = get_section_options(config, section)
            if next(current_options) then
                local num_options = 0
                for _ in pairs(current_options) do num_options = num_options + 1 end
                return {
                    change_summary = string_format("removed %s with %d settings", section_name, num_options),
                    impact_level = "high",
                    confidence = "high",
                    details = {options_count = num_options, source = "current_data"}
                }
            else
                return {
                    change_summary = string_format("removed %s", section_name),
                    impact_level = "high",
                    confidence = "medium",
                    details = {source = "no_data"}
                }
            end
        end
    else
        -- This is a field deletion
        local field_display = field and field:gsub("_", " ") or "field"
        return {
            change_summary = string_format("removed %s from %s", field_display, section or "section"),
            impact_level = "medium",
            confidence = "medium"
        }
    end
end

-- Analyze add operation changes
local function analyze_add_change(change, before_state)
    local config = change.config
    local section = change.section
    local session_id = change.session_id or change.callback_id

    local section_name = resolve_section_name(config, section, session_id, change, before_state)

    if before_state and before_state.section_exists then
        if before_state.section_exists.operation == "create_new" then
            return {
                change_summary = string_format("created new %s", section_name),
                impact_level = "medium",
                confidence = "high"
            }
        else
            return {
                change_summary = string_format("modified existing %s", section_name),
                impact_level = "low",
                confidence = "medium"
            }
        end
    else
        return {
            change_summary = string_format("created new %s", section_name),
            impact_level = "medium",
            confidence = "low"
        }
    end
end

-- Analyze list-add operation changes
local function analyze_list_add_change(change)
    local field = change.field
    local new_value = change.value

    if field then
        local field_display = field:gsub("_", " ")  -- Make field names readable
        return {
            change_summary = string_format("added '%s' to %s list", new_value or "value", field_display),
            impact_level = "low",
            confidence = "medium"
        }
    else
        return {
            change_summary = string_format("added '%s' to list", new_value or "value"),
            impact_level = "low",
            confidence = "medium"
        }
    end
end

-- Analyze unknown method changes
local function analyze_unknown_change(change)
    local method = change.method or "unknown"
    local config = change.config or "unknown"
    local section = change.section or "unknown"
    local field = change.field or "unknown"

    -- Try to provide some context even for unknown methods
    if field ~= "unknown" then
        return {
            change_summary = string_format("%s %s.%s.%s", method, config, section, field),
            impact_level = "low",
            confidence = "low",
            details = {method = method, reason = "unknown_method"}
        }
    else
        return {
            change_summary = string_format("%s %s.%s", method, config, section),
            impact_level = "low",
            confidence = "low",
            details = {method = method, reason = "unknown_method"}
        }
    end
end

-- Analyze changes and generate intelligent descriptions
function M.analyze_changes(changes_list, debug_fn)
    if not changes_list or #changes_list == 0 then
        return {}
    end

    local analyzed_changes = {}
    stats.states_processed = stats.states_processed + #changes_list

    debug_log(string_format("Analyzing %d changes", #changes_list))

    for _, change in ipairs(changes_list) do
        local analysis = {
            original_change = change,
            change_summary = "unknown change",
            impact_level = "low",
            confidence = "low"
        }

        local method = change.method
        local before_state = change.before_state
        local config = change.config

        -- Use modular analysis functions based on method
        local success, result = pcall(function()
            if method == "set" then
                return analyze_set_change(change, before_state)
            elseif method == "delete" then
                return analyze_delete_change(change, before_state)
            elseif method == "remove" then
                return analyze_delete_change(change, before_state)  -- Use same logic as delete
            elseif method == "add" then
                return analyze_add_change(change, before_state)
            elseif method == "list-add" then
                return analyze_list_add_change(change)
            else
                return analyze_unknown_change(change)
            end
        end)

        if success and result then
            analysis = result
            analysis.original_change = change
        else
            -- Analysis failed, increment failure counter
            stats.analysis_failures = stats.analysis_failures + 1
            debug_log(string_format("Analysis failed for method '%s': %s", method or "nil", result), true)

            -- Fallback to unknown change analysis
            analysis = analyze_unknown_change(change)
            analysis.original_change = change
        end

        -- Config-specific impact adjustment
        if config == "firewall" then
            analysis.impact_level = "high"
        elseif config == "system" or config == "network" then
            analysis.impact_level = "medium"
        end

        table_insert(analyzed_changes, analysis)

        debug_log(string_format("  Analysis: %s [%s impact, %s confidence]",
            analysis.change_summary, analysis.impact_level, analysis.confidence))
    end

    debug_log(string_format("Analysis complete: %d changes processed", #analyzed_changes))
    return analyzed_changes
end

-- =============================================================================-
-- MODULE CONFIGURATION AND INTERFACE
-- =============================================================================-

-- Configure the module
function M.configure(new_config)
    for key, value in pairs(new_config or {}) do
        if config[key] ~= nil then
            config[key] = value
            debug_log(string_format("Config updated: %s = %s", key, tostring(value)))
        end
    end
end

-- Set debug callback
function M.set_debug_callback(callback)
    debug_callback = callback
    debug_log("Debug callback registered")
end

-- Get module statistics
function M.get_stats()
    local cache_total = stats.cache_hits + stats.cache_misses
    local cache_hit_rate = cache_total > 0 and (stats.cache_hits / cache_total * 100) or 0

    return {
        states_captured = stats.states_captured,
        states_processed = stats.states_processed,
        fields_captured = stats.fields_captured,
        cache_hits = stats.cache_hits,
        cache_misses = stats.cache_misses,
        cache_hit_rate = cache_hit_rate,
        active_sessions = stats.active_sessions,
        cache_entries = #uci_cache
    }
end

-- Get current configuration
function M.get_config()
    return config
end

-- Module cleanup
function M.cleanup()
    uci_cache = {}
    session_states = {}
    stats = {
        states_captured = 0,
        states_processed = 0,
        fields_captured = 0,
        cache_hits = 0,
        cache_misses = 0,
        active_sessions = 0,
        analysis_failures = 0
    }
    debug_log("Module cleanup complete")
end

-- Health check
function M.health_check()
    -- Test UCI availability
    local test_result = execute_uci_command("show system 2>/dev/null | head -1")
    local uci_available = test_result ~= nil

    -- Get current stats
    local current_stats = M.get_stats()

    return {
        uci_available = uci_available,
        module_initialized = debug_callback ~= nil,
        cache_functional = config.enable_caching,
        cache_entries = current_stats.cache_entries,
        active_sessions = current_stats.active_sessions,
        total_processed = current_stats.states_processed,
        analysis_failures = current_stats.analysis_failures
    }
end

-- =============================================================================-
-- MODULE RETURN
-- =============================================================================-

return M
