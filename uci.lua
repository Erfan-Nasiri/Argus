-- ==============================================================================
-- uci.lua - UCI Command-Line Interface (No LuCI Dependencies)
-- ==============================================================================

local M = {}

-- Load utilities
local utils = require "formatter.utils"

-- Performance: Pre-localize functions
local string_match, string_gsub, os_time, io_popen = string.match, string.gsub, os.time, io.popen

-- UCI configuration cache with TTL
M.uci_cache = {
    data = {},              -- Raw UCI show outputs
    section_resolutions = {},  -- Resolved section names
    last_cleanup = os_time(),
    ttl = 300,              -- 5 minutes
    max_entries = 50        -- Memory limit for embedded systems
}

-- Execute UCI command safely with comprehensive error handling
function M.execute_uci_command(command)
    local full_command = "uci " .. command .. " 2>/dev/null"
    local handle = io_popen(full_command, "r")
    if not handle then return nil end

    local output = handle:read("*a")
    local success = handle:close()

    if success and output and output ~= "" then
        return string_gsub(output, "\n$", "")  -- Remove trailing newline
    end
    return nil
end

-- Get UCI configuration data with caching
function M.get_uci_config_data(config)
    local cache_key = "config:" .. config
    local cached = M.uci_cache.data[cache_key]

    -- Check cache with timestamp validation
    if cached and (os_time() - cached.timestamp) < M.uci_cache.ttl then
        return cached.data
    end

    -- Execute uci show command
    local uci_output = M.execute_uci_command("show " .. config)
    if not uci_output then return nil end

    -- Parse UCI output into structured data
    local config_data = {}
    for line in string.gmatch(uci_output, "[^\n]+") do
        -- Parse lines like: dhcp.cfg0676c9=host
        -- or: dhcp.cfg0676c9.mac='00:11:22:33:44:55'
        local section_match = string_match(line, "^([^%.]+)%.([^%.=]+)=(.+)$")
        if section_match then
            local conf, section_id, section_type = string_match(line, "^([^%.]+)%.([^%.=]+)=(.+)$")
            if conf == config then
                if not config_data[section_id] then
                    config_data[section_id] = { [".type"] = section_type }
                end
            end
        else
            -- Parse option lines: dhcp.cfg0676c9.mac='00:11:22:33:44:55'
            local option_match = string_match(line, "^([^%.]+)%.([^%.]+)%.([^=]+)=(.+)$")
            if option_match then
                local conf, section_id, option, value = string_match(line, "^([^%.]+)%.([^%.]+)%.([^=]+)=(.+)$")
                if conf == config then
                    if not config_data[section_id] then
                        config_data[section_id] = {}
                    end
                    -- Remove quotes from values
                    local clean_value = string_match(value, "^'(.*)'$") or value
                    config_data[section_id][option] = clean_value
                end
            end
        end
    end

    -- Cache the result
    M.uci_cache.data[cache_key] = {
        data = config_data,
        timestamp = os_time()
    }

    return config_data
end

-- Get specific section data
function M.get_section_data(config, section_id)
    local config_data = M.get_uci_config_data(config)
    return config_data and config_data[section_id] or nil
end

return M
