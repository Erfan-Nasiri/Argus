-- ==============================================================================
-- uci.lua - Unified interface proxying engine-modules.uci_interface
-- ==============================================================================

local M = {}

local uci_interface = require "engine-modules.uci_interface"

local function copy_section(data)
    if type(data) ~= "table" then
        return nil
    end
    local result = {}
    for k, v in pairs(data) do
        result[k] = v
    end
    return result
end

function M.get_uci_config_data(config)
    if not config or config == "" then
        return nil
    end
    local dump, err = uci_interface.dump(config)
    if not dump then
        return nil, err
    end
    local sanitized = {}
    for section_id, section_data in pairs(dump) do
        sanitized[section_id] = copy_section(section_data) or {}
    end
    return sanitized
end

function M.get_section_data(config, section_id)
    if not config or not section_id then
        return nil
    end
    local data, err = uci_interface.get_all(config, section_id)
    if not data then
        return nil, err
    end
    return copy_section(data) or {}
end

function M.cleanup()
    if uci_interface.reset_metrics then
        uci_interface.reset_metrics()
    end
end

function M.health()
    local stats = uci_interface.get_stats and uci_interface.get_stats() or {}
    return {
        backend = stats.backend,
        backend_error = stats.backend_error,
        enable_native_uci = stats.enable_native_uci,
        calls_total = stats.calls_total or 0,
        available = uci_interface.is_available(),
    }
end

function M.debug_info()
    local stats = uci_interface.get_stats and uci_interface.get_stats() or {}
    return {
        backend = stats.backend,
        calls_shell = stats.calls_shell or 0,
        calls_native = stats.calls_native or 0,
        cache_hits = stats.cache_hits or 0,
        cache_misses = stats.cache_misses or 0,
    }
end

return M
