-- ==============================================================================
-- event_profile.lua - Canonical event metadata for Project Argus
-- ==============================================================================
-- Provides shared helpers for building event keys and classifying ubus
-- operations as "must keep" or "hard noise". The logger and tests both use
-- this module to stay in sync when adjusting noise filters.
-- ==============================================================================

local M = {}

local function normalize(value, fallback)
    if type(value) == "string" and value ~= "" then
        return value
    end
    return fallback
end

function M.event_key(object_name, method)
    return normalize(object_name, "unknown") .. "." .. normalize(method, "unknown")
end

-- Operations that must never be filtered, even if they look noisy.
M.NEEDED_EVENTS = {
    ["luci.setInitAction"] = true,
    ["service.set"] = true,
    ["service.start"] = true,
    ["service.stop"] = true,
    ["service.restart"] = true,
    ["service.instance.start"] = true,
    ["service.instance.stop"] = true,
    ["uci.set"] = true,
    ["uci.add"] = true,
    ["uci.delete"] = true,
    ["uci.commit"] = true,
    ["system.set"] = true,
    ["system.commit"] = true,
    ["network.interface.set"] = true,
    ["network.interface.add"] = true,
    ["network.interface.delete"] = true,
}

-- Explicit noise patterns that can be dropped before triage without risk.
M.HARD_NOISE_EVENTS = {
    ["session.access"] = true,
    ["network.interface.dump"] = true,
}

function M.is_needed_event(object_name, method)
    return M.NEEDED_EVENTS[M.event_key(object_name, method)] == true
end

function M.is_hard_noise(object_name, method)
    return M.HARD_NOISE_EVENTS[M.event_key(object_name, method)] == true
end

return M
