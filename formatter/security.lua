-- ==============================================================================
-- security.lua - Security Impact Assessment and Severity Tagging
-- ==============================================================================

local M = {}

-- Security impact classification matrix
M.security_matrix = {
    CRITICAL = {
        "firewall.zone",          -- Security boundaries
        "system.system",           -- System configuration
        "dropbear.dropbear",       -- SSH access points
        "rpcd.login",              -- Remote API authentication
        "uhttpd.main"              -- Web interface configuration
    },

    HIGH = {
        "firewall.rule",           -- Packet filtering rules
        "firewall.forwarding",     -- Network traffic forwarding
        "network.interface",       -- Network interface configuration
        "network.device",          -- Bridge/VLAN configuration
        "dhcp.dnsmasq"             -- DNS/DHCP server settings
    },

    MEDIUM = {
        "dhcp.odhcpd",             -- DHCPv6 server
        "dhcp.host",               -- Static DHCP leases
        "dhcp.lan",                -- LAN DHCP settings
        "dhcp.wan",                -- WAN DHCP settings
        "system.ntp",              -- Time synchronization
        "ucitrack.firewall",       -- Firewall dependencies
        "ucitrack.network"         -- Network dependencies
    },

    LOW = {
        "luci.main",               -- Web UI core settings
        "luci.themes",             -- Web UI themes
        "luci.apply",              -- Apply settings
        "luci.flash_keep",         -- Configuration backups
        "luci.diag",               -- Diagnostic tools
        "ucitrack.dropbear",       -- SSH dependencies
        "ucitrack.httpd",          -- Web server dependencies
        "ucitrack.system",         -- System dependencies
        "network.globals",         -- Global network settings
        "uhttpd.defaults"          -- Certificate defaults
    },

    INFO = {
        "ucitrack.wireless",       -- Wireless dependencies
        "ucitrack.olsr",           -- OLSR dependencies
        "ucitrack.samba",          -- Samba dependencies
        "ucitrack.tinyproxy",      -- Proxy dependencies
        "luci.languages",          -- Language settings
        "luci.ccache",             -- Client cache settings
        "action:setLocaltime",     -- Time changes
        "action:setInitAction",    -- Service state changes
        "action:read",             -- File reads
        "action:access",           -- System access
        "action:login",            -- User login
        "action:logout"            -- User logout
    }
}

-- Get security level by section type
function M.get_level_by_section_type(config, section_type)
    local lookup_key = section_type and (config .. "." .. section_type) or config

    -- First, try exact match
    for level, patterns in pairs(M.security_matrix) do
        for _, pattern in ipairs(patterns) do
            if pattern == lookup_key then
                return level
            end
        end
    end

    -- Then try wildcard matches
    for level, patterns in pairs(M.security_matrix) do
        for _, pattern in ipairs(patterns) do
            if pattern:sub(-2) == ".*" then
                local base_config = pattern:sub(1, -3)
                if config == base_config then
                    return level
                end
            end
        end
    end

    return "MEDIUM"  -- Safe default
end

-- Get severity for an action
function M.get_action_severity(action, config)
    -- First check for direct action mappings
    local action_key = "action:" .. action
    for level, patterns in pairs(M.security_matrix) do
        for _, pattern in ipairs(patterns) do
            if pattern == action_key then
                return level
            end
        end
    end

    -- Then check config-based mappings
    local config_key = config and config .. ".*" or nil
    if config_key then
        for level, patterns in pairs(M.security_matrix) do
            for _, pattern in ipairs(patterns) do
                if pattern == config_key then
                    return level
                end
            end
        end
    end

    return "INFO"  -- Default to INFO for unknown actions
end

-- Get severity level name
function M.get_severity_name(level)
    local names = {
        CRITICAL = "Critical",
        HIGH = "High",
        MEDIUM = "Medium",
        LOW = "Low",
        INFO = "Informational"
    }
    return names[level] or "Medium"
end

-- Get severity color (for UI integration)
function M.get_severity_color(level)
    local colors = {
        CRITICAL = "#FF0000",     -- Red
        HIGH = "#FF4500",         -- OrangeRed
        MEDIUM = "#FFA500",       -- Orange
        LOW = "#FFFF00",          -- Yellow
        INFO = "#00FF00"          -- Green
    }
    return colors[level] or "#CCCCCC"  -- Default gray
end

-- Calculate impact level for configuration changes (backward compatibility)
function M.get_config_impact(config_name)
    local impact_level = "medium"
    if config_name == "firewall" then
        impact_level = "high"
    elseif config_name == "system" then
        impact_level = "critical"
    end
    return impact_level
end

return M
