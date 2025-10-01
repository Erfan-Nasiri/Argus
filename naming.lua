-- ==============================================================================
-- naming.lua - Intelligent Section Resolution and Value Translation Engine
-- ==============================================================================
local M = {}

-- Load dependencies
local utils = require "formatter.utils"
local uci = require "formatter.uci"
-- Integrate the finalized CFGID resolver (pre-resolution cache, enhanced fallback)
local cfgid_resolver = require "formatter.cfgid_resolver"

-- Toggle: allow disabling the external CFGID resolver from naming
M.use_cfgid_resolver = true

function M.set_use_cfgid_resolver(enable)
    M.use_cfgid_resolver = not (enable == false)
end

-- Performance: Pre-localize functions
local string_find, string_sub, table_insert, pairs, ipairs, pcall, os_time =
      string.find, string.sub, table.insert, pairs, ipairs, pcall, os.time

-- Pattern-based intelligent section naming (most specific first)
M.intelligent_naming_rules = {
    -- Firewall intelligence
    firewall = {
        zone = {
            patterns = {
                {match = "name", format = "firewall zone '%s'"},
                {check = function(v) return v.network end, format = "firewall zone for network '%s'", field = "network"},
            },
            fallback = "firewall zone"
        },
        rule = {
            patterns = {
                {match = "name", format = "firewall rule '%s'"},
                {check = function(v) return v.src and v.dest end,
                 format = "firewall rule %s→%s", fields = {"src", "dest"}},
                {check = function(v) return v.dest_port and v.target == "ACCEPT" end,
                 format = "firewall rule allowing port %s", field = "dest_port"},
                {check = function(v) return v.dest_port and (v.target == "DROP" or v.target == "REJECT") end,
                 format = "firewall rule blocking port %s", field = "dest_port"},
            },
            fallback = "firewall rule"
        },
    },

    -- Network intelligence
    network = {
        interface = {
            patterns = {
                {match = "name", format = "network interface '%s'"},
                {match = ".name", format = "network interface '%s'"},
                {check = function(v) return v.proto == "static" and v.ipaddr end,
                 format = "static interface %s", field = "ipaddr"},
                {check = function(v) return v.proto == "dhcp" end, format = "DHCP interface"},
            },
            fallback = "network interface"
        },
        device = {
            patterns = {
                {match = "name", format = "network device '%s'"},
                {check = function(v) return v.type == "bridge" end, format = "bridge device"},
            },
            fallback = "network device"
        }
    },

    -- Wireless intelligence
    wireless = {
        ["wifi-device"] = {
            patterns = {
                {match = ".name", format = "WiFi radio '%s'"},
                {check = function(v) return v.channel end, format = "WiFi radio on channel %s", field = "channel"},
            },
            fallback = "WiFi radio"
        },
        ["wifi-iface"] = {
            patterns = {
                {match = "ssid", format = "WiFi network '%s'"},
                {check = function(v) return v.mode == "ap" and v.ssid end, format = "WiFi AP '%s'", field = "ssid"},
            },
            fallback = "WiFi interface"
        }
    },

    -- DHCP intelligence
    dhcp = {
        dnsmasq = {patterns = {}, fallback = "DHCP/DNS configuration"},
        host = {
            patterns = {
                {check = function(v) return v.name and v.mac end,
                 format = "DHCP reservation '%s' (%s)", fields = {"name", "mac"}},
                {match = "name", format = "DHCP reservation '%s'"},
                {match = "mac", format = "DHCP reservation for %s"},
            },
            fallback = "DHCP reservation"
        },
    },
}

-- Intelligent value translation system
M.value_intelligence = {
    -- Universal translations (context-free)
    universal = {
        ["1"] = "enabled", ["0"] = "disabled",
        ["true"] = "enabled", ["false"] = "disabled",
        ["on"] = "enabled", ["off"] = "disabled",
        ["yes"] = "enabled", ["no"] = "disabled"
    },

    -- Context-aware translations (config.field specific)
    contextual = {
        firewall = {
            target = {ACCEPT = "allow", DROP = "deny", REJECT = "reject", DENY = "deny", ALLOW = "allow"},
            family = {ipv4 = "IPv4", ipv6 = "IPv6", any = "IPv4/IPv6"},
            proto = {tcp = "TCP", udp = "UDP", icmp = "ICMP", all = "any protocol"}
        },
        network = {
            proto = {static = "static IP", dhcp = "DHCP", pppoe = "PPPoE", none = "disabled"},
            type = {bridge = "bridge", macvlan = "VLAN"}
        },
        wireless = {
            encryption = {none = "open", wep = "WEP", psk = "WPA-PSK", psk2 = "WPA2-PSK", sae = "WPA3"},
            mode = {ap = "Access Point", sta = "Client", adhoc = "Ad-Hoc", monitor = "Monitor"}
        },
        dhcp = {
            ignore = {["1"] = "disabled", ["0"] = "enabled"}
        }
    }
}

-- Field name beautification
M.field_names = {
    dest_port = "destination port", src_port = "source port", src_dport = "source port",
    dest_ip = "destination IP", src_ip = "source IP", proto = "protocol",
    iface = "interface", ["in"] = "interface", readethers = "read /etc/ethers", ssid = "network name", ipaddr = "IP address",
    netmask = "subnet mask", gateway = "gateway", dns = "DNS server",
    mac = "MAC address", hostname = "hostname", cname = "name"
}

-- Apply intelligent naming rules to resolve section descriptions
function M.apply_naming_intelligence(config, section_type, values)
    local config_rules = M.intelligent_naming_rules[config]
    if not config_rules then return nil end

    local type_rules = config_rules[section_type]
    if not type_rules or not type_rules.patterns then
        return type_rules and type_rules.fallback
    end

    -- Apply patterns in order (most specific first)
    for _, pattern in ipairs(type_rules.patterns) do
        if pattern.match then
            -- Simple field match
            local field_value = utils.safe_get(values, pattern.match, nil, "string")
            if field_value then
                return utils.safe_format(pattern.format, field_value)
            end
        elseif pattern.check then
            -- Complex condition check
            local check_ok, check_result = pcall(pattern.check, values)
            if check_ok and check_result then
                if pattern.fields then
                    -- Multiple field format
                    local field_values = {}
                    for _, field in ipairs(pattern.fields) do
                        table_insert(field_values, utils.safe_get(values, field, "unknown", "string"))
                    end
                    return utils.safe_format(pattern.format, unpack(field_values))
                elseif pattern.field then
                    -- Single field format
                    local field_value = utils.safe_get(values, pattern.field, "unknown", "string")
                    return utils.safe_format(pattern.format, field_value)
                else
                    -- Static format
                    return pattern.format
                end
            end
        end
    end

    return type_rules.fallback
end

-- Master section resolution with caching
function M.resolve_section_name(config, section_id, section_type, operation_data)
    -- Use the production-ready CFGID resolver as primary integration point.
    if not config or not section_id then return "unknown section" end

    -- Try resolver (it handles pre-resolution cache, UCI lookups, and enhanced fallback)
    if M.use_cfgid_resolver then
        -- Extract values from operation data for CFGID resolver
        local values = {}
        if operation_data and type(operation_data) == "table" then
            for _, change in ipairs(operation_data) do
                if change.values then
                    for k, v in pairs(change.values) do
                        values[k] = v
                    end
                end
            end
        end

        local ok, name = pcall(cfgid_resolver.resolve_cfgid, config, section_id, nil, { type = section_type, values = values })
        if ok and name and not string_find(name, "unknown") then
            return name
        end
    end

    -- Fallback to existing naming logic (preserve original behavior)
    local cache_key = config .. ":" .. section_id
    local cached = uci.uci_cache.section_resolutions[cache_key]

    if cached and (os_time() - cached.timestamp) < uci.uci_cache.ttl then
        return cached.name
    end

    local resolved_name = nil
    local section_data = uci.get_section_data(config, section_id)
    if section_data then
        local actual_type = section_data[".type"] or section_type
        resolved_name = M.apply_naming_intelligence(config, actual_type, section_data)
    end

    if not resolved_name then
        if section_type then
            resolved_name = utils.safe_format("%s %s [%s]", config, section_type, section_id)
        else
            resolved_name = utils.safe_format("%s section [%s]", config, section_id)
        end
    end

    uci.uci_cache.section_resolutions[cache_key] = {
        name = resolved_name,
        timestamp = os_time()
    }

    return resolved_name
end

-- Translate field names to human-readable format
function M.translate_field_name(field_name)
    return M.field_names[field_name] or field_name
end

-- Intelligent value translation with context awareness
function M.translate_value(config, field, value, add_quotes)
    if value == nil then return "unset" end

    local value_str = utils.safe_string(value)
    local result = nil

    -- Context-aware translation first
    local config_trans = utils.safe_get(M.value_intelligence.contextual, config, {}, "table")
    local field_trans = utils.safe_get(config_trans, field, {}, "table")
    result = field_trans[value_str]

    -- Universal translation fallback
    if not result then
        result = M.value_intelligence.universal[value_str]
    end

    -- Default handling
    if not result then
        result = value_str
        add_quotes = true
    end

    -- Apply quotes if requested
    return add_quotes and utils.safe_format("'%s'", result) or result
end

return M
