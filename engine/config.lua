-- ==============================================================================
-- engine/config.lua - Minimal Configuration for Project Argus
-- ==============================================================================
-- Goals:
--   - Simple, readable configuration
--   - Backwards-compatible with logger-engine.lua
--   - No deep merging, no mode profiles, no hot reload
-- ==============================================================================

local M = {}

-- --------------------------------------------------------------------------
-- CORE CONFIG (single source of truth)
-- --------------------------------------------------------------------------

local config = {
    metadata = {
        version = "2.0.0",
        schema  = "argus.minimal.v2",
    },

    -- Log paths
    paths = {
        base       = "/tmp/log/Audits",
        human      = "/tmp/log/Audits/format.log",
        key_value  = "/tmp/log/Audits/audit.log",
        json       = "/tmp/log/Audits/audit.json",
        auth       = "/tmp/log/Audits/audit_auth.log",
        security   = "/tmp/log/Audits/audit_security.log",
        debug      = "/tmp/log/Audits/debug.log",
        file_reads = "/tmp/log/Audits/filereads.txt",
    },

    -- Feature flags (high-level)
    features = {
        audit_logging          = true,
        human_readable         = true,
        key_value_pairs        = true,
        json_output            = false,
        authentication_log     = true,
        security_alerts        = true,
        before_after_tracking  = true,
        intelligent_descriptions = true,
        file_read_filtering    = true,

        -- For logger-engine mode logic
        operation_mode         = "balanced",
        enable_native_uci      = true,
    },

    -- Performance / batching
    performance = {
        flush_interval = 3,          -- seconds
        batch_size     = 30,         -- entries
        max_file_size  = 1024 * 1024 -- 1 MiB
    },

    -- Security-related settings
    security = {
        file_read_whitelist = {
            "/etc/sysupgrade.conf",
            "/proc/mounts",
            "/tmp/sysupgrade.tgz",
            "/etc/config/",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/dropbear/",
            "/etc/firewall",
            "/var/run/hostapd",
            "/etc/board.json",

            -- your noisy file-read paths can live here too if you want them dropped
            -- e.g. "/tmp/devinfo/", "/tmp/SIM/", "/tmp/lm75/"
        },

        exec_command_blacklist = {
            "/usr/sbin/ipsec status",
            "/etc/init.d/ipsec-manager restart",
        },

        redact_sensitive_values = true,
        blocked_user            = nil, -- optional: can be set via env
    },

    -- Debug flags (fine-grained)
    debug = {
        enabled            = true,
        console            = true,
        operation_flow     = true,
        session_management = true,
        uci_changes        = true,
        callback_tracking  = true,
        before_after       = true,
    },

    -- Optional: simple filters table (for logger-engine)
    filters = {
        mode_drop_events = {},  -- used by MODE_DROP_EVENTS in logger-engine
        ubus_message_types = nil,
        noise_hints = nil,
    },

    -- Simple module registry (rarely used, but cheap to keep)
    modules = {},

    -- Runtime state (minimal, but keeps shape that engine expects)
    _runtime = {
        hot_reload_count  = 0,
        mode_profile_name = "balanced",
    },
}

-- --------------------------------------------------------------------------
-- ENVIRONMENT OVERRIDES
-- --------------------------------------------------------------------------

local function apply_environment_overrides()
    -- Log directory override
    local log_dir = os.getenv("ARGUS_LOG_DIR")
    if log_dir and log_dir ~= "" then
        local p = config.paths
        p.base       = log_dir
        p.human      = log_dir .. "/format.log"
        p.key_value  = log_dir .. "/audit.log"
        p.json       = log_dir .. "/audit.json"
        p.auth       = log_dir .. "/audit_auth.log"
        p.security   = log_dir .. "/audit_security.log"
        p.debug      = log_dir .. "/debug.log"
        p.file_reads = log_dir .. "/filereads.txt"
    end

    -- Debug enable
    if os.getenv("ARGUS_DEBUG") == "1" then
        config.debug.enabled = true
        config.debug.console = true
    end

    -- Disable JSON output
    if os.getenv("ARGUS_DISABLE_JSON") == "1" then
        config.features.json_output = false
    end

    -- Disable security alerts
    if os.getenv("ARGUS_DISABLE_SECURITY_LOG") == "1" then
        config.features.security_alerts = false
    end

    -- Performance tuning
    local flush = tonumber(os.getenv("ARGUS_FLUSH_INTERVAL"))
    if flush and flush >= 1 then
        config.performance.flush_interval = flush
    end

    local batch = tonumber(os.getenv("ARGUS_BATCH_SIZE"))
    if batch and batch >= 1 then
        config.performance.batch_size = batch
    end

    -- Optional blocked user
    local blocked = os.getenv("ARGUS_BLOCK_USER")
    if blocked and blocked ~= "" then
        config.security.blocked_user = blocked
    end
end

-- --------------------------------------------------------------------------
-- BACKWARD COMPATIBILITY VIEW
--  (Keep the shapes logger-engine.lua expects: cfg.controls, cfg.settings, etc.)
-- --------------------------------------------------------------------------

local function create_compatibility_views()
    -- Legacy paths shape: cfg.paths.logs.*
    config.paths.base_directory = config.paths.base
    config.paths.logs = {
        human      = config.paths.human,
        key_value  = config.paths.key_value,
        json       = config.paths.json,
        auth       = config.paths.auth,
        security   = config.paths.security,
        debug      = config.paths.debug,
        file_reads = config.paths.file_reads,
    }

    -- Controls / logging flags (logger-engine uses cfg.controls or cfg.logging)
    local logging = {
        enable_audit_logging         = config.features.audit_logging,
        enable_human_readable        = config.features.human_readable,
        enable_key_value_pairs       = config.features.key_value_pairs,
        enable_json_output           = config.features.json_output,
        enable_authentication_log    = config.features.authentication_log,
        enable_security_alerts       = config.features.security_alerts,

        enable_debug_logging         = config.debug.enabled,
        show_debug_on_console        = config.debug.console,
        debug_operation_flow         = config.debug.operation_flow,
        debug_session_management     = config.debug.session_management,
        debug_uci_changes            = config.debug.uci_changes,
        debug_callback_tracking      = config.debug.callback_tracking,
        debug_before_after_operations= config.debug.before_after,

        enable_before_after_tracking = config.features.before_after_tracking,
        enable_intelligent_descriptions = config.features.intelligent_descriptions,

        -- file read filter wires directly to engine helpers
        file_read_filter_enabled     = config.features.file_read_filtering,

        -- batching + rotation
        auto_flush_interval_seconds  = config.performance.flush_interval,
        batch_size_for_immediate_flush = config.performance.batch_size,
    }

    config.logging = logging
    config.controls = logging

    -- Legacy settings table (logger-engine reads cfg.settings.max_file_size)
    config.settings = {
        max_file_size = config.performance.max_file_size,
    }

    -- Legacy outputs.rotation.max_file_size
    config.outputs = {
        rotation = {
            max_file_size = config.performance.max_file_size,
        },
    }
end

-- --------------------------------------------------------------------------
-- INTERNAL INIT GUARD
-- --------------------------------------------------------------------------

local initialized = false

local function init_once()
    if initialized then return end
    apply_environment_overrides()
    create_compatibility_views()
    initialized = true
end

-- --------------------------------------------------------------------------
-- PUBLIC API
-- --------------------------------------------------------------------------

function M.load(overrides)
    -- overrides currently unused on purpose, kept for API compatibility
    init_once()
    return config
end

-- Called early in logger-engine.lua
function M.setup_paths()
    init_once()
    M.ensure_paths(config)
end

function M.ensure_paths(cfg)
    cfg = cfg or config
    if cfg.paths and cfg.paths.base then
        os.execute("mkdir -p " .. cfg.paths.base .. " 2>/dev/null")
    end
end

-- Feature check shortcut
function M.is_enabled(cfg, feature_name)
    cfg = cfg or config
    return cfg.features and cfg.features[feature_name]
end

-- Debug flag helper
function M.should_debug(cfg, flag)
    cfg = cfg or config
    if not (cfg.debug and cfg.debug.enabled) then
        return false
    end
    if not flag then
        return cfg.debug.console
    end
    return cfg.debug[flag] ~= false
end

-- Path helper (used occasionally)
function M.get_path(cfg, key)
    cfg = cfg or config
    if not cfg.paths then return nil end
    if key == "base" then
        return cfg.paths.base
    end
    return cfg.paths[key]
end

-- Simple module registry (if you ever need it)
function M.register_module(cfg, name, module_ref)
    cfg = cfg or config
    if not cfg.modules then
        cfg.modules = {}
    end
    cfg.modules[name] = module_ref
    return true
end

function M.get_module(cfg, name)
    cfg = cfg or config
    return cfg.modules and cfg.modules[name]
end

-- Human-readable summary
function M.summary(cfg)
    cfg = cfg or config
    return string.format([[
Project Argus Configuration Summary:
  Schema: %s (version %s)
  Base Path: %s
  Logging: audit=%s human=%s kv=%s json=%s
  Debug: %s (console=%s)
  Before/After: %s
  Batching: size=%d interval=%ds
]],
        cfg.metadata.schema,
        cfg.metadata.version,
        cfg.paths.base,
        cfg.features.audit_logging and "ON" or "OFF",
        cfg.features.human_readable and "ON" or "OFF",
        cfg.features.key_value_pairs and "ON" or "OFF",
        cfg.features.json_output and "ON" or "OFF",
        cfg.debug.enabled and "ON" or "OFF",
        cfg.debug.console and "ON" or "OFF",
        cfg.features.before_after_tracking and "ON" or "OFF",
        cfg.performance.batch_size,
        cfg.performance.flush_interval
    )
end

-- Very small validation helper
function M.validate(cfg)
    cfg = cfg or config
    local errors = {}

    if not cfg.paths or not cfg.paths.base or cfg.paths.base == "" then
        table.insert(errors, "Missing paths.base")
    end

    if cfg.performance.flush_interval and cfg.performance.flush_interval < 1 then
        table.insert(errors, "performance.flush_interval must be >= 1")
    end

    if cfg.performance.batch_size and cfg.performance.batch_size < 1 then
        table.insert(errors, "performance.batch_size must be >= 1")
    end

    return (#errors == 0), errors
end

return M
