-- ==============================================================================
-- session_cleanup.lua - Standalone Session Management Module for Project Argus
-- ==============================================================================
-- Purpose: Manages memory-bounded session cleanup for UCI operation staging
-- Features: Time-based cleanup, memory limits, statistics tracking
-- Author: Project Argus Session Management
-- Lua 5.1 compliant, no external dependencies
-- ==============================================================================

local M = {}

-- Performance: Pre-localize standard library functions
local os_time = os.time
local pairs, ipairs = pairs, ipairs
local table_insert = table.insert
local string_format = string.format

-- ==============================================================================
-- CONFIGURATION
-- ==============================================================================

local DEFAULT_CONFIG = {
    max_session_age = 1800,      -- 30 minutes in seconds
    max_total_sessions = 50,     -- Maximum sessions to keep in memory
    cleanup_interval = 300,      -- Run cleanup every 5 minutes
    max_operations_per_session = 100,  -- Operations per session limit
    enable_statistics = true,    -- Track cleanup statistics
    debug_cleanup = false        -- Debug cleanup operations
}

-- ==============================================================================
-- MODULE STATE
-- ==============================================================================

local config = {}
local statistics = {
    total_cleanups = 0,
    sessions_cleaned = 0,
    operations_cleaned = 0,
    last_cleanup = 0,
    memory_pressure_cleanups = 0,
    age_based_cleanups = 0
}

local debug_callback = nil

-- ==============================================================================
-- UTILITY FUNCTIONS
-- ==============================================================================

-- Safe debug logging
local function debug_log(message, category)
    if config.debug_cleanup and debug_callback then
        debug_callback(string_format("[CLEANUP:%s] %s", category or "GENERAL", message))
    end
end

-- Calculate session age
local function get_session_age(session_data, current_time)
    local created_time = session_data.created_time or current_time
    return current_time - created_time
end

-- Count total operations across all sessions
local function count_total_operations(sessions_table)
    local total = 0
    for _, session_data in pairs(sessions_table) do
        total = total + (session_data.saves and #session_data.saves or 0)
    end
    return total
end

-- Get session with most operations (for LRU cleanup)
local function find_largest_session(sessions_table)
    local largest_session_id = nil
    local max_operations = 0
    
    for session_id, session_data in pairs(sessions_table) do
        local operation_count = session_data.saves and #session_data.saves or 0
        if operation_count > max_operations then
            max_operations = operation_count
            largest_session_id = session_id
        end
    end
    
    return largest_session_id, max_operations
end

-- Get oldest session
local function find_oldest_session(sessions_table, current_time)
    local oldest_session_id = nil
    local max_age = 0
    
    for session_id, session_data in pairs(sessions_table) do
        local age = get_session_age(session_data, current_time)
        if age > max_age then
            max_age = age
            oldest_session_id = session_id
        end
    end
    
    return oldest_session_id, max_age
end

-- ==============================================================================
-- CLEANUP ALGORITHMS
-- ==============================================================================

-- Age-based cleanup: Remove sessions older than max_session_age
local function cleanup_aged_sessions(sessions_table, current_time)
    local sessions_to_remove = {}
    local operations_to_clean = 0
    
    -- Find aged sessions
    for session_id, session_data in pairs(sessions_table) do
        local session_age = get_session_age(session_data, current_time)
        
        if session_age > config.max_session_age then
            table_insert(sessions_to_remove, {
                id = session_id,
                age = session_age,
                operations = session_data.saves and #session_data.saves or 0,
                user = session_data.user or "unknown"
            })
            operations_to_clean = operations_to_clean + (session_data.saves and #session_data.saves or 0)
        end
    end
    
    -- Remove aged sessions
    for _, session_info in ipairs(sessions_to_remove) do
        sessions_table[session_info.id] = nil
        debug_log(string_format("Cleaned aged session %s (user: %s, age: %ds, ops: %d)", 
            session_info.id, session_info.user, session_info.age, session_info.operations), "AGE")
    end
    
    -- Update statistics
    if config.enable_statistics then
        statistics.age_based_cleanups = statistics.age_based_cleanups + #sessions_to_remove
        statistics.sessions_cleaned = statistics.sessions_cleaned + #sessions_to_remove
        statistics.operations_cleaned = statistics.operations_cleaned + operations_to_clean
    end
    
    return #sessions_to_remove, operations_to_clean
end

-- Memory pressure cleanup: Remove sessions when limit exceeded
local function cleanup_memory_pressure(sessions_table, current_time)
    local sessions_count = 0
    for _ in pairs(sessions_table) do sessions_count = sessions_count + 1 end
    
    if sessions_count <= config.max_total_sessions then
        return 0, 0  -- No cleanup needed
    end
    
    local sessions_to_remove = sessions_count - config.max_total_sessions
    local sessions_removed = 0
    local operations_cleaned = 0
    
    debug_log(string_format("Memory pressure: %d sessions, limit %d, removing %d", 
        sessions_count, config.max_total_sessions, sessions_to_remove), "MEMORY")
    
    -- Remove oldest sessions first
    while sessions_removed < sessions_to_remove do
        local oldest_id, oldest_age = find_oldest_session(sessions_table, current_time)
        
        if not oldest_id then break end  -- No more sessions
        
        local session_data = sessions_table[oldest_id]
        local operation_count = session_data.saves and #session_data.saves or 0
        
        sessions_table[oldest_id] = nil
        sessions_removed = sessions_removed + 1
        operations_cleaned = operations_cleaned + operation_count
        
        debug_log(string_format("Memory cleanup: removed session %s (age: %ds, ops: %d)", 
            oldest_id, oldest_age, operation_count), "MEMORY")
    end
    
    -- Update statistics
    if config.enable_statistics then
        statistics.memory_pressure_cleanups = statistics.memory_pressure_cleanups + sessions_removed
        statistics.sessions_cleaned = statistics.sessions_cleaned + sessions_removed
        statistics.operations_cleaned = statistics.operations_cleaned + operations_cleaned
    end
    
    return sessions_removed, operations_cleaned
end

-- ==============================================================================
-- PUBLIC API
-- ==============================================================================

-- Initialize the module with configuration
function M.initialize(user_config, debug_fn)
    -- Merge user config with defaults
    config = {}
    for key, value in pairs(DEFAULT_CONFIG) do
        config[key] = user_config and user_config[key] or value
    end
    
    -- Set debug callback
    debug_callback = debug_fn
    
    -- Initialize statistics
    statistics.last_cleanup = os_time()
    
    debug_log("Session cleanup module initialized", "INIT")
    debug_log(string_format("Config: max_age=%ds, max_sessions=%d, cleanup_interval=%ds", 
        config.max_session_age, config.max_total_sessions, config.cleanup_interval), "INIT")
    
    return true
end

-- Main cleanup function - call this periodically
function M.cleanup_sessions(sessions_table, force_cleanup)
    -- Validate input parameter (was a typo: session_table -> sessions_table)
    if not sessions_table or type(sessions_table) ~= "table" then 
        debug_log("Invalid sessions_table passed to cleanup_sessions", "ERROR")
        return false , "Invalid input"
    end 
    
    local current_time = os_time()
    local time_since_last = current_time - statistics.last_cleanup
    
    -- Check if cleanup is needed
    if not force_cleanup and time_since_last < config.cleanup_interval then
        return false, "cleanup_not_due"
    end
    
    debug_log("Starting session cleanup cycle", "CYCLE")
    
    local total_sessions_before = 0
    for _ in pairs(sessions_table) do total_sessions_before = total_sessions_before + 1 end
    
    local total_operations_before = count_total_operations(sessions_table)
    
    -- Perform age-based cleanup first
    local aged_sessions_removed, aged_operations_cleaned = cleanup_aged_sessions(sessions_table, current_time)
    
    -- Perform memory pressure cleanup if needed
    local memory_sessions_removed, memory_operations_cleaned = cleanup_memory_pressure(sessions_table, current_time)
    
    -- Calculate totals
    local total_sessions_removed = aged_sessions_removed + memory_sessions_removed
    local total_operations_cleaned = aged_operations_cleaned + memory_operations_cleaned
    
    local total_sessions_after = 0
    for _ in pairs(sessions_table) do total_sessions_after = total_sessions_after + 1 end
    
    -- Update statistics
    if config.enable_statistics then
        statistics.total_cleanups = statistics.total_cleanups + 1
        statistics.last_cleanup = current_time
    end
    
    -- Log cleanup results
    if total_sessions_removed > 0 then
        debug_log(string_format("Cleanup complete: removed %d sessions (%d aged, %d memory), freed %d operations", 
            total_sessions_removed, aged_sessions_removed, memory_sessions_removed, total_operations_cleaned), "RESULT")
        debug_log(string_format("Sessions: %d -> %d, Operations: %d -> %d", 
            total_sessions_before, total_sessions_after, total_operations_before, 
            total_operations_before - total_operations_cleaned), "RESULT")
    else
        debug_log("Cleanup complete: no sessions removed", "RESULT")
    end
    
    return true, {
        sessions_removed = total_sessions_removed,
        operations_cleaned = total_operations_cleaned,
        aged_cleanups = aged_sessions_removed,
        memory_cleanups = memory_sessions_removed
    }
end

-- Check if cleanup should run (lightweight check for main loop)
function M.should_cleanup()
    local current_time = os_time()
    return (current_time - statistics.last_cleanup) >= config.cleanup_interval
end

-- Validate session before adding operations (prevent overloaded sessions)
function M.validate_session(session_data)
    if not session_data or not session_data.saves then
        return false, "invalid_session_data"
    end
    
    if #session_data.saves >= config.max_operations_per_session then
        return false, "session_operation_limit_exceeded"
    end
    
    return true
end

-- Get current statistics
function M.get_statistics()
    if not config.enable_statistics then
        return {enabled = false}
    end
    
    return {
        enabled = true,
        total_cleanups = statistics.total_cleanups,
        sessions_cleaned = statistics.sessions_cleaned,
        operations_cleaned = statistics.operations_cleaned,
        last_cleanup = statistics.last_cleanup,
        time_since_last_cleanup = os_time() - statistics.last_cleanup,
        age_based_cleanups = statistics.age_based_cleanups,
        memory_pressure_cleanups = statistics.memory_pressure_cleanups
    }
end

-- Get current configuration
function M.get_config()
    local config_copy = {}
    for key, value in pairs(config) do
        config_copy[key] = value
    end
    return config_copy
end

-- Update configuration at runtime
function M.update_config(new_config)
    local updated_keys = {}
    
    for key, value in pairs(new_config) do
        if config[key] ~= nil then
            config[key] = value
            table_insert(updated_keys, key)
        end
    end
    
    debug_log("Configuration updated: " .. table.concat(updated_keys, ", "), "CONFIG")
    return updated_keys
end

-- Manual session removal (for external triggers)
function M.remove_session(sessions_table, session_id, reason)
    local session_data = sessions_table[session_id]
    if not session_data then
        return false, "session_not_found"
    end
    
    local operation_count = session_data.saves and #session_data.saves or 0
    sessions_table[session_id] = nil
    
    debug_log(string_format("Manual removal: session %s (reason: %s, ops: %d)", 
        session_id, reason or "unknown", operation_count), "MANUAL")
    
    return true, operation_count
end

-- Health check for monitoring
function M.health_check(sessions_table)
    local current_time = os_time()
    local session_count = 0
    local total_operations = 0
    local oldest_age = 0
    
    for _, session_data in pairs(sessions_table) do
        session_count = session_count + 1
        total_operations = total_operations + (session_data.saves and #session_data.saves or 0)
        local age = get_session_age(session_data, current_time)
        if age > oldest_age then oldest_age = age end
    end
    
    return {
        session_count = session_count,
        total_operations = total_operations,
        oldest_session_age = oldest_age,
        memory_usage_percent = (session_count / config.max_total_sessions) * 100,
        cleanup_overdue = (current_time - statistics.last_cleanup) > (config.cleanup_interval * 2)
    }
end

return M