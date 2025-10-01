-- filepath: /openwrt-argus-logger/openwrt-argus-logger/src/modules/uci_session.lua
-- ==============================================================================
-- UCI Session Management Module
-- ==============================================================================
-- Purpose: Manages UCI session operations, staging changes, and correlating them
--          with session IDs for comprehensive logging.
-- Author: Enhanced for session-based UCI change tracking
-- ==============================================================================

local uci_session = {}

-- Track staged UCI operations by session ID
local staged_operations = {}

-- Stage a UCI operation for later processing
function uci_session.stage_operation(session_id, operation_data)
    if not session_id then return end

    if not staged_operations[session_id] then
        staged_operations[session_id] = { operations = {}, user = operation_data.user }
    end

    table.insert(staged_operations[session_id].operations, operation_data)
end

-- Apply staged UCI operations for a given session
function uci_session.apply_operations(session_id, user)
    if not staged_operations[session_id] then return end

    local operations = staged_operations[session_id].operations
    for _, operation in ipairs(operations) do
        -- Here you would apply the operation using UCI commands
        -- For example: os.execute("uci set " .. operation.config .. "=" .. operation.value)
    end

    -- Log the applied operations
    -- create_log_entries_for_operation({
    --     user = user,
    --     action = "set_applied",
    --     values = operations
    -- })

    -- Clear staged operations after applying
    staged_operations[session_id] = nil
end

-- Retrieve staged operations for a session
function uci_session.get_staged_operations(session_id)
    return staged_operations[session_id] and staged_operations[session_id].operations or {}
end

return uci_session