-- state_capture_queue.lua - lightweight non-blocking queue for before-state capture
local M = {}

local table_remove = table.remove
local table_insert = table.insert
local os_time = os.time

-- Simple in-memory queue (array) with max size to avoid unbounded memory
local queue = {}
local MAX_QUEUE_SIZE = 500

-- Enqueue a capture request. Non-blocking: if full, drop oldest.
function M.enqueue(request)
    if not request then return false, "invalid_request" end
    if #queue >= MAX_QUEUE_SIZE then
        -- drop oldest to make room
        table_remove(queue, 1)
    end
    table_insert(queue, request)
    return true
end

-- Process at most `limit` items from the queue. Returns number processed.
function M.process_once(limit)
    limit = limit or 10
    local processed = 0
    for i = 1, limit do
        if #queue == 0 then break end
        local item = table_remove(queue, 1)
        -- Best-effort processing: call provided handler if available
        if item and item.handler and type(item.handler) == "function" then
            pcall(item.handler, item)
        end
        processed = processed + 1
    end
    return processed
end

-- Expose a simple status function
function M.status()
    return { queued = #queue, max_queue = MAX_QUEUE_SIZE }
end

return M
