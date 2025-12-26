-- ==============================================================================
-- deduplication.lua - Log Message Deduplication Module
-- ==============================================================================
-- Purpose: Remove duplicate and redundant log messages from formatter output
-- Features: Exact duplicate removal, similar message merging, noise reduction
-- ==============================================================================

local M = {}

-- Load utilities
local utils = require "formatter.utils"

-- Performance: localize functions
local string_find = string.find
local string_gsub = string.gsub
local table_insert = table.insert
local table_concat = table.concat
local pairs = pairs

-- ==============================================================================
-- DEDUPLICATION CONFIGURATION
-- ==============================================================================

-- Deduplication settings
M.settings = {
    remove_exact_duplicates = true,
    remove_field_duplicates = true,  -- Remove duplicate fields within messages
    merge_similar_messages = true,
    max_similar_threshold = 3,  -- Maximum number of similar messages to keep
    preserve_order = true       -- Keep original order of messages
}

-- ==============================================================================
-- EXACT DUPLICATE REMOVAL
-- ==============================================================================

-- Remove exact duplicate messages from an array
function M.remove_exact_duplicates(messages)
    if not messages or #messages == 0 then return messages end

    local seen = {}
    local result = {}

    for _, message in ipairs(messages) do
        if message and message ~= "" and not seen[message] then
            seen[message] = true
            table_insert(result, message)
        end
    end

    return result
end

-- ==============================================================================
-- SIMILAR MESSAGE MERGING
-- ==============================================================================

-- Check if two messages are similar (same action, different parameters)
function M.are_similar_messages(msg1, msg2)
    if not msg1 or not msg2 then return false end

    -- Check for similar patterns
    local patterns = {
        -- "created network section [cfg123]" and "created network section [cfg456]"
        {"created (.+) section %[cfg%x+%]", "created %s sections"},
        -- "set section [cfg123]: field=value" and "set section [cfg456]: field=value"
        {"set section %[cfg%x+%]: (.+)", "set sections: %s"},
        -- "removed network section [cfg123]" and "removed network section [cfg456]"
        {"removed (.+) section %[cfg%x+%]", "removed %s sections"}
    }

    for _, pattern in ipairs(patterns) do
        local base1 = string_gsub(msg1, pattern[1], pattern[2])
        local base2 = string_gsub(msg2, pattern[1], pattern[2])

        if base1 == base2 and base1 ~= msg1 and base1 ~= msg2 then
            return true, base1
        end
    end

    return false
end

-- Merge similar messages into a single consolidated message
function M.merge_similar_messages(messages)
    if not messages or #messages <= 1 then return messages end

    local result = {}
    local processed = {}

    for i, msg1 in ipairs(messages) do
        if not processed[i] then
            local similar_count = 1
            local similar_indices = {i}

            -- Find all similar messages
            for j = i + 1, #messages do
                if not processed[j] then
                    local is_similar, merged_pattern = M.are_similar_messages(msg1, messages[j])
                    if is_similar then
                        similar_count = similar_count + 1
                        table_insert(similar_indices, j)
                        if similar_count >= M.settings.max_similar_threshold then
                            break
                        end
                    end
                end
            end

            -- Mark all similar messages as processed
            for _, idx in ipairs(similar_indices) do
                processed[idx] = true
            end

            -- Add consolidated message
            if similar_count > 1 then
                -- Create consolidated message
                local consolidated = string_gsub(msg1, "section %[cfg%x+%]", "sections")
                table_insert(result, consolidated)
            else
                table_insert(result, msg1)
            end
        end
    end

    return result
end

-- ==============================================================================
-- FIELD-LEVEL DEDUPLICATION
-- ==============================================================================

-- Remove duplicate fields within a single message string
function M.remove_duplicate_fields(messages)
    if not messages or #messages == 0 then return messages end

    local result = {}

    for _, message in ipairs(messages) do
        if not message or message == "" then
            table_insert(result, message)
        else
            -- Extract key=value pairs
            local fields = {}
            local unique_fields = {}
            for key, value in string.gmatch(message, "(%w+)=['\"]?([^',;]+)['\"]?") do
                if not unique_fields[key .. "=" .. value] then
                    unique_fields[key .. "=" .. value] = true
                    table_insert(fields, key .. "='" .. value .. "'")
                end
            end

            -- Rebuild message with unique fields
            local prefix = string.match(message, "^(.-set section %[cfg%x+%]: )")
            if not prefix then
                prefix = ""
            end
            local new_message = prefix .. table_concat(fields, ", ")

            table_insert(result, new_message)
        end
    end

    return result
end

-- ==============================================================================
-- MAIN DEDUPLICATION FUNCTION
-- ==============================================================================

-- Apply all deduplication strategies to a list of messages
function M.deduplicate_messages(messages)
    if not messages or #messages == 0 then return messages end

    local result = messages

    -- Step 1: Remove exact duplicates
    if M.settings.remove_exact_duplicates then
        result = M.remove_exact_duplicates(result)
    end

    -- Step 2: Remove duplicate fields within messages
    if M.settings.remove_field_duplicates then
        result = M.remove_duplicate_fields(result)
    end

    -- Step 3: Merge similar messages
    if M.settings.merge_similar_messages then
        result = M.merge_similar_messages(result)
    end

    return result
end

-- ==============================================================================
-- UTILITY FUNCTIONS
-- ==============================================================================

-- Clean and normalize messages before deduplication
function M.normalize_messages(messages)
    if not messages then return messages end

    local normalized = {}
    for _, msg in ipairs(messages) do
        if msg and msg ~= "" then
            -- Remove extra whitespace and normalize
            local clean_msg = string_gsub(msg, "%s+", " ")
            clean_msg = string_gsub(clean_msg, "^%s+", "")
            clean_msg = string_gsub(clean_msg, "%s+$", "")
            table_insert(normalized, clean_msg)
        end
    end

    return normalized
end

-- Get deduplication statistics
function M.get_stats(original_messages, deduplicated_messages)
    local original_count = original_messages and #original_messages or 0
    local final_count = deduplicated_messages and #deduplicated_messages or 0
    local removed_count = original_count - final_count

    return {
        original_count = original_count,
        final_count = final_count,
        removed_count = removed_count,
        reduction_percentage = original_count > 0 and math.floor((removed_count / original_count) * 100) or 0
    }
end

-- ==============================================================================
-- MODULE HEALTH AND TESTING
-- ==============================================================================

-- Health check
function M.health()
    return {
        module_loaded = true,
        settings = M.settings,
        functions_available = {
            remove_exact_duplicates = type(M.remove_exact_duplicates) == "function",
            remove_duplicate_fields = type(M.remove_duplicate_fields) == "function",
            merge_similar_messages = type(M.merge_similar_messages) == "function",
            deduplicate_messages = type(M.deduplicate_messages) == "function",
            normalize_messages = type(M.normalize_messages) == "function"
        }
    }
end

-- Test the deduplication functionality
function M.test()
    local test_messages = {
        "created network section [cfg123]",
        "created network section [cfg123]",  -- exact duplicate
        "created network section [cfg456]",  -- similar
        "set section [cfg123]: in='lan'",
        "set section [cfg456]: in='lan'",    -- similar
        "removed network section [cfg789]"
    }

    local deduplicated = M.deduplicate_messages(test_messages)
    local stats = M.get_stats(test_messages, deduplicated)

    return {
        original_count = #test_messages,
        deduplicated_count = #deduplicated,
        stats = stats,
        success = stats.removed_count > 0
    }
end

return M
