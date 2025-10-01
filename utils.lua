-- ==============================================================================
-- utils.lua - Defensive Utilities for Safe Operations
-- ==============================================================================

local M = {}

-- Performance: Pre-localize standard library functions
local string_format, string_gsub, string_match, string_lower, string_find, string_sub =
      string.format, string.gsub, string.match, string.lower, string.find, string.sub
local table_insert, table_concat = table.insert, table.concat
local pairs, ipairs, next, type, tostring, tonumber =
      pairs, ipairs, next, type, tostring, tonumber

-- Ultra-safe string formatter that never crashes
function M.safe_format(fmt, ...)
    local ok, result = pcall(string_format, fmt or "%s", ...)
    return ok and result or "format-error"
end

-- Ultra-safe table accessor with type checking
function M.safe_get(tbl, key, default, expected_type)
    if type(tbl) ~= "table" or not key then return default end
    local value = tbl[key]
    if expected_type and type(value) ~= expected_type then return default end
    return value or default
end

-- Safe string operations
function M.safe_string(value, default)
    local val_type = type(value)
    if val_type == "string" then return value end
    if val_type == "number" then return tostring(value) end
    if val_type == "table" then return table_concat(value, ",") end
    return default or "unknown"
end

return M
