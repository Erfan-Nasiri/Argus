-- engine-modules/uci_interface.lua
-- Minimal, shell-only UCI interface for Project Argus
-- Lua 5.1 compatible, no libuci-lua dependency

local io   = require("io")
local os   = require("os")
local string = require("string")
local table  = require("table")

local M = {}

----------------------------------------------------------------------
-- Internal helpers
----------------------------------------------------------------------

local stats = {
    backend        = "shell",
    calls          = 0,
    errors         = 0,
    last_error     = nil,
    last_cmd       = nil,
    last_success   = nil,
}

local current_config = {
    enable_native_uci = false,   -- we only use shell, but accept flag
    cache_ttl         = nil,
    max_entries       = nil,
}

local function shell_quote(s)
    if s == nil then return "''" end
    s = tostring(s)
    -- simple POSIX-safe single-quote escaping: ' -> '\'' 
    if s == "" then return "''" end
    return "'" .. s:gsub("'", "'\\''") .. "'"
end

local function run_uci(args)
    stats.calls = stats.calls + 1

    local cmd = "uci -q " .. table.concat(args, " ") .. " 2>/dev/null"
    stats.last_cmd = cmd

    local fh = io.popen(cmd, "r")
    if not fh then
        stats.errors = stats.errors + 1
        stats.last_error = "failed to popen: " .. cmd
        return nil, stats.last_error
    end

    local output = fh:read("*a")
    local ok, reason, code = fh:close()
    if not ok and code ~= 0 then
        stats.errors = stats.errors + 1
        stats.last_error = "uci failed: " .. cmd
        return nil, stats.last_error
    end

    -- strip trailing newline(s)
    output = output or ""
    output = output:gsub("%s+$", "")
    stats.last_success = os.time()
    return output, nil
end

----------------------------------------------------------------------
-- Public API
----------------------------------------------------------------------

-- backend(): return backend name + optional error
function M.backend()
    return stats.backend, nil
end

-- configure(opts): accepts same keys as old interface but ignores most
function M.configure(opts)
    opts = opts or {}
    current_config.enable_native_uci = opts.enable_native_uci ~= false
    current_config.cache_ttl         = opts.cache_ttl
    current_config.max_entries       = opts.max_entries
    -- we don't actually use these in shell-only mode, but we keep them
    -- so callers don't break.
end

-- get(package, section, option) -> value, error
function M.get(pkg, section, option)
    if not (pkg and section and option) then
        return nil, "missing package/section/option"
    end
    local arg = shell_quote(pkg .. "." .. section .. "." .. option)
    local out, err = run_uci({ "get", arg })
    if not out then return nil, err end
    if out == "" then return nil, "not found" end
    return out, nil
end

-- get_all(package, section) -> table of options, error
-- Returns only option key/value pairs, no metadata
function M.get_all(pkg, section)
    if not (pkg and section) then
        return nil, "missing package/section"
    end
    local arg = shell_quote(pkg .. "." .. section)
    local out, err = run_uci({ "show", arg })
    if not out then return nil, err end
    if out == "" then return {}, nil end

    local result = {}
    -- lines like:
    --   system.cfg01a2b3=system
    --   system.cfg01a2b3.hostname='OpenWrt'
    for line in out:gmatch("[^\r\n]+") do
        -- match "pkg.sec.opt='value'" or "pkg.sec='type'"
        -- first, extract right side
        local left, right = line:match("^([^=]+)=(.*)$")
        if left and right then
            -- left: package.section.option?  or package.section
            local p, s, opt = left:match("^([^.]+)%.([^.]+)%.(.+)$")
            if not (p and s and opt) then
                p, s = left:match("^([^.]+)%.(.+)$")
            end

            if p == pkg and s == section then
                -- strip quotes if present
                right = right:gsub("^'(.*)'$", "%1")
                if opt then
                    result[opt] = right
                else
                    -- line defining section type, we ignore here
                end
            end
        end
    end

    return result, nil
end

-- set(package, section, option, value) -> success, error
function M.set(pkg, section, option, value)
    if not (pkg and section and option) then
        return false, "missing package/section/option"
    end
    local key = shell_quote(pkg .. "." .. section .. "." .. option)
    local val = shell_quote(value)
    local out, err = run_uci({ "set", key .. "=" .. val })
    if out == nil and err then
        return false, err
    end
    return true, nil
end

-- commit(package) -> success, error
function M.commit(pkg)
    if not pkg then return false, "missing package" end
    local arg = shell_quote(pkg)
    local out, err = run_uci({ "commit", arg })
    if out == nil and err then
        return false, err
    end
    return true, nil
end

-- dump(package) -> table, error
-- Returns table[section_name] = { [".type"]=type, [".name"]=section_name, k=v ... }
function M.dump(pkg)
    if not pkg then return nil, "missing package" end
    local arg = shell_quote(pkg)
    local out, err = run_uci({ "show", arg })
    if not out then return nil, err end
    if out == "" then return {}, nil end

    local result = {}

    for line in out:gmatch("[^\r\n]+") do
        local left, right = line:match("^([^=]+)=(.*)$")
        if left and right then
            local p, rest = left:match("^([^.]+)%.(.+)$")
            if p == pkg then
                local sec, opt = rest:match("^([^.]+)%.(.+)$")
                if not (sec and opt) then
                    sec = rest
                end

                right = right:gsub("^'(.*)'$", "%1")

                local section = result[sec]
                if not section then
                    section = { [".name"] = sec }
                    result[sec] = section
                end

                if opt then
                    section[opt] = right
                else
                    -- section type line: "pkg.sec=type"
                    section[".type"] = right
                end
            end
        end
    end

    return result, nil
end

-- get_section_data(package, section) -> { type, name, options = {...} } or nil, err
function M.get_section_data(pkg, section)
    local dump_tbl, err = M.dump(pkg)
    if not dump_tbl then return nil, err end
    local sec = dump_tbl[section]
    if not sec then
        return nil, "section not found"
    end

    local info = {
        package = pkg,
        name    = section,
        type    = sec[".type"],
        options = {},
    }

    for k, v in pairs(sec) do
        if k ~= ".type" and k ~= ".name" then
            info.options[k] = v
        end
    end

    return info, nil
end

-- get_stats() -> statistics table
function M.get_stats()
    -- return a shallow copy so callers don't mutate internal table
    local t = {}
    for k, v in pairs(stats) do
        t[k] = v
    end
    t.cache_ttl = current_config.cache_ttl
    t.max_entries = current_config.max_entries
    return t
end

return M
