local event_profile = require("engine.event_profile")

local M = {}

local function noop() end

function M.build_event(parsed_data, callback_id, object_lookup)
    if not parsed_data then
        return nil
    end

    local message_data = parsed_data.data or {}
    local object_name = nil

    if object_lookup and parsed_data.objid then
        object_name = object_lookup[parsed_data.objid]
    end

    object_name = object_name
        or parsed_data.objpath
        or message_data.object
        or "unknown"

    local method = parsed_data.method or message_data.method or "unknown"

    return {
        user = parsed_data.user,
        object_name = object_name,
        method = method,
        data = message_data,
        objid = parsed_data.objid,
        callback_id = callback_id,
        family = parsed_data._family,
        direction = parsed_data._direction,
        key = event_profile.event_key(object_name, method),
    }
end

function M.fast_filter(event, log_fn)
    log_fn = log_fn or noop
    if event_profile.is_needed_event(event.object_name, event.method) then
        return true
    end

    if event_profile.is_hard_noise(event.object_name, event.method) then
        log_fn("FAST FILTER: Dropping hard-noise event %s", event.key)
        return false
    end

    return true
end

function M.triage(event, triage_map, should_filter_file_operation, log_fn)
    log_fn = log_fn or noop
    local user = event.user
    local object_name = event.object_name
    local method = event.method
    local message_data = event.data or {}

    if method == "access" and message_data.object == "backup" then
        log_fn("TRIAGED (special): backup access by user=%s", user or "-")
        return {
            type      = "backup_read",
            user      = user,
            obj_name  = object_name,
            method    = method,
            values    = message_data,
            config    = message_data.command
                        or message_data.name
                        or message_data.config
                        or object_name,
            source_ip = message_data.remote_addr or message_data.source_ip
        }
    end

    if not object_name or not method then
        log_fn("FILTERED: missing object/method")
        return nil
    end

    local key = event_profile.event_key(object_name, method)
    local operation_type = triage_map[key]

    if operation_type == "file_read" and should_filter_file_operation then
        local drop, resolved_path = should_filter_file_operation(message_data)
        if drop then
            log_fn("TRIAGE FILTER: skipped file_read '%s'", resolved_path or "<unknown>")
            return nil
        end
    end

    if not operation_type then
        log_fn("FILTERED: Discarding noisy event: method='%s' on object='%s'",
            tostring(method), tostring(object_name))
        return nil
    end

    log_fn("TRIAGED: %s as type '%s' (user=%s)",
        key, operation_type, user or "-")

    return {
        type      = operation_type,
        user      = user,
        obj_name  = object_name,
        method    = method,
        values    = message_data,
        config    = message_data.command
                    or message_data.name
                    or message_data.config
                    or object_name,
        source_ip = message_data.remote_addr or message_data.source_ip
    }
end

function M.should_log(operation, event, drop_events, mode_name, log_fn)
    log_fn = log_fn or noop
    local key = event_profile.event_key(
        (event and event.object_name) or operation.obj_name,
        (event and event.method) or operation.method
    )

    if drop_events and drop_events[key] then
        log_fn("FILTERED: %s suppressed by mode '%s'", key, mode_name or "balanced")
        return false
    end

    return true
end

return M
