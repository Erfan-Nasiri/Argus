local M = {}

function M.new(deps)
    deps = deps or {}

    local utils = assert(deps.utils, "utils required")
    local naming = assert(deps.naming, "naming required")
    local security = assert(deps.security, "security required")
    local deduplication = deps.deduplication
    local config = deps.config or {}

    local table_insert = deps.table_insert or table.insert
    local table_concat = deps.table_concat or table.concat
    local ipairs = deps.ipairs or ipairs
    local pairs_iter = deps.pairs or pairs
    local string_find = deps.string_find or string.find
    local string_sub = deps.string_sub or string.sub
    local string_match = deps.string_match or string.match

    local function should_skip_field(field)
        if type(field) ~= "string" then return true end
        if field == "ubus_rpc_session" or field == "type" then return true end
        if field:match("^%.") then return true end
        return false
    end

    local function deduplicate_messages(messages)
        if not config.enable_deduplication or not deduplication then
            return messages
        end
        return deduplication.deduplicate_messages(messages)
    end

    local function normalize_entry(entry)
        entry = entry or {}
        local method = entry.method or entry.type or "unknown"
        local config_name = entry.config or (entry.values and entry.values.config) or "unknown"
        local section = entry.section or (entry.values and entry.values.section)
        local section_type = entry.section_type or (entry.values and entry.values.type)
        local normalized = {
            method = method,
            config = config_name,
            section = section,
            section_type = section_type,
            field = entry.field,
            value = entry.value,
            values = entry.values,
        }

        if method == "set" and not normalized.field and entry.values then
            local expanded = {}
            for key, value in pairs_iter(entry.values) do
                if not should_skip_field(key) then
                    table_insert(expanded, {
                        method = "set",
                        config = config_name,
                        section = section,
                        section_type = section_type,
                        field = key,
                        value = value,
                        values = entry.values
                    })
                end
            end
            if #expanded > 0 then
                return expanded
            end
        end

        if method == "add" and not normalized.field and entry.values then
            local expanded = {}
            for key, value in pairs_iter(entry.values) do
                if not should_skip_field(key) then
                    table_insert(expanded, {
                        method = "add",
                        config = config_name,
                        section = section,
                        section_type = section_type,
                        field = key,
                        value = value,
                        values = entry.values
                    })
                end
            end
            if #expanded > 0 then
                return expanded
            end
        end

        return { normalized }
    end

    return function(raw_entries)
        local entries = {}
        for _, entry in ipairs(raw_entries or {}) do
            local normalized = normalize_entry(entry)
            for _, item in ipairs(normalized) do
                table_insert(entries, item)
            end
        end

        if #entries == 0 then
            return "applied unknown changes | changes: unknown changes | [impact: medium]"
        end

        local groups, order = {}, {}
        local config_name = "unknown"

        for _, change in ipairs(entries) do
            local key = utils.safe_format("%s::%s", change.config, change.section or "global")
            if not groups[key] then
                groups[key] = {
                    section = change.section,
                    config = change.config,
                    section_type = change.section_type,
                    changes = {}
                }
                table_insert(order, key)
            end
            table_insert(groups[key].changes, change)
        end

        local summaries = {}

        for _, key in ipairs(order) do
            local group = groups[key]
            local changes = group.changes
            local section_config = group.config or "unknown"
            local section_id = group.section
            local section_type = group.section_type

            config_name = section_config
            local section_name = naming.resolve_section_name(section_config, section_id, section_type, changes)
            local sample_values = changes[1] and changes[1].values or nil
            if sample_values and sample_values.name and section_name == utils.safe_format("%s section [%s]", section_config, section_id) then
                local pretty = utils.safe_format("%s '%s'", section_type or "section", sample_values.name)
                section_name = utils.safe_format("%s %s", section_config, pretty)
            end

            local deletes, removes, adds, list_adds, sets = {}, {}, {}, {}, {}

            for _, change in ipairs(changes) do
                local method = change.method
                local field = change.field
                local value = change.value

                if method == "delete" then
                    table_insert(deletes, utils.safe_format("removed %s", section_name))

                elseif method == "remove" then
                    if field then
                        local field_name = naming.translate_field_name(field)
                        table_insert(removes, utils.safe_format("removed %s field", field_name))
                    else
                        table_insert(removes, utils.safe_format("removed %s", section_name))
                    end

                elseif method == "add" then
                    if field and value then
                        local field_name = naming.translate_field_name(field)
                        local translated_value = naming.translate_value(section_config, field, value, true)
                        table_insert(adds, utils.safe_format("created %s with %s=%s",
                            section_name, field_name, translated_value))
                    else
                        table_insert(adds, utils.safe_format("created %s", section_name))
                    end

                elseif method == "list-add" then
                    if field and value then
                        local field_name = naming.translate_field_name(field)
                        local translated_value = naming.translate_value(section_config, field, value, true)
                        table_insert(list_adds, utils.safe_format("added %s to %s", translated_value, field_name))
                    end

                elseif method == "set" then
                    if field and value ~= nil then
                        local field_name = naming.translate_field_name(field)
                        local translated_value = naming.translate_value(section_config, field, value, true)
                        table_insert(sets, utils.safe_format("%s=%s", field_name, translated_value))
                    end
                end
            end

            for _, desc in ipairs(deletes) do table_insert(summaries, desc) end
            for _, desc in ipairs(removes) do table_insert(summaries, desc) end
            for _, desc in ipairs(adds) do table_insert(summaries, desc) end
            for _, desc in ipairs(list_adds) do table_insert(summaries, desc) end

            if #sets > 0 then
                local display_name = section_name
                if string_find(section_name, section_config .. " ", 1, true) == 1 then
                    display_name = string_sub(section_name, #section_config + 2)
                end
                table_insert(summaries, utils.safe_format("set %s: %s",
                    display_name, table_concat(sets, ", ")))
            end
        end

        local deduped = deduplicate_messages(summaries)
        local changes_detail = table_concat(deduped, "; ")
        if changes_detail == "" then
            changes_detail = "unknown changes"
        end

        local summary_prefix = utils.safe_format("applied %s changes", config_name)
        local impact_level = security.get_config_impact and security.get_config_impact(config_name) or "medium"

        return utils.safe_format("%s | changes: %s | [impact: %s]",
            summary_prefix, changes_detail, impact_level)
    end
end

return M
