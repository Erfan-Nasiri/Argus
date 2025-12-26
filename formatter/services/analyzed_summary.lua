local M = {}

function M.new(deps)
    deps = deps or {}

    local utils = assert(deps.utils, "utils required")
    local table_insert = deps.table_insert or table.insert
    local table_concat = deps.table_concat or table.concat
    local ipairs = deps.ipairs or ipairs

    local impact_priority = deps.impact_priority or { low = 1, medium = 2, high = 3 }

    return function(analyzed_changes, config_name)
        local all_summaries = {}
        local highest_impact = "low"

        for _, change_analysis in ipairs(analyzed_changes or {}) do
            local description = utils.safe_get(change_analysis, "change_summary", "unknown change", "string")
            local impact = utils.safe_get(change_analysis, "impact_level", "medium", "string")

            table_insert(all_summaries, description)

            if impact_priority[impact] and impact_priority[impact] > impact_priority[highest_impact] then
                highest_impact = impact
            end
        end

        local summary_prefix = utils.safe_format("applied %s changes", config_name or "unknown")
        local changes_detail = table_concat(all_summaries, "; ")
        if changes_detail == "" then
            changes_detail = "unknown changes"
        end

        return utils.safe_format("%s | changes: %s [impact: %s]",
            summary_prefix, changes_detail, highest_impact)
    end
end

return M
