-- Luacheck configuration tuned for Lua 5.1 + this OpenWrt Project Argus codebase

-- Use Lua 5.1 std (OpenWrt uses Lua 5.1)
std = "lua51"

-- Project-wide globals that luacheck should ignore (ubus, modules, CLI tools, etc.)
globals = {
  "ubus", "json", "cjson", "formatter", "uci", "naming", "utils",
  "deduplication", "security", "package", "io", "os", "string", "table"
}

-- Recommended stylistic limits for readability
max_line_length = 120
max_complexity = 20

-- Files/dirs to ignore (adjust if you add test fixtures)
exclude_files = {
  "vendor/**",
  "third_party/**"
}

-- Per-file overrides example (if you later split modules into their own dir)
-- files = {
--   ["tests/**"] = { std = "lua51", globals = { "busted", "describe", "it" } }
-- }

-- Helpful warnings to keep enabled; disable only with a comment near offending code
-- Keep checks strict for unused/undefined variables and global leakage.