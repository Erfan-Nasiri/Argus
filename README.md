# Modular UCI Change Processor Documentation

## Overview

The Modular UCI Change Processor is a comprehensive audit logging system designed for OpenWrt environments. It translates raw UCI (Unified Configuration Interface) operations into human-readable audit messages with intelligent section resolution, security impact assessment, and session-based correlation.

## Architecture

The formatter is organized into modular components for better maintainability and extensibility:

```
formatter_modular/
├── init.lua          # Main interface and core formatting logic
├── utils.lua         # Safe utility functions and data processing
├── uci.lua           # UCI command execution and caching
├── naming.lua        # Intelligent section naming and value translation
├── security.lua      # Security impact assessment and severity tagging
└── README.md         # This documentation
```

## Module Responsibilities

### init.lua - Main Interface
- **Primary Function**: `M.format(operation)` - Main formatting entry point
- **Session Processing**: `process_session_based_changes()` - Correlates related operations
- **Legacy Processing**: `process_legacy_uci_operations()` - Handles individual operations
- **Health Monitoring**: `M.health()` - System status and diagnostics
- **Maintenance**: `M.cleanup()` - Memory cleanup and cache management

### utils.lua - Utility Functions
- **Safe Operations**: `safe_format()`, `safe_get()`, `safe_string()`
- **Data Processing**: `format_value_for_display()`, `sanitize_sensitive_information()`
- **Table Utilities**: `clear_table()`, `table_size()`, `to_array()`
- **Validation**: `validate_operation()`, `validate_uci_operation()`

### uci.lua - UCI Operations
- **Command Execution**: `execute_uci_command()` - Safe UCI CLI execution
- **Caching**: TTL-based caching for UCI data retrieval
- **Data Parsing**: `parse_uci_show_output()` - UCI output processing
- **Section Management**: `get_section_data()`, `get_current_values()`

### naming.lua - Intelligent Naming
- **Section Resolution**: `resolve_section_name()` - Translates cryptic UCI sections
- **Value Translation**: `translate_value()` - Converts raw values to human-readable format
- **Field Translation**: `translate_field_name()` - Translates field names
- **Display Formatting**: `clean_display_name()` - Formats section names for display

### security.lua - Security Assessment
- **Impact Classification**: `get_level_by_section_type()` - Determines security impact
- **Action Severity**: `get_action_severity()` - Assesses action criticality
- **Security Matrix**: Comprehensive classification matrix (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **UI Integration**: `get_severity_color()` - Color coding for interfaces

## Output Format Changes

### Log Format Structure

The modular formatter produces structured audit logs with the following format:

```
[TIMESTAMP] [USER] [ACTION] [CONFIG.SECTION] [CHANGES] [IMPACT_LEVEL]
```

### Section Name Handling

#### 1. Intelligent Section Resolution

The formatter uses a multi-tier approach to resolve section names:

**Tier 1: Direct UCI Lookup**
```lua
-- Attempts to get section name from UCI configuration
local section_name = uci.show("firewall.@rule[0].name")
```

**Tier 2: Pattern-Based Resolution**
```lua
-- Uses naming patterns for common configurations
if config == "firewall" and section_type == "rule" then
    return "firewall rule"
end
```

**Tier 3: Intelligent Naming Rules**
```lua
-- Applies contextual naming rules
local display_name = naming.resolve_section_name(config, section_id, section_type)
```

#### 2. Section Name Translation Examples

| UCI Section | Translated Name | Context |
|-------------|----------------|---------|
| `firewall.@rule[0]` | `firewall rule` | Packet filtering rule |
| `network.@interface[0]` | `network interface (lan)` | LAN interface configuration |
| `system.@system[0]` | `system configuration` | System-wide settings |
| `dhcp.@host[0]` | `DHCP static lease` | Static IP assignment |
| `wireless.@wifi-device[0]` | `wireless device (radio0)` | Wireless radio configuration |

#### 3. Value Translation

Raw UCI values are translated to human-readable format:

```lua
-- Raw value: target = "ACCEPT"
-- Translated: target = "allow"

-- Raw value: proto = "tcp"
-- Translated: protocol = "TCP"
```

### Output Format Examples

#### Firewall Rule Change
```
user=root performed 'set' on firewall rule | changes: target=allow, dest_port=80 | [impact: high]
```

#### Network Interface Configuration
```
user=root performed 'set' on network interface (wan) | changes: proto=dhcp, hostname=myrouter | [impact: high]
```

#### System Configuration Update
```
user=root performed 'set' on system configuration | changes: hostname=newname, timezone=UTC | [impact: critical]
```

#### DHCP Lease Addition
```
user=root performed 'add' on DHCP static lease | changes: name=server, ip=192.168.1.100 | [impact: medium]
```

## API Reference

### Main Interface (init.lua)

#### M.format(operation)
Main formatting function that processes UCI operations.

**Parameters:**
- `operation` (table): UCI operation data structure

**Returns:**
- `string`: Formatted audit message

**Example:**
```lua
local formatter = require "formatter_modular.init"
local message = formatter.format({
    action = "set",
    config = "firewall",
    section = "cfg123",
    values = {target = "ACCEPT", dest_port = "80"}
})
-- Returns: "user=unknown performed 'set' on firewall rule | changes: target=allow, dest_port=80 | [impact: high]"
```

#### M.health()
Returns system health and diagnostic information.

**Returns:**
- `table`: Health status information

#### M.cleanup()
Performs memory cleanup and cache management.

### Utility Functions (utils.lua)

#### safe_format(fmt, ...)
Safe string formatting that never crashes.

#### safe_get(tbl, key, default, expected_type)
Safe table accessor with type checking.

#### format_value_for_display(value)
Formats values for human-readable display.

### UCI Operations (uci.lua)

#### execute_uci_command(command)
Executes UCI commands safely with error handling.

#### get_section_data(config, section_id)
Retrieves UCI section data with caching.

### Naming Intelligence (naming.lua)

#### resolve_section_name(config, section_id, section_type)
Resolves cryptic UCI section names to human-readable format.

#### translate_value(config, field, value, human_readable)
Translates raw UCI values to human-readable format.

### Security Assessment (security.lua)

#### get_level_by_section_type(config, section_type)
Determines security impact level for configuration changes.

#### get_action_severity(action, config)
Assesses severity level for specific actions.

## Configuration

### Security Matrix Configuration

The security impact is determined by a comprehensive matrix:

```lua
M.security_matrix = {
    CRITICAL = {"firewall.zone", "system.system", "dropbear.dropbear"},
    HIGH = {"firewall.rule", "network.interface", "dhcp.dnsmasq"},
    MEDIUM = {"dhcp.host", "system.ntp", "ucitrack.firewall"},
    LOW = {"luci.main", "network.globals", "uhttpd.defaults"},
    INFO = {"ucitrack.wireless", "action:login", "action:logout"}
}
```

### Cache Configuration

UCI data caching is configured with TTL:

```lua
local uci_cache = {
    data = {},
    timestamps = {},
    ttl = 300,  -- 5 minutes
    max_entries = 50
}
```

## Migration Guide

### From Monolithic to Modular

1. **Update Require Statement:**
   ```lua
   -- Old
   local formatter = require "formatter"

   -- New
   local formatter = require "formatter_modular.init"
   ```

2. **No API Changes Required:**
   - All existing function calls remain the same
   - Same return values and behavior
   - Backward compatibility maintained

3. **Enhanced Features Available:**
   - More detailed security classification
   - Better section name resolution
   - Improved error handling
   - Enhanced caching

## Troubleshooting

### Common Issues

#### Module Not Found
```
Error: module 'formatter_modular.init' not found
```
**Solution:** Ensure Lua path includes the formatter_modular directory:
```bash
export LUA_PATH="$LUA_PATH;./formatter_modular/?.lua"
```

#### UCI Command Failures
```
Error: UCI command execution failed
```
**Solution:** Verify UCI is available and properly configured:
```bash
which uci
uci show system
```

#### Cache Issues
```
Error: Cache data corrupted
```
**Solution:** Clear cache manually:
```lua
local formatter = require "formatter_modular.init"
formatter.cleanup()
```

## Performance Considerations

- **Caching**: UCI data is cached for 5 minutes to reduce system calls
- **Memory Management**: Automatic cleanup of temporary tables
- **Error Handling**: Comprehensive error handling prevents crashes
- **Localization**: Frequently used functions are pre-localized

## Security Features

- **Input Validation**: All inputs are validated and sanitized
- **Safe Execution**: UCI commands are executed with proper error handling
- **Impact Assessment**: All changes are classified by security impact
- **Audit Trail**: Comprehensive logging of all operations

## Testing

The modular formatter includes comprehensive test suites:

```lua
-- Test all modules
local formatter = require "formatter_modular.init"
local health = formatter.health()
print("Test Results:", health.test_results)

-- Test specific functions
local utils = require "formatter_modular.utils"
local test_results = utils.test_all_functions()
```

## Version History

- **v2.0.0**: Complete modular rewrite with enhanced security matrix
- **v1.5.0**: Added intelligent section naming and value translation
- **v1.0.0**: Initial monolithic formatter implementation

## Support

For issues or questions regarding the modular formatter:

1. Check the troubleshooting section above
2. Review the API documentation
3. Examine the test results for diagnostic information
4. Ensure all dependencies are properly installed

## License

This formatter is designed for OpenWrt environments and follows OpenWrt licensing guidelines.
