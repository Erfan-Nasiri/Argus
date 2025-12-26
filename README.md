#  Argus

**Audit Logging for OpenWrt LuCI Operations**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Lua 5.1](https://img.shields.io/badge/Lua-5.1-blue.svg)](https://www.lua.org/)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-19.07+-orange.svg)](https://openwrt.org/)

Audit logging system for OpenWrt that monitors LuCI web interface operations through ubus and generates readable logs of configuration changes.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Log Formats](#log-formats)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

OpenWrt's LuCI web interface communicates with the system through **ubus** (unified bus). Argus monitors these ubus events to create audit logs of user actions performed through the web interface.

**What it does:**
- Tracks configuration changes made through LuCI
- Records user authentication (login/logout)
- Captures before/after values for configuration changes
- Generates human-readable log entries
- Correlates multi-step operations within web sessions

**What it doesn't do:**
- Monitor direct SSH/CLI commands (only LuCI operations)
- Prevent or block unauthorized changes
- Provide real-time alerts

---

## Features

- **LuCI Operation Tracking**: Monitors user actions through the web interface
- **Session Correlation**: Groups related changes within web sessions
- **Before/After Capture**: Records configuration state before and after changes
- **Multi-Format Output**: Human-readable, key-value, and JSON logs
- **Anonymous Section Resolution**: Translates UCI section IDs to readable names
- **Authentication Logging**: Tracks login/logout events with source IPs
- **Configurable Modes**: Minimal, balanced, or forensic logging levels

---

## Installation

```bash
# Download
cd /tmp
wget https://github.com/Erfan-Nasiri/Argus/archive/main.tar.gz
tar -xzf main.tar.gz
cd Argus-main

# Install
mkdir -p /usr/lib/argus
cp -r engine engine-modules formatter /usr/lib/argus/
cp logger-engine.lua /usr/lib/argus/
chmod +x /usr/lib/argus/logger-engine.lua

# Setup init script
cp init.d/argus /etc/init.d/
chmod +x /etc/init.d/argus

# Start service
/etc/init.d/argus enable
/etc/init.d/argus start
```

**Requirements:**
- OpenWrt 19.07+
- LuCI web interface
- Lua 5.1 (pre-installed)
- ~2MB storage
- 32MB+ RAM recommended

---

## Quick Start

```bash
# Start monitoring
/etc/init.d/argus start

# Make a change via LuCI web interface
# (Login → Network → Interfaces → Edit LAN → Change IP → Save & Apply)

# View logs
tail -f /tmp/log/Audits/format.log
```

**Example output:**
```
Wed Dec 25 14:32:18 2024 [user: admin] Applied network changes: modified interface 'lan' (changed ipaddr from '192.168.1.1' to '192.168.2.1')
```

---

## Configuration

### Operating Modes

Edit `/usr/lib/argus/engine/config.lua`:

```lua
features = {
    operation_mode = "balanced",  -- minimal | balanced | forensic
}
```

| Mode | Description | Use Case |
|------|-------------|----------|
| **minimal** | Basic change logging | Low-resource devices |
| **balanced** | Standard with before/after | Default, production use |
| **forensic** | Maximum detail | Security audits |

### Configuration Structure

```lua
{
    paths = {
        base = "/tmp/log/Audits",
    },
    
    features = {
        operation_mode = "balanced",
        before_after_tracking = true,
        intelligent_descriptions = true,
        auth_session_tracking = true,
    },
    
    performance = {
        flush_interval = 3,           -- Seconds between writes
        batch_size = 30,              -- Events per batch
        max_pending_operations = 1000,
    },
    
    security = {
        redact_sensitive_values = true,
        max_failed_attempts = 5,
        lockout_window_seconds = 900,
    },
}
```

### Environment Variables

```bash
export ARGUS_LOG_DIR=/mnt/usb/logs    # Custom log location
export ARGUS_DEBUG=1                   # Enable debug output
export ARGUS_FLUSH_INTERVAL=5          # Write interval (seconds)
export ARGUS_BATCH_SIZE=50             # Events per batch
```

---

## Architecture

### System Overview

```
                    User Browser
                         │
                         │ HTTPS
                         ▼
                ┌─────────────────┐
                │   LuCI Web UI   │
                └────────┬────────┘
                         │
                         │ RPC Calls
                         ▼
                ┌─────────────────┐
                │  LuCI Backend   │
                │ (rpcd/uhttpd)   │
                └────────┬────────┘
                         │
                         │ IPC Messages
                         ▼
                ┌─────────────────┐
                │      ubus       │
                │  (Message Bus)  │
                │                 │
                │  luci.*, uci.*  │
                │  service.*, etc │
                └────────┬────────┘
                         │
                         │ ubus monitor
                         ▼
              ╔══════════════════════╗
              ║   Project Argus      ║
              ║   logger-engine.lua  ║
              ╚══════════╤═══════════╝
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
       format.log   audit.log   audit.json
```

### Processing Pipeline

```
    ubus monitor stream
            │
            ▼
    ┌───────────────┐
    │ User Filter   │  Keep user operations only
    └───────┬───────┘
            │
            ▼
    ┌───────────────┐
    │ JSON Parser   │  Extract structured data
    └───────┬───────┘  Map objid → objpath
            │
            ▼
    ┌───────────────┐
    │  Classifier   │  uci_change, auth_login,
    └───────┬───────┘  exec, reboot, etc.
            │
            ├──► Direct Operations → Log immediately
            │
            └──► UCI Changes → Stage in session
                       │
                       ▼
              ┌─────────────────┐
              │  Before/After   │  Query current state
              │  State Capture  │  Store before→after
              └────────┬────────┘
                       │
                       │ Wait for uci.apply...
                       │
                       ▼
              ┌─────────────────┐
              │  uci.apply      │  Trigger detected!
              │  Detected       │  Bundle all changes
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Formatter     │  Resolve CFGIDs
              │  (Translator)   │  Generate description
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Batch Writer   │  Write to logs
              └─────────────────┘
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
       format.log  audit.log  audit.json
```

### Event Flow Example

**Scenario: Admin changes LAN IP from 192.168.1.1 to 192.168.2.1**

**Step 1: User Action**
```
Admin opens LuCI web interface and navigates to Network → Interfaces → LAN
Changes IPv4 address field from 192.168.1.1 to 192.168.2.1
Clicks "Save & Apply" button
```

**Step 2: ubus Message (uci.set)**
```
LuCI sends ubus invoke message:
  Object: uci
  Method: set
  User: admin
  Data: {
    config: "network",
    section: "lan",
    values: {ipaddr: "192.168.2.1"},
    ubus_rpc_session: "4a89bc3f"
  }

ubus responds with status: 0 (success)
```

**Step 3: Argus Stages the Change**
```
Argus receives and processes the message:
  - Classifies as: uci_change
  - Links callback to session 4a89bc3f
  - Queries current value: uci get network.lan.ipaddr → "192.168.1.1"
  - Stores in memory:
      session: 4a89bc3f
      config: network
      section: lan
      field: ipaddr
      before: "192.168.1.1"
      after: "192.168.2.1"
  
  Does NOT log yet - waits for commit
```

**Step 4: ubus Message (uci.apply)**
```
LuCI sends ubus invoke message:
  Object: uci
  Method: apply
  User: admin
  Data: {
    rollback: true,
    ubus_rpc_session: "4a89bc3f"
  }

ubus responds with status: 0 (success)
```

**Step 5: Argus Triggers Logging**
```
Argus detects uci.apply:
  - Classifies as: uci_apply
  - Retrieves all staged changes for session 4a89bc3f
  - Groups changes by config file (network)
  - Sends to formatter module
```

**Step 6: Formatter Generates Description**
```
Formatter processes the change:
  - Resolves section "lan" → "interface 'lan'"
  - Builds natural language description
  - Output: "Applied network changes: modified interface 'lan' 
            (changed ipaddr from '192.168.1.1' to '192.168.2.1')"
```

**Step 7: Multi-Format Output**
```
format.log:
  Wed Dec 25 14:32:18 2024 [user: admin] Applied network changes: 
  modified interface 'lan' (changed ipaddr from '192.168.1.1' to '192.168.2.1')

audit.log:
  time="Wed Dec 25 14:32:18 2024" user="admin" action="set_applied" 
  category="uci" config="network" values="section=lan,field=ipaddr,
  before=192.168.1.1,after=192.168.2.1"

audit.json:
  {
    "timestamp": "2024-12-25T14:32:18Z",
    "user": "admin",
    "action": "set_applied",
    "config": "network",
    "changes": [{
      "section": "lan",
      "field": "ipaddr",
      "before": "192.168.1.1",
      "after": "192.168.2.1"
    }]
  }
```

### Core Components

| Component | Purpose |
|-----------|---------|
| **logger-engine.lua** | Main event loop, state management, coordination |
| **event_pipeline.lua** | Event classification, filtering, triage logic |
| **before_after.lua** | UCI state capture, before/after tracking |
| **formatter/init.lua** | Natural language generation, CFGID resolution |
| **uci_interface.lua** | Shell-based UCI queries (get, show, dump) |
| **config.lua** | Configuration management, mode profiles |

---

## Log Formats

### Human-Readable (`format.log`)

```
Wed Dec 25 14:32:18 2024 [user: admin] Applied network changes: modified interface 'lan' (changed ipaddr from '192.168.1.1' to '192.168.2.1')
```

### Key-Value (`audit.log`)

```
time="Wed Dec 25 14:32:18 2024" user="admin" action="set_applied" category="uci" config="network" values="section=lan,field=ipaddr,before=192.168.1.1,after=192.168.2.1"
```

### JSON (`audit.json`)

```json
{
  "timestamp": "2024-12-25T14:32:18Z",
  "user": "admin",
  "action": "set_applied",
  "config": "network",
  "changes": [{
    "section": "lan",
    "field": "ipaddr",
    "before": "192.168.1.1",
    "after": "192.168.2.1"
  }]
}
```

**Default location:** `/tmp/log/Audits/`

---

## Usage Examples

### Network Configuration Change

**Action:** Change LAN IP via LuCI (Network → Interfaces → LAN)

**Log:**
```
Wed Dec 25 15:32:45 2024 [user: admin] Applied network changes: modified interface 'lan' (changed ipaddr from '192.168.1.1' to '10.0.0.1', changed netmask from '255.255.255.0' to '255.255.0.0')
```

### Firewall Rule Addition

**Action:** Add port forward rule (Network → Firewall → Port Forwards)

**Log:**
```
Wed Dec 25 15:45:20 2024 [user: admin] Applied firewall changes: added new port forward rule 'SSH-Access' (proto=tcp, src_dport=2222, dest_ip=192.168.1.10, dest_port=22)
```

### DHCP Static Lease

**Action:** Add static lease (Network → DHCP → Static Leases)

**Log:**
```
Wed Dec 25 16:00:15 2024 [user: admin] Applied dhcp changes: added new static lease 'server' (mac=aa:bb:cc:dd:ee:ff, ip=192.168.1.100)
```

### Authentication Events

**Action:** Login attempts

**Log:**
```
Wed Dec 25 14:15:03 2024 [user: admin] Authentication failed: login attempt from 192.168.1.50
Wed Dec 25 14:15:25 2024 [user: admin] Authentication successful: login from 192.168.1.50
```

---

## Troubleshooting

### Service Not Starting

```bash
# Check status
/etc/init.d/argus status

# View system logs
logread | grep argus

# Test ubus monitor
ubus monitor -m invoke -m status
```

### No Logs Generated

```bash
# Enable debug mode
export ARGUS_DEBUG=1
/etc/init.d/argus restart

# Check debug output
tail -f /tmp/log/Audits/debug.log

# Verify directory
mkdir -p /tmp/log/Audits
```

### High Memory Usage

```bash
# Switch to minimal mode
# Edit /usr/lib/argus/engine/config.lua
operation_mode = "minimal"

# Reduce batch size
export ARGUS_BATCH_SIZE=50
export ARGUS_FLUSH_INTERVAL=5

# Restart
/etc/init.d/argus restart
```

---

## Performance

**Typical Usage:**
- Memory: 3-8 MB
- CPU: <1% idle, 2-5% during changes
- Storage: ~1MB per 1000 entries
- I/O: Batched writes every 3 seconds

---

## License

MIT License - see LICENSE file

---

## Links

- **Repository**: https://github.com/Erfan-Nasiri/Argus
- **Issues**: https://github.com/Erfan-Nasiri/Argus/issues
- **OpenWrt**: https://openwrt.org/
- **ubus**: https://openwrt.org/docs/techref/ubus

---

** Argus** - Audit logging for OpenWrt LuCI operations
