#  Argus

**Audit Logging for OpenWrt LuCI Operations**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
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
        flush_interval = 3,
        batch_size = 30,
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
export ARGUS_LOG_DIR=/mnt/usb/logs
export ARGUS_DEBUG=1
export ARGUS_FLUSH_INTERVAL=5
export ARGUS_BATCH_SIZE=50
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
                         │ RPC
                         ▼
                ┌─────────────────┐
                │  LuCI Backend   │
                │ (rpcd/uhttpd)   │
                └────────┬────────┘
                         │
                         │ IPC
                         ▼
                ┌─────────────────┐
                │      ubus       │
                │  (Message Bus)  │
                └────────┬────────┘
                         │
                         │ monitor
                         ▼
              ╔══════════════════════╗
              ║   Project Argus      ║
              ╚══════════╤═══════════╝
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
       format.log   audit.log   audit.json
```

### Processing Pipeline

```
    ubus monitor
            │
            ▼
    User Filter → Keep user operations only
            │
            ▼
    JSON Parser → Extract data, map objid to objpath
            │
            ▼
    Classifier → uci_change, auth_login, exec, etc.
            │
            ├──► Direct ops → Log now
            │
            └──► UCI changes → Stage in session
                       │
                       ▼
              Before/After Capture → Query UCI, store values
                       │
                       │ Wait for commit...
                       │
                       ▼
              uci.apply detected → Bundle changes
                       │
                       ▼
              Formatter → Resolve CFGIDs, generate text
                       │
                       ▼
              Batch Writer → Write logs
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
       format.log  audit.log  audit.json


```

### Core Components

| Component | Purpose |
|-----------|---------|
| **logger-engine.lua** | Main event loop, state management |
| **event_pipeline.lua** | Event classification and filtering |
| **before_after.lua** | UCI state capture and tracking |
| **formatter/init.lua** | Natural language generation |
| **uci_interface.lua** | Shell-based UCI queries |
| **config.lua** | Configuration management |

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

## Contributing

If you would like to contribute to this project, feel free to fork the repository and submit a pull request. Any improvements or additional features are welcome!

---

## License
This project is licensed under the GNU GPL v3 License , See the [LICENSE](https://github.com/Erfan-Nasiri/Argus/blob/main/LICENSE) file for more details.

---

## Links

- Repository: https://github.com/Erfan-Nasiri/Argus
- Issues: https://github.com/Erfan-Nasiri/Argus/issues
- OpenWrt: https://openwrt.org/
- ubus: https://openwrt.org/docs/techref/ubus
