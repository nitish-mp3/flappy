# KNX Failover Proxy

**Production-grade KNX/IP failover proxy for Home Assistant OS.**

Routes Home Assistant KNX traffic through a stable endpoint while managing backend selection, health checking, failover, and failback across TCP, UDP, and USB KNX interfaces.

---

## Architecture

```
Home Assistant (xknx)
        │
        ▼
┌─────────────────────────┐
│   KNX Failover Proxy    │  ← HA connects here (port 3671)
│   (TCP + UDP frontend)  │
├─────────────────────────┤
│   Health Monitor        │  ← Probes backends, triggers failover
│   Session Manager       │  ← Manages tunnel sessions, drains gracefully
│   Secure Engine         │  ← KNX IP Secure (ECDH + AES-128-CCM)
└────────┬────────────────┘
         │ Active backend selection
    ┌────┴────┬──────────┐
    ▼         ▼          ▼
 Primary    Backup      USB
 (TCP/UDP)  (TCP/UDP)   (via knxd)
```

## Features

- **Any-to-any failover**: TCP↔TCP, UDP↔UDP, TCP↔UDP, UDP↔TCP, IP↔USB
- **KNX IP Secure**: ECDH key exchange, AES-128-CCM encryption
- **Configurable failback**: auto (with delay), manual, or disabled
- **Production health checks**: DESCRIPTION probe + tunnel negotiation
- **Graceful session draining**: Sends DISCONNECT before switching backends
- **USB via knxd**: Proper KNX daemon for USB HID interfaces (socat fallback)
- **Metrics & observability**: JSON metrics file, structured logging
- **HA notifications**: Optional persistent notification on failover events

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `primary_host` | string | *required* | Primary KNX interface IP/hostname |
| `primary_port` | port | `3671` | Primary interface port |
| `primary_protocol` | tcp/udp/auto | `tcp` | Protocol to use for primary |
| `primary_secure` | bool | `false` | Enable KNX IP Secure for primary |
| `primary_device_password` | password | | Device password for secure mode |
| `primary_user_password` | password | | User password for secure mode |
| `backup_host` | string | *required* | Backup KNX interface IP/hostname |
| `backup_port` | port | `3671` | Backup interface port |
| `backup_protocol` | tcp/udp/auto | `udp` | Protocol to use for backup |
| `backup_secure` | bool | `false` | Enable KNX IP Secure for backup |
| `backup_device_password` | password | | Device password for backup secure |
| `backup_user_password` | password | | User password for backup secure |
| `frontend_protocol` | udp/tcp/both | `udp` | What protocol HA uses to connect |
| `listen_port` | port | `3671` | Port the proxy listens on |
| `usb_device` | string | | USB device path (e.g. `/dev/ttyACM0`) |
| `usb_baud` | int | `19200` | USB serial baud rate |
| `usb_priority` | last_resort/prefer | `last_resort` | USB priority in selection |
| `usb_knxd_extra_args` | string | | Extra args for knxd |
| `health_check_interval` | int | `5` | Seconds between health checks |
| `health_check_fall` | int | `3` | Failed checks before failover |
| `health_check_rise` | int | `2` | Successful checks before failback |
| `health_check_method` | probe/heartbeat/both | `probe` | Health check method |
| `connection_timeout` | int | `5` | Connection timeout in seconds |
| `failback_mode` | auto/manual/disabled | `auto` | How to handle primary recovery |
| `failback_delay_seconds` | int | `30` | Delay before auto-failback |
| `max_sessions` | int (1-16) | `8` | Maximum concurrent tunnel sessions |
| `session_timeout` | int | `120` | Idle session timeout in seconds |
| `drain_timeout_seconds` | int (1-30) | `5` | Timeout for graceful session drain |
| `log_level` | debug/info/warning/error | `info` | Logging verbosity |
| `notify_on_failover` | bool | `false` | HA persistent notification on failover |

## Deployment Scenarios

### Dual TCP
```yaml
primary_host: "192.168.1.10"
primary_protocol: tcp
backup_host: "192.168.1.11"
backup_protocol: tcp
```

### Mixed TCP + UDP
```yaml
primary_host: "192.168.1.10"
primary_protocol: tcp
backup_host: "192.168.1.11"
backup_protocol: udp
```

### IP Primary + USB Fallback
```yaml
primary_host: "192.168.1.10"
primary_protocol: tcp
backup_host: "192.168.1.11"
backup_protocol: udp
usb_device: "/dev/ttyACM0"
usb_priority: last_resort
```

### KNX IP Secure
```yaml
primary_host: "192.168.1.10"
primary_protocol: tcp
primary_secure: true
primary_device_password: "your-device-password"
backup_host: "192.168.1.11"
backup_protocol: tcp
backup_secure: true
backup_device_password: "your-backup-password"
```

## Troubleshooting

1. **Check logs**: Set `log_level: debug` to see all probe and tunnel negotiation details
2. **DEGRADED state**: All interfaces are unreachable — check network connectivity
3. **Tunnel rejected (0x22)**: Interface doesn't support the requested tunnel type — try changing protocol
4. **No more connections (0x24)**: All tunnel slots on the interface are occupied — reduce `max_sessions` or disconnect other clients
5. **USB not detected**: Ensure the device path exists and has read/write permissions

## Version History

- **3.0.0**: Complete rewrite — modular architecture, KNX Secure, knxd USB, configurable failback
- **2.7.0**: Previous version with basic TCP/UDP failover
