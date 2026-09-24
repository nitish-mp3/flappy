# Flappy KNX continuity

Flappy keeps Home Assistant’s KNX integration connected to the add-on’s stable KNXnet/IP endpoint. It selects a backend from an ordered list of IP and local USB interfaces, probes each independently, and reconnects existing sessions when possible. Discovery and monitor-only interfaces never enter the fallback order.

## Configuration and upgrade

New configuration lives in the Home Assistant ingress UI and is stored atomically in `/data/flappy.json`. On upgrade, the old `primary_*`, `backup_*`, `knxd_*`, and USB settings are imported into an ordered list. Review the order, save, then restart to switch to the new manager. Before that save, the existing manager continues running. A pending-apply notice appears after save. Restart briefly interrupts active tunnels; Home Assistant reconnects to the same add-on endpoint.

The UI does not return stored KNX Secure passwords. Leave a password field empty to retain it; enter a new value to change it. A failed save leaves the last saved configuration intact. Concurrent edits with a stale revision are rejected.

The first UI save also preserves the exact old Supervisor options file as `/data/flappy.json.legacy-options.json`. To roll back, stop Flappy, back up `/data/flappy.json`, copy that saved options file over `/data/options.json`, remove `/data/flappy.json`, then start Flappy. Keep both backups until the old route and sessions are verified. These file operations can be done through the Home Assistant terminal or a backup restore.

## Failover behaviour

New installations check each interface every second, mark it down after two failed checks, and mark it up after two successful checks. Probe timeout is configurable. Failure selects the next healthy fallback. Automatic failback waits for the configured delay and a 3-second minimum stability/dwell guard, even if the configured delay is zero. Manual and disabled failback still switch away from a failed interface; they control recovery to a preferred interface only.

Checks use valid KNXnet/IP DESCRIPTION responses. These prove protocol reachability, but do not reserve or prove that a tunnel slot is available. A live tunnel rejection triggers a short cooldown. The proxy negotiates a replacement before releasing the old tunnel and preserves the Home Assistant session and sequence mapping when a switch succeeds. If hardware vanishes, failure detection and tunnel negotiation take time; zero telegram loss cannot be guaranteed.

## Discovery, USB and monitoring

Network scan sends bounded KNXnet/IP multicast discovery on the selected IPv4 interface. USB scan lists supported KNX USB HID devices. You can also enter a hostname/IP or device path directly. USB identity can be matched by serial when its bus path changes. Auto USB selection requires exactly one matching device.

USB can appear anywhere in the fallback order. Native USB uses a passive telegram tap; knxd gets a separate server port and configurable KNX individual/tunnel addresses. Default addresses are unique within Flappy, but must be checked against the site’s ETS plan. The legacy serial socat mode remains available for compatible hardware.

Fallback monitoring reports traffic already carried by the proxy without taking another tunnel slot. Monitor-only IP entries can open a separate receive-only tunnel and need a free hardware slot. Monitoring never sends group reads/writes and keeps at most 20 recent raw cEMI frames in memory. Up to four monitors and 32 interfaces are allowed. Native USB monitoring is passive.

Interface up/down transitions and backend selections are stored in a bounded SQLite history of up to 5,000 events. The dashboard shows recent events, latency, check counts, last-up/down times, sessions, byte counts, and forwarded telegram counts.

## Applying and validating

After saving, restart from the UI to apply the configuration. Keep Home Assistant’s KNX integration pointed at the add-on host and frontend port. The dashboard warns when runtime status is stale or a saved configuration is unapplied.

Regression checks run with `python -m unittest discover -s addon/tests -v`. They cover config migration/persistence, concurrent edits, failback stability, discovery parsing, KNX description probes, USB tunnel ownership/retransmissions, and a local UDP proxy hot-switch. USB drivers, KNX IP Secure gateways, Supervisor persistence, Ingress, and real multi-device failover still need validation on target HAOS hardware before production rollout.
