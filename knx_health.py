#!/usr/bin/env python3
"""
KNX Health Check Module
========================
Protocol-level health checking for KNX/IP interfaces.
Supports two methods:
  - probe:     DESCRIPTION_REQUEST + CONNECT attempt (cold check)
  - heartbeat: CONNECTIONSTATE_REQUEST on active session (warm check)
"""

import socket
import struct
import logging
import time
from typing import Optional

from knx_const import (
    MAGIC, PROTO_UDP, PROTO_TCP,
    CONNECT_REQ, CONNECT_RESP, DISCONNECT_REQ,
    DESCRIPTION_REQ, DESCRIPTION_RESP,
    CONNSTATE_REQ, CONNSTATE_RESP,
    E_NO_ERROR,
    CRI_TUNNEL_V1, CRI_TUNNEL_V2,
    make_frame, make_hpai, parse_frame, parse_hpai,
    read_tcp_frame, valid_desc_response,
)

log = logging.getLogger('knx_health')


def clear_ghost_sessions(host: str, port: int, proto: str = 'tcp',
                          timeout: int = 3) -> int:
    """
    Send DISCONNECT_REQUEST for channel IDs 1-8 to force-clear any
    ghost tunnel sessions left on the gateway from previous addon instances.

    This is necessary because:
    1. When the addon restarts, old sessions are NOT properly disconnected
       (SIGTERM/SIGKILL doesn't wait for clean DISCONNECT)
    2. The gateway holds these ghost sessions for 60-120 seconds (heartbeat timeout)
    3. During that time, ALL tunnel slots are occupied
    4. Every CONNECT attempt gets 0x22 (no more connections)

    Returns the number of DISCONNECT_REQ sent (not necessarily accepted).
    """
    cleared = 0
    for ch_id in range(1, 9):
        try:
            hpai = make_hpai('0.0.0.0', 0,
                             PROTO_TCP if proto == 'tcp' else PROTO_UDP)
            body = bytes([ch_id, 0x00]) + hpai
            frame = make_frame(DISCONNECT_REQ, body)

            if proto == 'tcp':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                try:
                    s.connect((host, port))
                    s.sendall(frame)
                    # Try to read response (don't care about content)
                    try:
                        s.recv(64)
                    except Exception:
                        pass
                    cleared += 1
                finally:
                    s.close()
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                try:
                    s.bind(('0.0.0.0', 0))
                    s.sendto(frame, (host, port))
                    try:
                        s.recv(64)
                    except Exception:
                        pass
                    cleared += 1
                finally:
                    s.close()
        except Exception:
            pass
        time.sleep(0.1)  # Small delay between requests

    log.info(f"Sent {cleared} DISCONNECT requests to {host}:{port} "
             f"[{proto}] to clear ghost sessions")
    return cleared


class HealthResult:
    """Result of a health check."""
    __slots__ = ['ok', 'protocol', 'latency_ms', 'error', 'tunnel_ok', 'timestamp']

    def __init__(self, ok: bool, protocol: str = 'none',
                 latency_ms: float = 0, error: str = '',
                 tunnel_ok: bool = False):
        self.ok         = ok
        self.protocol   = protocol
        self.latency_ms = latency_ms
        self.error      = error
        self.tunnel_ok  = tunnel_ok
        self.timestamp  = time.monotonic()

    def __repr__(self):
        return (f"HealthResult(ok={self.ok}, proto={self.protocol}, "
                f"latency={self.latency_ms:.0f}ms, tunnel={self.tunnel_ok})")


def probe_description_udp(host: str, port: int, timeout: int = 5) -> HealthResult:
    """Send UDP DESCRIPTION_REQUEST and validate response."""
    # Build DESCRIPTION_REQUEST dynamically with 0.0.0.0:0 HPAI
    # Port 0 tells the gateway to reply to the UDP source address,
    # which is the only reliable option behind NAT or Docker.
    hpai = make_hpai('0.0.0.0', 0, PROTO_UDP)
    desc_req = make_frame(DESCRIPTION_REQ, hpai)
    start = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind(('0.0.0.0', 0))
        local_addr = s.getsockname()
        log.debug(f"UDP probe {host}:{port} from {local_addr[0]}:{local_addr[1]} (timeout={timeout}s)")
        s.sendto(desc_req, (host, port))
        data, src = s.recvfrom(512)
        elapsed = (time.monotonic() - start) * 1000
        if valid_desc_response(data):
            log.debug(f"UDP probe {host}:{port} OK ({elapsed:.0f}ms, {len(data)}B from {src[0]}:{src[1]})")
            return HealthResult(True, 'udp', elapsed, tunnel_ok=False)
        log.debug(f"UDP probe {host}:{port} got invalid response ({len(data)}B)")
        return HealthResult(False, 'udp', elapsed, error='invalid response')
    except socket.timeout:
        elapsed = (time.monotonic() - start) * 1000
        log.debug(f"UDP probe {host}:{port} timed out after {elapsed:.0f}ms")
        return HealthResult(False, 'udp', error=f'timeout ({timeout}s)')
    except Exception as e:
        log.debug(f"UDP probe {host}:{port} error: {e}")
        return HealthResult(False, 'udp', error=str(e))
    finally:
        s.close()


def probe_description_tcp(host: str, port: int, timeout: int = 5) -> HealthResult:
    """Send TCP DESCRIPTION_REQUEST and validate response."""
    hpai = make_hpai('0.0.0.0', 0, PROTO_TCP)
    desc_req = make_frame(DESCRIPTION_REQ, hpai)
    start = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        log.debug(f"TCP probe {host}:{port} connecting (timeout={timeout}s)")
        s.connect((host, port))
        s.sendall(desc_req)
        data = s.recv(512)
        elapsed = (time.monotonic() - start) * 1000
        if valid_desc_response(data):
            log.debug(f"TCP probe {host}:{port} OK ({elapsed:.0f}ms, {len(data)}B)")
            return HealthResult(True, 'tcp', elapsed, tunnel_ok=False)
        log.debug(f"TCP probe {host}:{port} got invalid response ({len(data)}B)")
        return HealthResult(False, 'tcp', elapsed, error='invalid response')
    except socket.timeout:
        elapsed = (time.monotonic() - start) * 1000
        log.debug(f"TCP probe {host}:{port} timed out after {elapsed:.0f}ms")
        return HealthResult(False, 'tcp', error=f'timeout ({timeout}s)')
    except ConnectionRefusedError:
        log.debug(f"TCP probe {host}:{port} connection refused")
        return HealthResult(False, 'tcp', error='connection refused')
    except Exception as e:
        log.debug(f"TCP probe {host}:{port} error: {e}")
        return HealthResult(False, 'tcp', error=str(e))
    finally:
        s.close()


def probe_tunnel_udp(host: str, port: int, timeout: int = 5) -> HealthResult:
    """
    Full UDP tunnel probe: CONNECT → verify → DISCONNECT.
    Tests actual tunnel availability, not just discovery.
    """
    start = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind(('0.0.0.0', 0))

        # Try multiple CRI/HPAI combinations for maximum compatibility
        cri_variants = [CRI_TUNNEL_V1, CRI_TUNNEL_V2]
        hpai_variants = [
            ('0.0.0.0', 0, PROTO_UDP, '0.0.0.0', 0, PROTO_UDP),
        ]
        local_ip, local_port = s.getsockname()
        if local_ip != '0.0.0.0':
            hpai_variants.append(
                (local_ip, local_port, PROTO_UDP, local_ip, local_port, PROTO_UDP)
            )

        for cri in cri_variants:
            for ctrl_ip, ctrl_port, ctrl_proto, data_ip, data_port, data_proto in hpai_variants:
                body = (
                    make_hpai(ctrl_ip, ctrl_port, ctrl_proto)
                    + make_hpai(data_ip, data_port, data_proto)
                    + cri
                )
                s.sendto(make_frame(CONNECT_REQ, body), (host, port))

                try:
                    raw, _ = s.recvfrom(1024)
                except socket.timeout:
                    continue

                svc, rbody = parse_frame(raw)
                if svc != CONNECT_RESP or not rbody or len(rbody) < 2:
                    continue

                status = rbody[1]
                if status == E_NO_ERROR:
                    channel_id = rbody[0]
                    elapsed = (time.monotonic() - start) * 1000
                    # Clean disconnect
                    _disconnect_udp(s, host, port, channel_id)
                    return HealthResult(True, 'udp', elapsed, tunnel_ok=True)

        elapsed = (time.monotonic() - start) * 1000
        return HealthResult(False, 'udp', elapsed, error='all tunnel attempts rejected')
    except socket.timeout:
        return HealthResult(False, 'udp', error='timeout')
    except Exception as e:
        return HealthResult(False, 'udp', error=str(e))
    finally:
        s.close()


def probe_tunnel_tcp(host: str, port: int, timeout: int = 5) -> HealthResult:
    """
    Full TCP tunnel probe: CONNECT → verify → DISCONNECT.
    """
    start = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        local_ip, local_port = s.getsockname()

        cri_variants = [CRI_TUNNEL_V1, CRI_TUNNEL_V2]
        hpai_variants = [
            ('0.0.0.0', 0, PROTO_TCP, '0.0.0.0', 0, PROTO_TCP),
            ('0.0.0.0', 0, PROTO_UDP, '0.0.0.0', 0, PROTO_UDP),
            ('0.0.0.0', 0, PROTO_TCP, local_ip, local_port, PROTO_TCP),
        ]

        for cri in cri_variants:
            for ctrl_ip, ctrl_port, ctrl_proto, data_ip, data_port, data_proto in hpai_variants:
                body = (
                    make_hpai(ctrl_ip, ctrl_port, ctrl_proto)
                    + make_hpai(data_ip, data_port, data_proto)
                    + cri
                )
                s.sendall(make_frame(CONNECT_REQ, body))

                try:
                    svc, rbody = read_tcp_frame(s)
                except Exception:
                    continue

                if svc != CONNECT_RESP or not rbody or len(rbody) < 2:
                    continue

                status = rbody[1]
                if status == E_NO_ERROR:
                    channel_id = rbody[0]
                    elapsed = (time.monotonic() - start) * 1000
                    _disconnect_tcp(s, channel_id)
                    return HealthResult(True, 'tcp', elapsed, tunnel_ok=True)

        elapsed = (time.monotonic() - start) * 1000
        return HealthResult(False, 'tcp', elapsed, error='all tunnel attempts rejected')
    except socket.timeout:
        return HealthResult(False, 'tcp', error='timeout')
    except Exception as e:
        return HealthResult(False, 'tcp', error=str(e))
    finally:
        s.close()


def _disconnect_udp(sock: socket.socket, host: str, port: int, channel_id: int):
    """Best-effort UDP disconnect to free the tunnel slot."""
    try:
        body = bytes([channel_id, 0x00]) + make_hpai('0.0.0.0', 0, PROTO_UDP)
        sock.sendto(make_frame(DISCONNECT_REQ, body), (host, port))
    except Exception:
        pass


def _disconnect_tcp(sock: socket.socket, channel_id: int):
    """Best-effort TCP disconnect to free the tunnel slot."""
    try:
        body = bytes([channel_id, 0x00]) + make_hpai('0.0.0.0', 0, PROTO_TCP)
        sock.sendall(make_frame(DISCONNECT_REQ, body))
    except Exception:
        pass


def detect_protocol(host: str, port: int, prefer: str = 'tcp',
                    timeout: int = 5) -> str:
    """
    Detect whether a KNX endpoint is alive and which protocol to use.
    Returns 'tcp', 'udp', or 'none'.

    IMPORTANT: This function uses DESCRIPTION_REQUEST probes only.
    It does NOT open tunnel connections (CONNECT), because each CONNECT
    consumes one of the hardware's limited tunnel slots (typically 1-4).
    Using CONNECT for health checks causes "tunnel slot starvation" where
    health probes steal all available slots from real client sessions.

    Strategy:
    1. Try DESCRIPTION_REQUEST via the preferred protocol first.
    2. Try the other protocol as fallback.
    3. If the gateway responds to DESCRIPTION, it is alive — return
       the preferred protocol (the user's configured choice).
    """
    log.info(f"Probing {host}:{port} (prefer={prefer}, timeout={timeout}s)")

    # Build probe order based on preference
    if prefer in ('tcp', 'auto'):
        probe_order = [
            ('tcp', probe_description_tcp),
            ('udp', probe_description_udp),
        ]
    else:
        probe_order = [
            ('udp', probe_description_udp),
            ('tcp', probe_description_tcp),
        ]

    for proto, probe_fn in probe_order:
        result = probe_fn(host, port, timeout)
        if result.ok:
            chosen = prefer if prefer in ('tcp', 'udp') else proto
            log.info(f"Probe {host}:{port} → alive via {proto.upper()} "
                     f"({result.latency_ms:.0f}ms), will use {chosen.upper()}")
            return chosen
        else:
            log.info(f"Probe {host}:{port} → {proto.upper()} failed: {result.error}")

    log.warning(f"Probe {host}:{port} → unreachable (all protocols failed)")
    return 'none'


def send_heartbeat_udp(host: str, port: int, channel_id: int,
                       timeout: int = 5) -> HealthResult:
    """
    Send a CONNECTIONSTATE_REQUEST heartbeat (UDP) for an active session.
    Returns HealthResult with success/failure.
    """
    start = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind(('0.0.0.0', 0))
        body = bytes([channel_id, 0x00]) + make_hpai('0.0.0.0', 0, PROTO_UDP)
        s.sendto(make_frame(CONNSTATE_REQ, body), (host, port))

        raw, _ = s.recvfrom(512)
        svc, rbody = parse_frame(raw)
        elapsed = (time.monotonic() - start) * 1000

        if svc == CONNSTATE_RESP and rbody and len(rbody) >= 2:
            status = rbody[1]
            if status == E_NO_ERROR:
                return HealthResult(True, 'udp', elapsed)
            return HealthResult(False, 'udp', elapsed,
                                error=f'heartbeat status 0x{status:02x}')

        return HealthResult(False, 'udp', elapsed, error='bad heartbeat response')
    except socket.timeout:
        return HealthResult(False, 'udp', error='heartbeat timeout')
    except Exception as e:
        return HealthResult(False, 'udp', error=str(e))
    finally:
        s.close()


def send_heartbeat_tcp(sock: socket.socket, channel_id: int,
                       timeout: int = 5) -> HealthResult:
    """
    Send a CONNECTIONSTATE_REQUEST heartbeat (TCP) on existing connection.
    """
    start = time.monotonic()
    old_timeout = sock.gettimeout()
    try:
        sock.settimeout(timeout)
        body = bytes([channel_id, 0x00]) + make_hpai('0.0.0.0', 0, PROTO_TCP)
        sock.sendall(make_frame(CONNSTATE_REQ, body))

        svc, rbody = read_tcp_frame(sock)
        elapsed = (time.monotonic() - start) * 1000

        if svc == CONNSTATE_RESP and rbody and len(rbody) >= 2:
            status = rbody[1]
            if status == E_NO_ERROR:
                return HealthResult(True, 'tcp', elapsed)
            return HealthResult(False, 'tcp', elapsed,
                                error=f'heartbeat status 0x{status:02x}')

        return HealthResult(False, 'tcp', elapsed, error='bad heartbeat response')
    except socket.timeout:
        return HealthResult(False, 'tcp', error='heartbeat timeout')
    except Exception as e:
        return HealthResult(False, 'tcp', error=str(e))
    finally:
        try:
            sock.settimeout(old_timeout)
        except Exception:
            pass
