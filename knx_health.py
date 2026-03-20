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
    desc_req = b'\x06\x10\x02\x03\x00\x0e\x08\x01\x00\x00\x00\x00\x0e\x57'
    start = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind(('0.0.0.0', 0))
        s.sendto(desc_req, (host, port))
        data, _ = s.recvfrom(512)
        elapsed = (time.monotonic() - start) * 1000
        if valid_desc_response(data):
            return HealthResult(True, 'udp', elapsed, tunnel_ok=False)
        return HealthResult(False, 'udp', elapsed, error='invalid response')
    except socket.timeout:
        return HealthResult(False, 'udp', error='timeout')
    except Exception as e:
        return HealthResult(False, 'udp', error=str(e))
    finally:
        s.close()


def probe_description_tcp(host: str, port: int, timeout: int = 5) -> HealthResult:
    """Send TCP DESCRIPTION_REQUEST and validate response."""
    desc_req = b'\x06\x10\x02\x03\x00\x0e\x08\x01\x00\x00\x00\x00\x0e\x57'
    start = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(desc_req)
        data = s.recv(512)
        elapsed = (time.monotonic() - start) * 1000
        if valid_desc_response(data):
            return HealthResult(True, 'tcp', elapsed, tunnel_ok=False)
        return HealthResult(False, 'tcp', elapsed, error='invalid response')
    except socket.timeout:
        return HealthResult(False, 'tcp', error='timeout')
    except Exception as e:
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
    Detect the supported protocol for a KNX endpoint.
    Returns 'tcp', 'udp', or 'none'.

    Strategy:
    1. Try the preferred protocol first (both description + tunnel)
    2. Try the other protocol
    3. Fall back to description-only if tunnel fails (some gateways
       answer discovery but may have all tunnel slots occupied)
    """
    log.debug(f"Detecting protocol for {host}:{port} (prefer={prefer})")

    if prefer == 'tcp':
        order = [
            ('tcp', probe_tunnel_tcp),
            ('udp', probe_tunnel_udp),
            ('tcp', probe_description_tcp),
            ('udp', probe_description_udp),
        ]
    elif prefer == 'udp':
        order = [
            ('udp', probe_tunnel_udp),
            ('tcp', probe_tunnel_tcp),
            ('udp', probe_description_udp),
            ('tcp', probe_description_tcp),
        ]
    else:
        # auto: try TCP first (modern KNX tunnelling)
        order = [
            ('tcp', probe_tunnel_tcp),
            ('udp', probe_tunnel_udp),
            ('tcp', probe_description_tcp),
            ('udp', probe_description_udp),
        ]

    for proto, probe_fn in order:
        result = probe_fn(host, port, timeout)
        if result.ok:
            log.debug(f"  → {proto} OK ({result.latency_ms:.0f}ms, tunnel={result.tunnel_ok})")
            return proto
        else:
            log.debug(f"  → {proto} failed: {result.error}")

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
