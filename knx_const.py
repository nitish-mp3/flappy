#!/usr/bin/env python3
"""
KNX/IP Protocol Constants & Frame Helpers
==========================================
Shared constants, frame builders, and parsers used by all proxy modules.
"""

import socket
import struct
from typing import Optional, Tuple

# ── Version ───────────────────────────────────────────────────────────
VERSION = "4.2.8"

# ── File Paths ────────────────────────────────────────────────────────
BACKEND_FILE        = "/run/knx-active-backend"
BACKEND_REJECT_FILE = "/run/knx-backend-reject"
STATE_FILE          = "/run/knx-failover.state"
METRICS_FILE        = "/run/knx-metrics.json"

# ── KNXnet/IP Frame ──────────────────────────────────────────────────
MAGIC = b'\x06\x10'
HEADER_SIZE = 6

# ── Service Types ─────────────────────────────────────────────────────
SEARCH_REQ        = 0x0201
SEARCH_RESP       = 0x0202
DESCRIPTION_REQ   = 0x0203
DESCRIPTION_RESP  = 0x0204
CONNECT_REQ       = 0x0205
CONNECT_RESP      = 0x0206
CONNSTATE_REQ     = 0x0207
CONNSTATE_RESP    = 0x0208
DISCONNECT_REQ    = 0x0209
DISCONNECT_RESP   = 0x020A
SEARCH_REQ_EXT    = 0x020B
SEARCH_RESP_EXT   = 0x020C

# Tunnelling
TUNNELLING_REQ    = 0x0420
TUNNELLING_ACK    = 0x0421

# Secure (KNX IP Secure extension)
SECURE_WRAPPER         = 0x0950
SECURE_SESSION_REQ     = 0x0951
SECURE_SESSION_RESP    = 0x0952
SECURE_SESSION_AUTH    = 0x0953
SECURE_SESSION_STATUS  = 0x0954
SECURE_TIMER_NOTIFY    = 0x0955

# ── HPAI Protocol Codes ──────────────────────────────────────────────
PROTO_UDP = 0x01   # IPV4_UDP per EN 13321-2
PROTO_TCP = 0x02   # IPV4_TCP per EN 13321-2

# ── CONNECT Status Codes ─────────────────────────────────────────────
E_NO_ERROR           = 0x00
E_HOST_PROTOCOL      = 0x01
E_VERSION_NOT_SUPP   = 0x02
E_SEQ_NUMBER         = 0x04
E_CONNTYPE_NOT_SUPP  = 0x22
E_CONN_OPTION        = 0x23
E_NO_MORE_CONNS      = 0x24
E_NO_MORE_UNIQUE_IDS = 0x25
E_DATA_CONN          = 0x26
E_KNX_CONN           = 0x27
E_TUNNELLING_LAYER   = 0x29

# Status codes that indicate a hard rejection (not transient)
HARD_REJECT_CODES = {E_CONNTYPE_NOT_SUPP, E_DATA_CONN, E_TUNNELLING_LAYER}

# ── CRI (Connection Request Information) variants ─────────────────────
CRI_TUNNEL_V1 = b'\x04\x04\x02\x00'   # Tunnelling v1 (link layer)
CRI_TUNNEL_V2 = b'\x04\x04\x04\x00'   # Tunnelling v2 (raw)
CRI_TUNNEL_EX = b'\x04\x04\x02\x01'   # Vendor-specific variant

# ── Common CRD (Connection Response Data) ─────────────────────────────
CRD_DEFAULT = b'\x04\x04\x00\x00'

# ── Service name map (for logging) ────────────────────────────────────
SERVICE_NAMES = {
    SEARCH_REQ:       "SEARCH_REQUEST",
    SEARCH_RESP:      "SEARCH_RESPONSE",
    DESCRIPTION_REQ:  "DESCRIPTION_REQUEST",
    DESCRIPTION_RESP: "DESCRIPTION_RESPONSE",
    CONNECT_REQ:      "CONNECT_REQUEST",
    CONNECT_RESP:     "CONNECT_RESPONSE",
    CONNSTATE_REQ:    "CONNECTIONSTATE_REQUEST",
    CONNSTATE_RESP:   "CONNECTIONSTATE_RESPONSE",
    DISCONNECT_REQ:   "DISCONNECT_REQUEST",
    DISCONNECT_RESP:  "DISCONNECT_RESPONSE",
    SEARCH_REQ_EXT:   "SEARCH_REQUEST_EXT",
    SEARCH_RESP_EXT:  "SEARCH_RESPONSE_EXT",
    TUNNELLING_REQ:   "TUNNELLING_REQUEST",
    TUNNELLING_ACK:   "TUNNELLING_ACK",
    SECURE_WRAPPER:        "SECURE_WRAPPER",
    SECURE_SESSION_REQ:    "SECURE_SESSION_REQUEST",
    SECURE_SESSION_RESP:   "SECURE_SESSION_RESPONSE",
    SECURE_SESSION_AUTH:   "SECURE_SESSION_AUTH",
    SECURE_SESSION_STATUS: "SECURE_SESSION_STATUS",
    SECURE_TIMER_NOTIFY:   "SECURE_TIMER_NOTIFY",
}

def svc_name(svc: int) -> str:
    """Return human-readable name for a KNX service type."""
    return SERVICE_NAMES.get(svc, f"0x{svc:04x}")


# ═══════════════════════════════════════════════════════════════════════
# Frame helpers
# ═══════════════════════════════════════════════════════════════════════

def make_frame(svc: int, body: bytes) -> bytes:
    """Build a complete KNXnet/IP frame."""
    return MAGIC + struct.pack('>HH', svc, HEADER_SIZE + len(body)) + body


def make_hpai(ip: str, port: int, proto: int = PROTO_UDP) -> bytes:
    """Build an 8-byte HPAI (Host Protocol Address Information) block."""
    try:
        ip_bytes = socket.inet_aton(ip)
    except OSError:
        ip_bytes = b'\x00\x00\x00\x00'
    return bytes([8, proto]) + ip_bytes + struct.pack('>H', port)


def parse_hpai(data: bytes, off: int) -> Tuple[str, int, int, int]:
    """
    Parse an HPAI starting at offset `off`.
    Returns (ip, port, proto, next_offset).
    """
    if off + 8 > len(data):
        return '0.0.0.0', 0, PROTO_UDP, off + 8
    length = data[off]
    proto  = data[off + 1]
    ip     = socket.inet_ntoa(data[off + 2:off + 6])
    port   = struct.unpack('>H', data[off + 6:off + 8])[0]
    return ip, port, proto, off + length


def parse_frame(data: bytes) -> Tuple[Optional[int], Optional[bytes]]:
    """
    Parse a KNXnet/IP frame from raw bytes.
    Returns (service_type, body) or (None, None) if invalid.
    """
    if len(data) < HEADER_SIZE or data[:2] != MAGIC:
        return None, None
    svc   = struct.unpack('>H', data[2:4])[0]
    total = struct.unpack('>H', data[4:6])[0]
    if total < HEADER_SIZE or total > len(data):
        return None, None
    return svc, data[HEADER_SIZE:total]


def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Read exactly `n` bytes from a TCP socket.

    Raises socket.timeout so callers can handle timeouts
    without desynchronizing the TCP stream.
    """
    buf = b''
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise  # Caller must handle — partial read would desync stream
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def read_tcp_frame(sock: socket.socket) -> Tuple[Optional[int], Optional[bytes]]:
    """Read one complete KNXnet/IP frame from a TCP stream."""
    hdr = recv_exact(sock, HEADER_SIZE)
    if not hdr or hdr[:2] != MAGIC:
        return None, None
    svc   = struct.unpack('>H', hdr[2:4])[0]
    total = struct.unpack('>H', hdr[4:6])[0]
    if total < HEADER_SIZE:
        return None, None
    body = recv_exact(sock, total - HEADER_SIZE)
    if body is None:
        return None, None
    return svc, body


def tunnel_channel_id(body: bytes) -> int:
    """Extract channel_id from a TUNNELLING_REQ/ACK body.

    Body layout (connection header):
      body[0] = structure length (0x04)
      body[1] = communication channel ID
      body[2] = sequence counter
      body[3] = reserved
    """
    return body[1] if len(body) >= 4 else 0


def valid_desc_response(data: bytes) -> bool:
    """Check if raw bytes are a valid KNXnet/IP DESCRIPTION_RESPONSE."""
    if len(data) < HEADER_SIZE:
        return False
    if data[:2] != MAGIC:
        return False
    svc = struct.unpack('>H', data[2:4])[0]
    total = struct.unpack('>H', data[4:6])[0]
    if svc != DESCRIPTION_RESP:
        return False
    if total < HEADER_SIZE or len(data) < total:
        return False
    return True
