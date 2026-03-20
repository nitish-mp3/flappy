#!/usr/bin/env python3
"""
KNX/IP UDP Responder
====================
Listens on the same port as the TCP proxy (UDP) and answers KNXnet/IP
DESCRIPTION_REQUEST frames with a valid DESCRIPTION_RESPONSE.

Why this exists:
  xknx (the library used by HA's KNX integration) always sends a UDP
  DESCRIPTION_REQUEST to whatever host:port you configure — even when
  "TCP Tunneling v2" mode is selected in the UI.  If no UDP response
  arrives within 2 seconds the whole connection attempt fails before
  any TCP connection is ever made.

  This script intercepts that probe, replies with a minimal but spec-
  compliant DESCRIPTION_RESPONSE that advertises TCP Tunneling v2
  support, then xknx proceeds to open the TCP connection which
  HAProxy handles normally.

  All other UDP frames are silently dropped — we are not a KNX router.
"""

import socket
import struct
import sys
import os
import logging
import time

# ---------------------------------------------------------------------------
# KNX/IP frame constants (KNX spec 3.8.2)
# ---------------------------------------------------------------------------
KNXIP_MAGIC          = bytes([0x06, 0x10])   # header size 6, protocol version 1.0
DESCRIPTION_REQUEST  = bytes([0x02, 0x03])   # service type: DESCRIPTION_REQUEST
DESCRIPTION_RESPONSE = bytes([0x02, 0x04])   # service type: DESCRIPTION_RESPONSE

# Pre-built DESCRIPTION_RESPONSE body (64 bytes):
#   DIB 1 – DEVICE_INFO      (54 bytes): medium TP, virtual addr 15.15.0
#   DIB 2 – SERVICE_FAMILIES (10 bytes): Core v2, DevMgmt v2, Tunnelling v2+v1
_DIB_DEVICE_INFO = bytes([
    0x36,       # struct length = 54
    0x01,       # DIB type: DEVICE_INFO
    0x02,       # KNX medium: TP
    0x00,       # device status: OK
    0xFF, 0x00, # individual address 15.15.0 (proxy virtual)
    0x00, 0x00, # project installation ID
    0xAA, 0xBB, 0xCC, 0x00, 0x01, 0x02,  # serial number (6 bytes)
    0xE0, 0x00, 0x17, 0x0C,              # multicast 224.0.23.12 (4 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # MAC address (6 bytes)
])
_name = b'KNX Failover Proxy\x00'
_DIB_DEVICE_INFO += _name + bytes(30 - len(_name))  # friendly name padded to 30 bytes

_DIB_SERVICES = bytes([
    0x0A,       # struct length = 10
    0x02,       # DIB type: SUPPORTED_SERVICE_FAMILIES
    0x02, 0x02, # KNXnet/IP Core, version 2
    0x03, 0x02, # KNXnet/IP Device Management, version 2
    0x04, 0x02, # KNXnet/IP Tunnelling, version 2  ← TCP
    0x04, 0x01, # KNXnet/IP Tunnelling, version 1  ← UDP
])

_RESPONSE_BODY = _DIB_DEVICE_INFO + _DIB_SERVICES
_RESPONSE_TOTAL_LEN = struct.pack('>H', 6 + len(_RESPONSE_BODY))
DESCRIPTION_RESPONSE_FRAME = (
    KNXIP_MAGIC + DESCRIPTION_RESPONSE + _RESPONSE_TOTAL_LEN + _RESPONSE_BODY
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_level_str = os.environ.get('LOG_LEVEL', 'info').upper()
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(
    level=log_level,
    format='%(asctime)s [UDP]  %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('knx_udp')

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def is_description_request(data: bytes) -> bool:
    """Return True if this UDP datagram is a KNXnet/IP DESCRIPTION_REQUEST."""
    if len(data) < 6:
        return False
    if data[0:2] != KNXIP_MAGIC:
        return False
    if data[2:4] != DESCRIPTION_REQUEST:
        return False
    return True


def run(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass  # SO_REUSEPORT not available on all kernels

    sock.bind(('0.0.0.0', port))
    sock.settimeout(1.0)  # allows clean shutdown via KeyboardInterrupt

    log.info(f"KNX/IP UDP responder listening on port {port}/udp")
    log.info(f"DESCRIPTION_RESPONSE frame ready ({len(DESCRIPTION_RESPONSE_FRAME)} bytes)")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            continue
        except OSError as e:
            log.error(f"Socket error: {e}")
            time.sleep(1)
            continue

        if is_description_request(data):
            log.info(f"DESCRIPTION_REQUEST from {addr[0]}:{addr[1]} — sending response")
            try:
                sent = sock.sendto(DESCRIPTION_RESPONSE_FRAME, addr)
                log.debug(f"Sent {sent} bytes to {addr[0]}:{addr[1]}")
            except OSError as e:
                log.error(f"Failed to send DESCRIPTION_RESPONSE to {addr}: {e}")
        else:
            # Log unknown frames at debug level only — don't spam on discovery traffic
            if len(data) >= 4:
                svc = data[2:4].hex() if len(data) >= 4 else '??'
                log.debug(f"Ignoring UDP frame from {addr[0]}:{addr[1]}: service=0x{svc}")


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3672
    try:
        run(port)
    except KeyboardInterrupt:
        log.info("UDP responder shutting down")