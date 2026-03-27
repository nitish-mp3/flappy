#!/usr/bin/env python3
"""
KNX USB HID Transport — Native USB Interface
===============================================
Direct communication with KNX USB interfaces via USB HID protocol.
Replaces knxd for USB access when knxd is not available.

Architecture:
  KNX Bus ←→ [USB KNX Interface] ←→ [This Module] ←→ [Local KNXnet/IP]
                                        (HID cEMI)       (127.0.0.1:port)

The module exposes the USB device as a local KNXnet/IP tunnelling endpoint,
so the proxy treats it exactly like any other IP backend.

Usage:
  # Discovery mode (used by pre-flight script):
  python3 knx_usb.py --discover

  # Bridge mode (used by run.sh):
  python3 knx_usb.py --bridge /dev/bus/usb/003/012 --port 13671
"""

import os
import sys
import json
import time
import struct
import socket
import signal
import logging
import threading
from typing import Optional, List, Dict, Tuple

log = logging.getLogger('knx_usb')

# ── Try to import pyusb ──────────────────────────────────────────────
_PYUSB_AVAILABLE = False
try:
    import usb.core
    import usb.util
    _PYUSB_AVAILABLE = True
except ImportError:
    pass

# ═══════════════════════════════════════════════════════════════════════
# Known KNX USB Device Identifiers
# ═══════════════════════════════════════════════════════════════════════

KNOWN_KNX_DEVICES = [
    # (vendor_id, product_id, vendor_name, description)
    (0x0908, 0x02DC, "Siemens", "OCI702 KNX USB Interface"),
    (0x0681, 0x0014, "Siemens", "N148 KNX/LPB Bus Interface"),
    (0x28C2, 0x0001, "Weinzierl", "KNX USB Interface 312"),
    (0x28C2, 0x0002, "Weinzierl", "KNX USB Interface Stick 332"),
    (0x28C2, 0x0003, "Weinzierl", "KNX USB Interface 330"),
    (0x28C2, 0x0004, "Weinzierl", "KNX USB Interface 320"),
    (0x28C2, 0x0005, "Weinzierl", "KNX USB Interface 312.1"),
    (0x147B, 0x5120, "ABB", "USB/S1.2 KNX USB Interface"),
    (0x135E, 0x0026, "Hager", "TYFS122 KNX USB Interface"),
]

# Generic HID class for fallback detection
KNX_HID_USAGE_PAGE = 0xFF00  # Vendor-defined HID usage page for KNX


# ═══════════════════════════════════════════════════════════════════════
# KNX USB HID Protocol Constants
# ═══════════════════════════════════════════════════════════════════════

# HID Report structure (64 bytes max per EN 13321-2)
HID_REPORT_SIZE = 64
HID_REPORT_ID = 0x01  # KNX data report

# KNX USB Transfer Protocol Header
KNX_USB_HEADER_SIZE = 8
KNX_USB_PROTOCOL_VERSION = 0x00
KNX_USB_HEADER_LENGTH = 0x08

# EMI types
EMI_CEMI = 0x03  # cEMI message

# KNX USB Service IDs
USB_SVC_TUNNEL = 0x0001        # Tunnelling
USB_SVC_BUSMON = 0x0002        # Bus monitor
USB_SVC_CONFIG = 0x0003        # Configuration
USB_SVC_DEVICE_FEAT = 0x0004   # Device feature

# cEMI Message Codes
CEMI_L_DATA_REQ = 0x11     # L_Data.req
CEMI_L_DATA_CON = 0x2E     # L_Data.con
CEMI_L_DATA_IND = 0x29     # L_Data.ind

# Feature IDs for device queries
FEAT_DEVICE_DESCRIPTOR = 0x01
FEAT_SERIAL_NUMBER = 0x06
FEAT_BUS_STATUS = 0x05


class KNXUSBDevice:
    """Represents a discovered KNX USB device."""

    __slots__ = ['bus', 'address', 'vendor_id', 'product_id',
                 'vendor_name', 'product_name', 'serial_number',
                 'device_path', 'usb_device']

    def __init__(self):
        self.bus: int = 0
        self.address: int = 0
        self.vendor_id: int = 0
        self.product_id: int = 0
        self.vendor_name: str = ""
        self.product_name: str = ""
        self.serial_number: str = ""
        self.device_path: str = ""
        self.usb_device = None  # usb.core.Device reference

    def to_dict(self) -> dict:
        return {
            'bus': self.bus,
            'address': self.address,
            'vendor_id': f"0x{self.vendor_id:04x}",
            'product_id': f"0x{self.product_id:04x}",
            'vendor': self.vendor_name,
            'product': self.product_name,
            'serial': self.serial_number,
            'path': self.device_path,
        }

    def __repr__(self):
        return (f"KNXUSBDevice({self.vendor_name} {self.product_name} "
                f"serial={self.serial_number} path={self.device_path})")


# ═══════════════════════════════════════════════════════════════════════
# USB Discovery
# ═══════════════════════════════════════════════════════════════════════

def discover_knx_devices() -> List[KNXUSBDevice]:
    """
    Discover all KNX USB interfaces connected to the system.
    Returns a list of KNXUSBDevice objects.

    Uses two strategies:
    1. Match against known vendor/product ID database
    2. Scan all HID devices for KNX-compatible descriptors
    """
    if not _PYUSB_AVAILABLE:
        log.warning("pyusb not available — cannot discover USB devices")
        return []

    devices = []
    seen = set()  # (bus, address) pairs to avoid duplicates

    # Strategy 1: Known device database
    for vid, pid, vendor, desc in KNOWN_KNX_DEVICES:
        try:
            for dev in usb.core.find(find_all=True, idVendor=vid, idProduct=pid):
                key = (dev.bus, dev.address)
                if key in seen:
                    continue
                seen.add(key)

                knx_dev = KNXUSBDevice()
                knx_dev.bus = dev.bus
                knx_dev.address = dev.address
                knx_dev.vendor_id = vid
                knx_dev.product_id = pid
                knx_dev.vendor_name = vendor
                knx_dev.product_name = desc
                knx_dev.device_path = f"/dev/bus/usb/{dev.bus:03d}/{dev.address:03d}"
                knx_dev.usb_device = dev

                # Try to read serial number
                try:
                    knx_dev.serial_number = usb.util.get_string(dev, dev.iSerialNumber) or ""
                except Exception:
                    knx_dev.serial_number = ""

                devices.append(knx_dev)
                log.info(f"Found KNX device: {vendor} {desc} "
                         f"(serial={knx_dev.serial_number}) at {knx_dev.device_path}")
        except usb.core.USBError as e:
            log.debug(f"USB scan error for {vid:04x}:{pid:04x}: {e}")
        except Exception:
            pass

    # Strategy 2: Scan all HID devices with vendor-defined usage
    if not devices:
        log.debug("No known devices found, scanning all HID class devices...")
        try:
            for dev in usb.core.find(find_all=True, bDeviceClass=0x00):
                key = (dev.bus, dev.address)
                if key in seen:
                    continue

                # Check if any interface is HID class (0x03)
                try:
                    cfg = dev.get_active_configuration()
                    if cfg is None:
                        continue
                    has_hid = any(
                        intf.bInterfaceClass == 0x03
                        for intf in cfg
                    )
                    if not has_hid:
                        continue
                except Exception:
                    continue

                seen.add(key)
                knx_dev = KNXUSBDevice()
                knx_dev.bus = dev.bus
                knx_dev.address = dev.address
                knx_dev.vendor_id = dev.idVendor
                knx_dev.product_id = dev.idProduct
                knx_dev.vendor_name = "Unknown"
                knx_dev.product_name = "HID Device (possible KNX)"
                knx_dev.device_path = f"/dev/bus/usb/{dev.bus:03d}/{dev.address:03d}"
                knx_dev.usb_device = dev

                try:
                    knx_dev.serial_number = usb.util.get_string(dev, dev.iSerialNumber) or ""
                except Exception:
                    knx_dev.serial_number = ""

                try:
                    name = usb.util.get_string(dev, dev.iProduct) or ""
                    knx_dev.product_name = name if name else knx_dev.product_name
                except Exception:
                    pass

                try:
                    vname = usb.util.get_string(dev, dev.iManufacturer) or ""
                    knx_dev.vendor_name = vname if vname else knx_dev.vendor_name
                except Exception:
                    pass

                devices.append(knx_dev)
                log.info(f"Found HID device: {knx_dev.vendor_name} "
                         f"{knx_dev.product_name} at {knx_dev.device_path}")
        except Exception as e:
            log.debug(f"HID scan error: {e}")

    return devices


# ═══════════════════════════════════════════════════════════════════════
# KNX USB HID Transport
# ═══════════════════════════════════════════════════════════════════════

class KNXUSBTransport:
    """
    Handles low-level KNX USB HID communication.
    Sends/receives KNX cEMI frames via USB HID interrupt transfers.
    """

    def __init__(self, device_path: str = "", usb_device=None):
        self.device_path = device_path
        self.dev = usb_device
        self.ep_in = None    # Interrupt IN endpoint
        self.ep_out = None   # Interrupt OUT endpoint
        self.interface = None
        self.running = False
        self._lock = threading.Lock()

    def open(self) -> bool:
        """Open and configure the USB device."""
        if not _PYUSB_AVAILABLE:
            log.error("pyusb not available")
            return False

        try:
            # Find the device if not provided
            if self.dev is None:
                if not self.device_path:
                    log.error("No device path specified")
                    return False
                # Parse /dev/bus/usb/BBB/DDD
                parts = self.device_path.split('/')
                if len(parts) >= 5:
                    bus = int(parts[4])
                    addr = int(parts[5]) if len(parts) > 5 else None
                    for dev in usb.core.find(find_all=True):
                        if dev.bus == bus and (addr is None or dev.address == addr):
                            self.dev = dev
                            break

            if self.dev is None:
                log.error(f"USB device not found: {self.device_path}")
                return False

            # Reset the device first to release any stale claims
            try:
                self.dev.reset()
                log.debug("USB device reset")
            except (usb.core.USBError, NotImplementedError) as e:
                log.debug(f"USB reset skipped: {e}")

            # Detach kernel drivers from ALL interfaces (not just 0)
            # The HID driver (usbhid) may be bound to any interface
            try:
                cfg = self.dev.get_active_configuration()
                if cfg is None:
                    self.dev.set_configuration()
                    cfg = self.dev.get_active_configuration()
            except usb.core.USBError:
                try:
                    self.dev.set_configuration()
                    cfg = self.dev.get_active_configuration()
                except usb.core.USBError as e:
                    log.error(f"Cannot configure USB device: {e}")
                    return False

            for intf in cfg:
                intf_num = intf.bInterfaceNumber
                try:
                    if self.dev.is_kernel_driver_active(intf_num):
                        self.dev.detach_kernel_driver(intf_num)
                        log.debug(f"Detached kernel driver from interface {intf_num}")
                except (usb.core.USBError, NotImplementedError) as e:
                    log.debug(f"Could not detach kernel driver from interface {intf_num}: {e}")

            # Find HID interface and endpoints
            for intf in cfg:
                if intf.bInterfaceClass == 0x03:  # HID class
                    self.interface = intf
                    break

            if self.interface is None:
                log.error("No HID interface found on device")
                return False

            # Claim the interface
            try:
                usb.util.claim_interface(self.dev, self.interface)
            except usb.core.USBError as e:
                log.error(f"Cannot claim interface {self.interface.bInterfaceNumber}: {e}")
                return False

            # Find IN and OUT endpoints
            for ep in self.interface:
                if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                    self.ep_in = ep
                elif usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT:
                    self.ep_out = ep

            if self.ep_in is None:
                log.error("No interrupt IN endpoint found")
                return False

            self.running = True
            log.info(f"USB device opened: {self.device_path} "
                     f"(IN=0x{self.ep_in.bEndpointAddress:02x}"
                     f"{', OUT=0x' + format(self.ep_out.bEndpointAddress, '02x') if self.ep_out else ', no OUT'})")
            return True

        except Exception as e:
            log.error(f"Failed to open USB device: {e}")
            return False

    def close(self):
        """Close the USB device and re-attach kernel drivers."""
        self.running = False
        if self.dev and self.interface:
            intf_num = self.interface.bInterfaceNumber
            try:
                usb.util.release_interface(self.dev, self.interface)
            except Exception:
                pass
            # Re-attach kernel driver so the device is usable again
            try:
                self.dev.attach_kernel_driver(intf_num)
            except Exception:
                pass
            try:
                usb.util.dispose_resources(self.dev)
            except Exception:
                pass
        self.dev = None
        log.info("USB device closed")

    def send_cemi(self, cemi_data: bytes) -> bool:
        """Send a cEMI frame to the KNX bus via USB HID."""
        report = self._build_hid_report(cemi_data)
        return self._write_report(report)

    def recv_cemi(self, timeout_ms: int = 1000) -> Optional[bytes]:
        """Receive a cEMI frame from the KNX bus via USB HID."""
        report = self._read_report(timeout_ms)
        if report is None:
            return None
        return self._parse_hid_report(report)

    def is_connected(self) -> bool:
        """Check if the USB device is still connected."""
        if not self.dev or not self.running:
            return False
        try:
            # Try a control transfer to check presence
            self.dev.ctrl_transfer(0x80, 0x06, 0x0100, 0, 64)
            return True
        except usb.core.USBError:
            return False
        except Exception:
            return False

    # ── HID Report Framing ────────────────────────────────────────────

    def _build_hid_report(self, cemi_data: bytes) -> bytes:
        """
        Build a 64-byte KNX USB HID report containing a cEMI frame.

        Format (per EN 13321-2):
        Byte 0:     Report ID (0x01)
        Byte 1:     Packet info (reserved | sequence)
        Byte 2-3:   Data length (of KNX USB Transfer Protocol data)
        Byte 4:     Protocol version (0x00)
        Byte 5:     Header length (0x08)
        Byte 6-7:   Body length
        Byte 8:     Protocol ID (0x01 = KNX Tunnel)
        Byte 9:     EMI ID (0x03 = cEMI)
        Byte 10:    Manufacturer code MSB (0x00)
        Byte 11:    Manufacturer code LSB (0x00)
        Byte 12+:   cEMI data
        Padded to 64 bytes with 0x00
        """
        body_length = len(cemi_data)
        transfer_length = KNX_USB_HEADER_SIZE + body_length

        report = bytearray(HID_REPORT_SIZE)
        report[0] = HID_REPORT_ID
        report[1] = 0x13  # Single packet, start, end
        struct.pack_into('>H', report, 2, transfer_length)
        report[4] = KNX_USB_PROTOCOL_VERSION
        report[5] = KNX_USB_HEADER_LENGTH
        struct.pack_into('>H', report, 6, body_length)
        report[8] = 0x01  # Protocol ID: KNX Tunnel
        report[9] = EMI_CEMI
        report[10] = 0x00  # Manufacturer MSB
        report[11] = 0x00  # Manufacturer LSB
        report[12:12 + body_length] = cemi_data

        return bytes(report)

    def _parse_hid_report(self, report: bytes) -> Optional[bytes]:
        """
        Parse a KNX USB HID report and extract the cEMI frame.
        Returns the cEMI data or None if invalid.
        """
        if len(report) < 12:
            return None

        report_id = report[0]
        if report_id != HID_REPORT_ID:
            return None

        # Parse KNX USB Transfer Protocol Header
        transfer_length = struct.unpack_from('>H', report, 2)[0]
        if transfer_length < KNX_USB_HEADER_SIZE:
            return None

        proto_version = report[4]
        header_length = report[5]
        body_length = struct.unpack_from('>H', report, 6)[0]
        proto_id = report[8]
        emi_id = report[9]

        if emi_id != EMI_CEMI:
            log.debug(f"Non-cEMI report (emi_id=0x{emi_id:02x})")
            return None

        if body_length == 0:
            return None

        # cEMI data starts after the 12-byte header
        cemi_start = 12
        cemi_end = cemi_start + body_length
        if cemi_end > len(report):
            cemi_end = len(report)

        return bytes(report[cemi_start:cemi_end])

    def _write_report(self, report: bytes) -> bool:
        """Write a HID report to the device."""
        with self._lock:
            try:
                if self.ep_out:
                    self.ep_out.write(report)
                else:
                    # Use control transfer as fallback (SET_REPORT)
                    self.dev.ctrl_transfer(
                        0x21,  # bmRequestType: Class, Interface, Host-to-Device
                        0x09,  # bRequest: SET_REPORT
                        0x0200 | HID_REPORT_ID,  # wValue: Report Type (Output) | Report ID
                        self.interface.bInterfaceNumber,
                        report,
                    )
                return True
            except usb.core.USBError as e:
                log.debug(f"USB write error: {e}")
                return False
            except Exception as e:
                log.debug(f"USB write exception: {e}")
                return False

    def _read_report(self, timeout_ms: int = 1000) -> Optional[bytes]:
        """Read a HID report from the device."""
        try:
            data = self.ep_in.read(HID_REPORT_SIZE, timeout=timeout_ms)
            if data is not None and len(data) > 0:
                return bytes(data)
            return None
        except usb.core.USBTimeoutError:
            return None
        except usb.core.USBError as e:
            if self.running:
                log.debug(f"USB read error: {e}")
            return None
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════
# KNXnet/IP Bridge — exposes USB as local KNXnet/IP tunnel
# ═══════════════════════════════════════════════════════════════════════

class KNXUSBBridge:
    """
    Bridges a KNX USB device to a local KNXnet/IP tunnelling endpoint.
    The proxy connects to 127.0.0.1:<port> as if it were a remote KNX gateway.

    This is the same architecture that knxd uses — the proxy doesn't know
    or care whether the backend is a real IP gateway or a USB bridge.

    Handles:
    - KNXnet/IP CONNECT/DISCONNECT negotiation
    - TUNNELLING_REQUEST/ACK relay
    - CONNECTIONSTATE_REQUEST heartbeat
    - cEMI ↔ USB HID translation
    """

    # Default individual address for tunnel connections: 15.15.250 (0xFFFA)
    # This is used in the CRD of CONNECT_RESP so the client (e.g. xknx)
    # uses it as the source address in outgoing L_Data.req frames.
    # A valid address is REQUIRED — 0.0.0 causes USB interfaces to
    # reject frames because the source doesn't match any assigned address.
    USB_TUNNEL_ADDR = b'\x04\x04\xFF\xFA'  # CRD: 15.15.250

    def __init__(self, usb_transport: KNXUSBTransport, port: int = 13671):
        self.usb = usb_transport
        self.port = port
        self.running = False
        self.server_sock: Optional[socket.socket] = None
        self.active_channel: int = 0
        self.next_channel: int = 1
        self._client_sock: Optional[socket.socket] = None
        self._client_addr = None
        self._recv_seq: int = 0
        self._send_seq: int = 0
        self._usb_reader_thread: Optional[threading.Thread] = None
        self._tunnel_crd = self.USB_TUNNEL_ADDR

    def start(self) -> bool:
        """Start the local KNXnet/IP server."""
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(('127.0.0.1', self.port))
            self.server_sock.listen(2)
            self.server_sock.settimeout(2.0)
            self.running = True

            threading.Thread(target=self._accept_loop, daemon=True,
                             name='usb-bridge-accept').start()

            # Start USB reader thread
            self._usb_reader_thread = threading.Thread(
                target=self._usb_read_loop, daemon=True, name='usb-reader')
            self._usb_reader_thread.start()

            log.info(f"KNX USB bridge listening on 127.0.0.1:{self.port}")
            return True
        except Exception as e:
            log.error(f"Failed to start USB bridge: {e}")
            return False

    def stop(self):
        """Stop the bridge."""
        self.running = False
        if self._client_sock:
            try:
                self._client_sock.close()
            except Exception:
                pass
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        log.info("KNX USB bridge stopped")

    def _accept_loop(self):
        """Accept incoming TCP connections from the proxy."""
        while self.running:
            try:
                sock, addr = self.server_sock.accept()
                log.info(f"USB bridge: client connected from {addr}")
                # Only allow one client at a time (like a real KNX interface)
                if self._client_sock:
                    try:
                        self._client_sock.close()
                    except Exception:
                        pass
                self._client_sock = sock
                self._client_sock.settimeout(120.0)
                threading.Thread(target=self._handle_client, args=(sock,),
                                 daemon=True, name='usb-bridge-client').start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log.debug(f"USB bridge accept error: {e}")
                    time.sleep(1)

    def _handle_client(self, sock: socket.socket):
        """Handle KNXnet/IP protocol with a connected client."""
        from knx_const import (
            MAGIC, HEADER_SIZE,
            CONNECT_REQ, CONNECT_RESP, CONNSTATE_REQ, CONNSTATE_RESP,
            DISCONNECT_REQ, DISCONNECT_RESP,
            TUNNELLING_REQ, TUNNELLING_ACK, DESCRIPTION_REQ, DESCRIPTION_RESP,
            PROTO_TCP, E_NO_ERROR,
            make_frame, make_hpai, parse_frame, read_tcp_frame,
        )

        try:
            while self.running and sock == self._client_sock:
                try:
                    svc, body = read_tcp_frame(sock)
                except socket.timeout:
                    continue
                if svc is None:
                    break

                if svc == DESCRIPTION_REQ:
                    # Build a simple description response
                    name = b'KNX USB Bridge\x00'
                    name = name + bytes(30 - len(name))
                    dib = (
                        b'\x36\x01\x02\x00\xff\x00\x00\x00'
                        b'\xaa\xbb\xcc\x00\x01\x03'
                        b'\xe0\x00\x17\x0c'
                        b'\x00\x00\x00\x00\x00\x00'
                    ) + name
                    dib_svc = b'\x08\x02\x02\x02\x03\x02\x04\x02'
                    resp = make_frame(DESCRIPTION_RESP, dib + dib_svc)
                    sock.sendall(resp)

                elif svc == CONNECT_REQ:
                    # Accept the connection
                    ch_id = self.next_channel
                    self.next_channel = (self.next_channel % 255) + 1
                    self.active_channel = ch_id
                    self._recv_seq = 0
                    self._send_seq = 0

                    resp_body = (
                        bytes([ch_id, E_NO_ERROR])
                        + make_hpai('0.0.0.0', 0, PROTO_TCP)
                        + self._tunnel_crd
                    )
                    sock.sendall(make_frame(CONNECT_RESP, resp_body))
                    addr_hi, addr_lo = self._tunnel_crd[2], self._tunnel_crd[3]
                    addr_str = f"{addr_hi >> 4}.{addr_hi & 0x0F}.{addr_lo}"
                    log.info(f"USB bridge: tunnel ch={ch_id} established "
                             f"(individual address {addr_str})")

                elif svc == CONNSTATE_REQ:
                    if body and len(body) >= 1:
                        ch_id = body[0]
                        # Always respond OK — we own the USB device
                        resp = make_frame(CONNSTATE_RESP, bytes([ch_id, E_NO_ERROR]))
                        sock.sendall(resp)

                elif svc == DISCONNECT_REQ:
                    if body and len(body) >= 1:
                        ch_id = body[0]
                        resp = make_frame(
                            DISCONNECT_RESP,
                            bytes([ch_id, E_NO_ERROR])
                            + make_hpai('0.0.0.0', 0, PROTO_TCP)
                        )
                        sock.sendall(resp)
                        self.active_channel = 0
                        log.info(f"USB bridge: tunnel ch={ch_id} disconnected")

                elif svc == TUNNELLING_REQ:
                    if body and len(body) >= 4:
                        # body[0:4] = connection header (length, ch_id, seq, reserved)
                        ch_id = body[1]
                        seq = body[2]

                        # Send ACK back to client
                        ack_body = bytes([4, ch_id, seq, 0x00])
                        sock.sendall(make_frame(TUNNELLING_ACK, ack_body))

                        # Extract cEMI and forward to USB
                        cemi = body[4:]
                        if len(cemi) > 0:
                            mc = cemi[0] if cemi else 0
                            ok = self.usb.send_cemi(cemi)
                            log.debug(f"USB→bus: cEMI mc=0x{mc:02X} "
                                      f"len={len(cemi)} {'OK' if ok else 'FAIL'}")

                elif svc == TUNNELLING_ACK:
                    # Client acknowledged our TUNNELLING_REQUEST — nothing to do
                    pass

        except Exception as e:
            if self.running:
                log.debug(f"USB bridge client handler: {e}")
        finally:
            if sock == self._client_sock:
                self._client_sock = None
            try:
                sock.close()
            except Exception:
                pass
            log.info("USB bridge: client disconnected")

    def _usb_read_loop(self):
        """Read cEMI frames from USB and forward to connected client."""
        from knx_const import (
            TUNNELLING_REQ, make_frame,
        )

        while self.running:
            if not self.usb.running:
                time.sleep(1)
                continue

            cemi = self.usb.recv_cemi(timeout_ms=500)
            if cemi is None:
                continue

            mc = cemi[0] if cemi else 0
            log.debug(f"bus→USB: cEMI mc=0x{mc:02X} len={len(cemi)}")

            # Only forward if we have an active tunnel and client
            if self.active_channel == 0 or self._client_sock is None:
                continue

            # Build TUNNELLING_REQUEST to send to the client
            conn_header = bytes([4, self.active_channel, self._send_seq & 0xFF, 0x00])
            frame = make_frame(TUNNELLING_REQ, conn_header + cemi)
            self._send_seq = (self._send_seq + 1) & 0xFF

            try:
                self._client_sock.sendall(frame)
            except Exception as e:
                log.debug(f"USB bridge: failed to forward to client: {e}")

    def is_alive(self) -> bool:
        """Check if the bridge is running and USB is connected."""
        return self.running and self.usb.is_connected()


# ═══════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    if len(sys.argv) < 2:
        print("Usage:")
        print("  knx_usb.py --discover            # List KNX USB devices")
        print("  knx_usb.py --bridge PATH --port N # Start USB-to-KNXnet/IP bridge")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == '--discover':
        devices = discover_knx_devices()
        if not devices:
            print(json.dumps({"devices": [], "count": 0}))
            sys.exit(0)

        result = {
            "devices": [d.to_dict() for d in devices],
            "count": len(devices),
        }
        print(json.dumps(result, indent=2))
        sys.exit(0)

    elif mode == '--bridge':
        if len(sys.argv) < 3:
            print("Error: --bridge requires device path")
            sys.exit(1)

        device_path = sys.argv[2]
        port = 13671
        if '--port' in sys.argv:
            port_idx = sys.argv.index('--port')
            if port_idx + 1 < len(sys.argv):
                port = int(sys.argv[port_idx + 1])

        log.info(f"Starting KNX USB bridge: {device_path} → 127.0.0.1:{port}")

        # Open USB device
        transport = KNXUSBTransport(device_path=device_path)
        if not transport.open():
            log.error("Failed to open USB device")
            sys.exit(1)

        # Start bridge
        bridge = KNXUSBBridge(transport, port)
        if not bridge.start():
            transport.close()
            log.error("Failed to start bridge")
            sys.exit(1)

        # Write PID file
        pid_file = "/run/knx-usb-bridge.pid"
        try:
            with open(pid_file, 'w') as f:
                f.write(str(os.getpid()))
        except Exception:
            pass

        # Handle signals
        def stop_handler(*_):
            bridge.stop()
            transport.close()
            sys.exit(0)

        signal.signal(signal.SIGTERM, stop_handler)
        signal.signal(signal.SIGINT, stop_handler)

        # Run watchdog loop
        try:
            while bridge.is_alive():
                time.sleep(2)
        except KeyboardInterrupt:
            pass

        log.warning("USB device disconnected or bridge stopped")
        bridge.stop()
        transport.close()
        sys.exit(1)  # Non-zero exit signals run.sh to failover

    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)


if __name__ == '__main__':
    main()
