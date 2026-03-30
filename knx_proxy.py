#!/usr/bin/env python3
"""
KNX/IP Failover Proxy  v4.1.3
===============================
Production-grade KNX/IP tunnelling proxy with:
  - TCP ↔ TCP, TCP ↔ UDP, UDP ↔ TCP, UDP ↔ UDP
  - KNX IP Secure tunnelling support
  - Graceful session draining on failover
  - Per-session metrics and JSON state
  - Structured logging

Architecture:
  HA / xknx  ←→  [KNX Proxy Frontend]  ←→  [Backend Connector]  ←→  KNX Interface
                      (TCP + UDP)              (TCP or UDP)
"""

import socket
import struct
import threading
import time
import logging
import os
import sys
import signal
import json
from typing import Optional, Tuple

from knx_const import (
    VERSION, MAGIC, HEADER_SIZE,
    PROTO_UDP, PROTO_TCP,
    SEARCH_REQ, SEARCH_RESP, DESCRIPTION_REQ, DESCRIPTION_RESP,
    CONNECT_REQ, CONNECT_RESP, CONNSTATE_REQ, CONNSTATE_RESP,
    DISCONNECT_REQ, DISCONNECT_RESP,
    SEARCH_REQ_EXT, SEARCH_RESP_EXT,
    TUNNELLING_REQ, TUNNELLING_ACK,
    SECURE_WRAPPER, SECURE_SESSION_REQ, SECURE_SESSION_RESP,
    SECURE_SESSION_AUTH, SECURE_SESSION_STATUS,
    E_NO_ERROR, E_NO_MORE_CONNS, E_DATA_CONN, HARD_REJECT_CODES,
    CRD_DEFAULT,
    make_frame, make_hpai, parse_hpai, parse_frame,
    read_tcp_frame, tunnel_channel_id, svc_name, BACKEND_FILE,
)
from knx_session import (
    Session, SessionManager,
    read_backend, report_backend_reject, clear_backend_reject,
)
from knx_transport import UDPTransport, TCPTransport, BackendConnector
from knx_secure import is_secure_available, SecureSession, SecureSessionManager

# ── Configuration from environment ────────────────────────────────────
FRONTEND_MODE = os.environ.get('FRONTEND_PROTOCOL', 'both').strip().lower()
if FRONTEND_MODE not in ('udp', 'tcp', 'both'):
    raise SystemExit(f"Invalid FRONTEND_PROTOCOL={FRONTEND_MODE!r}")

ENABLE_UDP = FRONTEND_MODE in ('udp', 'both')
ENABLE_TCP = FRONTEND_MODE in ('tcp', 'both')

# Session config from env (set by run.sh)
MAX_SESSIONS     = int(os.environ.get('MAX_SESSIONS', '8'))
SESSION_TIMEOUT  = int(os.environ.get('SESSION_TIMEOUT', '120'))
DRAIN_TIMEOUT    = int(os.environ.get('DRAIN_TIMEOUT', '5'))

# Secure config
PRIMARY_SECURE      = os.environ.get('PRIMARY_SECURE', 'false').lower() == 'true'
BACKUP_SECURE       = os.environ.get('BACKUP_SECURE', 'false').lower() == 'true'
PRIMARY_DEVICE_PW   = os.environ.get('PRIMARY_DEVICE_PASSWORD', '')
PRIMARY_USER_PW     = os.environ.get('PRIMARY_USER_PASSWORD', '')
PRIMARY_USER_ID     = int(os.environ.get('PRIMARY_USER_ID', '1'))
BACKUP_DEVICE_PW    = os.environ.get('BACKUP_DEVICE_PASSWORD', '')
BACKUP_USER_PW      = os.environ.get('BACKUP_USER_PASSWORD', '')
BACKUP_USER_ID      = int(os.environ.get('BACKUP_USER_ID', '1'))

# ── Logging ───────────────────────────────────────────────────────────
_lvl = os.environ.get('LOG_LEVEL', 'info').upper()
logging.basicConfig(
    level=getattr(logging, _lvl, logging.INFO),
    format='%(asctime)s [%(name)s] %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('knx_proxy')

# Quiet down some noisy loggers at non-debug levels
if _lvl != 'DEBUG':
    logging.getLogger('knx_transport').setLevel(logging.INFO)
    logging.getLogger('knx_session').setLevel(logging.INFO)
    logging.getLogger('knx_health').setLevel(logging.INFO)
    logging.getLogger('knx_secure').setLevel(logging.INFO)


# ═══════════════════════════════════════════════════════════════════════
# DIB / Description Response Builder
# ═══════════════════════════════════════════════════════════════════════

def _build_dib_payload() -> bytes:
    """Build the Device Information Block + Service Families DIB."""
    name = b'KNX Failover Proxy\x00'
    name = name + bytes(30 - len(name))

    dib_device = (
        b'\x36\x01'           # length=54, type=DEVICE_INFO
        b'\x02\x00'           # medium=TP, status=OK
        b'\xff\x00'           # individual address 15.15.0
        b'\x00\x00'           # project installation ID
        b'\xaa\xbb\xcc\x00\x01\x02'  # serial number
        b'\xe0\x00\x17\x0c'   # multicast 224.0.23.12
        b'\x00\x00\x00\x00\x00\x00'  # MAC
    ) + name

    # Build service families based on frontend mode
    if FRONTEND_MODE == 'udp':
        dib_svc = b'\x08\x02\x02\x02\x03\x02\x04\x01'  # Tunnelling v1 (UDP)
    elif FRONTEND_MODE == 'tcp':
        dib_svc = b'\x08\x02\x02\x02\x03\x02\x04\x02'  # Tunnelling v2 (TCP)
    else:
        dib_svc = b'\x0a\x02\x02\x02\x03\x02\x04\x02\x04\x01'  # Both v1 + v2

    return dib_device + dib_svc


DIB_PAYLOAD = _build_dib_payload()
DESCRIPTION_RESPONSE = make_frame(DESCRIPTION_RESP, DIB_PAYLOAD)


def build_search_resp(port: int, svc: int, proto: int) -> bytes:
    """Build a SEARCH_RESPONSE with HPAI + DIB."""
    body = make_hpai('0.0.0.0', port, proto) + DIB_PAYLOAD
    return make_frame(svc, body)


# ═══════════════════════════════════════════════════════════════════════
# KNX Proxy
# ═══════════════════════════════════════════════════════════════════════

class KNXProxy:
    """
    Main KNX/IP proxy engine.
    Accepts connections from HA on the frontend (TCP+UDP),
    routes them to the active backend KNX interface.
    """

    # Class-level cache of individual addresses (hi, lo) known to be KNX IP
    # Secure slots on the backend.  Persists across sessions so that on the
    # SECOND connection we proactively request a non-secure slot BEFORE
    # sending CONNECT_RESP to the client (preventing individual address
    # mismatch from the very first frame).
    _known_secure_ias: set = set()

    def __init__(self, port: int):
        self.port = port
        self.running = True

        # Session management
        self.sessions = SessionManager(
            max_sessions=MAX_SESSIONS,
            session_timeout=SESSION_TIMEOUT,
            drain_timeout=DRAIN_TIMEOUT,
        )

        # Backend connector
        self.connector = BackendConnector(connect_timeout=5.0)

        # Per-backend cooldown: maps (host, port) -> earliest_retry_time
        # Prevents hammering a backend that just rejected us
        self._backend_cooldowns: dict = {}
        self._cooldown_seconds = 10  # seconds to wait after a rejection
        self._last_sighup_time: float = 0  # prevent rapid SIGHUP storms

        # Secure session manager
        self.secure_mgr = SecureSessionManager()

        # Frontend transports
        self.udp: Optional[UDPTransport] = None
        self.tcp: Optional[TCPTransport] = None

        if ENABLE_UDP:
            self.udp = UDPTransport(port, self._dispatch_udp)
        if ENABLE_TCP:
            self.tcp = TCPTransport(port, self._handle_tcp_client)

        # Signal handlers
        signal.signal(signal.SIGHUP, lambda *_: threading.Thread(
            target=self._on_sighup, daemon=True).start())
        signal.signal(signal.SIGTERM, lambda *_: self._on_stop())
        signal.signal(signal.SIGINT, lambda *_: self._on_stop())

        log.info(f"KNX/IP Proxy v{VERSION} | port={port} | frontend={FRONTEND_MODE} "
                 f"| max_sessions={MAX_SESSIONS} | secure={'yes' if is_secure_available() else 'no'}")

    # ──────────────────────────────────────────────────────────────────
    # Signal handlers
    # ──────────────────────────────────────────────────────────────────

    def _on_sighup(self):
        """
        Backend changed — hot re-route all sessions to the new backend.
        Instead of draining (which disconnects HA and makes devices unavailable),
        we open new backend connections and swap them in-place.
        The client session is never interrupted.
        """
        # Cooldown: don't process SIGHUP if we just handled one
        now = time.monotonic()
        if now - self._last_sighup_time < 5.0:
            log.debug("SIGHUP: ignored (cooldown — last swap was < 5s ago)")
            return
        self._last_sighup_time = now

        log.info("SIGHUP received — hot re-routing sessions to new backend")
        self.sessions.record_failover()
        clear_backend_reject()

        new_backend = read_backend()
        if new_backend is None:
            log.warning("No backend configured — draining sessions as fallback")
            udp_sock = self.udp.sock if self.udp else None
            self.sessions.drain_all(udp_sock)
            return

        b_host, b_port, b_proto = new_backend
        sessions = self.sessions.get_all()

        if not sessions:
            log.info("No active sessions — backend switch complete")
            return

        log.info(f"Re-routing {len(sessions)} sessions to {b_proto.upper()} {b_host}:{b_port}")

        success = 0
        failed = 0
        for sess in sessions:
            if not sess.alive or sess.draining:
                continue
            try:
                self._hot_swap_backend(sess, b_host, b_port, b_proto)
                success += 1
            except Exception as e:
                log.warning(f"Hot-swap failed for ch={sess.channel_id}: {e}")
                failed += 1

        log.info(f"Hot re-route complete: {success} re-routed, {failed} failed")

    def _on_stop(self):
        """Graceful shutdown — disconnect all backend sessions."""
        log.info("Shutting down — disconnecting all sessions from backends")
        self.running = False

        # Send DISCONNECT to every active backend so the gateway
        # releases the tunnel slot immediately instead of holding it
        # for the heartbeat timeout (60-120 seconds).
        sessions = self.sessions.get_all()
        for sess in sessions:
            try:
                self._disconnect_backend(sess)
                sess.close()
            except Exception:
                pass
        log.info(f"Shutdown complete — {len(sessions)} sessions disconnected")

    # ──────────────────────────────────────────────────────────────────
    # Backend connection
    # ──────────────────────────────────────────────────────────────────

    def _get_secure_config(self, host: str, port: int) -> Tuple[bool, str, str, int]:
        """Determine if a backend should use secure mode."""
        backend = read_backend()
        if backend is None:
            return False, '', '', 1

        b_host, b_port, _ = backend

        # Check primary
        if PRIMARY_SECURE and b_host == host:
            return True, PRIMARY_DEVICE_PW, PRIMARY_USER_PW, PRIMARY_USER_ID
        # Check backup
        if BACKUP_SECURE and b_host == host:
            return True, BACKUP_DEVICE_PW, BACKUP_USER_PW, BACKUP_USER_ID

        return False, '', '', 1

    def _establish_secure_session(
        self, bsock: socket.socket, b_host: str, b_port: int,
        device_pw: str, user_pw: str, user_id: int,
    ) -> Optional['SecureSession']:
        """
        Establish a KNX IP Secure session with the backend:
          1. Send SESSION_REQUEST (ECDH public key)
          2. Receive SESSION_RESPONSE (server ECDH key → derive shared key)
          3. Send SESSION_AUTHENTICATE (user password MAC)
          4. Receive SESSION_STATUS (auth result)
        Returns the authenticated SecureSession, or None on failure.
        """
        if not is_secure_available():
            log.error("KNX IP Secure requested but cryptography library not available")
            return None

        sec = SecureSession(device_pw, user_pw, user_id)

        # 1. SESSION_REQUEST
        req_frame = sec.build_session_request()
        try:
            bsock.sendall(req_frame)
        except Exception as e:
            log.error(f"Secure handshake: failed to send SESSION_REQUEST: {e}")
            return None

        # 2. SESSION_RESPONSE
        try:
            bsock.settimeout(5.0)
            svc, body = read_tcp_frame(bsock)
        except Exception as e:
            log.error(f"Secure handshake: failed to read SESSION_RESPONSE: {e}")
            return None

        if svc != SECURE_SESSION_RESP or body is None:
            log.error(f"Secure handshake: expected SESSION_RESPONSE (0x0952), "
                      f"got {svc_name(svc) if svc else 'None'}")
            return None

        if not sec.process_session_response(body):
            log.error("Secure handshake: SESSION_RESPONSE processing failed")
            return None

        log.info(f"Secure handshake: key exchange OK, session_id={sec.session_id}")

        # 3. SESSION_AUTHENTICATE
        auth_frame = sec.build_session_authenticate()
        try:
            bsock.sendall(auth_frame)
        except Exception as e:
            log.error(f"Secure handshake: failed to send SESSION_AUTHENTICATE: {e}")
            return None

        # 4. SESSION_STATUS
        try:
            bsock.settimeout(5.0)
            svc, body = read_tcp_frame(bsock)
        except Exception as e:
            log.error(f"Secure handshake: failed to read SESSION_STATUS: {e}")
            return None

        if svc != SECURE_SESSION_STATUS or body is None:
            log.error(f"Secure handshake: expected SESSION_STATUS (0x0954), "
                      f"got {svc_name(svc) if svc else 'None'}")
            return None

        if not sec.process_session_status(body):
            log.error("Secure handshake: authentication failed — "
                      "check device_password and user_password")
            return None

        log.info(f"Secure session established with {b_host}:{b_port} "
                 f"(session_id={sec.session_id}, user_id={user_id})")
        return sec

    def _negotiate_tunnel_secure(
        self, bsock: socket.socket, sec: 'SecureSession',
        client_cri: Optional[bytes] = None,
    ) -> Tuple[Optional[int], Optional[bytes], Optional[int]]:
        """
        Negotiate a KNX tunnel through a KNX IP Secure session.
        Sends CONNECT_REQUEST wrapped in SECURE_WRAPPER, reads back the
        SECURE_WRAPPER containing CONNECT_RESPONSE.
        Returns (channel_id, crd, status) or (None, None, status) on failure.
        """
        from knx_const import CRI_TUNNEL_V1

        cri = client_cri if (client_cri and len(client_cri) >= 4) else CRI_TUNNEL_V1
        ctrl = make_hpai('0.0.0.0', 0, PROTO_TCP)
        data = make_hpai('0.0.0.0', 0, PROTO_TCP)
        inner_body = ctrl + data + cri
        inner_frame = make_frame(CONNECT_REQ, inner_body)

        # Wrap in SECURE_WRAPPER
        wrapped = sec.encrypt_frame(inner_frame)
        try:
            bsock.sendall(wrapped)
        except Exception as e:
            log.error(f"Secure tunnel negotiation: failed to send CONNECT_REQ: {e}")
            return None, None, E_DATA_CONN

        # Read response — should be SECURE_WRAPPER containing CONNECT_RESP
        try:
            bsock.settimeout(5.0)
            svc, body = read_tcp_frame(bsock)
        except Exception as e:
            log.error(f"Secure tunnel negotiation: failed to read response: {e}")
            return None, None, E_DATA_CONN

        if svc is None:
            log.error("Secure tunnel negotiation: backend closed connection")
            return None, None, E_DATA_CONN

        # Decrypt if wrapped
        if svc == SECURE_WRAPPER:
            inner = sec.decrypt_frame(body)
            if inner is None:
                log.error("Secure tunnel negotiation: failed to decrypt response")
                return None, None, E_DATA_CONN
            inner_svc, inner_body = parse_frame(inner)
            if inner_svc is None:
                log.error("Secure tunnel negotiation: invalid inner frame")
                return None, None, E_DATA_CONN
            svc, body = inner_svc, inner_body
        elif svc == CONNECT_RESP:
            # Some gateways may reply with plain CONNECT_RESP even in secure mode
            pass
        else:
            log.error(f"Secure tunnel negotiation: unexpected response "
                      f"{svc_name(svc)} (0x{svc:04X})")
            return None, None, E_DATA_CONN

        if svc != CONNECT_RESP or not body or len(body) < 2:
            log.error(f"Secure tunnel negotiation: expected CONNECT_RESP, "
                      f"got {svc_name(svc) if svc else 'None'}")
            return None, None, E_DATA_CONN

        ch_id, status = body[0], body[1]
        if status != 0x00:
            log.warning(f"Secure tunnel negotiation: rejected status=0x{status:02x}")
            return None, None, status

        # Parse CRD
        crd = CRD_DEFAULT
        if len(body) >= 10:
            _, _, _, r_off = parse_hpai(body, 2)
            if r_off < len(body):
                crd = body[r_off:]
        elif len(body) > 2:
            crd = body[2:]

        log.info(f"Secure tunnel negotiation: accepted ch={ch_id} crd={crd.hex()}")
        return ch_id, crd, 0x00

    def _create_session(self, client_type: str,
                        client_ctrl: Tuple[str, int],
                        client_data: Tuple[str, int],
                        client_sock: Optional[socket.socket],
                        connect_body: bytes):
        """
        Create a new tunnelling session: connect to backend,
        negotiate tunnel, set up relay.
        """
        # Check capacity
        if not self.sessions.has_capacity():
            log.warning(f"Session limit reached ({MAX_SESSIONS}) — rejecting CONNECT")
            self._send_connect_error(client_type, client_ctrl, client_sock, E_NO_MORE_CONNS)
            return

        # Read active backend
        backend = read_backend()
        if backend is None:
            log.warning("CONNECT rejected — no backend configured")
            self._send_connect_error(client_type, client_ctrl, client_sock, E_DATA_CONN)
            return

        b_host, b_port, b_proto = backend

        # Check cooldown — don't hammer a backend that just rejected us
        cooldown_key = (b_host, b_port)
        cooldown_until = self._backend_cooldowns.get(cooldown_key, 0)
        now = time.monotonic()
        if now < cooldown_until:
            remaining = cooldown_until - now
            log.info(f"CONNECT: backend {b_host}:{b_port} in cooldown "
                     f"({remaining:.0f}s remaining) — rejecting client")
            self._send_connect_error(client_type, client_ctrl, client_sock, E_NO_MORE_CONNS)
            return

        log.info(f"CONNECT: {client_type.upper()} client {client_ctrl[0]}:{client_ctrl[1]}"
                 f" → {b_proto.upper()} backend {b_host}:{b_port}")

        # Open backend socket
        try:
            bsock = self.connector.open_socket(b_host, b_port, b_proto)
        except Exception as e:
            log.error(f"Cannot reach backend {b_host}:{b_port} [{b_proto}]: {e}")
            report_backend_reject(b_host, b_port, b_proto, E_DATA_CONN)
            self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
            self._send_connect_error(client_type, client_ctrl, client_sock, E_DATA_CONN)
            return

        # Extract client CRI
        _, _, _, off = parse_hpai(connect_body, 0)
        _, _, _, off = parse_hpai(connect_body, off)
        client_cri = connect_body[off:] if off < len(connect_body) else None

        # Check if backend requires KNX IP Secure
        is_secure, device_pw, user_pw, user_id = self._get_secure_config(b_host, b_port)
        _secure_session = None

        if is_secure:
            # ── KNX IP Secure path ──
            # Secure always requires TCP
            if b_proto != 'tcp':
                try:
                    bsock.close()
                except Exception:
                    pass
                try:
                    bsock = self.connector.open_socket(b_host, b_port, 'tcp')
                except Exception as e:
                    log.error(f"Cannot reach backend {b_host}:{b_port} [tcp] for secure: {e}")
                    report_backend_reject(b_host, b_port, 'tcp', E_DATA_CONN)
                    self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
                    self._send_connect_error(client_type, client_ctrl, client_sock, E_DATA_CONN)
                    return
                b_proto = 'tcp'

            # Establish secure session (ECDH + auth)
            _secure_session = self._establish_secure_session(
                bsock, b_host, b_port, device_pw, user_pw, user_id
            )
            if _secure_session is None:
                try:
                    bsock.close()
                except Exception:
                    pass
                report_backend_reject(b_host, b_port, b_proto, E_DATA_CONN)
                self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
                self._send_connect_error(client_type, client_ctrl, client_sock, E_DATA_CONN)
                return

            # Negotiate tunnel inside the secure session
            ch_id, crd, status = self._negotiate_tunnel_secure(
                bsock, _secure_session, client_cri
            )
            if ch_id is None:
                try:
                    bsock.close()
                except Exception:
                    pass
                final_status = status if status else E_DATA_CONN
                report_backend_reject(b_host, b_port, b_proto, final_status)
                self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
                self._send_connect_error(client_type, client_ctrl, client_sock, final_status)
                return

        else:
            # ── Plain tunnel negotiation path ──
            # Negotiate tunnel
            try:
                ch_id, crd, status = self.connector.negotiate_tunnel(
                    bsock, b_host, b_port, b_proto, client_cri
                )
            except Exception as e:
                log.error(f"Backend tunnel negotiation error: {e}")
                report_backend_reject(b_host, b_port, b_proto, E_DATA_CONN)
                self._send_connect_error(client_type, client_ctrl, client_sock, E_DATA_CONN)
                return

            # For TCP, negotiate_tunnel opens fresh sockets per attempt.
            # The winning socket is in connector._last_good_sock.
            if self.connector._last_good_sock is not None:
                bsock = self.connector._last_good_sock

            if ch_id is None:
                final_status = status if status else E_DATA_CONN

                # Try protocol fallback if rejected with 0x22 (no free slots)
                if final_status == 0x22:
                    if b_proto == 'udp':
                        log.info("UDP tunnel rejected (0x22) — trying TCP fallback")
                        fb_sock, fb_ch, fb_crd, fb_status = self.connector.try_tcp_fallback(
                            b_host, b_port, client_cri
                        )
                        if fb_sock and fb_ch is not None:
                            bsock = fb_sock
                            ch_id = fb_ch
                            crd = fb_crd
                            b_proto = 'tcp'
                            log.info(f"TCP fallback succeeded: ch={ch_id}")
                        else:
                            report_backend_reject(b_host, b_port, 'udp', final_status)
                            self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
                            self._send_connect_error(client_type, client_ctrl, client_sock, final_status)
                            return
                    elif b_proto == 'tcp':
                        log.info("TCP tunnel rejected (0x22) — trying UDP fallback")
                        fb_sock, fb_ch, fb_crd, fb_status = self.connector.try_udp_fallback(
                            b_host, b_port, client_cri
                        )
                        if fb_sock and fb_ch is not None:
                            bsock = fb_sock
                            ch_id = fb_ch
                            crd = fb_crd
                            b_proto = 'udp'
                            log.info(f"UDP fallback succeeded: ch={ch_id}")
                        else:
                            report_backend_reject(b_host, b_port, 'tcp', final_status)
                            self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
                            self._send_connect_error(client_type, client_ctrl, client_sock, final_status)
                            return
                    else:
                        report_backend_reject(b_host, b_port, b_proto, final_status)
                        self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
                        self._send_connect_error(client_type, client_ctrl, client_sock, final_status)
                        return
                else:
                    report_backend_reject(b_host, b_port, b_proto, final_status)
                    self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
                    self._send_connect_error(client_type, client_ctrl, client_sock, final_status)
                    return

        if crd is None:
            crd = CRD_DEFAULT

        # Setup keep-alive timeout for the long-running socket relay
        if bsock:
            bsock.settimeout(65.0)

        # If non-secure mode and TCP backend: probe the assigned slot NOW,
        # before forwarding CONNECT_RESP to the client.  If it is a KNX IP Secure
        # slot (SECURE_WRAPPER response to plain CONNSTATE_REQ), switch to a plain
        # adjacent slot so the client is told the CORRECT individual address from
        # the very first frame.  This prevents CEMI source-address mismatches that
        # cause the backend to silently drop outgoing frames and stop forwarding
        # incoming bus telegrams to our tunnel.
        if not PRIMARY_SECURE and b_proto == 'tcp' and bsock and crd:
            bsock, ch_id, crd = self._avoid_secure_early(
                bsock, ch_id, crd, b_host, b_port, b_proto
            )
            if crd is None:
                crd = CRD_DEFAULT

        # Build client-facing CONNECT_RESPONSE
        # For TCP: HPAI must be 0.0.0.0:0 (= "use this TCP connection for data")
        # For UDP: HPAI is 0.0.0.0:0 (= "use sender address")
        c_proto = PROTO_TCP if client_type == 'tcp' else PROTO_UDP
        c_resp = bytes([ch_id, E_NO_ERROR]) + make_hpai('0.0.0.0', 0, c_proto) + crd
        c_frame = make_frame(CONNECT_RESP, c_resp)

        # Create session
        sess = Session(
            ch_id, client_type, client_ctrl, client_data, client_sock,
            b_proto, (b_host, b_port), bsock,
        )
        sess.crd = crd
        sess._secure_session = _secure_session
        # Track which individual address the client was told (from CRD in CONNECT_RESP)
        # and which backend slot we're actually on.  These may diverge if mid-relay
        # SECURE avoidance swaps to a different slot after CONNECT_RESP is sent.
        if crd and len(crd) >= 4:
            ia = (crd[2], crd[3])
            sess._client_ia = ia
            sess._backend_ia = ia

        # Register session (evicts old if channel ID collision)
        old = self.sessions.add(sess)
        if old:
            self._disconnect_backend(old)
            old.close()

        # Start backend relay thread
        threading.Thread(target=self._relay_from_backend, args=(sess,),
                         daemon=True, name=f'relay-{ch_id}').start()

        clear_backend_reject()
        # Clear cooldown for this backend since it accepted the connection
        self._backend_cooldowns.pop(cooldown_key, None)

        # Send CONNECT_RESPONSE to client
        udp_sock = self.udp.sock if self.udp else None
        if not sess.send_to_client(c_frame, udp_sock):
            self.sessions.remove(ch_id)
            self._disconnect_backend(sess)
            sess.close()
            return

        # Log CRD individual address
        if crd and len(crd) >= 4:
            ia_hi, ia_lo = crd[2], crd[3]
            ia_str = f"{(ia_hi >> 4) & 0xF}.{ia_hi & 0xF}.{ia_lo}"
            log.info(f"Session ch={ch_id}: tunnel address={ia_str} CRD={crd.hex()}")

        log.info(f"Session ch={ch_id} established: "
                 f"{client_type.upper()} {client_ctrl[0]}:{client_ctrl[1]} ↔ "
                 f"{b_proto.upper()} {b_host}:{b_port}")

    # ──────────────────────────────────────────────────────────────────
    # SECURE slot detection and avoidance
    # ──────────────────────────────────────────────────────────────────

    def _avoid_secure_early(
        self,
        bsock: socket.socket, ch_id: int, crd: bytes,
        b_host: str, b_port: int, b_proto: str,
    ) -> Tuple[socket.socket, int, bytes]:
        """
        Called right after a successful backend CONNECT, BEFORE the client sees
        CONNECT_RESP.  If the assigned individual address is in the known-secure
        cache (populated on first detection by _secure_reconnect), proactively
        reconnects to an adjacent plain slot so the client is told the CORRECT
        individual address from the very first frame.

        NOTE: We do NOT probe with CONNSTATE_REQ because the SCN-IP000.03 (and
        similar devices) only wrap TUNNELLING frames in SECURE_WRAPPER — management
        frames like CONNSTATE_RESP are returned plain even from a secure slot, so a
        probe cannot distinguish secure from non-secure before the first telegram.

        Returns (socket, channel_id, crd) — original if not in cache or no plain
        slot found; replacement otherwise.
        """
        if not crd or len(crd) < 4:
            return bsock, ch_id, crd

        ia_hi, ia_lo = crd[2], crd[3]

        # Not a known-secure slot → nothing to do
        if (ia_hi, ia_lo) not in KNXProxy._known_secure_ias:
            return bsock, ch_id, crd

        current_ia  = (ia_hi << 8) | ia_lo
        current_str = f"{(ia_hi >> 4) & 0xF}.{ia_hi & 0xF}.{ia_lo}"
        proto_code  = PROTO_TCP if b_proto == 'tcp' else PROTO_UDP
        log.info(f"Pre-session: slot {current_str} is known KNX IP Secure — "
                 f"scanning for plain slot before telling client")

        for delta in (-1, +1, -2, +2):
            alt_ia = current_ia + delta
            if alt_ia < 0 or alt_ia > 0xFFFF:
                continue
            alt_hi  = (alt_ia >> 8) & 0xFF
            alt_lo  = alt_ia & 0xFF
            alt_str = f"{(alt_hi >> 4) & 0xF}.{alt_hi & 0xF}.{alt_lo}"

            # Skip if we already know this candidate is also secure
            if (alt_hi, alt_lo) in KNXProxy._known_secure_ias:
                log.debug(f"Pre-session avoidance: {alt_str} also known secure — skipping")
                continue

            ext_cri = bytes([0x06, 0x04, 0x02, 0x00, alt_hi, alt_lo])

            try:
                new_sock = self.connector.open_socket(b_host, b_port, b_proto)
            except Exception as e:
                log.debug(f"Pre-session avoidance: connect failed for {alt_str}: {e}")
                continue

            try:
                ctrl_h = make_hpai('0.0.0.0', 0, proto_code)
                data_h = make_hpai('0.0.0.0', 0, proto_code)
                new_sock.settimeout(5.0)
                new_sock.sendall(make_frame(CONNECT_REQ, ctrl_h + data_h + ext_cri))
                r_svc, r_body = read_tcp_frame(new_sock)
            except Exception as e:
                log.debug(f"Pre-session avoidance: CONNECT error for {alt_str}: {e}")
                new_sock.close()
                continue

            if r_svc != CONNECT_RESP or not r_body or len(r_body) < 2:
                new_sock.close()
                continue

            new_ch, status = r_body[0], r_body[1]
            if status != 0x00:
                log.debug(f"Pre-session avoidance: {alt_str} rejected 0x{status:02x}")
                new_sock.close()
                if status in (0x24, 0x25):
                    break
                continue

            # Parse CRD from response
            new_crd = crd
            if len(r_body) >= 10:
                _, _, _, off = parse_hpai(r_body, 2)
                if off < len(r_body):
                    new_crd = r_body[off:]
            elif len(r_body) > 2:
                new_crd = r_body[2:]

            # Disconnect and close the secure slot, switch to plain candidate
            ia_str = alt_str
            if new_crd and len(new_crd) >= 4:
                n_hi, n_lo = new_crd[2], new_crd[3]
                ia_str = f"{(n_hi >> 4) & 0xF}.{n_hi & 0xF}.{n_lo}"

            try:
                disc = bytes([ch_id, 0x00]) + make_hpai('0.0.0.0', 0, proto_code)
                bsock.settimeout(2.0)
                bsock.sendall(make_frame(DISCONNECT_REQ, disc))
                time.sleep(0.15)
            except Exception:
                pass
            try:
                bsock.close()
            except Exception:
                pass

            new_sock.settimeout(65.0)
            log.info(f"Pre-session secure avoidance succeeded — plain slot {ia_str} (ch={new_ch})")
            return new_sock, new_ch, new_crd

        log.warning(f"Pre-session: no plain slot found adjacent to {current_str} — "
                    f"proceeding with secure slot (mid-relay avoidance will retry)")
        return bsock, ch_id, crd

    # ──────────────────────────────────────────────────────────────────
    # SECURE_WRAPPER mid-relay reconnect (fallback safety net)
    # ──────────────────────────────────────────────────────────────────

    def _secure_reconnect(self, sess: Session) -> bool:
        """
        When the relay detects SECURE_WRAPPER on a non-secure session,
        disconnect from the current backend tunnel slot and reconnect
        requesting a different individual address via extended CRI (6 bytes).

        Many KNX IP interfaces have multiple tunnel slots — some designated
        for KNX IP Secure and some for plain tunnelling.  The device assigns
        the first available slot on a generic CONNECT; if that happens to be
        a secure slot, all frames arrive wrapped in SECURE_WRAPPER.

        This method tries adjacent individual addresses (IA-1, IA+1, IA-2,
        IA+2) until it finds one that the device accepts.  After swapping,
        the relay resumes transparently.
        """
        crd = getattr(sess, 'crd', None)
        if not crd or len(crd) < 4:
            log.debug("SECURE avoidance: no CRD on session")
            return False

        ia_hi, ia_lo = crd[2], crd[3]
        current_ia = (ia_hi << 8) | ia_lo
        current_str = f"{(ia_hi >> 4) & 0xF}.{ia_hi & 0xF}.{ia_lo}"
        b_host, b_port = sess.backend_addr
        proto = sess.backend_type
        proto_code = PROTO_TCP if proto == 'tcp' else PROTO_UDP

        # Disconnect old backend channel (best-effort, before opening new)
        try:
            disc = bytes([sess._backend_ch, 0x00]) + make_hpai('0.0.0.0', 0, proto_code)
            sess.send_to_backend(make_frame(DISCONNECT_REQ, disc))
            time.sleep(0.3)
        except Exception:
            pass

        for delta in (-1, +1, -2, +2):
            alt_ia = current_ia + delta
            if alt_ia < 0 or alt_ia > 0xFFFF:
                continue

            alt_hi = (alt_ia >> 8) & 0xFF
            alt_lo = alt_ia & 0xFF
            alt_str = f"{(alt_hi >> 4) & 0xF}.{alt_hi & 0xF}.{alt_lo}"
            extended_cri = bytes([0x06, 0x04, 0x02, 0x00, alt_hi, alt_lo])

            log.info(f"SECURE avoidance: trying tunnel address "
                     f"{alt_str} (was {current_str})")

            try:
                sock = self.connector.open_socket(b_host, b_port, proto)
            except Exception as e:
                log.debug(f"SECURE avoidance: connect failed: {e}")
                continue

            ctrl = make_hpai('0.0.0.0', 0, proto_code)
            data_hpai = make_hpai('0.0.0.0', 0, proto_code)
            body = ctrl + data_hpai + extended_cri
            frame = make_frame(CONNECT_REQ, body)

            try:
                if proto == 'tcp':
                    sock.sendall(frame)
                    r_svc, r_body = read_tcp_frame(sock)
                else:
                    sock.send(frame)
                    raw = sock.recv(1024)
                    r_svc, r_body = parse_frame(raw)
            except Exception as e:
                log.debug(f"SECURE avoidance: CONNECT error for {alt_str}: {e}")
                sock.close()
                continue

            if r_svc != CONNECT_RESP or not r_body or len(r_body) < 2:
                sock.close()
                continue

            ch_id, status = r_body[0], r_body[1]
            if status != 0x00:
                log.debug(f"SECURE avoidance: {alt_str} rejected 0x{status:02x}")
                sock.close()
                if status in (0x24, 0x25):
                    break  # no more connections available
                continue

            # Parse CRD from response
            new_crd = CRD_DEFAULT
            if len(r_body) >= 10:
                _, _, _, off = parse_hpai(r_body, 2)
                if off < len(r_body):
                    new_crd = r_body[off:]
            elif len(r_body) > 2:
                new_crd = r_body[2:]

            new_ia_str = alt_str
            if new_crd and len(new_crd) >= 4:
                n_hi, n_lo = new_crd[2], new_crd[3]
                new_ia_str = f"{(n_hi >> 4) & 0xF}.{n_hi & 0xF}.{n_lo}"

            sock.settimeout(65.0)
            sess.reset_seq_for_reconnect()
            sess.swap_backend(sock, proto, (b_host, b_port), ch_id)
            sess.crd = new_crd

            # Record original IA as known-secure for future connections
            # so _avoid_secure_early can switch proactively next time.
            KNXProxy._known_secure_ias.add((ia_hi, ia_lo))
            log.debug(f"Recorded {current_str} as known KNX IP Secure slot")

            # Update backend IA so CEMI source rewriting activates immediately
            if new_crd and len(new_crd) >= 4:
                sess._backend_ia = (new_crd[2], new_crd[3])
                n_hi, n_lo = new_crd[2], new_crd[3]
                new_ia_str = f"{(n_hi >> 4) & 0xF}.{n_hi & 0xF}.{n_lo}"

            log.info(f"Session ch={ch_id}: SECURE avoidance succeeded — "
                     f"tunnel address={new_ia_str} CRD={new_crd.hex()}")
            return True

        log.warning("SECURE avoidance failed — no non-secure tunnel slot found")
        return False

    # ──────────────────────────────────────────────────────────────────
    # Backend → Client relay
    # ──────────────────────────────────────────────────────────────────

    def _relay_from_backend(self, sess: Session):
        """Read frames from backend and forward to client."""
        udp_sock = self.udp.sock if self.udp else None
        relay_count = 0
        secure_warned = False
        log.info(f"Relay thread started for ch={sess.channel_id} "
                 f"backend={sess.backend_addr} type={sess.backend_type}")

        while sess.alive and self.running:
            try:
                if sess.backend_type == 'tcp':
                    svc, body = read_tcp_frame(sess.backend_sock)
                    if svc is None:
                        log.info(f"Relay ch={sess.channel_id}: backend stream ended")
                        break
                    data = make_frame(svc, body)
                else:
                    data, _ = sess.backend_sock.recvfrom(2048)
                    svc, body = parse_frame(data)
                    if svc is None:
                        continue
            except socket.timeout:
                if time.monotonic() - sess.last_seen > SESSION_TIMEOUT:
                    log.info(f"Session ch={sess.channel_id} timed out in relay")
                    self.sessions.remove(sess.channel_id)
                    self._disconnect_backend(sess)
                    sess.close()
                continue
            except Exception as e:
                if sess.alive:
                    log.debug(f"Backend relay ch={sess.channel_id}: {e}")
                break

            sess.last_seen = time.monotonic()
            dest = sess.client_data or sess.client_ctrl

            if svc == SECURE_WRAPPER:
                # ── Secure termination: decrypt and process inner frame ──
                if sess._secure_session:
                    inner = sess._secure_session.decrypt_frame(body)
                    if inner is None:
                        log.warning(f"Relay ch={sess.channel_id}: "
                                    f"SECURE_WRAPPER decrypt failed — skipping")
                        continue
                    inner_svc, inner_body = parse_frame(inner)
                    if inner_svc is None:
                        log.warning(f"Relay ch={sess.channel_id}: "
                                    f"invalid inner frame after decrypt — skipping")
                        continue
                    # Replace svc/body/data with decrypted inner content
                    svc = inner_svc
                    body = inner_body
                    data = inner
                    # Fall through to process decrypted frame below
                else:
                    # Non-secure configuration — avoidance / passthrough
                    if not secure_warned:
                        secure_warned = True
                        log.warning(
                            f"Session ch={sess.channel_id}: backend sends "
                            f"SECURE_WRAPPER but secure=false — attempting "
                            f"auto-reconnect to non-secure tunnel slot"
                        )
                        if self._secure_reconnect(sess):
                            continue
                        log.warning(
                            f"Session ch={sess.channel_id}: SECURE avoidance "
                            f"failed — forwarding encrypted frames. "
                            f"Configure HA KNX for 'KNX IP Secure Tunnelling' "
                            f"or disable KNX IP Secure in ETS."
                        )
                    sess.send_to_client(data, udp_sock)
                    sess.telegrams_fwd += 1
                    continue

            if svc in (TUNNELLING_REQ, TUNNELLING_ACK, CONNSTATE_RESP, DISCONNECT_RESP):
                # Immediately ACK incoming TUNNELLING_REQ from backend
                # so it doesn't time out waiting for the full client round-trip
                if svc == TUNNELLING_REQ:
                    ack_body = bytes([0x04, body[1], body[2], 0x00])
                    ack_frame = make_frame(TUNNELLING_ACK, ack_body)
                    if sess._secure_session:
                        ack_frame = sess._secure_session.encrypt_frame(ack_frame)
                    sess.send_to_backend(ack_frame)

                # Rewrite channel_id and seq for client if needed
                if svc in (TUNNELLING_REQ, TUNNELLING_ACK) and len(data) > 8:
                    needs_ch = sess._backend_ch != sess.channel_id
                    seq_off = (sess._seq_in_offset if svc == TUNNELLING_REQ
                               else sess._seq_out_offset)
                    if needs_ch or seq_off:
                        data = bytearray(data)
                        if needs_ch:
                            data[7] = sess.channel_id
                        if seq_off:
                            data[8] = (data[8] + seq_off) & 0xFF
                        data = bytes(data)
                    if svc == TUNNELLING_REQ:
                        sess._last_in_seq = data[8]
                elif sess._backend_ch != sess.channel_id and len(data) > 6:
                    data = bytearray(data)
                    data[6] = sess.channel_id
                    data = bytes(data)

                ok = sess.send_to_client(data, udp_sock)
                if svc in (TUNNELLING_REQ, TUNNELLING_ACK):
                    sess.telegrams_fwd += 1
                    relay_count += 1
                    if relay_count <= 5 or relay_count % 50 == 0:
                        mc = body[4] if len(body) > 4 else 0
                        fwd_seq = data[8] if len(data) > 8 else body[2]
                        log.info(f"Relay ch={sess.channel_id}: {svc_name(svc)} "
                                 f"seq={fwd_seq} "
                                 f"mc=0x{mc:02X} len={len(body)} "
                                 f"→client={'OK' if ok else 'FAIL'} "
                                 f"(total={relay_count})")
                elif svc == CONNSTATE_RESP:
                    log.debug(f"Relay ch={sess.channel_id}: CONNSTATE_RESP → client")

            elif svc == DISCONNECT_REQ:
                # Backend initiated disconnect — rewrite ch for client
                if sess._backend_ch != sess.channel_id and len(data) > 6:
                    data = bytearray(data)
                    data[6] = sess.channel_id
                    data = bytes(data)
                sess.send_to_client(data, udp_sock)
                # Send ack back to backend
                ack_body = bytes([sess._backend_ch, 0x00]) + make_hpai('0.0.0.0', 0)
                ack_frame = make_frame(DISCONNECT_RESP, ack_body)
                if sess._secure_session:
                    ack_frame = sess._secure_session.encrypt_frame(ack_frame)
                sess.send_to_backend(ack_frame)
                self.sessions.remove(sess.channel_id)
                log.info(f"Session ch={sess.channel_id} closed by backend "
                         f"(uptime={sess.uptime():.0f}s, telegrams={sess.telegrams_fwd})")
                sess.close()
                return

            else:
                log.info(f"Relay ch={sess.channel_id}: unhandled "
                         f"{svc_name(svc)} svc=0x{svc:04X} len={len(body)}")

        # Backend connection lost — try hot-swap to new backend
        if sess.alive:
            log.info(f"Session ch={sess.channel_id} backend connection lost — attempting hot-swap")
            try:
                backend = read_backend()
                if backend:
                    b_host, b_port, b_proto = backend
                    # Only hot-swap if the backend is different or we can reconnect
                    self._hot_swap_backend(sess, b_host, b_port, b_proto)
                    # Restart relay loop with new backend
                    log.info(f"Session ch={sess.channel_id} relay resumed after hot-swap")
                    self._relay_from_backend(sess)
                    return
            except Exception as e:
                log.warning(f"Hot-swap failed for ch={sess.channel_id}: {e}")

            # Hot-swap failed — close the session
            self.sessions.remove(sess.channel_id)
            self._disconnect_backend(sess)
            log.info(f"Session ch={sess.channel_id} relay ended "
                     f"(uptime={sess.uptime():.0f}s, telegrams={sess.telegrams_fwd})")
            sess.close()

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    def _hot_swap_backend(self, sess: Session,
                          b_host: str, b_port: int, b_proto: str):
        """
        Open a new backend connection, negotiate a tunnel, and swap it
        into an existing session. The client never disconnects.
        """
        # Disconnect old backend (best-effort)
        try:
            old_proto = PROTO_TCP if sess.backend_type == 'tcp' else PROTO_UDP
            body = bytes([sess._backend_ch, 0x00]) + make_hpai('0.0.0.0', 0, old_proto)
            disc_frame = make_frame(DISCONNECT_REQ, body)
            if sess._secure_session:
                disc_frame = sess._secure_session.encrypt_frame(disc_frame)
            sess.send_to_backend(disc_frame)
        except Exception:
            pass

        # Check if new backend requires secure
        is_secure, device_pw, user_pw, user_id = self._get_secure_config(b_host, b_port)

        if is_secure:
            # Force TCP for secure
            b_proto = 'tcp'

        # Open new backend socket
        bsock = self.connector.open_socket(b_host, b_port, b_proto)

        if is_secure:
            # Establish secure session on new backend
            new_sec = self._establish_secure_session(
                bsock, b_host, b_port, device_pw, user_pw, user_id
            )
            if new_sec is None:
                bsock.close()
                raise RuntimeError("Hot-swap: secure session establishment failed")

            ch_id, crd, status = self._negotiate_tunnel_secure(bsock, new_sec)
            if ch_id is None:
                bsock.close()
                raise RuntimeError(
                    f"Hot-swap: secure tunnel rejected (status=0x{(status or 0):02x})")

            sess._secure_session = new_sec
        else:
            sess._secure_session = None

            # Negotiate tunnel
            ch_id, crd, status = self.connector.negotiate_tunnel(
                bsock, b_host, b_port, b_proto
            )

            # For TCP, negotiate_tunnel opens fresh sockets per attempt.
            if self.connector._last_good_sock is not None:
                bsock = self.connector._last_good_sock

            # Protocol fallback: if 0x22 on one protocol, try the other
            if ch_id is None and status == 0x22:
                alt_proto = 'udp' if b_proto == 'tcp' else 'tcp'
                log.info(f"Hot-swap: {b_proto.upper()} tunnel rejected (0x22) "
                         f"— trying {alt_proto.upper()} fallback")
                if alt_proto == 'udp':
                    fb_sock, fb_ch, fb_crd, fb_st = self.connector.try_udp_fallback(
                        b_host, b_port)
                else:
                    fb_sock, fb_ch, fb_crd, fb_st = self.connector.try_tcp_fallback(
                        b_host, b_port)
                if fb_sock and fb_ch is not None:
                    bsock = fb_sock
                    ch_id = fb_ch
                    crd = fb_crd
                    b_proto = alt_proto
                    log.info(f"Hot-swap: {alt_proto.upper()} fallback succeeded ch={ch_id}")
                else:
                    raise RuntimeError(
                        f"Backend rejected CONNECT on both protocols "
                        f"(status=0x{(status or 0):02x})")

        if ch_id is None:
            raise RuntimeError(f"Backend rejected CONNECT (status=0x{(status or 0):02x})")

        # Setup keep-alive timeout for the long-running socket relay
        bsock.settimeout(65.0)

        # Swap the backend in-place
        sess.reset_seq_for_reconnect()
        sess.swap_backend(bsock, b_proto, (b_host, b_port), ch_id)

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    def _disconnect_backend(self, sess: Session):
        """Send DISCONNECT_REQ to backend (best-effort)."""
        try:
            proto = PROTO_TCP if sess.backend_type == 'tcp' else PROTO_UDP
            body = bytes([sess._backend_ch, 0x00]) + make_hpai('0.0.0.0', 0, proto)
            frame = make_frame(DISCONNECT_REQ, body)
            if sess._secure_session:
                frame = sess._secure_session.encrypt_frame(frame)
            sess.send_to_backend(frame)
        except Exception:
            pass

    def _send_connect_error(self, ctype: str,
                            ctrl: Tuple[str, int],
                            csock: Optional[socket.socket],
                            code: int):
        """Send a CONNECT_RESPONSE with error status to the client."""
        proto = PROTO_TCP if ctype == 'tcp' else PROTO_UDP
        body = bytes([0x00, code]) + make_hpai('0.0.0.0', 0, proto) + CRD_DEFAULT
        frame = make_frame(CONNECT_RESP, body)
        try:
            if ctype == 'tcp' and csock:
                csock.sendall(frame)
            elif ctrl and self.udp:
                self.udp.sendto(frame, ctrl)
        except Exception as e:
            log.debug(f"Failed to send CONNECT error: {e}")

    def _send_raw(self, frame: bytes, ctype: str,
                  ctrl: Tuple[str, int],
                  csock: Optional[socket.socket]) -> bool:
        """Send raw frame to client."""
        try:
            if ctype == 'tcp' and csock:
                csock.sendall(frame)
            elif ctrl and self.udp:
                self.udp.sendto(frame, ctrl)
            return True
        except Exception as e:
            log.debug(f"_send_raw: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────
    # UDP dispatch
    # ──────────────────────────────────────────────────────────────────

    def _dispatch_udp(self, data: bytes, addr: Tuple[str, int]):
        """Handle a single incoming UDP packet."""
        svc, body = parse_frame(data)
        if svc is None:
            log.debug(f"Invalid KNX/IP frame from {addr[0]}:{addr[1]}")
            return

        log.debug(f"UDP {svc_name(svc)} from {addr[0]}:{addr[1]}")

        if svc == DESCRIPTION_REQ:
            self.udp.sendto(DESCRIPTION_RESPONSE, addr)

        elif svc == SEARCH_REQ:
            self.udp.sendto(build_search_resp(self.port, SEARCH_RESP, PROTO_UDP), addr)

        elif svc == SEARCH_REQ_EXT:
            self.udp.sendto(build_search_resp(self.port, SEARCH_RESP_EXT, PROTO_UDP), addr)

        elif svc == CONNECT_REQ:
            if not body or len(body) < 16:
                return
            ci, cp, _, off = parse_hpai(body, 0)
            di, dp, _, _   = parse_hpai(body, off)
            # Rewrite wildcard addresses to actual sender
            ci = ci if ci != '0.0.0.0' else addr[0]
            di = di if di != '0.0.0.0' else addr[0]
            cp = cp if cp != 0 else addr[1]
            dp = dp if dp != 0 else addr[1]
            threading.Thread(target=self._create_session,
                             args=('udp', (ci, cp), (di, dp), None, body),
                             daemon=True).start()

        elif svc in (TUNNELLING_REQ, TUNNELLING_ACK):
            if not body or len(body) < 4:
                return
            ch = tunnel_channel_id(body)
            sess = self.sessions.get(ch)
            if sess and sess.alive:
                sess.last_seen = time.monotonic()
                if svc == TUNNELLING_REQ:
                    sess._last_out_seq = body[2]
                fwd = data
                needs_ch = sess._backend_ch != sess.channel_id
                seq_off = (sess._seq_out_offset if svc == TUNNELLING_REQ
                           else sess._seq_in_offset)
                if (needs_ch or seq_off) and len(fwd) > 8:
                    fwd = bytearray(fwd)
                    if needs_ch:
                        fwd[7] = sess._backend_ch
                    if seq_off:
                        fwd[8] = (fwd[8] - seq_off) & 0xFF
                    fwd = bytes(fwd)
                # Rewrite CEMI source address for UDP path (same logic as TCP)
                if (svc == TUNNELLING_REQ
                        and sess._client_ia and sess._backend_ia
                        and sess._client_ia != sess._backend_ia
                        and len(fwd) > 15):
                    fwd = bytearray(fwd)
                    al = fwd[11]              # body starts at offset 6; AL at body[5]=fwd[11]
                    shi = 14 + al             # CEMI src hi in full UDP frame
                    slo = 15 + al
                    if (len(fwd) > slo
                            and fwd[shi] == sess._client_ia[0]
                            and fwd[slo] == sess._client_ia[1]):
                        fwd[shi] = sess._backend_ia[0]
                        fwd[slo] = sess._backend_ia[1]
                    fwd = bytes(fwd)
                if sess._secure_session:
                    fwd = sess._secure_session.encrypt_frame(fwd)
                sess.send_to_backend(fwd)
                sess.telegrams_fwd += 1

        elif svc == CONNSTATE_REQ:
            if not body:
                return
            ch = body[0]
            sess = self.sessions.get(ch)
            if sess and sess.alive:
                sess.last_seen = time.monotonic()
                fwd = data
                if sess._backend_ch != sess.channel_id and len(fwd) > 6:
                    fwd = bytearray(fwd)
                    fwd[6] = sess._backend_ch
                    fwd = bytes(fwd)
                if sess._secure_session:
                    fwd = sess._secure_session.encrypt_frame(fwd)
                if not sess.send_to_backend(fwd):
                    log.debug(f"UDP CONNSTATE fwd failed ch={ch} — responding locally")
                    resp_body = bytes([ch, 0x00])
                    self.udp.sendto(make_frame(CONNSTATE_RESP, resp_body), addr)
            else:
                resp_body = bytes([ch, 0x00])
                self.udp.sendto(make_frame(CONNSTATE_RESP, resp_body), addr)

        elif svc in (DISCONNECT_REQ, DISCONNECT_RESP):
            ch = body[0] if body else 0
            sess = self.sessions.remove(ch)
            if sess:
                fwd = data
                if sess._backend_ch != sess.channel_id and len(fwd) > 6:
                    fwd = bytearray(fwd)
                    fwd[6] = sess._backend_ch
                    fwd = bytes(fwd)
                if sess._secure_session:
                    fwd = sess._secure_session.encrypt_frame(fwd)
                sess.send_to_backend(fwd)
                log.info(f"Session ch={ch} disconnected by UDP client "
                         f"(uptime={sess.uptime():.0f}s, telegrams={sess.telegrams_fwd})")
                sess.close()

        elif svc in (SECURE_SESSION_REQ, SECURE_WRAPPER):
            # KNX IP Secure requires TCP — cannot operate over UDP
            log.warning(f"Secure frame {svc_name(svc)} received via UDP — "
                        f"KNX IP Secure requires TCP frontend")

    # ──────────────────────────────────────────────────────────────────
    # Secure tunneling — transparent TCP passthrough
    # ──────────────────────────────────────────────────────────────────

    def _handle_secure_passthrough(self, client_sock: socket.socket,
                                    client_addr: Tuple[str, int],
                                    first_svc: int, first_body: bytes):
        """
        Handle KNX IP Secure tunneling by relaying all TCP data between
        client and backend transparently. The proxy does NOT terminate or
        inspect the secure session — the ECDH key exchange and AES-CCM
        encryption happen end-to-end between client (xknx) and the
        KNX gateway.

        Flow:
          1. Client sends SESSION_REQUEST → forwarded to backend
          2. Backend replies SESSION_RESPONSE → forwarded to client
          3. Client sends SESSION_AUTHENTICATE → forwarded to backend
          4. Backend replies SESSION_STATUS → forwarded to client
          5. All subsequent traffic (SECURE_WRAPPER) relayed as raw bytes
        """
        backend = read_backend()
        if backend is None:
            log.warning("Secure passthrough rejected — no backend configured")
            return

        b_host, b_port, _ = backend

        # KNX IP Secure always runs over TCP
        try:
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_sock.settimeout(5.0)
            backend_sock.connect((b_host, b_port))
        except Exception as e:
            log.error(f"Secure passthrough: cannot connect to backend "
                      f"{b_host}:{b_port}: {e}")
            return

        # Forward the initial SECURE_SESSION_REQ to the backend
        first_frame = make_frame(first_svc, first_body)
        try:
            backend_sock.sendall(first_frame)
        except Exception as e:
            log.error(f"Secure passthrough: failed to forward SESSION_REQ: {e}")
            backend_sock.close()
            return

        log.info(f"Secure tunnel passthrough: "
                 f"{client_addr[0]}:{client_addr[1]} ↔ {b_host}:{b_port}")

        # Set relay timeouts — long enough for idle KNX sessions,
        # short enough to detect shutdown promptly
        client_sock.settimeout(10.0)
        backend_sock.settimeout(10.0)

        stop = threading.Event()

        def _relay(src: socket.socket, dst: socket.socket, label: str):
            """Relay data from src to dst until either side closes."""
            try:
                while not stop.is_set() and self.running:
                    try:
                        data = src.recv(4096)
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                    if not data:
                        break
                    try:
                        dst.sendall(data)
                    except Exception:
                        break
            finally:
                stop.set()

        t_c2b = threading.Thread(target=_relay,
                                  args=(client_sock, backend_sock, "c→b"),
                                  daemon=True)
        t_b2c = threading.Thread(target=_relay,
                                  args=(backend_sock, client_sock, "b→c"),
                                  daemon=True)
        t_c2b.start()
        t_b2c.start()

        # Wait until one side closes or proxy shuts down
        while not stop.is_set() and self.running:
            stop.wait(timeout=2.0)

        stop.set()

        # Clean up backend socket (client socket closed by caller's finally)
        try:
            backend_sock.close()
        except Exception:
            pass

        # Wait for relay threads to finish
        t_c2b.join(timeout=3)
        t_b2c.join(timeout=3)

        log.info(f"Secure tunnel passthrough ended: "
                 f"{client_addr[0]}:{client_addr[1]} ↔ {b_host}:{b_port}")

    # ──────────────────────────────────────────────────────────────────
    # TCP client handler
    # ──────────────────────────────────────────────────────────────────

    def _handle_tcp_client(self, sock: socket.socket, addr: Tuple[str, int]):
        """Handle a connected TCP client."""
        log.info(f"TCP client connected: {addr[0]}:{addr[1]}")
        # CRITICAL: xknx sends CONNECTIONSTATE_REQUEST every 60s.
        # Timeout must be > 60s to avoid dropping the connection before
        # the next heartbeat arrives. 120s gives comfortable margin.
        sock.settimeout(120.0)
        ch_id = None

        try:
            while self.running:
                try:
                    svc, body = read_tcp_frame(sock)
                except socket.timeout:
                    # Timeout is fine — just loop back and wait for more data.
                    # The maintenance loop handles stale session cleanup.
                    continue
                if svc is None:
                    break

                log.debug(f"TCP {svc_name(svc)} from {addr[0]}:{addr[1]}")

                if svc == DESCRIPTION_REQ:
                    try:
                        sock.sendall(DESCRIPTION_RESPONSE)
                    except Exception as e:
                        log.error(f"TCP DESCRIPTION_RESPONSE failed: {e}")
                        break

                elif svc == SEARCH_REQ:
                    try:
                        sock.sendall(build_search_resp(self.port, SEARCH_RESP, PROTO_TCP))
                    except Exception as e:
                        log.error(f"TCP SEARCH_RESPONSE failed: {e}")
                        break

                elif svc == SEARCH_REQ_EXT:
                    try:
                        sock.sendall(build_search_resp(self.port, SEARCH_RESP_EXT, PROTO_TCP))
                    except Exception as e:
                        log.error(f"TCP SEARCH_RESPONSE_EXT failed: {e}")
                        break

                elif svc == CONNECT_REQ:
                    ctrl = (addr[0], addr[1])
                    self._create_session('tcp', ctrl, ctrl, sock, body)
                    # Find the channel ID assigned to this TCP client
                    ch_id = self.sessions.find_by_client_sock(sock)

                elif svc in (TUNNELLING_REQ, TUNNELLING_ACK):
                    if not body or len(body) < 4:
                        continue
                    ch = tunnel_channel_id(body)
                    sess = self.sessions.get(ch)
                    if sess and sess.alive:
                        sess.last_seen = time.monotonic()
                        # Immediately ACK client TUNNELLING_REQ so xknx
                        # doesn't timeout waiting for backend round-trip
                        if svc == TUNNELLING_REQ:
                            ack_body = bytes([0x04, body[1], body[2], 0x00])
                            try:
                                sock.sendall(make_frame(TUNNELLING_ACK, ack_body))
                            except Exception:
                                pass
                        # Rewrite channel_id and seq for backend
                        fwd_body = body
                        needs_ch = sess._backend_ch != sess.channel_id
                        if svc == TUNNELLING_REQ:
                            sess._last_out_seq = body[2]
                            seq_off = sess._seq_out_offset
                        else:
                            seq_off = sess._seq_in_offset
                        if needs_ch or seq_off:
                            fwd_body = bytearray(body)
                            if needs_ch:
                                fwd_body[1] = sess._backend_ch
                            if seq_off:
                                fwd_body[2] = (body[2] - seq_off) & 0xFF
                            fwd_body = bytes(fwd_body)
                        # Rewrite CEMI source address when the backend slot IA
                        # differs from what the client was told in CONNECT_RESP.
                        # The SCN-IP000.03 (and many other interfaces) silently
                        # drop TUNNELLING_REQ whose CEMI src does not match the
                        # assigned tunnel slot IA, preventing any bus traffic.
                        if (svc == TUNNELLING_REQ
                                and sess._client_ia and sess._backend_ia
                                and sess._client_ia != sess._backend_ia
                                and len(fwd_body) >= 10):
                            fwd_body = bytearray(fwd_body)
                            al = fwd_body[5]           # CEMI additional-info length
                            shi = 8 + al               # CEMI source-address high byte
                            slo = 9 + al               # CEMI source-address low byte
                            if (len(fwd_body) > slo
                                    and fwd_body[shi] == sess._client_ia[0]
                                    and fwd_body[slo] == sess._client_ia[1]):
                                fwd_body[shi] = sess._backend_ia[0]
                                fwd_body[slo] = sess._backend_ia[1]
                                log.debug(f"CEMI src rewrite: "
                                          f"{sess._client_ia[0]:02X}{sess._client_ia[1]:02X}"
                                          f"→{sess._backend_ia[0]:02X}{sess._backend_ia[1]:02X}")
                            fwd_body = bytes(fwd_body)
                        fwd_frame = make_frame(svc, fwd_body)
                        if sess._secure_session:
                            fwd_frame = sess._secure_session.encrypt_frame(fwd_frame)
                        ok = sess.send_to_backend(fwd_frame)
                        if svc == TUNNELLING_REQ:
                            sess.telegrams_fwd += 1
                            b_seq = fwd_body[2] if isinstance(fwd_body, (bytearray, bytes)) else body[2]
                            log.info(f"Client→Backend ch={ch}: "
                                     f"seq={body[2]}→{b_seq} len={len(body)} "
                                     f"fwd={'OK' if ok else 'FAIL'}"
                                     f"{' [secure]' if sess._secure_session else ''})")
                    else:
                        log.warning(f"No session for {svc_name(svc)} "
                                    f"ch={ch} from {addr[0]}:{addr[1]}")

                elif svc == CONNSTATE_REQ:
                    if not body:
                        continue
                    ch = body[0]
                    sess = self.sessions.get(ch)
                    if sess and sess.alive:
                        sess.last_seen = time.monotonic()
                        # Rewrite channel for backend if it differs
                        fwd_body = body
                        if sess._backend_ch != sess.channel_id:
                            fwd_body = bytearray(body)
                            fwd_body[0] = sess._backend_ch
                            fwd_body = bytes(fwd_body)
                        # Try to forward to backend; if that fails,
                        # respond locally to keep the client session alive.
                        fwd_frame = make_frame(svc, fwd_body)
                        if sess._secure_session:
                            fwd_frame = sess._secure_session.encrypt_frame(fwd_frame)
                        if not sess.send_to_backend(fwd_frame):
                            log.debug(f"CONNSTATE fwd failed ch={ch} — responding locally")
                            resp_body = bytes([ch, 0x00])
                            try:
                                sock.sendall(make_frame(CONNSTATE_RESP, resp_body))
                            except Exception:
                                pass
                    else:
                        # No session — still respond to avoid client disconnect
                        resp_body = bytes([ch, 0x00])
                        try:
                            sock.sendall(make_frame(CONNSTATE_RESP, resp_body))
                        except Exception:
                            pass

                elif svc in (DISCONNECT_REQ, DISCONNECT_RESP):
                    ch = body[0] if body else 0
                    sess = self.sessions.remove(ch)
                    if sess:
                        fwd_body = body
                        if sess._backend_ch != sess.channel_id:
                            fwd_body = bytearray(body)
                            fwd_body[0] = sess._backend_ch
                            fwd_body = bytes(fwd_body)
                        fwd_frame = make_frame(svc, fwd_body)
                        if sess._secure_session:
                            fwd_frame = sess._secure_session.encrypt_frame(fwd_frame)
                        sess.send_to_backend(fwd_frame)
                        log.info(f"Session ch={ch} disconnected by TCP client "
                                 f"(uptime={sess.uptime():.0f}s, telegrams={sess.telegrams_fwd})")
                        sess.close()
                    break

                elif svc == SECURE_SESSION_REQ:
                    # Client wants KNX IP Secure — switch to transparent relay
                    self._handle_secure_passthrough(sock, addr, svc, body)
                    return  # Passthrough took over; caller's finally closes sock

                elif svc in (SECURE_WRAPPER,
                             SECURE_SESSION_AUTH, SECURE_SESSION_STATUS):
                    # These should only appear after SESSION_REQ (passthrough).
                    # If seen here, the client sent them out of order.
                    log.warning(f"Unexpected {svc_name(svc)} without active "
                                f"secure session — ignoring")

        except Exception as e:
            log.debug(f"TCP client {addr}: {e}")
        finally:
            if ch_id is not None:
                sess = self.sessions.remove(ch_id)
                if sess:
                    self._disconnect_backend(sess)
                    log.info(f"Session ch={ch_id} cleaned up on TCP disconnect "
                             f"(uptime={sess.uptime():.0f}s)")
                    sess.close()
            try:
                sock.close()
            except Exception:
                pass
            log.info(f"TCP client {addr[0]}:{addr[1]} disconnected")

    # ──────────────────────────────────────────────────────────────────
    # Cleanup + Metrics loop
    # ──────────────────────────────────────────────────────────────────

    def _maintenance_loop(self):
        """Periodic session cleanup, backend heartbeat, and metrics writing."""
        while self.running:
            time.sleep(30)
            self.sessions.cleanup_stale()
            self._send_backend_heartbeats()
            self.sessions.write_metrics()

    def _send_backend_heartbeats(self):
        """
        Send CONNECTIONSTATE_REQUEST to the backend for every active session.
        KNX gateways disconnect tunnels that don't receive heartbeats within
        their timeout (typically 60-120s, some use 30s).
        The proxy must proactively heartbeat — relying on the client to
        forward theirs is unreliable (timing, protocol mismatch).
        """
        sessions = self.sessions.get_all()
        for sess in sessions:
            if not sess.alive or sess.draining:
                continue
            try:
                b_proto = PROTO_TCP if sess.backend_type == 'tcp' else PROTO_UDP
                hb_body = bytes([sess._backend_ch, 0x00]) + make_hpai('0.0.0.0', 0, b_proto)
                hb_frame = make_frame(CONNSTATE_REQ, hb_body)
                if sess._secure_session:
                    hb_frame = sess._secure_session.encrypt_frame(hb_frame)
                if not sess.send_to_backend(hb_frame):
                    log.warning(f"Backend heartbeat failed ch={sess._backend_ch}")
                else:
                    log.debug(f"Backend heartbeat sent ch={sess._backend_ch}")
            except Exception as e:
                log.debug(f"Backend heartbeat error ch={sess._backend_ch}: {e}")

    # ──────────────────────────────────────────────────────────────────
    # Main
    # ──────────────────────────────────────────────────────────────────

    def run(self):
        """Start the proxy and block until shutdown."""
        # Start transports
        if self.udp:
            self.udp.start()
        if self.tcp:
            self.tcp.start()

        # Start maintenance loop
        threading.Thread(target=self._maintenance_loop, daemon=True,
                         name='maintenance').start()

        log.info("KNX proxy ready — waiting for connections...")

        # Main thread: just wait for shutdown signal
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

        # Shutdown
        log.info("Shutting down KNX proxy...")

        # Stop transports
        if self.udp:
            self.udp.stop()
        if self.tcp:
            self.tcp.stop()

        # Drain all sessions
        udp_sock = None  # Already closed
        self.sessions.drain_all(udp_sock)
        self.sessions.write_metrics()

        # Close secure sessions
        self.secure_mgr.close_all()

        log.info(f"KNX proxy stopped (total sessions: {self.sessions._total_created}, "
                 f"failovers: {self.sessions._total_failovers})")


# ═══════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3671
    try:
        KNXProxy(port).run()
    except OSError as e:
        log.error(f"FATAL: Cannot bind port {port}: {e}")
        sys.exit(1)