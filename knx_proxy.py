#!/usr/bin/env python3
"""
KNX/IP Failover Proxy  v3.0.0
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
BACKUP_DEVICE_PW    = os.environ.get('BACKUP_DEVICE_PASSWORD', '')
BACKUP_USER_PW      = os.environ.get('BACKUP_USER_PASSWORD', '')

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
        """Graceful shutdown."""
        self.running = False

    # ──────────────────────────────────────────────────────────────────
    # Backend connection
    # ──────────────────────────────────────────────────────────────────

    def _get_secure_config(self, host: str, port: int) -> Tuple[bool, str, str]:
        """Determine if a backend should use secure mode."""
        backend = read_backend()
        if backend is None:
            return False, '', ''

        b_host, b_port, _ = backend

        # Check primary
        if PRIMARY_SECURE and b_host == host:
            return True, PRIMARY_DEVICE_PW, PRIMARY_USER_PW
        # Check backup
        if BACKUP_SECURE and b_host == host:
            return True, BACKUP_DEVICE_PW, BACKUP_USER_PW

        return False, '', ''

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

        # Negotiate tunnel
        try:
            ch_id, crd, status = self.connector.negotiate_tunnel(
                bsock, b_host, b_port, b_proto, client_cri
            )
        except Exception as e:
            log.error(f"Backend tunnel negotiation error: {e}")
            bsock.close()
            report_backend_reject(b_host, b_port, b_proto, E_DATA_CONN)
            self._send_connect_error(client_type, client_ctrl, client_sock, E_DATA_CONN)
            return

        if ch_id is None:
            final_status = status if status else E_DATA_CONN

            # Try protocol fallback if rejected with 0x22 (no free slots)
            # Many KNX gateways have separate TCP and UDP tunnel slot pools.
            # When one protocol's slots are full, the other may still work.
            if final_status == 0x22:
                if b_proto == 'udp':
                    log.info("UDP tunnel rejected (0x22) — trying TCP fallback")
                    bsock.close()
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
                    bsock.close()
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
                    bsock.close()
                    report_backend_reject(b_host, b_port, b_proto, final_status)
                    self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
                    self._send_connect_error(client_type, client_ctrl, client_sock, final_status)
                    return
            else:
                bsock.close()
                report_backend_reject(b_host, b_port, b_proto, final_status)
                self._backend_cooldowns[cooldown_key] = time.monotonic() + self._cooldown_seconds
                self._send_connect_error(client_type, client_ctrl, client_sock, final_status)
                return

        if crd is None:
            crd = CRD_DEFAULT

        # Setup keep-alive timeout for the long-running socket relay
        if bsock:
            bsock.settimeout(65.0)

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

        log.info(f"Session ch={ch_id} established: "
                 f"{client_type.upper()} {client_ctrl[0]}:{client_ctrl[1]} ↔ "
                 f"{b_proto.upper()} {b_host}:{b_port}")

    # ──────────────────────────────────────────────────────────────────
    # Backend → Client relay
    # ──────────────────────────────────────────────────────────────────

    def _relay_from_backend(self, sess: Session):
        """Read frames from backend and forward to client."""
        udp_sock = self.udp.sock if self.udp else None

        while sess.alive and self.running:
            try:
                if sess.backend_type == 'tcp':
                    svc, body = read_tcp_frame(sess.backend_sock)
                    if svc is None:
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

            if svc in (TUNNELLING_REQ, TUNNELLING_ACK, CONNSTATE_RESP, DISCONNECT_RESP):
                sess.send_to_client(data, udp_sock)
                if svc in (TUNNELLING_REQ, TUNNELLING_ACK):
                    sess.telegrams_fwd += 1

            elif svc == DISCONNECT_REQ:
                # Backend initiated disconnect
                sess.send_to_client(data, udp_sock)
                # Send ack back to backend
                ack_body = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0)
                sess.send_to_backend(make_frame(DISCONNECT_RESP, ack_body))
                self.sessions.remove(sess.channel_id)
                log.info(f"Session ch={sess.channel_id} closed by backend "
                         f"(uptime={sess.uptime():.0f}s, telegrams={sess.telegrams_fwd})")
                sess.close()
                return

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
            body = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0, old_proto)
            sess.send_to_backend(make_frame(DISCONNECT_REQ, body))
        except Exception:
            pass

        # Open new backend socket
        bsock = self.connector.open_socket(b_host, b_port, b_proto)

        # Negotiate tunnel
        ch_id, crd, status = self.connector.negotiate_tunnel(
            bsock, b_host, b_port, b_proto
        )

        # Protocol fallback: if 0x22 on one protocol, try the other
        if ch_id is None and status == 0x22:
            bsock.close()
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
            bsock.close()
            raise RuntimeError(f"Backend rejected CONNECT (status=0x{(status or 0):02x})")

        # Setup keep-alive timeout for the long-running socket relay
        bsock.settimeout(65.0)

        # Swap the backend in-place
        sess.swap_backend(bsock, b_proto, (b_host, b_port), ch_id)

    # ──────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────

    def _disconnect_backend(self, sess: Session):
        """Send DISCONNECT_REQ to backend (best-effort)."""
        try:
            proto = PROTO_TCP if sess.backend_type == 'tcp' else PROTO_UDP
            body = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0, proto)
            sess.send_to_backend(make_frame(DISCONNECT_REQ, body))
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
                sess.send_to_backend(data)
                sess.telegrams_fwd += 1

        elif svc == CONNSTATE_REQ:
            if not body:
                return
            ch = body[0]
            sess = self.sessions.get(ch)
            if sess and sess.alive:
                sess.last_seen = time.monotonic()
                if not sess.send_to_backend(data):
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
                sess.send_to_backend(data)
                log.info(f"Session ch={ch} disconnected by UDP client "
                         f"(uptime={sess.uptime():.0f}s, telegrams={sess.telegrams_fwd})")
                sess.close()

        elif svc in (SECURE_SESSION_REQ, SECURE_WRAPPER):
            log.debug(f"Secure frame from UDP client — passing through")
            # For secure-to-secure passthrough, forward as-is
            # The backend connector handles the secure establishment

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
                        sess.send_to_backend(make_frame(svc, body))
                        sess.telegrams_fwd += 1

                elif svc == CONNSTATE_REQ:
                    if not body:
                        continue
                    ch = body[0]
                    sess = self.sessions.get(ch)
                    if sess and sess.alive:
                        sess.last_seen = time.monotonic()
                        # Try to forward to backend; if that fails,
                        # respond locally to keep the client session alive.
                        if not sess.send_to_backend(make_frame(svc, body)):
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
                        sess.send_to_backend(make_frame(svc, body))
                        log.info(f"Session ch={ch} disconnected by TCP client "
                                 f"(uptime={sess.uptime():.0f}s, telegrams={sess.telegrams_fwd})")
                        sess.close()
                    break

                elif svc in (SECURE_SESSION_REQ, SECURE_WRAPPER,
                             SECURE_SESSION_AUTH, SECURE_SESSION_STATUS):
                    log.debug(f"Secure frame from TCP client — passing through")

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
                hb_body = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0, b_proto)
                hb_frame = make_frame(CONNSTATE_REQ, hb_body)
                if not sess.send_to_backend(hb_frame):
                    log.warning(f"Backend heartbeat failed ch={sess.channel_id}")
                else:
                    log.debug(f"Backend heartbeat sent ch={sess.channel_id}")
            except Exception as e:
                log.debug(f"Backend heartbeat error ch={sess.channel_id}: {e}")

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