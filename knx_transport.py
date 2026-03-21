#!/usr/bin/env python3
"""
KNX Transport Layer
====================
Provides unified TCP and UDP transport for the KNX proxy frontend.
Handles socket lifecycle, multicast-safe binding, and NAT-aware HPAI rewriting.
"""

import socket
import threading
import time
import logging
from typing import Optional, Callable, Tuple

log = logging.getLogger('knx_transport')


class UDPTransport:
    """
    UDP frontend transport.
    Listens for incoming UDP KNXnet/IP frames and dispatches them.
    """

    def __init__(self, port: int, dispatch_fn: Callable):
        self.port = port
        self.dispatch = dispatch_fn
        self.sock: Optional[socket.socket] = None
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Bind and start the UDP listener."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.settimeout(2.0)
        self.running = True

        self._thread = threading.Thread(target=self._recv_loop,
                                         daemon=True, name='udp-recv')
        self._thread.start()
        log.info(f"UDP transport bound to 0.0.0.0:{self.port}")

    def _recv_loop(self):
        """Main UDP receive loop."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError as e:
                if self.running:
                    log.error(f"UDP recv error: {e}")
                    time.sleep(1)
                continue

            # Dispatch in a separate thread to avoid blocking
            threading.Thread(target=self.dispatch,
                             args=(data, addr),
                             daemon=True).start()

    def sendto(self, data: bytes, addr: Tuple[str, int]) -> bool:
        """Send data to a specific address."""
        try:
            self.sock.sendto(data, addr)
            return True
        except Exception as e:
            log.debug(f"UDP sendto {addr}: {e}")
            return False

    def stop(self):
        """Close the UDP socket."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        log.info("UDP transport stopped")


class TCPTransport:
    """
    TCP frontend transport.
    Accepts incoming TCP connections and dispatches them to handlers.
    """

    def __init__(self, port: int, handler_fn: Callable):
        self.port = port
        self.handler = handler_fn
        self.server: Optional[socket.socket] = None
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Bind and start the TCP listener."""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        self.server.bind(('0.0.0.0', self.port))
        self.server.listen(16)
        self.server.settimeout(2.0)
        self.running = True

        self._thread = threading.Thread(target=self._accept_loop,
                                         daemon=True, name='tcp-accept')
        self._thread.start()
        log.info(f"TCP transport bound to 0.0.0.0:{self.port}")

    def _accept_loop(self):
        """Main TCP accept loop."""
        while self.running:
            try:
                sock, addr = self.server.accept()
                threading.Thread(target=self.handler,
                                 args=(sock, addr),
                                 daemon=True,
                                 name=f'tcp-{addr[0]}:{addr[1]}').start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log.error(f"TCP accept error: {e}")
                    time.sleep(1)

    def stop(self):
        """Close the TCP server socket."""
        self.running = False
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass
        log.info("TCP transport stopped")


class BackendConnector:
    """
    Creates backend connections (TCP or UDP) to KNX interfaces.
    Handles the full CONNECT negotiation with CRI/HPAI compatibility matrix.
    """

    def __init__(self, connect_timeout: float = 5.0):
        self.connect_timeout = connect_timeout

    def open_socket(self, host: str, port: int, proto: str) -> socket.socket:
        """
        Open a raw socket to the backend.
        Uses connect_timeout for the initial connection, then resets
        to a longer timeout suitable for long-lived relay (must be
        > 60s to survive the xknx heartbeat cycle).
        """
        if proto == 'tcp':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.connect_timeout)
            s.connect((host, port))
            return s
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.connect_timeout)
            s.bind(('0.0.0.0', 0))
            s.connect((host, port))
            return s

    def negotiate_tunnel(self, bsock: socket.socket, host: str, port: int,
                         proto: str, client_cri: Optional[bytes] = None
                         ) -> Tuple[Optional[int], Optional[bytes], Optional[int]]:
        """
        Negotiate a KNX tunnel with the backend.
        Returns (channel_id, crd, status) or (None, None, status) on failure.

        Uses a minimal set of CRI/HPAI combinations to avoid exhausting
        the hardware's limited tunnel slots. Aborts immediately on
        0x22 (no more connections) or 0x24 (no more unique IDs) since
        additional attempts would only make the situation worse.
        """
        import time as _time
        from knx_const import (
            CONNECT_REQ, CONNECT_RESP, PROTO_TCP, PROTO_UDP,
            CRI_TUNNEL_V1, CRI_TUNNEL_V2,
            make_frame, make_hpai, parse_hpai, parse_frame, read_tcp_frame,
        )

        b_local_ip, b_local_port = bsock.getsockname()[:2]

        # Build a MINIMAL set of attempts — do not brute-force
        # Most KNX hardware accepts the first standard combination.
        attempts = []
        if proto == 'tcp':
            attempts = [
                ('0.0.0.0', 0, PROTO_TCP, '0.0.0.0', 0, PROTO_TCP,
                 CRI_TUNNEL_V1, 'tcp-zero+v1'),
                ('0.0.0.0', 0, PROTO_TCP, '0.0.0.0', 0, PROTO_TCP,
                 CRI_TUNNEL_V2, 'tcp-zero+v2'),
                ('0.0.0.0', 0, PROTO_TCP, b_local_ip, b_local_port, PROTO_TCP,
                 CRI_TUNNEL_V1, 'tcp-local+v1'),
            ]
        else:
            attempts = [
                ('0.0.0.0', 0, PROTO_UDP, '0.0.0.0', 0, PROTO_UDP,
                 CRI_TUNNEL_V1, 'udp-zero+v1'),
                ('0.0.0.0', 0, PROTO_UDP, '0.0.0.0', 0, PROTO_UDP,
                 CRI_TUNNEL_V2, 'udp-zero+v2'),
                ('0.0.0.0', 0, PROTO_UDP, b_local_ip, b_local_port, PROTO_UDP,
                 CRI_TUNNEL_V1, 'udp-local+v1'),
                (b_local_ip, b_local_port, PROTO_UDP, b_local_ip, b_local_port, PROTO_UDP,
                 CRI_TUNNEL_V1, 'udp-both+v1'),
            ]

        # If client sent a specific CRI, try it first
        if client_cri and client_cri not in (CRI_TUNNEL_V1, CRI_TUNNEL_V2):
            first = attempts[0]
            attempts.insert(0, (
                first[0], first[1], first[2], first[3], first[4], first[5],
                client_cri, 'client-cri',
            ))

        last_status = None
        for i, (ctrl_ip, ctrl_port, ctrl_proto, data_ip, data_port,
                data_proto, cri, label) in enumerate(attempts):

            # Small delay between retries to let hardware breathe
            if i > 0:
                _time.sleep(0.5)

            body = (
                make_hpai(ctrl_ip, ctrl_port, ctrl_proto)
                + make_hpai(data_ip, data_port, data_proto)
                + cri
            )
            req_frame = make_frame(CONNECT_REQ, body)

            try:
                if proto == 'tcp':
                    bsock.sendall(req_frame)
                    svc, rbody = read_tcp_frame(bsock)
                else:
                    bsock.send(req_frame)
                    raw = bsock.recv(1024)
                    svc, rbody = parse_frame(raw)
            except socket.timeout:
                log.debug(f"CONNECT timeout ({label})")
                continue
            except Exception as e:
                log.debug(f"CONNECT error ({label}): {e}")
                continue

            if svc != CONNECT_RESP or not rbody or len(rbody) < 2:
                continue

            ch_id = rbody[0]
            status = rbody[1]
            last_status = status

            if status == 0x00:
                # Extract CRD
                crd = b'\x04\x04\x00\x00'
                if len(rbody) >= 10:
                    _, _, _, r_off = parse_hpai(rbody, 2)
                    if r_off < len(rbody):
                        crd = rbody[r_off:]
                elif len(rbody) > 2:
                    crd = rbody[2:]

                log.info(f"Backend CONNECT accepted ({label}) ch={ch_id}")
                return ch_id, crd, 0x00

            log.debug(f"Backend CONNECT rejected ({label}) status=0x{status:02x}")

            # EARLY ABORT on truly fatal errors only:
            # 0x24 = no more unique IDs — hardware limitation, retrying is useless
            # 0x25 = individual address in use — specific to requested address
            if status in (0x24, 0x25):
                log.warning(f"Backend fatal rejection (0x{status:02x}) — aborting negotiation")
                return None, None, status

            # For 0x22 (no more connections): DON'T abort early.
            # Some gateways reject specific HPAI combos with 0x22 but accept others.
            # Ghost sessions from previous addon restarts may also free up between retries.
            # Use a longer delay to give the gateway time to recycle.
            if status == 0x22 and i < len(attempts) - 1:
                log.debug(f"Backend busy (0x22) — waiting 1s before next attempt")
                _time.sleep(1.0)  # Extra delay on top of the 0.5s base delay

        log.warning(f"All CONNECT attempts failed (last_status=0x{(last_status if last_status is not None else 0):02x})")
        return None, None, last_status

    def try_tcp_fallback(self, host: str, port: int,
                          client_cri: Optional[bytes] = None
                          ) -> Tuple[Optional[socket.socket], Optional[int], Optional[bytes], Optional[int]]:
        """
        Emergency fallback: if UDP CONNECT is rejected with 0x22,
        try TCP to the same host.

        Returns (socket, channel_id, crd, status) or (None, None, None, status).
        """
        log.info(f"Attempting TCP fallback for {host}:{port}")
        try:
            bsock = self.open_socket(host, port, 'tcp')
            ch_id, crd, status = self.negotiate_tunnel(bsock, host, port, 'tcp', client_cri)
            if ch_id is not None:
                return bsock, ch_id, crd, status
            bsock.close()
            return None, None, None, status
        except Exception as e:
            log.warning(f"TCP fallback failed: {e}")
            return None, None, None, 0x26

    def try_udp_fallback(self, host: str, port: int,
                          client_cri: Optional[bytes] = None
                          ) -> Tuple[Optional[socket.socket], Optional[int], Optional[bytes], Optional[int]]:
        """
        Emergency fallback: if TCP CONNECT is rejected with 0x22,
        try UDP to the same host.

        Many KNX gateways have separate TCP and UDP tunnel slot pools.
        When TCP slots are exhausted, UDP slots may still be available.

        Returns (socket, channel_id, crd, status) or (None, None, None, status).
        """
        log.info(f"Attempting UDP fallback for {host}:{port}")
        try:
            bsock = self.open_socket(host, port, 'udp')
            ch_id, crd, status = self.negotiate_tunnel(bsock, host, port, 'udp', client_cri)
            if ch_id is not None:
                return bsock, ch_id, crd, status
            bsock.close()
            return None, None, None, status
        except Exception as e:
            log.warning(f"UDP fallback failed: {e}")
            return None, None, None, 0x26
