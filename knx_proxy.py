#!/usr/bin/env python3
"""
KNX/IP Failover Proxy  v2.5.0

- Listens on TCP and UDP on the same port
- Routes to backend (host:port:proto) from /run/knx-active-backend
- SIGHUP drops all sessions so HA reconnects to new backend on failover
- Handles all 4 combos: UDP client↔UDP backend, UDP↔TCP, TCP↔UDP, TCP↔TCP
"""

import socket, struct, threading, time, logging, os, sys, signal
from typing import Optional, Tuple

VERSION      = "2.5.0"
BACKEND_FILE = "/run/knx-active-backend"
MAGIC        = b'\x06\x10'

DESCRIPTION_REQ  = 0x0203
DESCRIPTION_RESP = 0x0204
CONNECT_REQ      = 0x0205
CONNECT_RESP     = 0x0206
CONNSTATE_REQ    = 0x0207
CONNSTATE_RESP   = 0x0208
DISCONNECT_REQ   = 0x0209
DISCONNECT_RESP  = 0x020A
TUNNELLING_REQ   = 0x0420
TUNNELLING_ACK   = 0x0421

PROTO_UDP = 0x01
PROTO_TCP = 0x06

_lvl = os.environ.get('LOG_LEVEL', 'info').upper()
logging.basicConfig(
    level=getattr(logging, _lvl, logging.INFO),
    format='%(asctime)s [KNX]  %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('knx_proxy')


# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------
def make_frame(svc: int, body: bytes) -> bytes:
    return MAGIC + struct.pack('>HH', svc, 6 + len(body)) + body

def make_hpai(ip: str, port: int, proto: int = PROTO_UDP) -> bytes:
    try:
        return bytes([8, proto]) + socket.inet_aton(ip) + struct.pack('>H', port)
    except OSError:
        return bytes([8, proto]) + b'\x00\x00\x00\x00' + struct.pack('>H', port)

def parse_hpai(data: bytes, off: int) -> Tuple[str, int, int, int]:
    """Returns (ip, port, proto_byte, next_offset)."""
    if off + 8 > len(data):
        return '0.0.0.0', 0, PROTO_UDP, off + 8
    length = data[off]
    proto  = data[off + 1]
    ip     = socket.inet_ntoa(data[off + 2:off + 6])
    port   = struct.unpack('>H', data[off + 6:off + 8])[0]
    return ip, port, proto, off + length

def parse_frame(data: bytes) -> Tuple[Optional[int], Optional[bytes]]:
    if len(data) < 6 or data[:2] != MAGIC:
        return None, None
    svc   = struct.unpack('>H', data[2:4])[0]
    total = struct.unpack('>H', data[4:6])[0]
    if total < 6 or total > len(data):
        return None, None
    return svc, data[6:total]

def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b''
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf

def read_tcp_frame(sock: socket.socket) -> Tuple[Optional[int], Optional[bytes]]:
    hdr = recv_exact(sock, 6)
    if not hdr or hdr[:2] != MAGIC:
        return None, None
    svc   = struct.unpack('>H', hdr[2:4])[0]
    total = struct.unpack('>H', hdr[4:6])[0]
    if total < 6:
        return None, None
    body = recv_exact(sock, total - 6)
    if body is None:
        return None, None
    return svc, body

def tunnel_channel_id(body: bytes) -> int:
    """
    KNX TUNNELLING structure:
      body[0] = header length (04)
      body[1] = reserved     (00)
      body[2] = channel_id   <-- this is what we want
      body[3] = seq_counter
    """
    return body[2] if len(body) >= 4 else 0


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------
def read_backend() -> Optional[Tuple[str, int, str]]:
    try:
        line = open(BACKEND_FILE).read().strip()
        if not line or line == 'none':
            return None
        parts = line.rsplit(':', 2)
        if len(parts) == 3:
            return parts[0], int(parts[1]), parts[2].lower()
        if len(parts) == 2:
            return parts[0], int(parts[1]), 'udp'
    except Exception as e:
        log.debug(f"read_backend: {e}")
    return None


# ---------------------------------------------------------------------------
# DESCRIPTION_RESPONSE — advertises both UDP v1 and TCP v2
# xknx picks based on user setting in HA
# ---------------------------------------------------------------------------
def _build_description_response() -> bytes:
    name = b'KNX Failover Proxy\x00'
    name = name + bytes(30 - len(name))
    dib1 = (
        b'\x36\x01'                          # len=54, DEVICE_INFO
        b'\x02\x00'                          # medium=TP, status=OK
        b'\xff\x00'                          # individual addr 15.15.0
        b'\x00\x00'                          # project install id
        b'\xaa\xbb\xcc\x00\x01\x02'         # serial
        b'\xe0\x00\x17\x0c'                  # multicast 224.0.23.12
        b'\x00\x00\x00\x00\x00\x00'         # MAC
    ) + name
    dib2 = (
        b'\x0a\x02'   # len=10, SUPPORTED_SERVICE_FAMILIES
        b'\x02\x02'   # Core v2
        b'\x03\x02'   # Device Management v2
        b'\x04\x02'   # Tunnelling v2 (TCP)
        b'\x04\x01'   # Tunnelling v1 (UDP)
    )
    return make_frame(DESCRIPTION_RESP, dib1 + dib2)

DESCRIPTION_RESPONSE = _build_description_response()


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
class Session:
    __slots__ = ['channel_id', 'client_type', 'client_ctrl', 'client_data',
                 'client_sock', 'backend_type', 'backend_addr',
                 'backend_sock', 'last_seen', 'alive']

    def __init__(self, channel_id, client_type, client_ctrl, client_data,
                 client_sock, backend_type, backend_addr, backend_sock):
        self.channel_id   = channel_id
        self.client_type  = client_type
        self.client_ctrl  = client_ctrl
        self.client_data  = client_data
        self.client_sock  = client_sock
        self.backend_type = backend_type
        self.backend_addr = backend_addr
        self.backend_sock = backend_sock
        self.last_seen    = time.monotonic()
        self.alive        = True

    def send_to_backend(self, data: bytes) -> bool:
        try:
            if self.backend_type == 'tcp':
                self.backend_sock.sendall(data)
            else:
                self.backend_sock.sendto(data, self.backend_addr)
            return True
        except Exception as e:
            log.debug(f"send_to_backend ch={self.channel_id}: {e}")
            return False

    def close(self):
        self.alive = False
        for s in (self.backend_sock, self.client_sock):
            if s:
                try: s.close()
                except Exception: pass


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------
class KNXProxy:
    SESSION_TIMEOUT = 120

    def __init__(self, port: int):
        self.port     = port
        self.sessions = {}
        self.lock     = threading.Lock()
        self.running  = True

        # UDP socket — NO SO_REUSEPORT (avoids packet splitting with stale procs)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind(('0.0.0.0', port))
        self.udp.settimeout(2.0)
        log.info(f"UDP socket bound to 0.0.0.0:{port}")

        # TCP server socket — SO_REUSEADDR only
        self.tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_srv.bind(('0.0.0.0', port))
        self.tcp_srv.listen(8)
        self.tcp_srv.settimeout(2.0)
        log.info(f"TCP socket bound to 0.0.0.0:{port}")

        signal.signal(signal.SIGHUP,  self._on_sighup)
        signal.signal(signal.SIGTERM, self._on_stop)
        signal.signal(signal.SIGINT,  self._on_stop)
        log.info(f"KNX/IP proxy v{VERSION} — port {port} (TCP+UDP) ready")

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------
    def _on_sighup(self, *_):
        # Run in a thread to avoid signal handler / lock interaction
        threading.Thread(target=self._do_sighup, daemon=True).start()

    def _do_sighup(self):
        log.info("Backend changed — dropping all sessions")
        with self.lock:
            sessions, self.sessions = list(self.sessions.values()), {}
        for sess in sessions:
            self._notify_client_disconnect(sess)
            sess.close()

    def _on_stop(self, *_):
        self.running = False

    def _notify_client_disconnect(self, sess: Session):
        try:
            body  = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0)
            frame = make_frame(DISCONNECT_REQ, body)
            if sess.client_type == 'tcp' and sess.client_sock:
                sess.client_sock.sendall(frame)
            elif sess.client_ctrl:
                self.udp.sendto(frame, sess.client_ctrl)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Backend connection
    # ------------------------------------------------------------------
    def _open_backend(self, host: str, port: int, proto: str) -> Optional[socket.socket]:
        try:
            if proto == 'tcp':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect((host, port))
                return s
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(5.0)
                s.bind(('0.0.0.0', 0))
                return s
        except Exception as e:
            log.error(f"Cannot connect to backend {host}:{port} [{proto}]: {e}")
            return None

    def _create_session(self, client_type: str, client_ctrl: tuple,
                        client_data: tuple, client_sock,
                        connect_body: bytes):
        backend = read_backend()
        if backend is None:
            log.warning("No backend — rejecting CONNECT")
            self._send_connect_error(client_type, client_ctrl, client_sock, 0x26)
            return

        b_host, b_port, b_proto = backend
        log.info(f"CONNECT from {client_type.upper()} {client_ctrl[0]}:{client_ctrl[1]}"
                 f" → backend {b_proto.upper()} {b_host}:{b_port}")

        bsock = self._open_backend(b_host, b_port, b_proto)
        if bsock is None:
            self._send_connect_error(client_type, client_ctrl, client_sock, 0x26)
            return

        b_local_port = bsock.getsockname()[1]
        b_hpai_proto = PROTO_TCP if b_proto == 'tcp' else PROTO_UDP

        # Skip client HPAIs, keep CRI
        _, _, _, off = parse_hpai(connect_body, 0)
        _, _, _, off = parse_hpai(connect_body, off)
        cri = connect_body[off:]

        new_body  = (make_hpai('0.0.0.0', b_local_port, b_hpai_proto) +
                     make_hpai('0.0.0.0', b_local_port, b_hpai_proto) + cri)
        req_frame = make_frame(CONNECT_REQ, new_body)

        try:
            if b_proto == 'tcp':
                bsock.sendall(req_frame)
                resp_svc, resp_body = read_tcp_frame(bsock)
            else:
                bsock.sendto(req_frame, (b_host, b_port))
                raw, _ = bsock.recvfrom(1024)
                resp_svc, resp_body = parse_frame(raw)
        except socket.timeout:
            log.error(f"Backend CONNECT timeout {b_host}:{b_port}")
            bsock.close()
            self._send_connect_error(client_type, client_ctrl, client_sock, 0x26)
            return
        except Exception as e:
            log.error(f"Backend CONNECT error: {e}")
            bsock.close()
            self._send_connect_error(client_type, client_ctrl, client_sock, 0x26)
            return

        if resp_svc != CONNECT_RESP or not resp_body or len(resp_body) < 10:
            log.error(f"Bad CONNECT_RESP from backend svc=0x{resp_svc:04x if resp_svc else 0}")
            bsock.close()
            self._send_connect_error(client_type, client_ctrl, client_sock, 0x26)
            return

        ch_id  = resp_body[0]
        status = resp_body[1]

        if status != 0x00:
            log.warning(f"Backend refused: status=0x{status:02x}")
            bsock.close()
            self._send_raw(make_frame(CONNECT_RESP, resp_body), client_type, client_ctrl, client_sock)
            return

        _, _, _, r_off = parse_hpai(resp_body, 2)
        crd = resp_body[r_off:]

        c_proto   = PROTO_TCP if client_type == 'tcp' else PROTO_UDP
        c_resp    = bytes([ch_id, 0x00]) + make_hpai('0.0.0.0', self.port, c_proto) + crd
        c_frame   = make_frame(CONNECT_RESP, c_resp)

        sess = Session(
            channel_id=ch_id,
            client_type=client_type,
            client_ctrl=client_ctrl,
            client_data=client_data,
            client_sock=client_sock,
            backend_type=b_proto,
            backend_addr=(b_host, b_port),
            backend_sock=bsock,
        )

        with self.lock:
            old = self.sessions.pop(ch_id, None)
            if old: old.close()
            self.sessions[ch_id] = sess

        threading.Thread(target=self._relay_from_backend, args=(sess,),
                         daemon=True, name=f"relay-{ch_id}").start()

        if not self._send_raw(c_frame, client_type, client_ctrl, client_sock):
            with self.lock: self.sessions.pop(ch_id, None)
            sess.close()
            return

        log.info(f"Session {ch_id} established: "
                 f"{client_type.upper()} {client_ctrl[0]}:{client_ctrl[1]} "
                 f"↔ {b_proto.upper()} {b_host}:{b_port}")

    def _send_raw(self, frame, ctype, ctrl, csock) -> bool:
        try:
            if ctype == 'tcp' and csock:
                csock.sendall(frame)
            elif ctrl:
                self.udp.sendto(frame, ctrl)
            return True
        except Exception as e:
            log.debug(f"_send_raw: {e}")
            return False

    def _send_connect_error(self, ctype, ctrl, csock, code):
        body  = bytes([0x00, code]) + make_hpai('0.0.0.0', 0) + b'\x04\x04\x00\x00'
        self._send_raw(make_frame(CONNECT_RESP, body), ctype, ctrl, csock)

    # ------------------------------------------------------------------
    # Backend → client relay
    # ------------------------------------------------------------------
    def _relay_from_backend(self, sess: Session):
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
                if time.monotonic() - sess.last_seen > self.SESSION_TIMEOUT:
                    log.info(f"Session {sess.channel_id} timed out")
                    with self.lock: self.sessions.pop(sess.channel_id, None)
                    sess.close()
                continue
            except Exception as e:
                if sess.alive:
                    log.debug(f"relay ch={sess.channel_id}: {e}")
                break

            sess.last_seen = time.monotonic()
            dest = sess.client_data or sess.client_ctrl

            if svc in (TUNNELLING_REQ, TUNNELLING_ACK, CONNSTATE_RESP, DISCONNECT_RESP):
                self._send_raw(data, sess.client_type, dest, sess.client_sock)
            elif svc == DISCONNECT_REQ:
                self._send_raw(data, sess.client_type, sess.client_ctrl, sess.client_sock)
                ack = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0)
                sess.send_to_backend(make_frame(DISCONNECT_RESP, ack))
                with self.lock: self.sessions.pop(sess.channel_id, None)
                log.info(f"Session {sess.channel_id} closed by backend")
                sess.close()
                return

        if sess.alive:
            with self.lock: self.sessions.pop(sess.channel_id, None)
            sess.close()

    # ------------------------------------------------------------------
    # UDP dispatch
    # ------------------------------------------------------------------
    def _dispatch_udp(self, data: bytes, addr: tuple):
        svc, body = parse_frame(data)
        if svc is None:
            log.debug(f"Unparseable UDP from {addr[0]}:{addr[1]} ({len(data)}B)")
            return

        log.debug(f"UDP svc=0x{svc:04x} from {addr[0]}:{addr[1]}")

        if svc == DESCRIPTION_REQ:
            log.info(f"DESCRIPTION_REQUEST from {addr[0]}:{addr[1]}")
            try:
                self.udp.sendto(DESCRIPTION_RESPONSE, addr)
            except Exception as e:
                log.error(f"DESCRIPTION_RESPONSE failed: {e}")

        elif svc == CONNECT_REQ:
            if not body or len(body) < 16:
                return
            ci, cp, _, off = parse_hpai(body, 0)
            di, dp, _, _   = parse_hpai(body, off)
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
            ch = tunnel_channel_id(body)   # body[2]
            with self.lock:
                sess = self.sessions.get(ch)
            if sess and sess.alive:
                sess.last_seen = time.monotonic()
                sess.send_to_backend(data)

        elif svc == CONNSTATE_REQ:
            if not body:
                return
            ch = body[0]
            with self.lock:
                sess = self.sessions.get(ch)
            if sess and sess.alive:
                sess.last_seen = time.monotonic()
                sess.send_to_backend(data)

        elif svc in (DISCONNECT_REQ, DISCONNECT_RESP):
            ch = body[0] if body else 0
            with self.lock:
                sess = self.sessions.pop(ch, None)
            if sess:
                sess.send_to_backend(data)
                log.info(f"Session {ch} disconnected by UDP client")
                sess.close()

    # ------------------------------------------------------------------
    # TCP client handler
    # ------------------------------------------------------------------
    def _handle_tcp_client(self, sock: socket.socket, addr: tuple):
        log.info(f"TCP client connected: {addr[0]}:{addr[1]}")
        sock.settimeout(30.0)
        ch_id = None
        try:
            while self.running:
                svc, body = read_tcp_frame(sock)
                if svc is None:
                    break

                log.debug(f"TCP svc=0x{svc:04x} from {addr[0]}:{addr[1]}")

                if svc == DESCRIPTION_REQ:
                    log.info(f"TCP DESCRIPTION_REQUEST from {addr[0]}:{addr[1]}")
                    try:
                        sock.sendall(DESCRIPTION_RESPONSE)
                    except Exception as e:
                        log.error(f"TCP DESCRIPTION_RESPONSE failed: {e}")
                        break

                elif svc == CONNECT_REQ:
                    ctrl = (addr[0], addr[1])
                    self._create_session('tcp', ctrl, ctrl, sock, body)
                    with self.lock:
                        for ch, s in self.sessions.items():
                            if s.client_sock is sock:
                                ch_id = ch
                                break

                elif svc in (TUNNELLING_REQ, TUNNELLING_ACK):
                    if not body or len(body) < 4:
                        continue
                    ch = tunnel_channel_id(body)  # body[2]
                    with self.lock:
                        sess = self.sessions.get(ch)
                    if sess and sess.alive:
                        sess.last_seen = time.monotonic()
                        sess.send_to_backend(make_frame(svc, body))

                elif svc == CONNSTATE_REQ:
                    if not body:
                        continue
                    ch = body[0]
                    with self.lock:
                        sess = self.sessions.get(ch)
                    if sess and sess.alive:
                        sess.last_seen = time.monotonic()
                        sess.send_to_backend(make_frame(svc, body))

                elif svc in (DISCONNECT_REQ, DISCONNECT_RESP):
                    ch = body[0] if body else 0
                    with self.lock:
                        sess = self.sessions.pop(ch, None)
                    if sess:
                        sess.send_to_backend(make_frame(svc, body))
                        log.info(f"Session {ch} disconnected by TCP client")
                        sess.close()
                    break

        except Exception as e:
            log.debug(f"TCP client {addr}: {e}")
        finally:
            if ch_id is not None:
                with self.lock:
                    sess = self.sessions.pop(ch_id, None)
                if sess:
                    sess.close()
            try:
                sock.close()
            except Exception:
                pass
            log.info(f"TCP client {addr[0]}:{addr[1]} disconnected")

    # ------------------------------------------------------------------
    # TCP accept loop
    # ------------------------------------------------------------------
    def _tcp_accept_loop(self):
        while self.running:
            try:
                sock, addr = self.tcp_srv.accept()
                threading.Thread(target=self._handle_tcp_client,
                                 args=(sock, addr), daemon=True,
                                 name=f"tcp-{addr[0]}").start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log.error(f"TCP accept: {e}")
                    time.sleep(1)

    # ------------------------------------------------------------------
    # Cleanup loop
    # ------------------------------------------------------------------
    def _cleanup_loop(self):
        while self.running:
            time.sleep(30)
            now = time.monotonic()
            with self.lock:
                stale = [ch for ch, s in self.sessions.items()
                         if now - s.last_seen > self.SESSION_TIMEOUT]
                for ch in stale:
                    log.info(f"Session {ch} timed out")
                    s = self.sessions.pop(ch)
                    s.close()

    # ------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------
    def run(self):
        threading.Thread(target=self._cleanup_loop,    daemon=True, name="cleanup").start()
        threading.Thread(target=self._tcp_accept_loop, daemon=True, name="tcp-accept").start()
        log.info("Proxy running — waiting for connections")

        while self.running:
            try:
                data, addr = self.udp.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError as e:
                if self.running:
                    log.error(f"UDP recv error: {e}")
                    time.sleep(1)
                continue
            threading.Thread(target=self._dispatch_udp,
                             args=(data, addr), daemon=True).start()

        with self.lock:
            for s in self.sessions.values():
                s.close()
            self.sessions.clear()
        for s in (self.udp, self.tcp_srv):
            try: s.close()
            except Exception: pass
        log.info("Proxy stopped")


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3672
    try:
        KNXProxy(port).run()
    except OSError as e:
        log.error(f"FATAL: Cannot bind port {port}: {e}")
        log.error("Is another process already using this port? Check with: ss -tulpn | grep 3672")
        sys.exit(1)