#!/usr/bin/env python3
"""
KNX Failover Proxy — Full KNX/IP UDP Tunnel Proxy  v2.3.0

Handles the complete KNXnet/IP v1 tunnel protocol:
  - DESCRIPTION_REQUEST  → DESCRIPTION_RESPONSE  (advertises UDP v1)
  - CONNECT_REQUEST      → proxied with HPAI rewriting so ALL frames
                           are mediated by this proxy (enables failover)
  - TUNNELLING frames    → relayed bidirectionally client ↔ backend
  - CONNECTIONSTATE      → relayed (keepalive)
  - DISCONNECT           → relayed, session cleaned up

Backend is read from /run/knx-active-backend (written by run.sh).
SIGHUP causes all sessions to be cleanly terminated so HA reconnects
to the new backend immediately after a failover.
"""
import socket, struct, threading, time, logging, os, sys, signal
from typing import Optional, Tuple

VERSION = "2.3.0"
BACKEND_FILE = "/run/knx-active-backend"
MAGIC = b'\x06\x10'

# Service type identifiers
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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
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

def make_hpai(ip: str, port: int) -> bytes:
    """8-byte IPv4 UDP HPAI. Use ip='0.0.0.0' to let receiver fill in source IP."""
    try:
        return b'\x08\x01' + socket.inet_aton(ip) + struct.pack('>H', port)
    except OSError:
        return b'\x08\x01\x00\x00\x00\x00' + struct.pack('>H', port)

def parse_hpai(data: bytes, offset: int) -> Tuple[str, int, int]:
    """Returns (ip, port, next_offset)."""
    if offset + 8 > len(data):
        return '0.0.0.0', 0, offset + 8
    length = data[offset]
    ip = socket.inet_ntoa(data[offset + 2:offset + 6])
    port = struct.unpack('>H', data[offset + 6:offset + 8])[0]
    return ip, port, offset + length

def parse_frame(data: bytes) -> Tuple[Optional[int], Optional[bytes]]:
    """Returns (service_type, body) or (None, None) on bad frame."""
    if len(data) < 6 or data[:2] != MAGIC:
        return None, None
    svc = struct.unpack('>H', data[2:4])[0]
    total = struct.unpack('>H', data[4:6])[0]
    if total < 6 or total > len(data):
        return None, None
    return svc, data[6:total]

# ---------------------------------------------------------------------------
# Pre-built DESCRIPTION_RESPONSE
# Advertises UDP Tunnelling v1 only — forces xknx to use UDP mode.
# ---------------------------------------------------------------------------
def _build_desc_resp() -> bytes:
    name_raw = b'KNX Failover Proxy\x00'
    name = name_raw + bytes(30 - len(name_raw))
    dib1 = (
        b'\x36\x01'                          # len=54, DEVICE_INFO
        b'\x02\x00'                          # medium=TP, status=OK
        b'\xff\x00'                          # individual addr 15.15.0
        b'\x00\x00'                          # project install ID
        b'\xaa\xbb\xcc\x00\x01\x02'         # serial number
        b'\xe0\x00\x17\x0c'                  # multicast 224.0.23.12
        b'\x00\x00\x00\x00\x00\x00'         # MAC address
    ) + name
    dib2 = (
        b'\x06\x02'   # len=6, SUPPORTED_SERVICE_FAMILIES
        b'\x02\x01'   # KNXnet/IP Core v1
        b'\x04\x01'   # KNXnet/IP Tunnelling v1 (UDP)
    )
    body = dib1 + dib2
    return make_frame(DESCRIPTION_RESP, body)

DESCRIPTION_RESPONSE = _build_desc_resp()

# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
class Session:
    __slots__ = ('channel_id', 'client_ctrl', 'client_data',
                 'backend', 'bsock', 'last_seen', 'alive')

    def __init__(self, channel_id, client_ctrl, client_data, backend, bsock):
        self.channel_id  = channel_id
        self.client_ctrl = client_ctrl   # (ip, port) — xknx control endpoint
        self.client_data = client_data   # (ip, port) — xknx data endpoint
        self.backend     = backend       # (ip, port) — KNX interface
        self.bsock       = bsock         # UDP socket toward backend
        self.last_seen   = time.monotonic()
        self.alive       = True

    def close(self):
        self.alive = False
        try:
            self.bsock.close()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------
class KNXProxy:
    SESSION_TIMEOUT = 120   # seconds without any frame

    def __init__(self, listen_port: int):
        self.listen_port = listen_port
        self.sessions: dict = {}    # channel_id -> Session
        self.lock = threading.Lock()
        self.running = True

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        self.sock.bind(('0.0.0.0', listen_port))
        self.sock.settimeout(2.0)

        signal.signal(signal.SIGHUP,  self._on_sighup)
        signal.signal(signal.SIGTERM, self._on_sigterm)
        signal.signal(signal.SIGINT,  self._on_sigterm)

        log.info(f"KNX/IP proxy v{VERSION} — UDP port {listen_port}")

    # ------------------------------------------------------------------
    # Signal handlers
    # ------------------------------------------------------------------
    def _on_sighup(self, *_):
        """Backend changed — drop all sessions so HA reconnects to new backend."""
        log.info("SIGHUP: backend changed — terminating all sessions")
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for sess in sessions:
            try:
                body = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0)
                self.sock.sendto(make_frame(DISCONNECT_REQ, body), sess.client_ctrl)
            except Exception:
                pass
            sess.close()

    def _on_sigterm(self, *_):
        log.info("Stopping proxy...")
        self.running = False

    # ------------------------------------------------------------------
    # Backend config
    # ------------------------------------------------------------------
    def get_backend(self) -> Optional[Tuple[str, int]]:
        try:
            line = open(BACKEND_FILE).read().strip()
            if not line or line == 'none':
                return None
            host, port_s = line.rsplit(':', 1)
            return host, int(port_s)
        except Exception as e:
            log.warning(f"Cannot read backend from {BACKEND_FILE}: {e}")
            return None

    # ------------------------------------------------------------------
    # Frame dispatch (called in a short-lived thread per datagram)
    # ------------------------------------------------------------------
    def dispatch(self, data: bytes, addr: Tuple[str, int]):
        svc, body = parse_frame(data)
        if svc is None:
            return

        if svc == DESCRIPTION_REQ:
            log.info(f"DESCRIPTION_REQUEST from {addr[0]}:{addr[1]} — sending response")
            try:
                self.sock.sendto(DESCRIPTION_RESPONSE, addr)
            except Exception as e:
                log.error(f"Failed to send DESCRIPTION_RESPONSE: {e}")

        elif svc == CONNECT_REQ:
            self._handle_connect(body, addr)

        elif svc == CONNSTATE_REQ:
            ch = body[0] if body else 0
            with self.lock:
                sess = self.sessions.get(ch)
            if sess and sess.alive:
                sess.last_seen = time.monotonic()
                try:
                    sess.bsock.sendto(data, sess.backend)
                except Exception:
                    pass

        elif svc in (DISCONNECT_REQ, DISCONNECT_RESP):
            ch = body[0] if body else 0
            with self.lock:
                sess = self.sessions.pop(ch, None)
            if sess:
                try:
                    sess.bsock.sendto(data, sess.backend)
                except Exception:
                    pass
                sess.close()
                log.info(f"Session {ch} disconnected by client")

        elif svc == TUNNELLING_REQ:
            if len(body) < 4:
                return
            ch = body[1]
            with self.lock:
                sess = self.sessions.get(ch)
            if sess and sess.alive:
                sess.last_seen = time.monotonic()
                try:
                    sess.bsock.sendto(data, sess.backend)
                except Exception:
                    pass

        elif svc == TUNNELLING_ACK:
            if len(body) < 4:
                return
            ch = body[1]
            with self.lock:
                sess = self.sessions.get(ch)
            if sess and sess.alive:
                try:
                    sess.bsock.sendto(data, sess.backend)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # CONNECT_REQUEST handler
    # ------------------------------------------------------------------
    def _handle_connect(self, body: bytes, client_ctrl_addr: Tuple[str, int]):
        backend = self.get_backend()
        if backend is None:
            log.warning("No backend configured — rejecting CONNECT_REQUEST")
            err = bytes([0x00, 0x26]) + make_hpai('0.0.0.0', 0) + b'\x04\x04\x02\x00'
            try:
                self.sock.sendto(make_frame(CONNECT_RESP, err), client_ctrl_addr)
            except Exception:
                pass
            return

        # Parse client HPAIs
        c_ctrl_ip, c_ctrl_port, off = parse_hpai(body, 0)
        c_data_ip, c_data_port, off = parse_hpai(body, off)
        cri = body[off:]   # Connection Request Information

        # Resolve xknx data addr (0.0.0.0 → use packet source IP)
        data_ip   = c_data_ip   if c_data_ip   != '0.0.0.0' else client_ctrl_addr[0]
        data_port = c_data_port if c_data_port != 0         else client_ctrl_addr[1]
        client_data_addr = (data_ip, data_port)

        # Open a dedicated socket toward the backend
        bsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bsock.settimeout(5.0)
        bsock.bind(('0.0.0.0', 0))
        b_port = bsock.getsockname()[1]

        # Forward CONNECT_REQUEST with our proxy address as both HPAIs.
        # Using 0.0.0.0 lets the backend learn our real IP from the packet.
        new_body = make_hpai('0.0.0.0', b_port) + make_hpai('0.0.0.0', b_port) + cri
        try:
            bsock.sendto(make_frame(CONNECT_REQ, new_body), backend)
            resp_raw, _ = bsock.recvfrom(1024)
        except socket.timeout:
            log.error(f"Backend {backend[0]}:{backend[1]} — CONNECT_REQUEST timed out")
            bsock.close()
            err = bytes([0x00, 0x26]) + make_hpai('0.0.0.0', 0) + b'\x04\x04\x02\x00'
            try:
                self.sock.sendto(make_frame(CONNECT_RESP, err), client_ctrl_addr)
            except Exception:
                pass
            return
        except Exception as e:
            log.error(f"Backend connect error: {e}")
            bsock.close()
            return

        resp_svc, rbody = parse_frame(resp_raw)
        if resp_svc != CONNECT_RESP or not rbody or len(rbody) < 14:
            log.error(f"Unexpected backend response svc=0x{resp_svc:04x}")
            bsock.close()
            return

        ch_id  = rbody[0]
        status = rbody[1]
        # rbody[2:10] = backend data HPAI  (we replace this with ours)
        # rbody[10:14] = CRD
        crd = rbody[10:14]

        if status != 0x00:
            log.warning(f"Backend refused connection: status=0x{status:02x}")
            bsock.close()
            # Forward the error as-is so HA sees it
            try:
                self.sock.sendto(make_frame(CONNECT_RESP, rbody), client_ctrl_addr)
            except Exception:
                pass
            return

        # Register session BEFORE sending response (relay thread may start receiving)
        sess = Session(ch_id, client_ctrl_addr, client_data_addr, backend, bsock)
        with self.lock:
            old = self.sessions.pop(ch_id, None)
            if old:
                old.close()
            self.sessions[ch_id] = sess

        # Start backend → client relay
        threading.Thread(
            target=self._relay, args=(sess,),
            daemon=True, name=f"relay-{ch_id}"
        ).start()

        # Send CONNECT_RESPONSE to xknx.
        # Replace backend data HPAI with OUR listen port so xknx sends
        # all tunnel frames to us (not directly to the backend).
        new_rbody = bytes([ch_id, 0x00]) + make_hpai('0.0.0.0', self.listen_port) + crd
        try:
            self.sock.sendto(make_frame(CONNECT_RESP, new_rbody), client_ctrl_addr)
        except Exception as e:
            log.error(f"Failed to send CONNECT_RESPONSE to client: {e}")
            with self.lock:
                self.sessions.pop(ch_id, None)
            sess.close()
            return

        log.info(
            f"Session {ch_id} established: "
            f"{client_ctrl_addr[0]}:{client_ctrl_addr[1]} ↔ "
            f"{backend[0]}:{backend[1]}"
        )

    # ------------------------------------------------------------------
    # Backend → client relay (one thread per session)
    # ------------------------------------------------------------------
    def _relay(self, sess: Session):
        while sess.alive and self.running:
            try:
                data, _ = sess.bsock.recvfrom(1024)
            except socket.timeout:
                if time.monotonic() - sess.last_seen > self.SESSION_TIMEOUT:
                    log.info(f"Session {sess.channel_id} timed out")
                    with self.lock:
                        self.sessions.pop(sess.channel_id, None)
                    sess.close()
                break
            except Exception as e:
                if sess.alive:
                    log.debug(f"Relay error session {sess.channel_id}: {e}")
                break

            svc, body = parse_frame(data)
            if svc is None:
                continue

            sess.last_seen = time.monotonic()

            if svc in (TUNNELLING_REQ, TUNNELLING_ACK,
                       CONNSTATE_RESP, DISCONNECT_RESP):
                try:
                    self.sock.sendto(data, sess.client_data)
                except Exception as e:
                    log.debug(f"Forward to client error: {e}")

            elif svc == DISCONNECT_REQ:
                try:
                    self.sock.sendto(data, sess.client_ctrl)
                except Exception:
                    pass
                # ACK the backend
                ack = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0)
                try:
                    sess.bsock.sendto(make_frame(DISCONNECT_RESP, ack), sess.backend)
                except Exception:
                    pass
                with self.lock:
                    self.sessions.pop(sess.channel_id, None)
                sess.close()
                log.info(f"Session {sess.channel_id} disconnected by backend")
                break

    # ------------------------------------------------------------------
    # Periodic cleanup of stale sessions
    # ------------------------------------------------------------------
    def _cleanup(self):
        while self.running:
            time.sleep(30)
            now = time.monotonic()
            with self.lock:
                stale = [
                    ch for ch, s in self.sessions.items()
                    if now - s.last_seen > self.SESSION_TIMEOUT
                ]
                for ch in stale:
                    log.info(f"Removing stale session {ch}")
                    s = self.sessions.pop(ch, None)
                    if s:
                        s.close()

    # ------------------------------------------------------------------
    # Main receive loop
    # ------------------------------------------------------------------
    def run(self):
        threading.Thread(target=self._cleanup, daemon=True, name="cleanup").start()
        log.info("Ready — waiting for connections")
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError as e:
                if self.running:
                    log.error(f"Socket error: {e}")
                    time.sleep(1)
                continue
            threading.Thread(
                target=self.dispatch, args=(data, addr),
                daemon=True
            ).start()

        with self.lock:
            for s in self.sessions.values():
                s.close()
            self.sessions.clear()
        try:
            self.sock.close()
        except Exception:
            pass
        log.info("Proxy stopped")


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3672
    KNXProxy(port).run()