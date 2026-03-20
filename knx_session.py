#!/usr/bin/env python3
"""
KNX Session Manager
====================
Manages KNX tunnelling sessions: creation, lifecycle, metrics, draining.
"""

import socket
import struct
import threading
import time
import logging
import json
import os
from typing import Optional, Tuple, Dict, List

from knx_const import (
    MAGIC, PROTO_UDP, PROTO_TCP, BACKEND_FILE, BACKEND_REJECT_FILE,
    METRICS_FILE, VERSION,
    CONNECT_REQ, CONNECT_RESP, CONNSTATE_REQ, CONNSTATE_RESP,
    DISCONNECT_REQ, DISCONNECT_RESP, TUNNELLING_REQ, TUNNELLING_ACK,
    DESCRIPTION_REQ, DESCRIPTION_RESP, SEARCH_REQ, SEARCH_RESP,
    SEARCH_REQ_EXT, SEARCH_RESP_EXT,
    SECURE_WRAPPER, SECURE_SESSION_REQ, SECURE_SESSION_RESP,
    SECURE_SESSION_AUTH, SECURE_SESSION_STATUS,
    E_NO_ERROR, E_NO_MORE_CONNS, E_DATA_CONN, HARD_REJECT_CODES,
    CRI_TUNNEL_V1, CRI_TUNNEL_V2, CRI_TUNNEL_EX, CRD_DEFAULT,
    make_frame, make_hpai, parse_hpai, parse_frame, read_tcp_frame,
    tunnel_channel_id, svc_name,
)

log = logging.getLogger('knx_session')


class Session:
    """
    Represents one active KNX tunnelling session between a client and a backend.
    Tracks lifecycle, metrics, and handles graceful drain.
    """
    __slots__ = [
        'channel_id', 'client_type', 'client_ctrl', 'client_data',
        'client_sock', 'backend_type', 'backend_addr', 'backend_sock',
        'last_seen', 'alive', 'created_at',
        'bytes_in', 'bytes_out', 'telegrams_fwd', 'errors',
        'draining', 'drain_event',
    ]

    def __init__(self, channel_id: int, client_type: str,
                 client_ctrl: Tuple[str, int], client_data: Tuple[str, int],
                 client_sock: Optional[socket.socket],
                 backend_type: str, backend_addr: Tuple[str, int],
                 backend_sock: socket.socket):
        self.channel_id   = channel_id
        self.client_type  = client_type
        self.client_ctrl  = client_ctrl
        self.client_data  = client_data
        self.client_sock  = client_sock
        self.backend_type = backend_type
        self.backend_addr = backend_addr
        self.backend_sock = backend_sock
        self.last_seen    = time.monotonic()
        self.created_at   = time.monotonic()
        self.alive        = True
        self.draining     = False
        self.drain_event  = threading.Event()

        # Metrics
        self.bytes_in     = 0
        self.bytes_out    = 0
        self.telegrams_fwd = 0
        self.errors       = 0

    def send_to_backend(self, data: bytes) -> bool:
        """Send data to the backend socket."""
        try:
            if self.backend_type == 'tcp':
                self.backend_sock.sendall(data)
            else:
                self.backend_sock.send(data)
            self.bytes_out += len(data)
            return True
        except Exception as e:
            log.debug(f"send_to_backend ch={self.channel_id}: {e}")
            self.errors += 1
            return False

    def send_to_client(self, data: bytes, udp_sock: Optional[socket.socket] = None) -> bool:
        """Send data to the client."""
        try:
            if self.client_type == 'tcp' and self.client_sock:
                self.client_sock.sendall(data)
            elif self.client_ctrl and udp_sock:
                udp_sock.sendto(data, self.client_ctrl)
            self.bytes_in += len(data)
            return True
        except Exception as e:
            log.debug(f"send_to_client ch={self.channel_id}: {e}")
            self.errors += 1
            return False

    def close(self):
        """Close the session and release resources."""
        self.alive = False
        self.drain_event.set()
        for s in (self.backend_sock, self.client_sock):
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    def uptime(self) -> float:
        """Return session uptime in seconds."""
        return time.monotonic() - self.created_at

    def to_dict(self) -> dict:
        """Return session info as a dict for metrics."""
        return {
            'channel_id': self.channel_id,
            'client_type': self.client_type,
            'client_addr': f"{self.client_ctrl[0]}:{self.client_ctrl[1]}" if self.client_ctrl else "?",
            'backend_type': self.backend_type,
            'backend_addr': f"{self.backend_addr[0]}:{self.backend_addr[1]}" if self.backend_addr else "?",
            'uptime_s': round(self.uptime(), 1),
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
            'telegrams': self.telegrams_fwd,
            'errors': self.errors,
            'draining': self.draining,
        }


class SessionManager:
    """
    Manages all active tunnelling sessions.
    Handles creation, lookup, draining, cleanup, and metrics.
    """

    def __init__(self, max_sessions: int = 8, session_timeout: int = 120,
                 drain_timeout: int = 5):
        self.max_sessions   = max_sessions
        self.session_timeout = session_timeout
        self.drain_timeout  = drain_timeout

        self._sessions: Dict[int, Session] = {}
        self._lock = threading.Lock()
        self._total_created = 0
        self._total_failovers = 0
        self._start_time = time.monotonic()

    @property
    def active_count(self) -> int:
        """Number of active sessions."""
        with self._lock:
            return len(self._sessions)

    def get(self, channel_id: int) -> Optional[Session]:
        """Get a session by channel ID (thread-safe)."""
        with self._lock:
            return self._sessions.get(channel_id)

    def add(self, session: Session) -> Optional[Session]:
        """
        Add a session. If a session with the same channel_id exists,
        the old one is evicted and returned for cleanup.
        """
        with self._lock:
            old = self._sessions.pop(session.channel_id, None)
            self._sessions[session.channel_id] = session
            self._total_created += 1
        if old:
            log.info(f"Evicted old session ch={old.channel_id} for new connection")
        return old

    def remove(self, channel_id: int) -> Optional[Session]:
        """Remove and return a session by channel ID."""
        with self._lock:
            return self._sessions.pop(channel_id, None)

    def has_capacity(self) -> bool:
        """Check if we can accept another session."""
        with self._lock:
            return len(self._sessions) < self.max_sessions

    def find_by_client_sock(self, sock: socket.socket) -> Optional[int]:
        """Find channel_id for a TCP client socket."""
        with self._lock:
            for ch, s in self._sessions.items():
                if s.client_sock is sock:
                    return ch
        return None

    def get_all(self) -> List[Session]:
        """Get a snapshot of all sessions."""
        with self._lock:
            return list(self._sessions.values())

    def drain_all(self, udp_sock: Optional[socket.socket] = None):
        """
        Gracefully drain all sessions. Sends DISCONNECT_REQ to both
        client and backend, waits up to drain_timeout for acknowledgement.
        """
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            self._total_failovers += 1

        if not sessions:
            return

        log.info(f"Draining {len(sessions)} sessions (timeout={self.drain_timeout}s)")
        threads = []
        for sess in sessions:
            t = threading.Thread(target=self._drain_one, args=(sess, udp_sock),
                                 daemon=True)
            t.start()
            threads.append(t)

        # Wait for drain to complete
        deadline = time.monotonic() + self.drain_timeout
        for t in threads:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                t.join(timeout=remaining)

        # Force-close any remaining
        for sess in sessions:
            if sess.alive:
                log.debug(f"Force-closing session ch={sess.channel_id} after drain timeout")
                sess.close()

    def _drain_one(self, sess: Session, udp_sock: Optional[socket.socket]):
        """Drain a single session gracefully."""
        sess.draining = True
        try:
            # Send DISCONNECT_REQ to client
            body = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0)
            frame = make_frame(DISCONNECT_REQ, body)
            sess.send_to_client(frame, udp_sock)

            # Send DISCONNECT_REQ to backend
            proto = PROTO_TCP if sess.backend_type == 'tcp' else PROTO_UDP
            body = bytes([sess.channel_id, 0x00]) + make_hpai('0.0.0.0', 0, proto)
            frame = make_frame(DISCONNECT_REQ, body)
            sess.send_to_backend(frame)

            # Wait briefly for responses
            sess.drain_event.wait(timeout=min(self.drain_timeout, 2.0))
        except Exception as e:
            log.debug(f"Drain error ch={sess.channel_id}: {e}")
        finally:
            sess.close()

    def cleanup_stale(self):
        """Remove sessions that have timed out."""
        now = time.monotonic()
        stale = []
        with self._lock:
            for ch, s in list(self._sessions.items()):
                if now - s.last_seen > self.session_timeout:
                    stale.append(self._sessions.pop(ch))

        for s in stale:
            log.info(f"Session ch={s.channel_id} timed out after {s.uptime():.0f}s")
            try:
                # Best-effort disconnect to backend
                proto = PROTO_TCP if s.backend_type == 'tcp' else PROTO_UDP
                body = bytes([s.channel_id, 0x00]) + make_hpai('0.0.0.0', 0, proto)
                s.send_to_backend(make_frame(DISCONNECT_REQ, body))
            except Exception:
                pass
            s.close()

    def write_metrics(self):
        """Write metrics to the metrics file for external consumption."""
        try:
            with self._lock:
                sessions_info = [s.to_dict() for s in self._sessions.values()]

            metrics = {
                'version': VERSION,
                'uptime_s': round(time.monotonic() - self._start_time, 1),
                'active_sessions': len(sessions_info),
                'total_sessions_created': self._total_created,
                'total_failovers': self._total_failovers,
                'max_sessions': self.max_sessions,
                'sessions': sessions_info,
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            }

            with open(METRICS_FILE, 'w', encoding='utf-8') as f:
                json.dump(metrics, f, indent=2)
        except Exception as e:
            log.debug(f"Failed to write metrics: {e}")

    def record_failover(self):
        """Increment the failover counter."""
        self._total_failovers += 1


# ══════════════════════════════════════════════════════════════════════
# Backend File I/O
# ══════════════════════════════════════════════════════════════════════

def read_backend() -> Optional[Tuple[str, int, str]]:
    """
    Read the active backend from the state file.
    Returns (host, port, proto) or None.
    """
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


def report_backend_reject(host: str, port: int, proto: str, status: int):
    """Write a backend rejection report for the backend manager."""
    try:
        with open(BACKEND_REJECT_FILE, 'w', encoding='ascii') as f:
            f.write(f"host={host}\n")
            f.write(f"port={port}\n")
            f.write(f"proto={proto}\n")
            f.write(f"status=0x{status:02x}\n")
            f.write(f"ts={int(time.time())}\n")
    except Exception:
        pass


def clear_backend_reject():
    """Clear the rejection report file."""
    try:
        os.remove(BACKEND_REJECT_FILE)
    except FileNotFoundError:
        pass
    except Exception:
        pass
