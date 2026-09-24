"""Opt-in receive-only tunnel. Never emits group read/write telegrams."""
import collections
import socket
import threading
import time
from knx_const import (make_frame, make_hpai, parse_frame, read_tcp_frame, TUNNELLING_REQ,
                       TUNNELLING_ACK, CONNSTATE_REQ, CONNSTATE_RESP, DISCONNECT_REQ,
                       DISCONNECT_RESP, SECURE_WRAPPER)
from knx_transport import BackendConnector


class TelegramMonitor:
    def __init__(self, item, endpoint):
        self.item, self.endpoint = item, endpoint
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.status = dict(state='connecting', received=0, duplicates=0, error='', last_telegram=None)
        self.recent = collections.deque(maxlen=20)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def snapshot(self):
        with self.lock:
            return {**self.status, 'recent': list(self.recent)}

    def stop(self):
        self.stop_event.set()

    def run(self):
        while not self.stop_event.is_set():
            sock, ch, secure = None, None, None
            host, port, proto = self.endpoint
            try:
                connector = BackendConnector(2)
                sock = connector.open_socket(host, port, proto)
                if self.item.get('secure'):
                    # Reuse existing, tested secure handshake implementation.
                    from knx_proxy import KNXProxy
                    secure = KNXProxy._establish_secure_session(
                        None, sock, host, port, self.item.get('device_password', ''),
                        self.item.get('user_password', ''), self.item.get('user_id', 1))
                    if secure is None:
                        raise RuntimeError('Secure authentication failed')
                    ch, _, status = KNXProxy._negotiate_tunnel_secure(None, sock, secure)
                else:
                    ch, _, status = connector.negotiate_tunnel(sock, host, port, proto)
                    sock = getattr(connector, '_last_good_sock', None) or sock
                if ch is None:
                    raise RuntimeError(f'Tunnel unavailable (status {status}); monitoring needs a free slot')
                with self.lock:
                    self.status.update(state='connected', error='')
                sock.settimeout(1)
                hpai = make_hpai('0.0.0.0', 0, 2 if proto == 'tcp' else 1)
                last_hb, pending_hb, expected = time.monotonic(), None, None

                def send(service, body):
                    frame = make_frame(service, body)
                    if secure:
                        frame = secure.encrypt_frame(frame)
                    sock.sendall(frame) if proto == 'tcp' else sock.send(frame)

                while not self.stop_event.is_set():
                    now = time.monotonic()
                    if pending_hb and now - pending_hb > 10:
                        raise RuntimeError('Monitor heartbeat timed out')
                    if now - last_hb >= 30:
                        send(CONNSTATE_REQ, bytes([ch, 0]) + hpai)
                        last_hb = pending_hb = now
                    try:
                        svc, body = read_tcp_frame(sock) if proto == 'tcp' else parse_frame(sock.recv(4096))
                    except socket.timeout:
                        continue
                    if svc is None:
                        raise RuntimeError('Monitor connection closed')
                    if svc == SECURE_WRAPPER and secure:
                        svc, body = parse_frame(secure.decrypt_frame(body) or b'')
                    if svc == CONNSTATE_RESP and body and len(body) >= 2 and body[0] == ch:
                        if body[1]:
                            raise RuntimeError('Monitor heartbeat rejected')
                        pending_hb = None
                    elif svc == DISCONNECT_REQ:
                        send(DISCONNECT_RESP, bytes([ch, 0]))
                        raise RuntimeError('Monitor disconnected by interface')
                    elif svc == TUNNELLING_REQ and body and len(body) >= 4 and body[1] == ch:
                        seq = body[2]
                        duplicate = expected is not None and seq == ((expected - 1) & 255)
                        valid = expected is None or seq == expected or duplicate
                        send(TUNNELLING_ACK, bytes([4, ch, seq, 0 if valid else 4]))
                        if not valid:
                            continue
                        with self.lock:
                            if duplicate:
                                self.status['duplicates'] += 1
                                continue
                            expected = (seq + 1) & 255
                            stamp = time.time()
                            self.status['received'] += 1
                            self.status['last_telegram'] = stamp
                            self.recent.appendleft(dict(timestamp=stamp, cemi=body[4:260].hex()))
            except Exception as exc:
                with self.lock:
                    self.status.update(state='retrying', error=str(exc))
            finally:
                if sock:
                    if ch is not None:
                        try:
                            frame = make_frame(DISCONNECT_REQ, bytes([ch, 0]) +
                                               make_hpai('0.0.0.0', 0, 2 if proto == 'tcp' else 1))
                            if secure:
                                frame = secure.encrypt_frame(frame)
                            sock.sendall(frame) if proto == 'tcp' else sock.send(frame)
                        except OSError:
                            pass
                    sock.close()
            self.stop_event.wait(30)

