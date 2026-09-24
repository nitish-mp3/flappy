"""Bounded, non-connecting KNXnet/IP multicast discovery."""
import socket
import time
from knx_const import make_frame, make_hpai, parse_frame, SEARCH_REQ, SEARCH_RESP


def parse_search(data, source):
    service, body = parse_frame(data)
    if service != SEARCH_RESP or not body or len(body) < 10 or body[:2] != b'\x08\x01':
        return None
    host = socket.inet_ntoa(body[2:6])
    port = int.from_bytes(body[6:8], 'big')
    if host == '0.0.0.0':
        host = source[0]
    item = dict(host=host, port=port or source[1], name=host, protocol='auto', families=[])
    offset = 8
    while offset < len(body):
        length = body[offset]
        if length < 2 or offset + length > len(body):
            return None
        dib = body[offset:offset + length]
        if dib[1] == 1 and length >= 54:
            item['name'] = dib[24:54].split(b'\0')[0].decode('utf-8', errors='replace')
            item['serial'] = dib[8:14].hex()
        if dib[1] == 2:
            item['families'] = [{'id': dib[i], 'version': dib[i+1]}
                                for i in range(2, length-1, 2)]
        offset += length
    if not item['families']:
        return None
    item['tunnelling'] = any(f['id'] == 4 for f in item['families'])
    return item


def discover(timeout=3, local_ip='0.0.0.0'):
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((local_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        if local_ip != '0.0.0.0':
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        # The route-selected local address ensures legacy gateways can reply.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect(('224.0.23.12', 3671))
            reply_ip = local_ip if local_ip != '0.0.0.0' else route.getsockname()[0]
        sock.sendto(make_frame(SEARCH_REQ, make_hpai(reply_ip, sock.getsockname()[1])),
                    ('224.0.23.12', 3671))
        deadline = time.monotonic() + timeout
        while len(found) < 128:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            item = parse_search(data, addr)
            if item:
                found[(item['host'], item['port'])] = item
    return list(found.values())
