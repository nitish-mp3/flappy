"""Ordered mixed-media backend management; proxy retains ownership of HA sessions."""
import json
import logging
import os
import shlex
import shutil
import signal
import subprocess
import sys
import socket
import queue
import urllib.request
import threading
import time
from pathlib import Path
from knx_config import load_config, validate, atomic_write
from knx_health import probe_description_udp, probe_description_tcp
from knx_events import record, last_transitions
from knx_monitor import TelegramMonitor

ROOT = Path(__file__).resolve().parent
STATUS_FILE = '/run/flappy-interfaces.json'
SELECT_FILE = '/run/flappy-select.json'
log = logging.getLogger('knx_manager')


def notify_worker(messages, stop):
    token = os.environ.get('SUPERVISOR_TOKEN', '')
    while not stop.is_set():
        try:
            message = messages.get(timeout=1)
        except queue.Empty:
            continue
        if not token:
            continue
        try:
            req = urllib.request.Request('http://supervisor/core/api/services/persistent_notification/create',
                  method='POST', data=json.dumps(dict(title='Flappy KNX failover', message=message,
                  notification_id='knx_failover')).encode(), headers={
                  'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception:
            log.warning('Home Assistant notification failed')


class Selection:
    """Pure selection policy: fail immediately once down; stable delayed failback."""
    def __init__(self):
        self.active = None
        self.pending = None
        self.pending_since = 0
        self.changed_at = 0

    def choose(self, entries, states, now, mode, delay, manual=None):
        available = [e['id'] for e in entries if e['role'] == 'fallback'
                     and states.get(e['id'], {}).get('healthy') is True]
        if manual in available:
            if manual != self.active:
                self.active, self.changed_at = manual, now
            self.pending = None
        elif self.active not in available:
            self.active = available[0] if available else None
            self.changed_at = now
            self.pending = None
        elif available and available[0] != self.active and mode == 'auto':
            if self.pending != available[0]:
                self.pending, self.pending_since = available[0], now
            # A zero delay still waits for a stable recovery and a short dwell.
            if now - self.pending_since >= max(3, delay) and now - self.changed_at >= 3:
                self.active, self.pending = available[0], None
                self.changed_at = now
        else:
            self.pending = None
        return self.active


class Endpoint:
    def __init__(self, item, cfg, index, stop):
        self.item, self.cfg, self.stop = item, cfg, stop
        self.port = 13671 + index
        self.bridge = None
        self.bridge_protocol = 'udp'
        self.monitor = None
        self.lock = threading.Lock()
        self.good = self.bad = 0
        self.retry_at = 0
        self.state = dict(id=item['id'], name=item['name'], type=item['type'], role=item['role'],
                          healthy=None, status='checking', checks=0, failures=0,
                          last_check=None, last_up=None, last_down=None, error='',
                          latency_ms=None, endpoint=None)
        try:
            history = last_transitions(item['id'])
            self.state.update(last_up=history.get('up'), last_down=history.get('down'))
        except Exception:
            log.warning('Could not restore interface history for %s', item['id'])
        self.thread = threading.Thread(target=self.run, daemon=True)

    def snapshot(self):
        with self.lock:
            result = dict(self.state)
        if self.monitor:
            result['telegrams'] = self.monitor.snapshot()
        elif self.item.get('telegrams') and self.item['type'] == 'usb' and self.bridge_protocol == 'tcp':
            try:
                result['telegrams'] = json.loads(Path(f'/run/flappy-usb-{self.port}.json').read_text())
            except (OSError, ValueError):
                result['telegrams'] = dict(state='passive USB tap', received=0, duplicates=0,
                                           error='', last_telegram=None, recent=[])
        elif self.item.get('telegrams') and self.item['role'] == 'fallback':
            # Extra monitoring tunnels must not compete with HA for a fallback's
            # last slot. For fallback entries use the proxy's existing traffic.
            try:
                metrics = json.loads(Path('/run/knx-metrics.json').read_text())
                endpoint = result['endpoint']
                sessions = [s for s in metrics.get('sessions', []) if endpoint and
                            s['backend_addr'] == f'{endpoint[0]}:{endpoint[1]}']
            except (OSError, ValueError, KeyError):
                sessions = []
            result['telegrams'] = dict(state='proxy forwarded frames' if sessions else 'standby; no extra tunnel',
                     received=sum(s.get('telegrams', 0) for s in sessions), duplicates=0,
                     error='', last_telegram=None, recent=[])
        return result

    def usb_endpoint(self):
        item = self.item
        if self.bridge and self.bridge.poll() is None:
            return ('127.0.0.1', self.port, self.bridge_protocol)
        if time.monotonic() < self.retry_at:
            raise RuntimeError('USB bridge unavailable; retrying after cooldown')
        self.retry_at = time.monotonic() + 15
        device = item['device']
        if device == 'auto' or item.get('serial'):
            from knx_usb import discover_knx_devices
            devices = discover_knx_devices()
            if item.get('serial'):
                devices = [d for d in devices if d.serial_number == item['serial']
                           and (not item.get('vendor_id') or d.to_dict()['vendor_id'] == item['vendor_id'])
                           and (not item.get('product_id') or d.to_dict()['product_id'] == item['product_id'])]
            if len(devices) != 1:
                raise RuntimeError('USB identity missing or ambiguous; choose a specific device')
            device = devices[0].device_path
        if not os.path.exists(device):
            raise RuntimeError('USB device is missing')
        from knx_usb import resolve_usb_path
        device = resolve_usb_path(device)
        mode = item.get('mode', 'auto')
        if mode == 'auto':
            mode = 'knxd' if shutil.which('knxd') else (
                'native' if device.startswith(('/dev/bus/usb/', '/dev/hidraw')) else 'socat')
        if mode == 'native':
            self.bridge_protocol = 'tcp'
            cmd = [sys.executable, str(ROOT / 'knx_usb.py'), '--bridge', device,
                   '--port', str(self.port)]
        elif mode == 'knxd':
            self.bridge_protocol = 'udp'
            if not shutil.which('knxd'):
                raise RuntimeError('knxd is not installed; select Native for a USB HID interface')
            # Each bridge has its own unicast KNXnet/IP server port. No multicast routing.
            cmd = ['knxd', '-e', item['knx_address'], '-E', item['client_address'] + ':16',
                   '-D', '-T', f'--Server=224.0.23.12:{self.port}']
            if device.startswith('/dev/bus/usb/'):
                bus, address = device.split('/')[-2:]
                driver = f'usb:{int(bus)}:{int(address)}'
            else:
                driver = f'tpuarts:{device}:{item.get("baud", 19200)}'
            cmd += shlex.split(item.get('extra_args', '')) + ['-b', driver]
        elif mode == 'socat' and not device.startswith(('/dev/bus/usb/', '/dev/hidraw')):
            cmd = ['socat', f'UDP-LISTEN:{self.port},bind=127.0.0.1,fork,reuseaddr',
                   f'OPEN:{device},raw,echo=0,b{item.get("baud", 19200)},crtscts=0']
        else:
            raise RuntimeError('Serial socat is not a KNX protocol bridge. Use knxd or native USB.')
        env = dict(os.environ, FLAPPY_USB_MONITOR='1' if item.get('telegrams') else '0',
                   FLAPPY_USB_PID=f'/run/knx-usb-{self.port}.pid')
        Path(f'/run/flappy-usb-{self.port}.json').unlink(missing_ok=True)
        self.bridge = subprocess.Popen(cmd, env=env, start_new_session=True)
        if self.stop.wait(1):
            raise RuntimeError('Stopping')
        if self.bridge.poll() is not None:
            raise RuntimeError('USB bridge exited; check device permissions and driver')
        return ('127.0.0.1', self.port, self.bridge_protocol)

    def check(self):
        item = self.item
        endpoint = self.usb_endpoint() if item['type'] == 'usb' else (
            item['host'], item['port'], 'tcp' if item.get('secure') else item['protocol'])
        host, port, proto = endpoint
        if item['type'] == 'ip' and port == self.cfg['listen_port']:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect((host, port))
                if route.getpeername()[0] == route.getsockname()[0]:
                    raise RuntimeError('This address points back to Flappy; choose the physical interface')
        if item['type'] == 'usb' and proto == 'tcp':
            result = probe_description_tcp(host, port, self.cfg['connection_timeout'])
            if not result.ok:
                raise RuntimeError(result.error)
            return endpoint, result.latency_ms
        # UDP description is supported by many TCP gateways too; it consumes no tunnel.
        result = probe_description_udp(host, port, self.cfg['connection_timeout'])
        observed = 'udp'
        if not result.ok:
            result = probe_description_tcp(host, port, self.cfg['connection_timeout'])
            observed = 'tcp'
        if not result.ok:
            raise RuntimeError(result.error or 'No valid KNX description response')
        chosen = observed if proto == 'auto' else proto
        return (host, port, chosen), result.latency_ms

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            endpoint, latency, error = None, None, ''
            try:
                endpoint, latency = self.check()
            except Exception as exc:
                error = str(exc)
            ok = endpoint is not None
            with self.lock:
                previous = self.state['healthy']
                self.good = self.good + 1 if ok else 0
                self.bad = self.bad + 1 if not ok else 0
                healthy = previous
                if self.good >= self.cfg['health_check_rise']:
                    healthy = True
                if self.bad >= self.cfg['health_check_fall']:
                    healthy = False
                self.state.update(healthy=healthy, status='online' if healthy else
                                  ('offline' if healthy is False else 'checking'),
                                  last_check=time.time(), error=error, latency_ms=latency)
                self.state['checks'] += 1
                self.state['failures'] += int(not ok)
                if endpoint:
                    self.state['endpoint'] = endpoint
                if previous != healthy and healthy is not None:
                    stamp = time.time()
                    self.state['last_up' if healthy else 'last_down'] = stamp
                    try:
                        record(self.item['id'], 'up' if healthy else 'down',
                               'KNX description responding' if healthy else error)
                    except Exception:
                        log.exception('Unable to persist interface event')
            native_tap = self.item['type'] == 'usb' and self.bridge_protocol == 'tcp'
            if (ok and self.item.get('telegrams') and self.monitor is None and not native_tap
                    and self.item['role'] == 'monitor'):
                self.monitor = TelegramMonitor(self.item, endpoint)
            self.stop.wait(max(0.1, self.cfg['health_check_interval'] - (time.monotonic()-started)))
        if self.monitor:
            self.monitor.stop()
            self.monitor.thread.join(timeout=3)
        if self.bridge and self.bridge.poll() is None:
            os.killpg(self.bridge.pid, signal.SIGTERM)
            try:
                self.bridge.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.bridge.pid, signal.SIGKILL)


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(name)s] %(levelname)s %(message)s')
    cfg = validate(load_config())
    stop = threading.Event()
    notifications = queue.Queue(maxsize=8)
    if cfg.get('notify_on_failover'):
        threading.Thread(target=notify_worker, args=(notifications, stop), daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    atomic_write('/run/flappy-runtime.json', json.dumps(cfg))
    atomic_write('/run/knx-active-backend', 'none')
    atomic_write('/run/knx-manager.pid', str(os.getpid()))
    env = dict(os.environ)
    for key, value in dict(FRONTEND_PROTOCOL=cfg['frontend_protocol'], MAX_SESSIONS=cfg['max_sessions'],
                           SESSION_TIMEOUT=cfg['session_timeout'], DRAIN_TIMEOUT=cfg['drain_timeout_seconds'],
                           LOG_LEVEL=cfg['log_level'], FLAPPY_RUNTIME='/run/flappy-runtime.json').items():
        env[key] = str(value)
    children = {}
    child_retries, child_started, next_spawn = {}, {}, {}
    endpoints = [Endpoint(item, cfg, i, stop) for i, item in enumerate(cfg['interfaces'])]
    policy, last_backend = Selection(), None
    pending_signal = False
    proxy_started = 0
    rejected_until = {}
    for endpoint in endpoints:
        endpoint.thread.start()
    try:
        while not stop.is_set():
            for name, args in {'proxy': ['knx_proxy.py', str(cfg['listen_port'])],
                               'webui': ['knx_webui.py', '8099']}.items():
                if name not in children or children[name].poll() is not None:
                    now = time.monotonic()
                    if now < next_spawn.get(name, 0):
                        continue
                    child_retries[name] = 0 if now - child_started.get(name, now) > 60 else child_retries.get(name, 0) + 1
                    next_spawn[name] = now + min(30, 2 ** min(child_retries[name], 5))
                    child_started[name] = now
                    child_env = dict(env)
                    if name == 'webui':
                        child_env['FLAPPY_CONTROL_PID'] = str(os.getpid())
                    children[name] = subprocess.Popen([sys.executable, str(ROOT / args[0]), *args[1:]], env=child_env)
                    if name == 'proxy':
                        proxy_started = time.monotonic()
                        atomic_write('/run/knx-proxy.pid', str(children[name].pid))
            states = {ep.item['id']: ep.snapshot() for ep in endpoints}
            for state in states.values():
                limit = max(15, cfg['health_check_interval'] + cfg['connection_timeout'] * 2 + 5)
                if state['last_check'] and time.time() - state['last_check'] > limit:
                    state.update(healthy=False, status='stale', error='Health worker has not reported recently')
            # A real tunnel rejection overrides a successful description probe temporarily.
            try:
                reject = dict(line.strip().split('=', 1) for line in
                              Path('/run/knx-backend-reject').read_text().splitlines() if '=' in line)
                if time.time() - float(reject['ts']) < 15:
                    for state in states.values():
                        endpoint = state['endpoint']
                        if endpoint and endpoint[0] == reject['host'] and str(endpoint[1]) == reject['port']:
                            rejected_until[state['id']] = max(rejected_until.get(state['id'], 0),
                                                               float(reject['ts']) + 30)
            except (OSError, ValueError, KeyError):
                pass
            for ident, until in rejected_until.items():
                if ident in states and time.time() < until:
                    states[ident].update(healthy=False, status='tunnel_rejected',
                                         error='Tunnel rejected; cooling down for up to 30 seconds')
            manual = None
            try:
                request = json.loads(Path(SELECT_FILE).read_text())
                os.unlink(SELECT_FILE)
                if time.time() - request['timestamp'] < 10:
                    manual = request['id']
            except (OSError, ValueError, KeyError):
                pass
            active = policy.choose(cfg['interfaces'], states, time.monotonic(), cfg['failback_mode'],
                                   cfg['failback_delay_seconds'], manual)
            backend = tuple(states[active]['endpoint']) if active else None
            if backend != last_backend:
                atomic_write('/run/knx-active-backend', ':'.join(map(str, backend)) if backend else 'none')
                message = f'Backend selected: {active}' if active else 'No healthy fallback interfaces'
                try:
                    record(active or '', 'switch' if active else 'degraded', message)
                except Exception:
                    log.exception('Could not persist backend selection event')
                if cfg.get('notify_on_failover'):
                    try:
                        notifications.put_nowait(message)
                    except queue.Full:
                        pass
                # Keep HA sessions during short outages; no synthetic disconnect on all-down.
                pending_signal = bool(backend)
                last_backend = backend
            if pending_signal and time.monotonic() - proxy_started > 3 and children['proxy'].poll() is None:
                children['proxy'].send_signal(signal.SIGHUP)
                pending_signal = False
            for ident, state in states.items():
                state['active'] = ident == active
            atomic_write(STATUS_FILE, json.dumps(dict(interfaces=list(states.values()), active_id=active,
                          pending_id=policy.pending, revision=cfg['revision'], timestamp=time.time())))
            atomic_write('/run/knx-failover.state', f'state={"ACTIVE" if active else "DEGRADED"}\n'
                         f'version=4.4.0\nfailback_mode={cfg["failback_mode"]}\ntimestamp={time.time()}\n')
            stop.wait(0.5)
    finally:
        stop.set()
        for child in children.values():
            if child.poll() is None:
                child.terminate()
        for child in children.values():
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
        for endpoint in endpoints:
            endpoint.thread.join(timeout=5)


if __name__ == '__main__':
    main()
