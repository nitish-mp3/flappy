#!/usr/bin/env python3
"""
KNX Failover Proxy — Web UI Server
====================================
Provides a REST API and serves the web interface for configuration
and monitoring of the KNX failover proxy.

Runs on the HA add-on ingress port (default 8099).
"""

import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import logging
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

log = logging.getLogger('knx_webui')

OPTIONS_FILE = "/data/options.json"
STATE_FILE = "/run/knx-failover.state"
METRICS_FILE = "/run/knx-metrics.json"
BACKEND_FILE = "/run/knx-active-backend"
WWW_DIR = "/www"
VERSION = "4.4.0"
DISCOVERY_LOCK = threading.Lock()
RESTART_LOCK = threading.Lock()

SUPERVISOR_TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')


class APIHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the KNX web UI."""

    server_version = "KNXProxy/4.4.0"

    def log_message(self, fmt, *args):
        log.debug(fmt % args)

    def _authorized(self):
        # Ingress authenticates users. Trust the socket peer, never forwarded headers.
        if self.client_address[0] not in ('172.30.32.2', '127.0.0.1', '::1'):
            self._json({'error': 'Open Flappy through Home Assistant ingress'}, 403)
            return False
        return True

    # ── Response helpers ──────────────────────────────────────────────

    def _json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-cache, no-store')
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, path, content_type='application/octet-stream'):
        try:
            with open(path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            if 'text/html' in content_type:
                self.send_header('Cache-Control', 'no-cache')
            else:
                self.send_header('Cache-Control', 'public, max-age=3600')
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)

    def _read_body(self) -> bytes:
        length = int(self.headers.get('Content-Length', 0))
        if not 0 <= length <= 131072:
            raise ValueError('Request too large')
        self.connection.settimeout(10)
        return self.rfile.read(length) if length > 0 else b''

    # ── Routing ───────────────────────────────────────────────────────

    def do_GET(self):
        if not self._authorized():
            return
        path = urlparse(self.path).path.rstrip('/')
        if path in ('', '/'):
            self._serve_file(os.path.join(WWW_DIR, 'index.html'),
                             'text/html; charset=utf-8')
        elif path == '/api/status':
            self._api_status()
        elif path == '/api/config':
            self._api_get_config()
        elif path == '/api/sessions':
            self._api_sessions()
        elif path == '/api/metrics':
            self._api_metrics()
        elif path == '/api/usb':
            self._api_usb_discover()
        elif path == '/api/interfaces':
            self._api_interfaces()
        elif path == '/api/events':
            from knx_events import recent
            self._json({'events': recent()})
        elif path == '/api/version':
            self._json({'version': VERSION})
        else:
            safe = path.lstrip('/')
            fp = os.path.realpath(os.path.join(WWW_DIR, safe))
            if os.path.commonpath([fp, os.path.realpath(WWW_DIR)]) == os.path.realpath(WWW_DIR) and os.path.isfile(fp):
                ext = os.path.splitext(fp)[1].lower()
                mime = {'.css': 'text/css', '.js': 'application/javascript',
                        '.svg': 'image/svg+xml', '.png': 'image/png',
                        '.ico': 'image/x-icon', '.json': 'application/json',
                        }.get(ext, 'application/octet-stream')
                self._serve_file(fp, mime)
            else:
                self.send_error(404)

    def do_POST(self):
        if not self._authorized():
            return
        path = urlparse(self.path).path.rstrip('/')
        try:
            body = self._read_body()
        except (ValueError, socket.timeout):
            self._json({'error': 'Invalid or oversized request (limit 128 KiB)'}, 400)
            return
        if path == '/api/config':
            self._api_set_config(body)
        elif path == '/api/discover':
            self._api_discover(body)
        elif path == '/api/select':
            self._api_select(body)
        elif path == '/api/reload':
            self._api_reload()
        elif path == '/api/restart':
            self._api_restart()
        elif path == '/api/health':
            self._api_health_probe(body)
        else:
            self.send_error(404)

    # ── API Endpoints ─────────────────────────────────────────────────

    def _api_status(self):
        state = _read_state_file()
        backend = _read_backend_file()
        metrics = _read_metrics_file()
        self._json({
            'state': state.get('state', 'UNKNOWN'),
            'backend': backend,
            'version': state.get('version', VERSION),
            'failback_mode': state.get('failback_mode', ''),
            'primary_host': state.get('primary_host', ''),
            'primary_port': state.get('primary_port', ''),
            'backup_host': state.get('backup_host', ''),
            'backup_port': state.get('backup_port', ''),
            'active_sessions': metrics.get('active_sessions', 0),
            'max_sessions': metrics.get('max_sessions', 8),
            'total_sessions': metrics.get('total_sessions_created', 0),
            'total_failovers': metrics.get('total_failovers', 0),
            'uptime_s': metrics.get('uptime_s', 0),
            'sessions': metrics.get('sessions', []),
            'timestamp': state.get('timestamp', ''),
        })

    def _api_get_config(self):
        from knx_config import load_config
        cfg = load_config()
        for key in list(cfg):
            if 'password' in key:
                del cfg[key]
        for item in cfg['interfaces']:
            for key in ('device_password', 'user_password'):
                item[key + '_set'] = bool(item.pop(key, ''))
        self._json(cfg)

    def _api_set_config(self, body):
        from knx_config import save_config, load_config
        try:
            updates = json.loads(body)
            if not isinstance(updates, dict):
                raise ValueError('Expected a JSON object')
            old = {i['id']: i for i in load_config()['interfaces']}
            for item in updates.get('interfaces', []):
                for key in ('device_password', 'user_password'):
                    if key not in item and item.get('id') in old:
                        item[key] = old[item['id']].get(key, '')
                    item.pop(key + '_set', None)
            cfg = save_config(updates)
            self._json(dict(ok=True, persisted=True, revision=cfg['revision'],
                            needs_restart=True, message='Saved. Restart to apply.'))
        except RuntimeError as exc:
            self._json({'error': str(exc)}, 409)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            self._json({'error': str(exc)}, 400)
        except OSError:
            log.exception('Configuration save failed')
            self._json({'error': 'Could not persist configuration; previous configuration retained'}, 500)

    def _api_sessions(self):
        metrics = _read_metrics_file()
        self._json({
            'sessions': metrics.get('sessions', []),
            'active': metrics.get('active_sessions', 0),
            'max': metrics.get('max_sessions', 8),
        })

    def _api_metrics(self):
        self._json(_read_metrics_file())

    def _api_usb_discover(self):
        try:
            result = subprocess.run(
                ['python3', '/knx_usb.py', '--discover'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                self._json(json.loads(result.stdout))
            else:
                self._json({'devices': [], 'count': 0,
                            'error': result.stderr.strip()})
        except subprocess.TimeoutExpired:
            self._json({'devices': [], 'count': 0, 'error': 'Scan timed out'})
        except Exception as e:
            self._json({'devices': [], 'count': 0, 'error': str(e)})

    def _api_interfaces(self):
        from knx_config import load_config, CONFIG_FILE
        try:
            with open('/run/flappy-interfaces.json', encoding='utf-8') as f:
                data = json.load(f)
            data['stale'] = time.time() - data.get('timestamp', 0) > 15
        except (OSError, ValueError):
            data = {'interfaces': [], 'revision': None, 'stale': True}
        cfg = load_config()
        data['saved_revision'] = cfg['revision']
        data['legacy_mode'] = not os.path.exists(CONFIG_FILE) and data['revision'] is None
        data['needs_restart'] = os.path.exists(CONFIG_FILE) and data['revision'] != cfg['revision']
        self._json(data)

    def _api_discover(self, body):
        from knx_discovery import discover
        try:
            params = json.loads(body or b'{}')
            local_ip = params.get('local_ip', '0.0.0.0')
            socket.inet_aton(local_ip)
            if not DISCOVERY_LOCK.acquire(blocking=False):
                self._json({'error': 'A scan is already running'}, 409)
                return
            try:
                self._json({'devices': discover(local_ip=local_ip)})
            finally:
                DISCOVERY_LOCK.release()
        except (ValueError, OSError, AttributeError) as exc:
            self._json({'error': str(exc)}, 400)

    def _api_select(self, body):
        from knx_config import atomic_write
        try:
            ident = json.loads(body)['id']
            with open('/run/flappy-interfaces.json', encoding='utf-8') as f:
                runtime = json.load(f)
            if time.time() - runtime['timestamp'] > 15:
                raise ValueError('Runtime status is stale')
            if not any(i['id'] == ident and i['role'] == 'fallback' and i['healthy']
                       for i in runtime['interfaces']):
                raise ValueError('Select a healthy fallback interface')
            atomic_write('/run/flappy-select.json', json.dumps({'id': ident, 'timestamp': time.time()}))
            self._json({'ok': True, 'message': 'Switch requested'})
        except (ValueError, KeyError, OSError, TypeError) as exc:
            self._json({'error': str(exc)}, 400)

    def _api_reload(self):
        """Send SIGHUP to run.sh to trigger backend re-evaluation."""
        try:
            result = subprocess.run(
                ['pgrep', '-f', 'knx_proxy.py'],
                capture_output=True, text=True, timeout=5,
            )
            pids = result.stdout.strip().split('\n')
            sent = 0
            for p in pids:
                p = p.strip()
                if p:
                    os.kill(int(p), signal.SIGHUP)
                    sent += 1
            self._json({'ok': True, 'message': f'SIGHUP sent to {sent} process(es)'})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_restart(self):
        """Restart the add-on via HA Supervisor API."""
        if not SUPERVISOR_TOKEN:
            self._json({'error': 'Supervisor token not available'}, 503)
            return
        if not RESTART_LOCK.acquire(blocking=False):
            self._json({'ok': True, 'message': 'Add-on restart is already in progress'})
            return

        def restart_after_response():
            try:
                # Let the HTTP response reach ingress before Supervisor stops us.
                threading.Event().wait(0.2)
                req = urllib.request.Request(
                    'http://supervisor/addons/self/restart', method='POST',
                    headers={'Authorization': f'Bearer {SUPERVISOR_TOKEN}',
                             'Content-Type': 'application/json'},
                )
                with urllib.request.urlopen(req, timeout=10):
                    pass
            except Exception:
                log.warning('Supervisor did not confirm the restart request')
            finally:
                RESTART_LOCK.release()

        try:
            threading.Thread(target=restart_after_response, daemon=True).start()
            self._json({'ok': True, 'message': 'Add-on restart requested'})
        except Exception as e:
            RESTART_LOCK.release()
            self._json({'error': str(e)}, 500)

    def _api_health_probe(self, body: bytes):
        """Run an ad-hoc health probe against a given host."""
        try:
            params = json.loads(body)
            host = str(params.get('host', '')).strip()
            port = int(params.get('port', 3671))
            if not host:
                self._json({'error': 'host is required'}, 400)
                return
            import re
            if not re.match(r'^[a-zA-Z0-9._:\-]+$', host):
                self._json({'error': 'Invalid host format'}, 400)
                return
            if not (1 <= port <= 65535):
                self._json({'error': 'Invalid port'}, 400)
                return
            # Pass host/port as args (not string-interpolated) to avoid injection
            probe_script = (
                "import sys; sys.path.insert(0,'/'); "
                "from knx_health import detect_protocol; "
                "print(detect_protocol(sys.argv[1],int(sys.argv[2]),'tcp',5))"
            )
            result = subprocess.run(
                ['python3', '-c', probe_script, host, str(port)],
                capture_output=True, text=True, timeout=15,
            )
            proto = result.stdout.strip()
            self._json({'host': host, 'port': port,
                         'reachable': result.returncode == 0 and proto in ('tcp', 'udp'), 'protocol': proto if proto in ('tcp', 'udp') else 'none'})
        except Exception as e:
            self._json({'error': str(e)}, 500)


# ── File readers (safe) ──────────────────────────────────────────────

def _read_state_file() -> dict:
    state = {}
    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    k, v = line.split('=', 1)
                    state[k] = v
    except FileNotFoundError:
        pass
    return state


def _read_backend_file():
    try:
        line = open(BACKEND_FILE, 'r', encoding='utf-8').read().strip()
        if not line or line == 'none':
            return None
        parts = line.rsplit(':', 2)
        if len(parts) == 3:
            return {'host': parts[0], 'port': int(parts[1]),
                    'protocol': parts[2]}
        if len(parts) == 2:
            return {'host': parts[0], 'port': int(parts[1]),
                    'protocol': 'udp'}
    except Exception:
        pass
    return None


def _read_metrics_file() -> dict:
    try:
        with open(METRICS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


# ── Threaded HTTP server ──────────────────────────────────────────────

class ThreadedHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(24)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        request.settimeout(10)
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
            finally:
                self.shutdown_request(request)
            return
        t = threading.Thread(target=self._handle, args=(request, client_address))
        t.daemon = True
        t.start()

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            self._slots.release()


# ── Main ──────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    server = ThreadedHTTPServer(('0.0.0.0', port), APIHandler)
    log.info(f"KNX Web UI listening on 0.0.0.0:{port}")

    def stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    try:
        server.serve_forever()
    finally:
        server.server_close()
        log.info("Web UI stopped")


if __name__ == '__main__':
    main()
