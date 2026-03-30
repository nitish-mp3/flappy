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
VERSION = "4.3.10"

SUPERVISOR_TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')


class APIHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the KNX web UI."""

    server_version = "KNXProxy/4.1.3"

    def log_message(self, fmt, *args):
        log.debug(fmt % args)

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
        return self.rfile.read(length) if length > 0 else b''

    # ── Routing ───────────────────────────────────────────────────────

    def do_GET(self):
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
        elif path == '/api/version':
            self._json({'version': VERSION})
        else:
            safe = path.lstrip('/')
            fp = os.path.realpath(os.path.join(WWW_DIR, safe))
            if fp.startswith(os.path.realpath(WWW_DIR)) and os.path.isfile(fp):
                ext = os.path.splitext(fp)[1].lower()
                mime = {'.css': 'text/css', '.js': 'application/javascript',
                        '.svg': 'image/svg+xml', '.png': 'image/png',
                        '.ico': 'image/x-icon', '.json': 'application/json',
                        }.get(ext, 'application/octet-stream')
                self._serve_file(fp, mime)
            else:
                self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path.rstrip('/')
        body = self._read_body()
        if path == '/api/config':
            self._api_set_config(body)
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
        try:
            with open(OPTIONS_FILE, 'r', encoding='utf-8') as f:
                self._json(json.load(f))
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_set_config(self, body: bytes):
        try:
            updates = json.loads(body)
            if not isinstance(updates, dict):
                self._json({'error': 'Expected JSON object'}, 400)
                return

            # Read current options
            with open(OPTIONS_FILE, 'r', encoding='utf-8') as f:
                current = json.load(f)
            current.update(updates)

            # Write locally for immediate effect (current run)
            tmp = OPTIONS_FILE + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(current, f, indent=2)
            os.replace(tmp, OPTIONS_FILE)

            # Persist via HA Supervisor API so changes survive restart
            persisted = False
            persist_error = ''
            if SUPERVISOR_TOKEN:
                try:
                    req = urllib.request.Request(
                        'http://supervisor/addons/self/options',
                        method='POST',
                        data=json.dumps({'options': current}).encode(),
                        headers={
                            'Authorization': f'Bearer {SUPERVISOR_TOKEN}',
                            'Content-Type': 'application/json',
                        },
                    )
                    resp = urllib.request.urlopen(req, timeout=10)
                    resp_body = resp.read().decode('utf-8', errors='replace')
                    log.info(f"Supervisor options saved (HTTP {resp.status}): {resp_body[:200]}")
                    persisted = True
                except urllib.error.HTTPError as he:
                    err_body = he.read().decode('utf-8', errors='replace')[:300]
                    persist_error = f"HTTP {he.code}: {err_body}"
                    log.warning(f"Supervisor options save failed: {persist_error}")
                except Exception as e:
                    persist_error = str(e)
                    log.warning(f"Supervisor options save failed: {e}")
            else:
                persist_error = 'No SUPERVISOR_TOKEN available'
                log.warning("Cannot persist options — no SUPERVISOR_TOKEN")

            self._json({
                'ok': True,
                'persisted': persisted,
                'persist_error': persist_error,
                'needs_restart': True,
                'message': 'Configuration saved. Restart the add-on for changes to take effect.',
            })
        except json.JSONDecodeError:
            self._json({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self._json({'error': str(e)}, 500)

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
        """Return status of all configured interfaces (primary, backup, knxd, USB)."""
        try:
            cfg = {}
            try:
                with open(OPTIONS_FILE, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
            except Exception:
                pass

            state = _read_state_file()
            backend = _read_backend_file()
            current_state = state.get('state', 'UNKNOWN')

            interfaces = []

            # Primary
            ph = cfg.get('primary_host', '')
            if ph:
                active = (current_state == 'PRIMARY' and backend
                          and backend.get('host') == ph)
                interfaces.append({
                    'name': 'Primary',
                    'type': 'network',
                    'host': ph,
                    'port': cfg.get('primary_port', 3671),
                    'protocol': cfg.get('primary_protocol', 'tcp'),
                    'secure': cfg.get('primary_secure', False),
                    'active': active,
                    'status': 'active' if active else 'standby',
                })
            else:
                interfaces.append({
                    'name': 'Primary',
                    'type': 'network',
                    'host': '',
                    'port': 3671,
                    'protocol': '-',
                    'secure': False,
                    'active': False,
                    'status': 'not_configured',
                })

            # Backup
            bh = cfg.get('backup_host', '')
            if bh:
                active = (current_state == 'BACKUP' and backend
                          and backend.get('host') == bh)
                interfaces.append({
                    'name': 'Backup',
                    'type': 'network',
                    'host': bh,
                    'port': cfg.get('backup_port', 3671),
                    'protocol': cfg.get('backup_protocol', 'udp'),
                    'secure': cfg.get('backup_secure', False),
                    'active': active,
                    'status': 'active' if active else 'standby',
                })
            else:
                interfaces.append({
                    'name': 'Backup',
                    'type': 'network',
                    'host': '',
                    'port': 3671,
                    'protocol': '-',
                    'secure': False,
                    'active': False,
                    'status': 'not_configured',
                })

            # knxd
            kh = cfg.get('knxd_host', '')
            if kh:
                active = (current_state == 'KNXD' and backend
                          and backend.get('host') == kh)
                interfaces.append({
                    'name': 'knxd',
                    'type': 'network',
                    'host': kh,
                    'port': cfg.get('knxd_port', 3671),
                    'protocol': cfg.get('knxd_protocol', 'udp'),
                    'secure': False,
                    'active': active,
                    'status': 'active' if active else 'standby',
                })

            # USB
            ud = cfg.get('usb_device', '')
            usb_active = current_state == 'USB'
            usb_mode = cfg.get('usb_mode', 'auto')
            usb_status = 'not_configured'
            usb_error = ''
            if ud:
                usb_status = 'active' if usb_active else 'standby'
                # Check device existence
                if not os.path.exists(ud):
                    usb_status = 'device_missing'
                    usb_error = f'Device {ud} not found'
                else:
                    is_raw = ud.startswith('/dev/bus/usb/') or ud.startswith('/dev/hidraw')
                    # Check if bridge tools are available
                    has_knxd = os.path.isfile('/usr/bin/knxd') or os.path.isfile('/usr/local/bin/knxd')
                    has_pyusb = False
                    try:
                        import importlib
                        importlib.import_module('usb.core')
                        has_pyusb = True
                    except Exception:
                        pass
                    if is_raw and not has_knxd and not has_pyusb:
                        usb_status = 'no_driver'
                        usb_error = ('Raw USB HID device requires knxd or pyusb. '
                                     'Neither is installed. Rebuild the add-on.')
                    elif usb_mode == 'socat' and is_raw:
                        usb_status = 'incompatible'
                        usb_error = 'socat cannot handle raw USB devices. Use native or knxd mode.'

            interfaces.append({
                'name': 'USB',
                'type': 'usb',
                'device': ud,
                'mode': usb_mode,
                'baud': cfg.get('usb_baud', 19200),
                'priority': cfg.get('usb_priority', 'last_resort'),
                'active': usb_active,
                'status': usb_status,
                'error': usb_error,
            })

            self._json({
                'interfaces': interfaces,
                'current_state': current_state,
                'active_backend': backend,
            })
        except Exception as e:
            self._json({'error': str(e)}, 500)

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
        try:
            req = urllib.request.Request(
                'http://supervisor/addons/self/restart',
                method='POST',
                headers={
                    'Authorization': f'Bearer {SUPERVISOR_TOKEN}',
                    'Content-Type': 'application/json',
                },
            )
            urllib.request.urlopen(req, timeout=10)
            self._json({'ok': True, 'message': 'Add-on restart initiated'})
        except Exception as e:
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
                         'reachable': proto != 'none', 'protocol': proto})
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

    def process_request(self, request, client_address):
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
