"""Versioned, atomic UI-owned configuration. Supervisor options are import-only."""
import copy
import json
import os
import re
import tempfile
import threading
from pathlib import Path

CONFIG_FILE = os.environ.get('FLAPPY_CONFIG', '/data/flappy.json')
OPTIONS_FILE = '/data/options.json'
LOCK = threading.RLock()
DEFAULTS = dict(frontend_protocol='udp', listen_port=3671, health_check_interval=1,
                health_check_fall=2, health_check_rise=2, connection_timeout=1,
                failback_mode='auto', failback_delay_seconds=30, max_sessions=8,
                session_timeout=120, drain_timeout_seconds=5, log_level='info',
                notify_on_failover=False)


def atomic_write(path, text):
    directory = str(Path(path).parent)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.flappy-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def migrate(options):
    if not isinstance(options, dict):
        raise ValueError('Configuration must be a JSON object')
    if options.get('schema_version', 1) != 1:
        raise ValueError('Unsupported configuration schema version')
    cfg = {**DEFAULTS, **options}
    if 'interfaces' not in cfg:
        entries = []
        for prefix in ('primary', 'backup', 'knxd'):
            if not cfg.get(prefix + '_host'):
                continue
            item = dict(id=prefix, name=prefix.title(), type='ip', role='fallback')
            for key, default in dict(host='', port=3671, protocol='udp', secure=False,
                                     device_password='', user_password='', user_id=1).items():
                item[key] = cfg.get(prefix + '_' + key, default)
            entries.append(item)
        if cfg.get('usb_device'):
            usb = dict(id='usb', name='USB', type='usb', role='fallback',
                       device=cfg['usb_device'], mode=cfg.get('usb_mode', 'auto'),
                       baud=cfg.get('usb_baud', 19200),
                       extra_args=cfg.get('usb_knxd_extra_args', ''))
            entries.insert(0 if cfg.get('usb_priority') == 'prefer' else len(entries), usb)
        cfg['interfaces'] = entries
    cfg.setdefault('revision', 0)
    cfg['schema_version'] = 1
    return cfg


def load_config():
    with LOCK:
        path = CONFIG_FILE if os.path.exists(CONFIG_FILE) else OPTIONS_FILE
        try:
            with open(path, encoding='utf-8') as f:
                return migrate(json.load(f))
        except FileNotFoundError:
            return migrate({})


def validate(cfg):
    if cfg.get('schema_version', 1) != 1:
        raise ValueError('Unsupported configuration schema version')
    if type(cfg.get('notify_on_failover', False)) is not bool:
        raise ValueError('notify_on_failover must be true or false')
    def number(obj, key, lo, hi, default):
        value = obj.setdefault(key, default)
        if type(value) is not int or not lo <= value <= hi:
            raise ValueError(f'{key} must be an integer from {lo} to {hi}')

    for key, lo, hi in [('listen_port',1,65535), ('health_check_interval',1,300),
                        ('health_check_fall',1,20), ('health_check_rise',1,20),
                        ('connection_timeout',1,30), ('failback_delay_seconds',0,3600),
                        ('max_sessions',1,16), ('session_timeout',30,3600),
                        ('drain_timeout_seconds',1,30)]:
        number(cfg, key, lo, hi, DEFAULTS[key])
    for key, values in dict(frontend_protocol=('tcp','udp','both'),
                            failback_mode=('auto','manual','disabled'),
                            log_level=('debug','info','warning','error')).items():
        if cfg.get(key) not in values:
            raise ValueError(f'Invalid {key}')
    entries = cfg.get('interfaces')
    if not isinstance(entries, list) or len(entries) > 32:
        raise ValueError('Configure at most 32 interfaces (including monitors)')
    ids, endpoints, usb_identities, knxd_addresses = set(), set(), set(), []
    if sum(bool(i.get('telegrams')) for i in entries if isinstance(i, dict)) > 4:
        raise ValueError('At most 4 simultaneous telegram monitors are supported')
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise ValueError('Each interface must be an object')
        ident = item.get('id', '')
        if not isinstance(ident, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,48}', ident) or ident in ids:
            raise ValueError('Interface IDs must be unique letters, numbers, underscores or hyphens')
        ids.add(ident)
        if not isinstance(item.get('name'), str) or not 1 <= len(item['name']) <= 80:
            raise ValueError('Interface name must contain 1–80 characters')
        if item.get('role') not in ('fallback', 'monitor'):
            raise ValueError('Interface role must be fallback or monitor')
        if item.get('type') == 'ip':
            host = item.get('host', '')
            if not isinstance(host, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', host):
                raise ValueError('Enter an IPv4 address or hostname')
            number(item, 'port', 1, 65535, 3671)
            number(item, 'user_id', 1, 127, 1)
            if item.setdefault('protocol', 'auto') not in ('tcp','udp','auto'):
                raise ValueError('Invalid interface protocol')
            if type(item.setdefault('secure', False)) is not bool:
                raise ValueError('secure must be true or false')
            for key in ('device_password', 'user_password'):
                if not isinstance(item.setdefault(key, ''), str):
                    raise ValueError('Passwords must be strings')
            if item['secure'] and item['protocol'] == 'udp':
                raise ValueError('KNX IP Secure requires TCP or Auto')
            endpoint = ('ip', host.lower(), item['port'])
        elif item.get('type') == 'usb':
            device = item.get('device', '')
            if not isinstance(device, str) or (device != 'auto' and
                    (not device.startswith('/dev/') or '..' in device.split('/') or '\n' in device)):
                raise ValueError('USB device must be auto or an absolute /dev/ path')
            if item.setdefault('mode', 'auto') not in ('auto','native','knxd','socat'):
                raise ValueError('Invalid USB mode')
            number(item, 'baud', 1200, 115200, 19200)
            if not isinstance(item.setdefault('extra_args', ''), str):
                raise ValueError('USB extra arguments must be text')
            def address(key, default):
                value = item.setdefault(key, default)
                if not isinstance(value, str) or not re.fullmatch(r'\d{1,2}\.\d{1,2}\.\d{1,3}', value):
                    raise ValueError(f'{key} must be a KNX individual address, such as 1.1.240')
                area, line, device_number = map(int, value.split('.'))
                if area > 15 or line > 15 or device_number > 255:
                    raise ValueError(f'Invalid {key}')
                return area * 4096 + line * 256 + device_number
            base = (index % 15) * 17 + 1
            own = address('knx_address', f'15.{index // 15}.{base}')
            clients = address('client_address', f'15.{index // 15}.{base + 1}')
            if clients % 256 > 240 or clients <= own < clients + 16:
                raise ValueError('knxd tunnel address block needs 16 addresses in one line, excluding its own address')
            if item['mode'] in ('auto', 'knxd'):
                allocated = {own, *range(clients, clients + 16)}
                if any(allocated & other for other in knxd_addresses):
                    raise ValueError('knxd individual and tunnel addresses must not overlap between interfaces')
                knxd_addresses.append(allocated)
            endpoint = ('usb', device)
        else:
            raise ValueError('Interface type must be ip or usb')
        if endpoint in endpoints:
            raise ValueError('The same interface cannot be configured twice')
        endpoints.add(endpoint)
        for key in ('serial', 'vendor_id', 'product_id'):
            if key in item and (not isinstance(item[key], str) or len(item[key]) > 128):
                raise ValueError(f'Invalid USB {key}')
        if item['type'] == 'usb' and item.get('serial'):
            identity = (item.get('vendor_id'), item.get('product_id'), item['serial'])
            if identity in usb_identities:
                raise ValueError('The same USB serial identity cannot be configured twice')
            usb_identities.add(identity)
        if type(item.setdefault('telegrams', False)) is not bool:
            raise ValueError('telegrams must be true or false')
    # Local USB bridges reserve this small range. Avoid frontend/bridge collisions.
    if any(i['type'] == 'usb' for i in entries) and 13671 <= cfg['listen_port'] <= 13702:
        raise ValueError('Ports 13671–13702 are reserved for local USB bridges')
    if sum(i['type'] == 'usb' for i in entries) > 1 and any(
            i['type'] == 'usb' and i['device'] == 'auto' for i in entries):
        raise ValueError('With multiple USB interfaces, select explicit devices instead of Auto')
    return cfg

        

def save_config(updates):
    with LOCK:
        current = load_config()
        if updates.get('revision') != current['revision']:
            raise RuntimeError('Configuration changed. Reload this page before saving.')
        cfg = validate({**current, **copy.deepcopy(updates)})
        cfg['revision'] = current['revision'] + 1
        cfg['schema_version'] = 1
        legacy_backup = CONFIG_FILE + '.legacy-options.json'
        if not os.path.exists(CONFIG_FILE) and os.path.isfile(OPTIONS_FILE) and not os.path.exists(legacy_backup):
            with open(OPTIONS_FILE, encoding='utf-8') as legacy:
                atomic_write(legacy_backup, legacy.read())
        atomic_write(CONFIG_FILE, json.dumps(cfg, indent=2))
        return cfg
