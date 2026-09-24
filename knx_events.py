"""Bounded persistent event history, shared by manager and HTTP server."""
import os
import sqlite3
import time
from contextlib import contextmanager

DB = os.environ.get('FLAPPY_EVENTS', '/data/flappy-events.sqlite3')


@contextmanager
def connection():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    db = sqlite3.connect(DB, timeout=5)
    db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, timestamp REAL, '
               'interface_id TEXT, kind TEXT, message TEXT)')
    try:
        with db:
            yield db
    finally:
        db.close()


def record(ident, kind, message):
    with connection() as db:
        db.execute('INSERT INTO events(timestamp,interface_id,kind,message) VALUES (?,?,?,?)',
                   (time.time(), ident, kind, message))
        db.execute('DELETE FROM events WHERE id <= (SELECT MAX(id)-5000 FROM events)')


def recent(limit=200):
    with connection() as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute('SELECT * FROM events ORDER BY id DESC LIMIT ?',
                                                (min(500, max(1, limit)),))]


def last_transitions(ident):
    with connection() as db:
        return dict(db.execute('SELECT kind, MAX(timestamp) FROM events '
                               'WHERE interface_id=? AND kind IN (\'up\',\'down\') GROUP BY kind', (ident,)))
