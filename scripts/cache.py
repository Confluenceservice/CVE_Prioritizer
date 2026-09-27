#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.10.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

# Local SQLite cache for NIST NVD records, so re-running a scan doesn't re-download
# (and get throttled on) every CVE. Entries expire after a TTL because NVD records change:
# new CVSS scores get published and CISA adds CVEs to KEV.

import json
import logging
import os
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_TTL_HOURS = 24

_config = {
    'enabled': True,
    'ttl_seconds': DEFAULT_TTL_HOURS * 3600,
    'path': None,
}


def default_cache_path():
    """
    ~/.cache/cve_prioritizer/nvd.sqlite, honouring XDG_CACHE_HOME when set.
    """
    base = os.getenv('XDG_CACHE_HOME') or os.path.join(Path.home(), '.cache')
    return os.path.join(base, 'cve_prioritizer', 'nvd.sqlite')


def configure(enabled=True, ttl_hours=DEFAULT_TTL_HOURS, path=None):
    """
    Called once from the CLI before any worker starts.
    """
    _config['enabled'] = enabled
    _config['ttl_seconds'] = ttl_hours * 3600
    _config['path'] = path or default_cache_path()


def _connect():
    path = _config['path'] or default_cache_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # A fresh connection per call keeps this safe across worker threads; SQLite serialises
    # writers itself and timeout waits for a lock instead of failing.
    conn = sqlite3.connect(path, timeout=30)
    conn.execute('CREATE TABLE IF NOT EXISTS nvd (cve_id TEXT PRIMARY KEY, fetched_at REAL, data TEXT)')
    # Whole datasets that are expensive to download, e.g. the Nuclei template index
    conn.execute('CREATE TABLE IF NOT EXISTS blobs (name TEXT PRIMARY KEY, fetched_at REAL, data TEXT)')
    return conn


# Table and key-column names are fixed here, never taken from input
_TABLES = {'nvd': 'cve_id', 'blobs': 'name'}


def _read(table, key):
    if not _config['enabled']:
        return None
    column = _TABLES[table]
    try:
        conn = _connect()
        try:
            row = conn.execute(f'SELECT fetched_at, data FROM {table} WHERE {column} = ?', (key,)).fetchone()
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as err:
        logger.warning(f"{key} - cache read failed: {err}")
        return None
    if row is None or time.time() - row[0] > _config['ttl_seconds']:
        return None
    return json.loads(row[1])


def _write(table, key, value):
    if not _config['enabled']:
        return
    column = _TABLES[table]
    try:
        conn = _connect()
        try:
            with conn:
                conn.execute(f'INSERT OR REPLACE INTO {table} ({column}, fetched_at, data) VALUES (?, ?, ?)',
                             (key, time.time(), json.dumps(value)))
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as err:
        logger.warning(f"{key} - cache write failed: {err}")


def get(cve_id):
    """
    Returns the cached NVD record for cve_id, or None if missing, expired or caching is disabled.
    """
    return _read('nvd', cve_id)


def put(cve_id, record):
    """
    Stores an NVD record. Cache failures are logged and never stop a scan.
    """
    _write('nvd', cve_id, record)


def get_blob(name):
    """
    Returns a cached dataset by name, or None if missing, expired or caching is disabled.
    """
    return _read('blobs', name)


def put_blob(name, value):
    """
    Stores a JSON-serialisable dataset by name.
    """
    _write('blobs', name, value)
