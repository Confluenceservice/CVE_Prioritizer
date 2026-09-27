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
    return conn


def get(cve_id):
    """
    Returns the cached NVD record for cve_id, or None if missing, expired or caching is disabled.
    """
    if not _config['enabled']:
        return None
    try:
        conn = _connect()
        try:
            row = conn.execute('SELECT fetched_at, data FROM nvd WHERE cve_id = ?', (cve_id,)).fetchone()
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as err:
        logger.warning(f"{cve_id} - NVD cache read failed: {err}")
        return None
    if row is None or time.time() - row[0] > _config['ttl_seconds']:
        return None
    return json.loads(row[1])


def put(cve_id, record):
    """
    Stores an NVD record. Cache failures are logged and never stop a scan.
    """
    if not _config['enabled']:
        return
    try:
        conn = _connect()
        try:
            with conn:
                conn.execute('INSERT OR REPLACE INTO nvd (cve_id, fetched_at, data) VALUES (?, ?, ?)',
                             (cve_id, time.time(), json.dumps(record)))
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as err:
        logger.warning(f"{cve_id} - NVD cache write failed: {err}")
