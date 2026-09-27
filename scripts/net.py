#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.10.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

# Shared HTTP layer: every outbound request goes through http_get so it gets a timeout
# and automatic retries with exponential backoff on transient errors.

import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# (connect, read) seconds. Without a timeout a hung server blocks a worker thread forever.
DEFAULT_TIMEOUT = (10, 30)

# Transient statuses worth retrying: rate limited (429) and server-side errors
RETRY_STATUSES = (429, 500, 502, 503, 504)
# NVD answers rate-limited requests with 403 instead of 429
NVD_RETRY_STATUSES = RETRY_STATUSES + (403,)

MAX_RETRIES = 4
BACKOFF_FACTOR = 2  # waits 0s, 4s, 8s, 16s between attempts, unless the server sends Retry-After

_local = threading.local()


def _build_session(statuses):
    retry = Retry(
        total=MAX_RETRIES,
        # Rate limits and 5xx get the full backoff; a connection that can't be opened, a read that
        # times out or a refused proxy tunnel ("other") gets one quick retry, so an offline run
        # fails fast instead of stalling ~30s per request
        connect=1,
        read=1,
        other=1,
        status=MAX_RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=statuses,
        allowed_methods=frozenset(['GET']),
        respect_retry_after_header=True,
        raise_on_status=False,  # hand the final response back so raise_for_status() reports it
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session


def _session(nvd):
    """
    One session per thread and retry profile: sessions reuse TCP/TLS connections, and keeping
    them thread-local avoids sharing one Session across the worker threads.
    """
    key = 'nvd' if nvd else 'default'
    sessions = getattr(_local, 'sessions', None)
    if sessions is None:
        sessions = _local.sessions = {}
    if key not in sessions:
        sessions[key] = _build_session(NVD_RETRY_STATUSES if nvd else RETRY_STATUSES)
    return sessions[key]


def http_get(url, nvd=False, timeout=DEFAULT_TIMEOUT, **kwargs):
    """
    GET with timeout and retries. Set nvd=True for NIST NVD so its 403 rate-limit responses are retried.
    """
    return _session(nvd).get(url, timeout=timeout, **kwargs)
