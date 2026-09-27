#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.10.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import csv
import json
import logging
import os
import re
import threading
import requests
import click
from dotenv import load_dotenv
from termcolor import colored
from scripts import cache
from scripts.constants import (EPSS_URL, NIST_BASE_URL, NUCLEI_BASE_URL, VULNCHECK_BASE_URL, VULNCHECK_KEV_BASE_URL,
                               CISA_KEV_URL, CVELIST_RAW_BASE)
from scripts.net import http_get
import xml.etree.ElementTree as ET
from datetime import date, timedelta

load_dotenv()

# Configure logging to write to a file in the current working directory
logging.basicConfig(
    filename=os.path.join(os.getcwd(), 'cve_prioritizer_logs.txt'),
    filemode='w',  # Overwrite the log file on each run
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Short priority codes (JSON/HTML) mapped to the labels used in the terminal and CSV
PRIORITY_LABELS = {
    'P1+': 'Priority 1+',
    'P1': 'Priority 1',
    'P2': 'Priority 2',
    'P3': 'Priority 3',
    'P4': 'Priority 4',
    'UNSCORED': 'Unscored',
}


def to_float(value):
    """
    Returns value as a float, or None when it is missing or not numeric ("", None, "N/A").
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def classify(cvss_score, epss_score, kev, exploit_maturity_attacked, cvss_threshold, epss_threshold):
    """
    Single source of truth for the priority model. Returns a code from PRIORITY_LABELS.

    Known exploitation wins regardless of scores. Otherwise both CVSS and EPSS are needed;
    if either is missing the CVE is 'UNSCORED' so it is reported instead of silently dropped.
    """
    if kev or exploit_maturity_attacked:
        return 'P1+'

    cvss_score = to_float(cvss_score)
    epss_score = to_float(epss_score)
    if cvss_score is None or epss_score is None:
        return 'UNSCORED'

    severe = cvss_score >= cvss_threshold
    likely = epss_score >= epss_threshold
    if severe and likely:
        return 'P1'
    if severe:
        return 'P2'
    if likely:
        return 'P3'
    return 'P4'


# An EPSS rise of at least this much over 7 days is called out in the reason
EPSS_RISING_DELTA = 0.1


def _fmt(value):
    return f"{value:g}" if isinstance(value, float) else str(value)


def build_reason(priority, cvss_score, epss_score, cvss_threshold, epss_threshold, exploitation_evidence=(),
                 signals=()):
    """
    Explains a priority in one line, e.g.
    "CVSS 9.8 >= 6.0 and EPSS 0.54 >= 0.2; public exploit template (Nuclei)".
    exploitation_evidence: why a CVE is P1+ (KEV, CVSS v4 E:A, CISA SSVC active).
    signals: extra context that doesn't change the bucket (public exploit, EPSS trend, SSVC).
    """
    cvss = to_float(cvss_score)
    epss = to_float(epss_score)

    if priority == 'P1+':
        parts = ["Exploited: " + ", ".join(exploitation_evidence)]
    elif priority == 'UNSCORED':
        missing = [name for name, value in (("CVSS", cvss), ("EPSS", epss)) if value is None]
        parts = [f"No {' or '.join(missing)} score yet, review manually"]
    else:
        cvss_part = f"CVSS {_fmt(cvss)} {'>=' if cvss >= cvss_threshold else '<'} {_fmt(cvss_threshold)}"
        epss_part = f"EPSS {_fmt(epss)} {'>=' if epss >= epss_threshold else '<'} {_fmt(epss_threshold)}"
        joiner = " and " if priority in ('P1', 'P4') else " but "
        parts = [cvss_part + joiner + epss_part]

    return "; ".join(parts + [s for s in signals if s])


def signal_notes(public_exploit=None, epss_change_7d=None, ssvc=None):
    """
    Human-readable context for build_reason. Unknown values (None / '') are left out.
    """
    notes = []
    if public_exploit:
        notes.append("public exploit template (Nuclei)")
    change = to_float(epss_change_7d)
    if change is not None and change >= EPSS_RISING_DELTA:
        notes.append(f"EPSS up {change:+.2f} in 7 days")
    ssvc = ssvc or {}
    if ssvc.get('exploitation') and ssvc.get('exploitation') != 'active':
        details = [f"{ssvc['exploitation']} exploitation"]
        if ssvc.get('automatable') == 'yes':
            details.append("automatable")
        if ssvc.get('technical_impact'):
            details.append(f"{ssvc['technical_impact']} impact")
        notes.append("CISA SSVC: " + ", ".join(details))
    return notes


_kev_cache = None
_kev_lock = threading.Lock()


def get_cisa_kev():
    """
    Downloads the CISA KEV catalog once per run and returns it as {cveID: entry}.
    Worker threads share the cached copy; on failure an empty dict is cached so we don't retry per CVE.
    """
    global _kev_cache
    with _kev_lock:
        if _kev_cache is None:
            try:
                response = http_get(CISA_KEV_URL)
                response.raise_for_status()
                _kev_cache = {entry.get('cveID'): entry
                              for entry in response.json().get('vulnerabilities', [])}
            except (requests.exceptions.RequestException, ValueError) as err:
                logger.error(f"Unable to download CISA KEV catalog, ransomware data unavailable: {err}")
                _kev_cache = {}
        return _kev_cache


def kev_ransomware(cve_id):
    """
    Returns CISA's knownRansomwareCampaignUse for a CVE (e.g. 'KNOWN', 'UNKNOWN'), or '' if not listed.
    """
    entry = get_cisa_kev().get(cve_id)
    return str(entry.get('knownRansomwareCampaignUse')).upper() if entry else ''


NUCLEI_CACHE_KEY = 'nuclei_cve_ids'
_nuclei_ids = None
_nuclei_loaded = False
_nuclei_lock = threading.Lock()


def _parse_nuclei_index(text):
    """
    nuclei-templates/cves.json is JSON Lines: one {"ID": "CVE-...", ...} object per line.
    """
    ids = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            cve_id = json.loads(line).get('ID', '')
        except (ValueError, AttributeError):
            continue
        if cve_id:
            ids.add(cve_id.strip().upper())
    return ids


def get_nuclei_cves():
    """
    CVE IDs that have a public ProjectDiscovery Nuclei detection/exploitation template.
    Downloaded once per run and kept in the local cache for the cache TTL.
    Returns None when the index couldn't be loaded, so callers can report "unknown" instead of "no".
    """
    global _nuclei_ids, _nuclei_loaded
    with _nuclei_lock:
        if not _nuclei_loaded:
            _nuclei_loaded = True
            cached = cache.get_blob(NUCLEI_CACHE_KEY)
            if cached is not None:
                _nuclei_ids = set(cached)
            else:
                try:
                    response = http_get(NUCLEI_BASE_URL)
                    response.raise_for_status()
                    _nuclei_ids = _parse_nuclei_index(response.text)
                    cache.put_blob(NUCLEI_CACHE_KEY, sorted(_nuclei_ids))
                except requests.exceptions.RequestException as err:
                    logger.error(f"Unable to download the Nuclei template index, public exploit data unavailable: {err}")
                    _nuclei_ids = None
        return _nuclei_ids


def has_public_exploit(cve_id):
    """
    True / False, or None when unknown (index unavailable).
    """
    ids = get_nuclei_cves()
    return None if ids is None else cve_id in ids


# The EPSS API accepts a comma-separated list of CVEs and returns up to 100 rows per request
EPSS_BATCH_SIZE = 100

# {cve_id: {"epss": .., "percentile": .., "epss_change_7d": ..}} or {cve_id: None} when EPSS has no score for it
_epss_cache = {}
_epss_lock = threading.Lock()


EMPTY_EPSS = {"epss": None, "percentile": None, "epss_change_7d": None}


def _epss_change_7d(row, current):
    """
    Change in EPSS versus the score 7 days before the row's date, from scope=time-series data.
    None when there isn't a data point that old (e.g. brand-new CVEs).
    """
    try:
        target = date.fromisoformat(row.get("date")) - timedelta(days=7)
        past = [point for point in row.get("time-series") or []
                if point.get("date") and date.fromisoformat(point["date"]) <= target]
    except (TypeError, ValueError):
        return None
    if not past:
        return None
    reference = max(past, key=lambda point: point["date"])
    try:
        return round(current - float(reference.get("epss")), 5)
    except (TypeError, ValueError):
        return None


def _parse_epss_row(row):
    epss = float(row.get("epss"))
    return {"epss": epss, "percentile": float(row.get("percentile")), "epss_change_7d": _epss_change_7d(row, epss)}


def prefetch_epss(cve_ids):
    """
    Fetches EPSS scores for many CVEs in batches of EPSS_BATCH_SIZE (one request per 100 CVEs
    instead of one per CVE). A failed batch is skipped; epss_check then falls back to single lookups.
    """
    ids = sorted(set(cve_ids))
    for start in range(0, len(ids), EPSS_BATCH_SIZE):
        batch = ids[start:start + EPSS_BATCH_SIZE]
        try:
            response = http_get(EPSS_URL + f"?cve={','.join(batch)}&limit={len(batch)}&scope=time-series")
            response.raise_for_status()
            found = {row.get("cve"): _parse_epss_row(row) for row in response.json().get("data", [])}
        except (requests.exceptions.RequestException, ValueError, TypeError) as err:
            logger.warning(f"EPSS batch lookup failed, falling back to single lookups: {err}")
            continue
        with _epss_lock:
            for cve_id in batch:
                _epss_cache[cve_id] = found.get(cve_id)


# Collect EPSS Scores
def epss_check(cve_id):
    """
    Function collects EPSS from FIRST.org, using prefetched batch results when available
    """
    with _epss_lock:
        prefetched = cve_id in _epss_cache
        cached = _epss_cache.get(cve_id)
    if prefetched:
        if cached is None:
            logger.warning(f"{cve_id} - Not Found in EPSS.")
            click.echo(f"{cve_id:<18}Not Found in EPSS.")
            return dict(EMPTY_EPSS)
        return dict(cached)

    try:
        epss_url = EPSS_URL + f"?cve={cve_id}&scope=time-series"
        epss_response = http_get(epss_url)
        epss_response.raise_for_status()

        response_data = epss_response.json()
        if response_data.get("total") > 0:
            for cve in response_data.get("data"):
                return _parse_epss_row(cve)
        else:
            logger.warning(f"{cve_id} - Not Found in EPSS.")
            click.echo(f"{cve_id:<18}Not Found in EPSS.")
            return dict(EMPTY_EPSS)
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"{cve_id} - HTTP error occurred: {http_err}")
        click.echo(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError:
        logger.error(f"{cve_id} - Unable to connect to EPSS, check your Internet connection or try again")
        click.echo("Unable to connect to EPSS, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        logger.error(f"{cve_id} - The request to EPSS timed out")
        click.echo("The request to EPSS timed out")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"{cve_id} - An error occurred: {req_err}")
        click.echo(f"An error occurred: {req_err}")
    except ValueError as val_err:
        logger.error(f"{cve_id} - Error processing the response: {val_err}")
        click.echo(f"Error processing the response: {val_err}")

    return dict(EMPTY_EPSS)


def _nvd_cacheable(response_data):
    """
    Only cache records NVD has scored. Unscored ones ("Awaiting Analysis") are likely to change
    soon, so they are always fetched fresh.
    """
    for vulnerability in response_data.get("vulnerabilities") or []:
        metrics = (vulnerability.get("cve") or {}).get("metrics") or {}
        if any(key.startswith("cvssMetric") and value for key, value in metrics.items()):
            return True
    return False


def nvd_cached(cve_id):
    """
    True when a fresh NVD record for cve_id is in the local cache (no API call or throttling needed).
    """
    return cache.get(cve_id) is not None


# Check NIST NVD for the CVE
def nist_check(cve_id, api_key, cvss_version):
    """
    Function collects NVD Data
    """
    try:
        nvd_key = api_key or os.getenv('NIST_API')
        nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
        headers = {'apiKey': nvd_key} if nvd_key else {}

        response_data = cache.get(cve_id)
        if response_data is None:
            nvd_response = http_get(nvd_url, nvd=True, headers=headers)
            nvd_response.raise_for_status()

            response_data = nvd_response.json()
            if _nvd_cacheable(response_data):
                cache.put(cve_id, response_data)
        if response_data.get("totalResults") > 0:
            for unique_cve in response_data.get("vulnerabilities"):
                cisa_kev = unique_cve.get("cve").get("cisaExploitAdd", False)
                exploit_maturity_attacked = False
                ransomware = kev_ransomware(cve_id) if cisa_kev else ''

                cpe = unique_cve.get("cve").get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0].get("criteria", 'cpe:2.3:::::::::::')

                versions = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

                if cvss_version == 4:
                    versions = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

                metrics = unique_cve.get("cve").get("metrics", {})

                for version in versions:
                    if version in metrics:
                        for metric in metrics[version]:
                            if cvss_version == 4:
                                if "/E:A/" in metric.get("cvssData", {}).get("vectorString", ""):
                                    exploit_maturity_attacked = True
                            return {
                                "cvss_version": version.replace("cvssMetric", "CVSS "),
                                "cvss_baseScore": float(metric.get("cvssData", {}).get("baseScore", 0)),
                                "cvss_severity": metric.get("cvssData", {}).get("baseSeverity", ""),
                                "cisa_kev": cisa_kev,
                                "exploit_maturity_attacked": exploit_maturity_attacked,
                                "ransomware": ransomware,
                                "cpe": cpe,
                                "vector": metric.get("cvssData", {}).get("vectorString", "")
                            }

                if unique_cve.get("cve").get("vulnStatus") == "Awaiting Analysis":
                    click.echo(f"{cve_id:<18}Awaiting NVD Analysis")
                    logger.info(f"{cve_id} - Awaiting NVD Analysis")
                    return {
                        "cvss_version": "",
                        "cvss_baseScore": "",
                        "cvss_severity": "",
                        "cisa_kev": "",
                        "exploit_maturity_attacked": "",
                        "ransomware": "",
                        "cpe": "",
                        "vector": ""
                    }
        else:
            click.echo(f"{cve_id:<18}Not Found in NIST NVD.")
            logger.warning(f"{cve_id} - Not Found in NIST NVD.")
            return {
                "cvss_version": "",
                "cvss_baseScore": "",
                "cvss_severity": "",
                "cisa_kev": "",
                "exploit_maturity_attacked": "",
                "ransomware": "",
                "cpe": "",
                "vector": ""
            }
    except requests.exceptions.HTTPError:
        click.echo(f"{cve_id:<18}HTTP error occurred, check CVE ID or API Key")
        logger.error(f"{cve_id} - HTTP error occurred, check CVE ID or API Key")
    except requests.exceptions.ConnectionError:
        click.echo("Unable to connect to NIST NVD, check your Internet connection or try again")
        logger.error(f"{cve_id} - Unable to connect to NIST NVD, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        click.echo("The request to NIST NVD timed out")
        logger.error(f"{cve_id} - The request to NIST NVD timed out")
    except requests.exceptions.RequestException as req_err:
        click.echo(f"An error occurred: {req_err}")
        logger.error(f"{cve_id} - An error occurred: {req_err}")
    except ValueError as val_err:
        click.echo(f"Error processing the response: {val_err}")
        logger.error(f"{cve_id} - Error processing the response: {val_err}")

    return {
        "cvss_version": "",
        "cvss_baseScore": "",
        "cvss_severity": "",
        "cisa_kev": "",
        "exploit_maturity_attacked": "",
        "ransomware": "",
        "cpe": "",
        "vector": ""
    }


# Check Vulncheck NVD++
def vulncheck_check(cve_id, api_key, kev_check, cvss_version):
    """
    Function collects VulnCheck NVD2 Data
    """
    try:
        vulncheck_key = api_key or os.getenv('VULNCHECK_API')
        if not vulncheck_key:
            click.echo("VulnCheck requires an API key")
            logger.error("VulnCheck requires an API key")
            return {
                "cvss_version": "",
                "cvss_baseScore": "",
                "cvss_severity": "",
                "cisa_kev": "",
                "exploit_maturity_attacked": "",
                "ransomware": "",
                "cpe": "",
                "vector": ""
            }

        vulncheck_url = VULNCHECK_BASE_URL + f"?cve={cve_id}"
        header = {"accept": "application/json"}
        params = {"token": vulncheck_key}

        vulncheck_response = http_get(vulncheck_url, headers=header, params=params)
        vulncheck_response.raise_for_status()

        response_data = vulncheck_response.json()
        if response_data.get("_meta", {}).get("total_documents", 0) > 0:
            for unique_cve in response_data.get("data", []):
                vc_kev = False
                exploit_maturity_attacked = False
                vc_used_by_ransomware = ''
                if kev_check:
                    vc_kev, vc_used_by_ransomware = vulncheck_kev(unique_cve.get('id'), api_key)
                elif unique_cve.get("cisaExploitAdd"):
                    vc_kev = True
                    vc_used_by_ransomware = kev_ransomware(cve_id)

                cpe = unique_cve.get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0].get("criteria", 'cpe:2.3:::::::::::')

                versions = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

                if cvss_version == 4:
                    versions = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

                metrics = unique_cve.get("metrics", {})

                for version in versions:
                    if version in metrics:
                        for metric in metrics[version]:
                            if cvss_version == 4:
                                if "/E:A/" in metric.get("cvssData", {}).get("vectorString", ""):
                                    exploit_maturity_attacked = True
                            return {
                                "cvss_version": version.replace("cvssMetric", "CVSS "),
                                "cvss_baseScore": float(metric.get("cvssData", {}).get("baseScore", 0)),
                                "cvss_severity": metric.get("cvssData", {}).get("baseSeverity", ""),
                                "cisa_kev": vc_kev,
                                "exploit_maturity_attacked": exploit_maturity_attacked,
                                "ransomware": vc_used_by_ransomware,
                                "cpe": cpe,
                                "vector": metric.get("cvssData", {}).get("vectorString", "")
                            }

                if unique_cve.get("vulnStatus") == "Awaiting Analysis":
                    click.echo(f"{cve_id:<18}NIST Status: {unique_cve.get('vulnStatus')}")
                    logger.info(f"{cve_id} - NIST Status: {unique_cve.get('vulnStatus')}")
                    return {
                        "cvss_version": "",
                        "cvss_baseScore": "",
                        "cvss_severity": "",
                        "cisa_kev": "",
                        "exploit_maturity_attacked": "",
                        "ransomware": "",
                        "cpe": "",
                        "vector": ""
                    }
        else:
            click.echo(f"{cve_id:<18}Not Found in VulnCheck.")
            logger.warning(f"{cve_id} - Not Found in VulnCheck.")
            return {
                "cvss_version": "",
                "cvss_baseScore": "",
                "cvss_severity": "",
                "cisa_kev": "",
                "exploit_maturity_attacked": "",
                "ransomware": "",
                "cpe": "",
                "vector": ""
            }
    except requests.exceptions.HTTPError:
        click.echo(f"{cve_id:<18}HTTP error occurred, check CVE ID or API Key")
        logger.error(f"{cve_id} - HTTP error occurred, check CVE ID or API Key")
    except requests.exceptions.ConnectionError:
        click.echo("Unable to connect to VulnCheck, check your Internet connection or try again")
        logger.error(f"{cve_id} - Unable to connect to VulnCheck, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        click.echo("The request to VulnCheck timed out")
        logger.error(f"{cve_id} - The request to VulnCheck timed out")
    except requests.exceptions.RequestException as req_err:
        click.echo(f"An error occurred: {req_err}")
        logger.error(f"{cve_id} - An error occurred: {req_err}")
    except ValueError as val_err:
        click.echo(f"Error processing the response: {val_err}")
        logger.error(f"{cve_id} - Error processing the response: {val_err}")

    return {
        "cvss_version": "",
        "cvss_baseScore": "",
        "cvss_severity": "",
        "cisa_kev": "",
        "exploit_maturity_attacked": "",
        "ransomware": "",
        "cpe": "",
        "vector": ""
    }


def vulncheck_kev(cve_id, api_key):
    """
    Check Vulncheck's KEV catalog
    """

    vc_exploited = False
    vc_used_by_ransomware = False

    try:
        vulncheck_key = None
        if api_key:
            vulncheck_key = api_key
        elif os.getenv('VULNCHECK_API'):
            vulncheck_key = os.getenv('VULNCHECK_API')

        # local variables
        vulncheck_url = VULNCHECK_KEV_BASE_URL + f"?cve={cve_id}"
        header = {"accept": "application/json"}
        params = {"token": vulncheck_key}

        # Check if API has been provided
        if vulncheck_key:
            vulncheck_response = http_get(vulncheck_url, headers=header, params=params).json()

            if vulncheck_response.get('data'):
                vc_exploited = True
                vc_used_by_ransomware = str(vulncheck_response.get('data')[0].get('knownRansomwareCampaignUse')).upper()
                return vc_exploited, vc_used_by_ransomware
            else:
                return vc_exploited, vc_used_by_ransomware
        else:
            click.echo("VulnCheck requires an API key")
            logger.error(f"{cve_id} - VulnCheck requires an API key")
            exit()
    except requests.exceptions.ConnectionError:
        click.echo(f"Unable to connect to VulnCheck, Check your Internet connection or try again")
        logger.error(f"{cve_id} - Unable to connect to VulnCheck, Check your Internet connection or try again")
        return None, None


def _cvelist_path_for_cve(cve_id):
    try:
        parts = cve_id.split('-')
        year = parts[1]
        number = parts[2]
        num_int = int(number)
        if num_int < 1000:
            block = '0xxx'
        else:
            block = f"{str(num_int)[:-3]}xxx"
        return year, block
    except Exception:
        return None, None


EMPTY_SSVC = {"exploitation": "", "automatable": "", "technical_impact": ""}

# CVE JSON 5 metric keys, most preferred first
_CVELIST_CVSS_KEYS = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']


def _empty_cve_result():
    return {
        "cvss_version": "",
        "cvss_baseScore": "",
        "cvss_severity": "",
        "cisa_kev": "",
        "exploit_maturity_attacked": "",
        "ransomware": "",
        "cpe": "",
        "vector": "",
        "ssvc": dict(EMPTY_SSVC),
    }


def load_cvelist_record(cve_id, local_base_path=None):
    """
    Loads a CVE JSON 5 record from a local cvelistV5 mirror or from GitHub.
    Returns None when the record doesn't exist.
    """
    year, block = _cvelist_path_for_cve(cve_id)
    if not year:
        return None
    file_name = f"CVE-{year}-{cve_id.split('-')[2]}.json"
    if local_base_path:
        file_path = os.path.join(local_base_path, 'cves', year, block, file_name)
        if not os.path.exists(file_path):
            return None
        with open(file_path, 'r') as f:
            return json.load(f)
    resp = http_get(f"{CVELIST_RAW_BASE}/{year}/{block}/{file_name}")
    if resp.status_code != 200:
        return None
    return resp.json()


def _adp_metrics(containers):
    for entry in containers.get('adp', []) or []:
        for metric in entry.get('metrics', []) or []:
            yield metric


def parse_ssvc(record):
    """
    Extracts CISA's SSVC decision points from the "CISA ADP Vulnrichment" container:
    {"exploitation": "none|poc|active", "automatable": "yes|no", "technical_impact": "partial|total"}
    """
    for metric in _adp_metrics((record or {}).get('containers', {})):
        other = metric.get('other') or {}
        if other.get('type') == 'ssvc':
            options = {}
            for option in (other.get('content') or {}).get('options', []) or []:
                for key, value in option.items():
                    options[key.strip().lower()] = str(value).strip().lower()
            return {
                "exploitation": options.get('exploitation', ''),
                "automatable": options.get('automatable', ''),
                "technical_impact": options.get('technical impact', ''),
            }
    return dict(EMPTY_SSVC)


def ssvc_check(cve_id, local_base_path=None):
    """
    SSVC for CVEs looked up through another source (NVD, VulnCheck). Failures return empty values.
    """
    try:
        return parse_ssvc(load_cvelist_record(cve_id, local_base_path))
    except Exception as e:
        logger.warning(f"{cve_id} - Unable to load SSVC from cvelistV5: {e}")
        return dict(EMPTY_SSVC)


def _first_cvss(metrics):
    for metric in metrics or []:
        for key in _CVELIST_CVSS_KEYS:
            if key in metric:
                m = metric[key]
                score = to_float(m.get('baseScore'))
                return {
                    "cvss_version": key.replace('_', ' ').upper().replace('CVSS', 'CVSS '),
                    "cvss_baseScore": score if score is not None else "",
                    "cvss_severity": m.get('baseSeverity', ''),
                    "vector": m.get('vectorString', ''),
                }
    return None


def cvelist_check(cve_id, local_base_path=None):
    """
    Fetch minimal fields from CVEProject/cvelistV5 JSON (CVE JSON 5.x).
    Supports online raw fetch or local mirror lookup.
    """
    try:
        data = load_cvelist_record(cve_id, local_base_path)
        if data is None:
            click.echo(f"{cve_id:<18}Not Found in CVE List V5.")
            logger.warning(f"{cve_id} - Not Found in CVE List V5.")
            return _empty_cve_result()

        containers = data.get('containers', {})

        # Prefer the vendor's (CNA) score; fall back to the score CISA adds via Vulnrichment (ADP)
        cvss = _first_cvss(containers.get('cna', {}).get('metrics', [])) or _first_cvss(list(_adp_metrics(containers)))
        cvss = cvss or {"cvss_version": "", "cvss_baseScore": "", "cvss_severity": "", "vector": ""}

        # CPE-like affected; JSON5 uses affected products; we try to synthesize a CPE-ish string from vendor/product where possible
        affected = containers.get('cna', {}).get('affected', [])
        vendor = ''
        product = ''
        if affected:
            a0 = affected[0]
            vendor = (a0.get('vendor', '') or '').lower()
            product = (a0.get('product', '') or '').lower()
        cpe = f"cpe:2.3::{vendor}:{product}::::::::"  # placeholder consistent with existing code

        # ADP CISA: KEV listing
        cisa_kev = any((metric.get('other') or {}).get('type', '') == 'kev' for metric in _adp_metrics(containers))

        return {
            **cvss,
            "cisa_kev": cisa_kev,
            "exploit_maturity_attacked": False,
            "ransomware": '',
            "cpe": cpe,
            "ssvc": parse_ssvc(data),
        }
    except Exception as e:
        logger.error(f"{cve_id} - Error processing cvelistV5: {e}")
        return _empty_cve_result()


def colored_print(priority):
    """
    Function used to handle colored print
    """
    if priority in ('Priority 1+', 'Priority 1'):
        return colored(priority, 'red')
    elif priority in ('Priority 2', 'Priority 3'):
        return colored(priority, 'yellow')
    elif priority == 'Priority 4':
        return colored(priority, 'green')
    else:
        return colored(priority, 'white')


# Extract CVE product details
def parse_cpe(cpe_str):
    """
    Parses a CPE 2.3 string and extracts the vendor and product.
    Format: cpe:2.3:part:vendor:product:version:update:edition:language:...
    Returns empty strings for anything missing.
    """
    parts = (cpe_str or '').split(':')

    vendor = parts[3] if len(parts) > 3 else ''
    product = parts[4] if len(parts) > 4 else ''

    return vendor, product


# Truncate for printing
def truncate_string(input_string, max_length):
    """
    Truncates a string to a maximum length, appending an ellipsis if the string is too long.
    """
    input_string = input_string or ''
    if len(input_string) > max_length:
        return input_string[:max_length - 3] + "..."
    else:
        return input_string


def _display(value):
    """
    Renders missing values (None / "") as N/A so format specs like :<9 never fail.
    """
    return 'N/A' if value is None or value == '' else value


# CSV columns. New columns are appended at the end so existing spreadsheets/scripts keep working.
CSV_FIELDS = ['cve_id', 'priority', 'epss', 'epss_percentile', 'cvss', 'cvss_version', 'cvss_severity', 'kev',
              'ransomware', 'exploited', 'kev_source', 'cpe', 'vendor', 'product', 'vector',
              'epss_change_7d', 'public_exploit', 'ssvc_exploitation', 'ssvc_automatable', 'ssvc_technical_impact',
              'reason']

_output_lock = threading.Lock()


def write_csv_header(working_file):
    csv.writer(working_file).writerow(CSV_FIELDS)


def _csv_value(value):
    return '' if value is None else value


# Function manages the outputs
def print_and_write(working_file, row, verbose, color_enabled):
    """
    Prints one result to the terminal and, when working_file is set, appends it to the CSV.
    row is the result dict built by worker (JSON keys); priority is shown with its long label.
    """
    priority = PRIORITY_LABELS[row['priority']]
    color_priority = colored_print(priority)
    shown_priority = f"{color_priority:<22}" if color_enabled else f"{priority:<13}"
    cve_id = row['cve_id']

    # Format percentile for display (4 decimal places, handle None)
    epss_percentile = row['epss_percentile']
    percentile_str = f"{epss_percentile:.4f}" if epss_percentile is not None else "N/A"
    percentile_display = percentile_str[:12]  # Limit to 12 chars to match column width

    with _output_lock:
        if verbose:
            click.echo(f"{cve_id:<18}{shown_priority}{_display(row['epss']):<9}{percentile_display:<12}"
                       f"{_display(row['cvss_base_score']):<6}{row['cvss_version']:<10}{row['cvss_severity']:<10}"
                       f"{row['kev']:<7}{row['ransomware']:<12}{row['exploited']:<11}"
                       f"{truncate_string(row['vendor'], 15):<18}{truncate_string(row['product'], 20):<23}{row['vector']}")
            click.echo(f"{'':<18}Why: {row['reason']}")
        else:
            click.echo(f"{cve_id:<18}{shown_priority}")

        if working_file:
            values = dict(row, priority=priority, cvss=row['cvss_base_score'],
                          ssvc_exploitation=row['ssvc']['exploitation'],
                          ssvc_automatable=row['ssvc']['automatable'],
                          ssvc_technical_impact=row['ssvc']['technical_impact'])
            csv.writer(working_file).writerow([_csv_value(values[field]) for field in CSV_FIELDS])


def _tri_state(value):
    """True/False/None -> 'TRUE'/'FALSE'/'' (unknown)."""
    return '' if value is None else ('TRUE' if value else 'FALSE')


# Main function
def worker(cve_id, cvss_score, epss_score, verbose_print, sem, colored_output, cvss_v, save_output=None, api=None,
           nvd_plus=None, vc_kev=None, results=None, use_cvelist=False, cvelist_path=None, ssvc=False):
    """
    Main Function
    """
    try:
        kev_source = 'CISA'
        if use_cvelist:
            cve_result = cvelist_check(cve_id, cvelist_path)
            kev_source = 'CVE LIST V5'
        elif vc_kev:
            cve_result = vulncheck_check(cve_id, api, vc_kev, cvss_v)
            kev_source = 'VULNCHECK'
        elif nvd_plus:
            cve_result = vulncheck_check(cve_id, api, vc_kev, cvss_v)
        else:
            if 'vulncheck' in str(api).lower():
                click.echo("Wrong API Key provided (VulnCheck)")
                exit()
            cve_result = nist_check(cve_id, api, cvss_v)
        epss_result = epss_check(cve_id)

        # Extra signals: CISA SSVC (from cvelistV5) and public exploit templates (Nuclei)
        ssvc_result = cve_result.get('ssvc')
        if ssvc_result is None:
            ssvc_result = ssvc_check(cve_id, cvelist_path) if ssvc else dict(EMPTY_SSVC)
        public_exploit = has_public_exploit(cve_id)

        exploited = bool(cve_result.get('cisa_kev'))
        cvss4_attacked = bool(cve_result.get('exploit_maturity_attacked'))
        ssvc_active = ssvc_result.get('exploitation') == 'active'
        exploit_maturity_attacked = cvss4_attacked or ssvc_active

        priority = classify(cve_result.get('cvss_baseScore'), epss_result.get('epss'), exploited,
                            exploit_maturity_attacked, cvss_score, epss_score)

        evidence = []
        if exploited:
            evidence.append(f"listed in KEV ({kev_source})")
        if cvss4_attacked:
            evidence.append("CVSS v4 exploit maturity: Attacked")
        if ssvc_active:
            evidence.append("CISA SSVC: active exploitation")
        reason = build_reason(priority, cve_result.get('cvss_baseScore'), epss_result.get('epss'), cvss_score,
                              epss_score, evidence,
                              signal_notes(public_exploit, epss_result.get('epss_change_7d'), ssvc_result))

        vendor, product = parse_cpe(cve_result.get('cpe'))
        row = {
            'cve_id': cve_id,
            'priority': priority,
            'epss': epss_result.get('epss'),
            'epss_percentile': epss_result.get('percentile'),
            'epss_change_7d': epss_result.get('epss_change_7d'),
            'cvss_base_score': cve_result.get('cvss_baseScore'),
            'cvss_version': cve_result.get('cvss_version') or '',
            'cvss_severity': cve_result.get('cvss_severity') or '',
            'kev': 'TRUE' if exploited else 'FALSE',
            'ransomware': cve_result.get('ransomware') or '',
            'exploited': 'TRUE' if exploit_maturity_attacked else 'FALSE',
            'kev_source': kev_source,
            'public_exploit': _tri_state(public_exploit),
            'ssvc': ssvc_result,
            'cpe': cve_result.get('cpe') or '',
            'vendor': vendor,
            'product': product,
            'vector': cve_result.get('vector') or '',
            'reason': reason,
        }

        print_and_write(save_output, row, verbose_print, colored_output)

        if results is not None:
            results.append(row)
    except Exception as e:
        # Never drop a CVE silently: tell the user which one failed and why
        click.echo(f"{cve_id:<18}Error: {e}")
        logger.exception(f"Error in worker thread for CVE {cve_id}: {e}")
    finally:
        sem.release()


def update_env_file(file, key, value):
    """Update the .env file with the new key value."""
    env_file_path = file
    env_lines = []
    key_found = False

    # Read the current .env file and update the key if it exists
    if os.path.exists(env_file_path):
        with open(env_file_path, 'r') as file:
            for line in file:
                if line.startswith(key):
                    env_lines.append(f'{key}="{value}"\n')
                    key_found = True
                else:
                    env_lines.append(line)

    # If the key was not found, add it to the end
    if not key_found:
        env_lines.append(f'{key}="{value}"\n')

    # Write the changes back to the .env file
    with open(env_file_path, 'w') as file:
        file.writelines(env_lines)


def is_valid_cve(cve_id):
    return re.match(r'^CVE-\d{4}-\d{4,}$', cve_id) is not None


def parse_report(file, report_type):
    cve_ids = set()
    if report_type == 'nessus':
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            cve_ids.update(
                cve.text.strip().upper()
                for report_item in root.findall(".//ReportItem")
                for cve in report_item.findall("cve")
                if is_valid_cve(cve.text.strip().upper())
            )
            return cve_ids
        except ET.ParseError as e:
            click.echo(f"Error parsing XML file: {e}")
            return []
        except Exception as e:
            click.echo(f"An error occurred: {e}")
            return []
    elif report_type == 'openvas':
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            for nvt in root.findall(".//nvt"):
                # Look for ref elements that have type="cve"
                for ref in nvt.findall(".//ref[@type='cve']"):
                    cve = ref.get("id")
                    if cve:
                        cve_ids.add(cve.strip())
            return list(cve_ids)
        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}")
            return []
        except Exception as e:
            print(f"An error occurred: {e}")
            return []
    return list(cve_ids)
