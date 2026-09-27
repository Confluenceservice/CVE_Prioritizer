#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.10.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import json
import logging
import os
import re
import threading
import requests
import click
from dotenv import load_dotenv
from termcolor import colored
from scripts.constants import EPSS_URL, NIST_BASE_URL, VULNCHECK_BASE_URL, VULNCHECK_KEV_BASE_URL, CISA_KEV_URL, CVELIST_RAW_BASE
import xml.etree.ElementTree as ET

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
                response = requests.get(CISA_KEV_URL, timeout=30)
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


# Collect EPSS Scores
def epss_check(cve_id):
    """
    Function collects EPSS from FIRST.org
    """
    try:
        epss_url = EPSS_URL + f"?cve={cve_id}"
        epss_response = requests.get(epss_url)
        epss_response.raise_for_status()

        response_data = epss_response.json()
        if response_data.get("total") > 0:
            for cve in response_data.get("data"):
                results = {"epss": float(cve.get("epss")),
                           "percentile": float(cve.get("percentile"))}
                return results
        else:
            logger.warning(f"{cve_id} - Not Found in EPSS.")
            click.echo(f"{cve_id:<18}Not Found in EPSS.")
            return {"epss": None, "percentile": None}
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

    return {"epss": None, "percentile": None}


# Check NIST NVD for the CVE
def nist_check(cve_id, api_key, cvss_version):
    """
    Function collects NVD Data
    """
    try:
        nvd_key = api_key or os.getenv('NIST_API')
        nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
        headers = {'apiKey': nvd_key} if nvd_key else {}

        nvd_response = requests.get(nvd_url, headers=headers)
        nvd_response.raise_for_status()

        response_data = nvd_response.json()
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

        vulncheck_response = requests.get(vulncheck_url, headers=header, params=params)
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
            vulncheck_response = requests.get(vulncheck_url, headers=header, params=params).json()

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


def cvelist_check(cve_id, local_base_path=None):
    """
    Fetch minimal fields from CVEProject/cvelistV5 JSON (CVE JSON 5.x).
    Supports online raw fetch or local mirror lookup.
    """
    try:
        year, block = _cvelist_path_for_cve(cve_id)
        if not year:
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

        if local_base_path:
            file_path = os.path.join(local_base_path, 'cves', year, f"{block}", f"CVE-{year}-{cve_id.split('-')[2]}.json")
            if not os.path.exists(file_path):
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
            with open(file_path, 'r') as f:
                data = json.load(f)
        else:
            url = f"{CVELIST_RAW_BASE}/{year}/{block}/CVE-{year}-{cve_id.split('-')[2]}.json"
            resp = requests.get(url)
            if resp.status_code != 200:
                click.echo(f"{cve_id:<18}Not Found in CVE List V5.")
                logger.warning(f"{cve_id} - Not Found in CVE List V5.")
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
            data = resp.json()

        # Extract minimal fields from JSON 5.x containers
        containers = data.get('containers', {})

        # CNA metrics (cvssData) can be under metrics with version-specific keys or unified in JSON 5; handle common cases
        metrics = containers.get('cna', {}).get('metrics', [])
        cvss_version = ""
        cvss_score = ""
        cvss_severity = ""
        vector = ""
        for metric in metrics:
            # JSON 5.x may have a 'cvssV3_1', 'cvssV4_0', or 'cvssV2_0' object
            for key in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
                if key in metric:
                    m = metric[key]
                    cvss_version = key.replace('_', ' ').upper().replace('CVSS', 'CVSS ')
                    cvss_score = to_float(m.get('baseScore'))
                    cvss_score = cvss_score if cvss_score is not None else ""
                    cvss_severity = m.get('baseSeverity', '')
                    vector = m.get('vectorString', '')
                    break
            if cvss_version:
                break

        # CPE-like affected; JSON5 uses affected products; we try to synthesize a CPE-ish string from vendor/product where possible
        affected = containers.get('cna', {}).get('affected', [])
        vendor = ''
        product = ''
        if affected:
            a0 = affected[0]
            vendor = (a0.get('vendor', '') or '').lower()
            product = (a0.get('product', '') or '').lower()
        cpe = f"cpe:2.3::{vendor}:{product}::::::::"  # placeholder consistent with existing code

        # ADP CISA: KEV and possible SSVC; we set cisa_kev when present
        cisa_kev = False
        adp = containers.get('adp', [])
        for entry in adp:
            for metric in entry.get('metrics', []):
                if (metric.get('other') or {}).get('type', '') == 'kev':
                    cisa_kev = True
                    # Some records embed ssvc decision tree; we do not consume it yet
                    break

        # No explicit exploit maturity in JSON; return False; ransomware unknown
        return {
            "cvss_version": cvss_version,
            "cvss_baseScore": cvss_score,
            "cvss_severity": cvss_severity,
            "cisa_kev": cisa_kev,
            "exploit_maturity_attacked": False,
            "ransomware": '',
            "cpe": cpe,
            "vector": vector
        }
    except Exception as e:
        logger.error(f"{cve_id} - Error processing cvelistV5: {e}")
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


# Function manages the outputs
def print_and_write(working_file, cve_id, priority, epss, epss_percentile, cvss_base_score, cvss_version, cvss_severity, kev, ransomware,
                    exploited, source, verbose, cpe, vector, color_enabled):
    color_priority = colored_print(priority)
    vendor, product = parse_cpe(cpe)

    # Format percentile for display (4 decimal places, handle None)
    percentile_str = f"{epss_percentile:.4f}" if epss_percentile is not None else "N/A"
    percentile_display = percentile_str[:12]  # Limit to 12 chars to match column width

    if verbose:
        if color_enabled:
            click.echo(
                f"{cve_id:<18}{color_priority:<22}{_display(epss):<9}{percentile_display:<12}{_display(cvss_base_score):<6}"
                f"{cvss_version:<10}{cvss_severity:<10}"
                f"{kev:<7}{ransomware:<12}{exploited:<11}{truncate_string(vendor, 15):<18}"
                f"{truncate_string(product, 20):<23}{vector}")
        else:
            click.echo(f"{cve_id:<18}{priority:<13}{_display(epss):<9}{percentile_display:<12}{_display(cvss_base_score):<6}"
                       f"{cvss_version:<10}{cvss_severity:<10}"
                       f"{kev:<7}{ransomware:<12}{exploited:<11}{truncate_string(vendor, 15):<18}"
                       f"{truncate_string(product, 20):<23}{vector}")
    else:
        if color_enabled:
            click.echo(f"{cve_id:<18}{color_priority:<22}")
        else:
            click.echo(f"{cve_id:<18}{priority:<13}")
    if working_file:
        epss_csv = epss if epss is not None else ""
        percentile_csv = epss_percentile if epss_percentile is not None else ""
        working_file.write(f"{cve_id},{priority},{epss_csv},{percentile_csv},{cvss_base_score},{cvss_version},{cvss_severity},"
                           f"{kev},{ransomware},{exploited},{source},{cpe},{vendor},{product},{vector}\n")


# Main function
def worker(cve_id, cvss_score, epss_score, verbose_print, sem, colored_output, cvss_v, save_output=None, api=None,
           nvd_plus=None, vc_kev=None, results=None, use_cvelist=False, cvelist_path=None):
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

        exploited = bool(cve_result.get('cisa_kev'))
        exploit_maturity_attacked = bool(cve_result.get('exploit_maturity_attacked'))

        priority = classify(cve_result.get('cvss_baseScore'), epss_result.get('epss'), exploited,
                            exploit_maturity_attacked, cvss_score, epss_score)

        kev = 'TRUE' if exploited else 'FALSE'
        attacked = 'TRUE' if exploit_maturity_attacked else 'FALSE'
        ransomware = cve_result.get('ransomware') or ''

        print_and_write(save_output, cve_id, PRIORITY_LABELS[priority], epss_result.get('epss'),
                        epss_result.get('percentile'), cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                        cve_result.get('cvss_severity'), kev, ransomware, attacked, kev_source, verbose_print,
                        cve_result.get('cpe'), cve_result.get('vector'), colored_output)

        if results is not None:
            results.append({
                'cve_id': cve_id,
                'priority': priority,
                'epss': epss_result.get('epss'),
                'epss_percentile': epss_result.get('percentile'),
                'cvss_base_score': cve_result.get('cvss_baseScore'),
                'cvss_version': cve_result.get('cvss_version'),
                'cvss_severity': cve_result.get('cvss_severity'),
                'kev': kev,
                'ransomware': ransomware,
                'exploited': attacked,
                'kev_source': kev_source,
                'cpe': cve_result.get('cpe'),
                'vector': cve_result.get('vector')
            })
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
