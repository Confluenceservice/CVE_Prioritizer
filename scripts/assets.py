#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.10.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

# Asset context: which host each CVE was found on, how critical and exposed that host is,
# and the resulting order in which to fix things.
#
# A CVE's priority (P1+ ... P4) describes the vulnerability and doesn't change here.
# Asset context decides the *fix order* of findings: priority first, then internet exposure,
# then business criticality.

import csv
import ipaddress
import logging
import re
import xml.etree.ElementTree as ET

import click

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

CRITICALITY_LEVELS = ('low', 'medium', 'high', 'critical')
_TRUE = {'yes', 'y', 'true', '1'}
_FALSE = {'no', 'n', 'false', '0'}

# Lower sorts first. Unscored CVEs need a human look, so they sit above P4 but below scored P3s.
PRIORITY_ORDER = {'P1+': 0, 'P1': 1, 'P2': 2, 'P3': 3, 'UNSCORED': 4, 'P4': 5}
# Unknown exposure/criticality (host not in the asset file) sorts between the known extremes
EXPOSURE_ORDER = {True: 0, None: 1, False: 2}
CRITICALITY_ORDER = {'critical': 0, 'high': 1, None: 2, 'medium': 2, 'low': 3}


# ---------- Findings (host + CVE) from scanner reports ----------

def _finding(host, cve, ip='', port=''):
    return {'host': host or ip, 'ip': ip or '', 'cve_id': cve.upper(), 'port': port or ''}


def parse_nessus_findings(file):
    """
    Nessus v2 (.nessus) report -> [{"host", "ip", "cve_id", "port"}].
    The host is the FQDN or hostname when Nessus resolved one, else the scanned target name.
    """
    findings = []
    root = ET.parse(file).getroot()
    for report_host in root.iter('ReportHost'):
        tags = {tag.get('name'): (tag.text or '').strip() for tag in report_host.iter('tag')}
        ip = tags.get('host-ip', '')
        host = tags.get('host-fqdn') or tags.get('hostname') or report_host.get('name', '')
        for item in report_host.iter('ReportItem'):
            port = item.get('port', '')
            if port and port != '0' and item.get('protocol'):
                port = f"{port}/{item.get('protocol')}"
            elif port == '0':
                port = ''
            for cve in item.findall('cve'):
                for cve_id in CVE_PATTERN.findall(cve.text or ''):
                    findings.append(_finding(host, cve_id, ip, port))
    return findings


def parse_openvas_findings(file):
    """
    OpenVAS / Greenbone XML report -> [{"host", "ip", "cve_id", "port"}].
    CVEs come from <ref type="cve"> (GVM 9+) or the older comma-separated <cve> element.
    """
    findings = []
    root = ET.parse(file).getroot()
    for result in root.iter('result'):
        host_el = result.find('host')
        if host_el is None:
            continue
        ip = (host_el.text or '').strip()
        hostname = (host_el.findtext('hostname') or '').strip()
        port = (result.findtext('port') or '').strip()
        nvt = result.find('nvt')
        if nvt is None:
            continue
        cves = [ref.get('id', '') for ref in nvt.iter('ref') if ref.get('type') == 'cve']
        cves += CVE_PATTERN.findall(nvt.findtext('cve') or '')
        for cve_id in cves:
            if CVE_PATTERN.fullmatch(cve_id.strip()):
                findings.append(_finding(hostname, cve_id.strip(), ip, port))
    return findings


def parse_csv_findings(file):
    """
    Generic findings CSV with a header row containing at least "host" and "cve" (or "cve_id").
    Lets exports from other scanners (Qualys, Rapid7, ...) be used with a quick column rename.
    Optional columns: ip, port.
    """
    reader = csv.DictReader(file)
    fields = {name.strip().lower(): name for name in (reader.fieldnames or [])}
    cve_field = fields.get('cve') or fields.get('cve_id')
    if 'host' not in fields or not cve_field:
        raise ValueError('findings CSV needs "host" and "cve" columns')
    findings = []
    for row in reader:
        for cve_id in CVE_PATTERN.findall(row.get(cve_field) or ''):
            findings.append(_finding((row.get(fields['host']) or '').strip(), cve_id,
                                     (row.get(fields.get('ip', ''), '') or '').strip(),
                                     (row.get(fields.get('port', ''), '') or '').strip()))
    return findings


def dedupe(findings):
    """Same host/CVE/port reported twice (e.g. by two plugins) counts once."""
    seen = set()
    unique = []
    for finding in findings:
        key = (finding['host'].lower(), finding['cve_id'], finding['port'])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


# ---------- Asset inventory ----------

def _parse_bool(value):
    value = (value or '').strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    return None


class AssetInventory:
    """
    Asset CSV: host,criticality,internet_facing[,owner]
      host             hostname, FQDN, IP address or CIDR range (e.g. 10.0.5.0/24)
      criticality      low | medium | high | critical
      internet_facing  yes | no
    Lookup order: exact name, short name (web01 matches web01.corp.local), exact IP, then the
    most specific CIDR range containing the IP.
    """

    def __init__(self, entries=()):
        self.by_name = {}
        self.networks = []
        for entry in entries:
            self._add(entry)

    def _add(self, entry):
        host = entry['host']
        try:
            network = ipaddress.ip_network(host, strict=False)
        except ValueError:
            name = host.lower()
            self.by_name[name] = entry
            # web01.corp.local in the inventory also matches a scanner that only reports "web01";
            # an exact entry for the short name wins
            self.by_name.setdefault(name.split('.')[0], entry)
            return
        if network.num_addresses == 1:
            self.by_name[str(network.network_address)] = entry
        else:
            self.networks.append((network, entry))
            # Most specific range first
            self.networks.sort(key=lambda item: item[0].prefixlen, reverse=True)

    def lookup(self, host='', ip=''):
        for name in (host, ip):
            name = (name or '').strip().lower()
            if not name:
                continue
            if name in self.by_name:
                return self.by_name[name]
            short = name.split('.')[0]
            if not _is_ip(name) and short in self.by_name:
                return self.by_name[short]
        for candidate in (ip, host):
            try:
                address = ipaddress.ip_address((candidate or '').strip())
            except ValueError:
                continue
            for network, entry in self.networks:
                if address.version == network.version and address in network:
                    return entry
        return None


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def load_assets(file):
    """
    Reads the asset CSV. Rows with problems are skipped with a warning naming the line,
    so one typo doesn't lose the whole inventory.
    """
    reader = csv.DictReader(file)
    fields = {name.strip().lower(): name for name in (reader.fieldnames or [])}
    if 'host' not in fields:
        raise ValueError('asset CSV needs a "host" column')
    entries = []
    for line_number, row in enumerate(reader, start=2):
        def get(column):
            return (row.get(fields.get(column, ''), '') or '').strip()

        host = get('host')
        if not host:
            continue
        criticality = get('criticality').lower() or None
        if criticality and criticality not in CRITICALITY_LEVELS:
            click.echo(f"Asset file line {line_number}: unknown criticality '{criticality}' for {host}, "
                       f"expected one of {', '.join(CRITICALITY_LEVELS)}; ignoring it")
            criticality = None
        internet_facing = _parse_bool(get('internet_facing'))
        if get('internet_facing') and internet_facing is None:
            click.echo(f"Asset file line {line_number}: internet_facing should be yes or no for {host}; ignoring it")
        entries.append({'host': host, 'criticality': criticality, 'internet_facing': internet_facing,
                        'owner': get('owner')})
    return AssetInventory(entries)


# ---------- Fix order ----------

def _exposure_text(internet_facing):
    return {True: 'internet-facing', False: 'internal', None: 'exposure unknown'}[internet_facing]


def build_fix_order(findings, results_by_cve, inventory=None):
    """
    Joins scanner findings with CVE results and asset context, sorted into fix order:
    priority, then internet-facing before internal, then criticality, then CVSS and EPSS.
    """
    inventory = inventory or AssetInventory()
    rows = []
    for finding in dedupe(findings):
        result = results_by_cve.get(finding['cve_id'])
        if result is None:
            continue  # CVE couldn't be looked up; it is already reported in the CVE results
        asset = inventory.lookup(finding['host'], finding['ip']) or {}
        internet_facing = asset.get('internet_facing')
        criticality = asset.get('criticality')
        context = f"{_exposure_text(internet_facing)} host"
        if criticality:
            context += f" (criticality: {criticality})"
        rows.append({
            'host': finding['host'],
            'ip': finding['ip'],
            'port': finding['port'],
            'cve_id': finding['cve_id'],
            'priority': result['priority'],
            'internet_facing': {True: 'TRUE', False: 'FALSE', None: ''}[internet_facing],
            'criticality': criticality or '',
            'owner': asset.get('owner', ''),
            'in_inventory': 'TRUE' if asset else 'FALSE',
            'cvss_base_score': result.get('cvss_base_score'),
            'epss': result.get('epss'),
            'reason': f"{result['priority']} on {context}; {result.get('reason', '')}".rstrip('; '),
        })

    def score(value):
        try:
            return -float(value)
        except (TypeError, ValueError):
            return 0.0

    def fix_order_key(row):
        internet_facing = {'TRUE': True, 'FALSE': False, '': None}[row['internet_facing']]
        return (PRIORITY_ORDER.get(row['priority'], len(PRIORITY_ORDER)),
                EXPOSURE_ORDER[internet_facing],
                CRITICALITY_ORDER.get(row['criticality'] or None, 2),
                score(row['cvss_base_score']),
                score(row['epss']),
                row['host'].lower(), row['cve_id'])

    rows.sort(key=fix_order_key)
    for rank, row in enumerate(rows, start=1):
        row['rank'] = rank
    return rows


HOST_CSV_FIELDS = ['rank', 'host', 'ip', 'port', 'cve_id', 'priority', 'internet_facing', 'criticality', 'owner',
                   'in_inventory', 'cvss_base_score', 'epss', 'reason']


def write_fix_order_csv(file, rows):
    writer = csv.writer(file)
    writer.writerow(HOST_CSV_FIELDS)
    for row in rows:
        writer.writerow(['' if row[field] is None else row[field] for field in HOST_CSV_FIELDS])


def print_fix_order(rows, limit=20):
    """Top of the fix order in the terminal: what to patch first, and where."""
    if not rows:
        return
    click.echo(f"\nFix order by host (top {min(limit, len(rows))} of {len(rows)} findings)")
    click.echo(f"{'#':<5}{'HOST':<32}{'CVE-ID':<18}{'PRIORITY':<10}{'EXPOSURE':<18}CRITICALITY")
    click.echo("-" * 95)
    for row in rows[:limit]:
        exposure = {'TRUE': 'internet-facing', 'FALSE': 'internal', '': 'unknown'}[row['internet_facing']]
        host = row['host'] if len(row['host']) <= 30 else row['host'][:27] + '...'
        click.echo(f"{row['rank']:<5}{host:<32}{row['cve_id']:<18}{row['priority']:<10}{exposure:<18}"
                   f"{row['criticality'] or 'unknown'}")
