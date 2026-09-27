#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.10.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import fade
import json
import os
import threading
import time
import xml.etree.ElementTree as ET
from threading import Semaphore

import click
from dotenv import load_dotenv
from datetime import datetime, timezone

from scripts.constants import LOGO, SIMPLE_HEADER, VERBOSE_HEADER
from scripts import cache
from scripts.assets import (build_fix_order, load_assets, parse_csv_findings, parse_nessus_findings,
                            parse_openvas_findings, print_fix_order, write_fix_order_csv)
from scripts.helpers import is_valid_cve, nvd_cached, prefetch_epss, update_env_file, worker, write_csv_header

load_dotenv()
Throttle_msg = ''


# argparse setup
@click.command()
@click.option('-a', '--api', type=str, help='Your API Key')
@click.option('-c', '--cve', type=str, help='Unique CVE-ID')
@click.option('-e', '--epss', type=float, default=0.2, help='EPSS threshold (Default 0.2)')
@click.option('-f', '--file', type=click.File('r'), help='TXT file with CVEs (One per Line)')
@click.option('-j', '--json_file', type=click.Path(), required=False, help='JSON output')
@click.option('-n', '--cvss', type=float, default=6.0, help='CVSS threshold (Default 6.0)')
@click.option('-o', '--output', type=click.File('w'), help='Output filename')
@click.option('-t', '--threads', type=int, default=100, help='Number of concurrent threads')
@click.option('-v', '--verbose', is_flag=True, help='Verbose mode')
@click.option('-l', '--list', help='Comma separated list of CVEs')
@click.option('-nc', '--no-color', is_flag=True, help='Disable Colored Output')
@click.option('-sa', '--set-api', is_flag=True, help='Save API keys')
@click.option('-vc', '--vulncheck', is_flag=True, help='Use NVD++ - Requires VulnCheck API')
@click.option('-vck', '--vulncheck_kev', is_flag=True, help='Use Vulncheck KEV - Requires VulnCheck API')
@click.option('--cvelistv5', is_flag=True, help='Use CVE List V5 (cvelistV5) as source')
@click.option('--cvelist-path', type=click.Path(exists=True, file_okay=False), required=False,
              help='Local path to cvelistV5 mirror for offline/fast lookups (used by --cvelistv5 and --ssvc)')
@click.option('--ssvc', is_flag=True,
              help="Add CISA's SSVC assessment from cvelistV5 (already included with --cvelistv5)")
@click.option('--nessus', is_flag=True, help='Parse Nessus file')
@click.option('--openvas', is_flag=True, help='Parse OpenVAS file')
@click.option('--findings-csv', is_flag=True, help='Parse a CSV of findings with "host" and "cve" columns')
@click.option('--assets', type=click.File('r'),
              help='Asset CSV (host,criticality,internet_facing,owner) to order findings by exposure and criticality')
@click.option('--hosts-output', type=click.File('w'), help='Write the per-host fix order to this CSV file')
@click.option('--report', type=click.Choice(['html', 'pdf']), help='Generate a report in HTML or PDF format')
@click.option('--cvss-version', type=int, default=3, help='Preferred CVSS version (3 or 4)')
@click.option('--no-cache', is_flag=True, help='Always fetch fresh NIST NVD data (skip the local cache)')
@click.option('--cache-ttl', type=click.FloatRange(min=0), default=cache.DEFAULT_TTL_HOURS, show_default=True,
              help='Hours a cached NIST NVD record stays fresh')
def main(api, cve, epss, file, cvss, output, threads, verbose, list, no_color, set_api, vulncheck, vulncheck_kev,
         json_file, nessus, openvas, report, cvss_version, cvelistv5, cvelist_path, no_cache, cache_ttl, ssvc,
         findings_csv, assets, hosts_output):

    # Global Arguments
    color_enabled = not no_color
    throttle_msg = ''

    # standard args
    header = VERBOSE_HEADER if verbose else SIMPLE_HEADER
    epss_threshold = epss
    cvss_threshold = cvss
    sem = Semaphore(threads)
    cache.configure(enabled=not no_cache, ttl_hours=cache_ttl)

    # Temporal lists
    cve_list = []
    findings = []  # host-level findings from scanner reports
    threads = []

    if set_api:
        services = ['nist_nvd', 'vulncheck']
        service = click.prompt("Please choose a service to set the API key",
                               type=click.Choice(services, case_sensitive=False))
        api_key = click.prompt(f"Enter the API key for {service}", hide_input=True)

        if service == 'nist_nvd':
            update_env_file('.env', 'NIST_API', api_key)
        elif service == 'vulncheck':
            update_env_file('.env', 'VULNCHECK_API', api_key)

        click.echo(f"API key for {service} updated successfully.")
    if verbose:
        header = VERBOSE_HEADER

    if cve:
        cve_list.append(cve)
    elif list:
        cve_list = [c.strip() for c in list.split(',') if c.strip()]
    elif file:
        parser = (parse_nessus_findings if nessus else parse_openvas_findings if openvas
                  else parse_csv_findings if findings_csv else None)
        if parser:
            try:
                findings = parser(file)
            except (ET.ParseError, ValueError) as e:
                click.echo(f"Error reading {file.name}: {e}")
                exit(1)
            cve_list = sorted({finding['cve_id'] for finding in findings})
        else:
            cve_list = [line.strip() for line in file if line.strip()]

    if not api and not os.getenv('NIST_API') and not vulncheck and not cvelistv5:
        if len(cve_list) > 75:
            throttle_msg = 'Large number of CVEs detected, requests will be throttle to avoid API issues'
            faded_text = fade.greenblue(LOGO)
            click.echo(faded_text + throttle_msg + '\n' +
                       'Warning: Using this tool without specifying a NIST API may result in errors'
                       + '\n\n' + header)
        else:
            faded_text = fade.greenblue(LOGO)
            click.echo(faded_text + 'Warning: Using this tool without specifying a NIST API may result in errors'
                       + '\n\n' + header)
    else:
        faded_text = fade.greenblue(LOGO)
        click.echo(faded_text + header)

    if output:
        write_csv_header(output)

    # Normalise once so the EPSS prefetch and the workers see the same IDs
    cve_list = [c.strip().upper() for c in cve_list]
    uses_nvd = not (vulncheck or vulncheck_kev or cvelistv5)

    # One EPSS request per 100 CVEs instead of one per CVE
    prefetch_epss([c for c in cve_list if is_valid_cve(c)])

    results = []
    for cve in cve_list:
        throttle = 1
        if len(cve_list) > 75 and not os.getenv('NIST_API') and not api and not vulncheck:
            throttle = 6
        if (vulncheck or vulncheck_kev) and (os.getenv('VULNCHECK_API') or api):
            throttle = 0.25
        elif (vulncheck or vulncheck_kev) and not os.getenv('VULNCHECK_API') and not api:
            click.echo("VulnCheck requires an API key")
            exit()
        elif cvelistv5:
            throttle = 0.1
        if uses_nvd and nvd_cached(cve):
            throttle = 0  # served from the local cache, no NVD request to pace
        if not is_valid_cve(cve):
            click.echo(f'{cve} Error: CVEs should be provided in the standard format CVE-0000-0000*')
        else:
            sem.acquire()
            t = threading.Thread(target=worker, args=(cve, cvss_threshold, epss_threshold, verbose,
                                                      sem, color_enabled, cvss_version, output, api, vulncheck,
                                                      vulncheck_kev, results, cvelistv5, cvelist_path, ssvc))
            threads.append(t)
            t.start()
            time.sleep(throttle)

    for t in threads:
        t.join()

    # Asset context: order the scanner's host-level findings by priority, exposure and criticality
    fix_order = []
    if assets and not findings:
        click.echo("\n--assets needs host-level findings: use -f with --nessus, --openvas or --findings-csv")
    if findings:
        try:
            inventory = load_assets(assets) if assets else None
        except ValueError as e:
            click.echo(f"\nError reading {assets.name}: {e}")
            inventory = None
        fix_order = build_fix_order(findings, {r['cve_id']: r for r in results}, inventory)
        print_fix_order(fix_order)
        if hosts_output:
            write_fix_order_csv(hosts_output, fix_order)

    metadata = {
        'generator': 'CVE Prioritizer',
        'generation_date': datetime.now(timezone.utc).isoformat(),
        'total_cves': len(cve_list),
        'cvss_threshold': cvss_threshold,
        'epss_threshold': epss_threshold,
    }
    output_data = {
        'metadata': metadata,
        'cves': results,
    }
    if findings:
        output_data['findings'] = fix_order

    if json_file:
        with open(json_file, 'w') as json_output:
            json.dump(output_data, json_output, indent=4)

    if report:
        from scripts.report_generator import generate_report

        generate_report(
            data=output_data,
            output_path=f"report.{report}",
            format=report
        )

if __name__ == '__main__':
    main()
