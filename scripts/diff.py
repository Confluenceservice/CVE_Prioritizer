#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.10.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

# Diff mode: compare this run with an earlier JSON output (--baseline) and report what changed,
# e.g. "CVE-X was added to KEV", "EPSS for CVE-Y jumped +0.4", "2 findings fixed on web01".

import json

import click

from scripts.assets import PRIORITY_ORDER

# EPSS increases of at least this much since the baseline are reported
EPSS_SPIKE_DELTA = 0.1

# Most important first; also the display order
CHANGE_TYPES = {
    'NEWLY_KEV': 'added to CISA KEV',
    'PRIORITY_UP': 'priority raised',
    'NEW': 'new CVE',
    'NEW_PUBLIC_EXPLOIT': 'public exploit published',
    'EPSS_SPIKE': 'EPSS spiked',
    'NEWLY_SCORED': 'now scored',
    'PRIORITY_DOWN': 'priority lowered',
    'RESOLVED': 'no longer present',
}


def load_baseline(path):
    """
    Reads an earlier -j output. Returns None (with a message) if it can't be used, so a bad
    baseline never stops the scan itself.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        click.echo(f"Baseline {path} not found; this run will be the baseline next time if saved with -j")
        return None
    except (OSError, ValueError) as err:
        click.echo(f"Unable to read baseline {path}: {err}")
        return None
    if not isinstance(data, dict) or not isinstance(data.get('cves'), list):
        click.echo(f"Baseline {path} is not a CVE Prioritizer JSON output (-j); skipping the comparison")
        return None
    return data


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _change(change, cve_id, before, after, detail, priority):
    return {'change': change, 'cve_id': cve_id, 'before': before, 'after': after, 'detail': detail,
            'priority': priority}


def compare_cves(baseline_cves, current_cves):
    """
    One entry per change; a CVE can have several (e.g. NEWLY_KEV and PRIORITY_UP).
    """
    before_by_id = {c.get('cve_id'): c for c in baseline_cves if c.get('cve_id')}
    after_by_id = {c.get('cve_id'): c for c in current_cves if c.get('cve_id')}
    changes = []

    for cve_id, now in after_by_id.items():
        priority = now.get('priority', '')
        old = before_by_id.get(cve_id)
        if old is None:
            changes.append(_change('NEW', cve_id, '', priority, f"new, {priority}", priority))
            continue

        old_priority = old.get('priority', '')
        if old_priority != priority:
            if old_priority == 'UNSCORED':
                changes.append(_change('NEWLY_SCORED', cve_id, old_priority, priority,
                                       f"scored: now {priority}", priority))
            elif priority in PRIORITY_ORDER and old_priority in PRIORITY_ORDER and priority != 'UNSCORED':
                kind = 'PRIORITY_UP' if PRIORITY_ORDER[priority] < PRIORITY_ORDER[old_priority] else 'PRIORITY_DOWN'
                changes.append(_change(kind, cve_id, old_priority, priority, f"{old_priority} -> {priority}",
                                       priority))

        if old.get('kev') != 'TRUE' and now.get('kev') == 'TRUE':
            changes.append(_change('NEWLY_KEV', cve_id, 'FALSE', 'TRUE',
                                   f"added to KEV ({now.get('kev_source', '')})".replace(' ()', ''), priority))

        # Only FALSE -> TRUE: an unknown ('' / missing) baseline can't prove the exploit is new
        if old.get('public_exploit') == 'FALSE' and now.get('public_exploit') == 'TRUE':
            changes.append(_change('NEW_PUBLIC_EXPLOIT', cve_id, 'FALSE', 'TRUE',
                                   "public exploit template (Nuclei)", priority))

        old_epss, new_epss = _to_float(old.get('epss')), _to_float(now.get('epss'))
        if old_epss is not None and new_epss is not None and new_epss - old_epss >= EPSS_SPIKE_DELTA:
            changes.append(_change('EPSS_SPIKE', cve_id, old_epss, new_epss,
                                   f"EPSS {old_epss:g} -> {new_epss:g} ({new_epss - old_epss:+.2f})", priority))

    for cve_id, old in before_by_id.items():
        if cve_id not in after_by_id:
            changes.append(_change('RESOLVED', cve_id, old.get('priority', ''), '',
                                   f"was {old.get('priority', '')}", old.get('priority', '')))

    order = list(CHANGE_TYPES)
    changes.sort(key=lambda c: (order.index(c['change']), PRIORITY_ORDER.get(c['priority'], len(PRIORITY_ORDER)),
                                c['cve_id']))
    return changes


def _finding_key(finding):
    return (str(finding.get('host', '')).lower(), finding.get('cve_id'), finding.get('port', ''))


def compare_findings(baseline_findings, current_findings):
    """
    Host-level changes, only meaningful when both runs came from scanner reports.
    new: on a host now, not before. fixed: on a host before, not now.
    """
    before = {_finding_key(f): f for f in baseline_findings}
    after = {_finding_key(f): f for f in current_findings}
    new = [after[k] for k in after if k not in before]
    fixed = [before[k] for k in before if k not in after]
    # Keep the current fix order for new findings; sort fixed ones by their old rank
    new.sort(key=lambda f: f.get('rank', 0))
    fixed.sort(key=lambda f: f.get('rank', 0))
    return {'new': new, 'fixed': fixed}


def compare(baseline, current_cves, current_findings=None):
    result = {
        'baseline_date': (baseline.get('metadata') or {}).get('generation_date', ''),
        'cves': compare_cves(baseline.get('cves', []), current_cves),
    }
    baseline_findings = baseline.get('findings')
    if baseline_findings is not None and current_findings is not None:
        result['findings'] = compare_findings(baseline_findings, current_findings)
    return result


def summary_counts(changes):
    counts = {}
    for change in changes['cves']:
        counts[change['change']] = counts.get(change['change'], 0) + 1
    return counts


def print_changes(changes, limit=30):
    baseline_date = changes.get('baseline_date') or 'baseline'
    cve_changes = changes['cves']
    findings = changes.get('findings')
    click.echo(f"\nChanges since {baseline_date}")
    if not cve_changes and not (findings and (findings['new'] or findings['fixed'])):
        click.echo("No changes.")
        return

    counts = summary_counts(changes)
    parts = [f"{counts[kind]} {label}" for kind, label in CHANGE_TYPES.items() if counts.get(kind)]
    if findings:
        parts.append(f"{len(findings['new'])} new host findings")
        parts.append(f"{len(findings['fixed'])} host findings fixed")
    click.echo(", ".join(parts))

    if cve_changes:
        width = max(len(label) for label in CHANGE_TYPES.values()) + 2
        click.echo(f"{'CHANGE':<{width}}{'CVE-ID':<18}{'PRIORITY':<10}DETAIL")
        click.echo("-" * (width + 60))
        for change in cve_changes[:limit]:
            click.echo(f"{CHANGE_TYPES[change['change']]:<{width}}{change['cve_id']:<18}{change['priority']:<10}"
                       f"{change['detail']}")
        if len(cve_changes) > limit:
            click.echo(f"... and {len(cve_changes) - limit} more (see the JSON output)")
