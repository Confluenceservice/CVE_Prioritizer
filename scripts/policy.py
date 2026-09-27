#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.10.2"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

# Scoring policy: the organisation-specific parts of prioritisation, loaded from a YAML file
# (--policy). Without a policy file every default below reproduces the tool's standard behaviour.
#
# Validation is strict on purpose: a typo such as "thresold:" is an error, not a silently ignored
# key that leaves the defaults in place.

import copy
from datetime import date, timedelta

# Scored priorities from lowest to highest. P1+ is reserved for exploitation evidence, so
# escalation rules never produce it.
LADDER = ['P4', 'P3', 'P2', 'P1']
PRIORITIES = ('P1+', 'P1', 'P2', 'P3', 'P4', 'UNSCORED')

DEFAULT_POLICY = {
    'thresholds': {'cvss': 6.0, 'epss': 0.2},
    # Which evidence of real-world exploitation makes a CVE P1+
    'exploitation': {'kev': True, 'cvss4_attacked': True, 'ssvc_active': True},
    # Minimum priority when a signal is present, e.g. {"public_exploit": "P1"}. Off by default.
    'minimum_priority': {'public_exploit': None, 'epss_rising': None, 'ssvc_poc': None},
    # Raise a finding's priority by N levels based on its host. Off by default.
    'host_escalation': {'internet_facing': 0, 'criticality': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}},
    # Days to fix per priority; adds a due_date to results. Off by default.
    'sla_days': {},
}

_MIN_PRIORITY_VALUES = ('P1', 'P2', 'P3')

_policy = copy.deepcopy(DEFAULT_POLICY)


class PolicyError(ValueError):
    pass


def _check_keys(section, data, allowed):
    if not isinstance(data, dict):
        raise PolicyError(f"'{section}' must be a mapping")
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise PolicyError(f"unknown key(s) in '{section}': {', '.join(map(str, unknown))} "
                          f"(allowed: {', '.join(allowed)})")


def _number(section, key, value, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= value <= maximum:
        raise PolicyError(f"'{section}.{key}' must be a number from {minimum} to {maximum}, got {value!r}")
    return float(value)


def _levels(section, key, value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= len(LADDER) - 1:
        raise PolicyError(f"'{section}.{key}' must be a whole number of levels from 0 to {len(LADDER) - 1}, "
                          f"got {value!r}")
    return value


def validate(data):
    """
    Returns a complete policy (defaults filled in) from parsed YAML, or raises PolicyError
    with a message naming the offending key.
    """
    policy = copy.deepcopy(DEFAULT_POLICY)
    if data is None:
        return policy
    _check_keys('policy', data, list(DEFAULT_POLICY))

    thresholds = data.get('thresholds', {})
    _check_keys('thresholds', thresholds, ['cvss', 'epss'])
    if 'cvss' in thresholds:
        policy['thresholds']['cvss'] = _number('thresholds', 'cvss', thresholds['cvss'], 0, 10)
    if 'epss' in thresholds:
        policy['thresholds']['epss'] = _number('thresholds', 'epss', thresholds['epss'], 0, 1)

    exploitation = data.get('exploitation', {})
    _check_keys('exploitation', exploitation, list(DEFAULT_POLICY['exploitation']))
    for key, value in exploitation.items():
        if not isinstance(value, bool):
            raise PolicyError(f"'exploitation.{key}' must be true or false, got {value!r}")
        policy['exploitation'][key] = value

    minimum = data.get('minimum_priority', {})
    _check_keys('minimum_priority', minimum, list(DEFAULT_POLICY['minimum_priority']))
    for key, value in minimum.items():
        if value is not None and value not in _MIN_PRIORITY_VALUES:
            raise PolicyError(f"'minimum_priority.{key}' must be one of {', '.join(_MIN_PRIORITY_VALUES)} "
                              f"or empty, got {value!r}")
        policy['minimum_priority'][key] = value

    escalation = data.get('host_escalation', {})
    _check_keys('host_escalation', escalation, ['internet_facing', 'criticality'])
    if 'internet_facing' in escalation:
        policy['host_escalation']['internet_facing'] = _levels('host_escalation', 'internet_facing',
                                                               escalation['internet_facing'])
    criticality = escalation.get('criticality', {})
    _check_keys('host_escalation.criticality', criticality, list(DEFAULT_POLICY['host_escalation']['criticality']))
    for key, value in criticality.items():
        policy['host_escalation']['criticality'][key] = _levels('host_escalation.criticality', key, value)

    sla = data.get('sla_days', {})
    _check_keys('sla_days', sla, list(PRIORITIES))
    for key, value in sla.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PolicyError(f"'sla_days.{key}' must be a whole number of days, got {value!r}")
        policy['sla_days'][key] = value

    return policy


def load(path):
    import yaml  # only needed when a policy file is used

    with open(path) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as err:
            raise PolicyError(f"invalid YAML: {err}")
    return validate(data)


def configure(policy=None):
    """Called once from the CLI before any worker starts; None restores the defaults."""
    global _policy
    _policy = copy.deepcopy(policy) if policy else copy.deepcopy(DEFAULT_POLICY)


def current():
    return _policy


def raise_priority(priority, levels):
    """
    Moves a scored priority up the ladder P4 -> P3 -> P2 -> P1, stopping at P1.
    P1+ and UNSCORED are left alone.
    """
    if levels <= 0 or priority not in LADDER:
        return priority
    return LADDER[min(LADDER.index(priority) + levels, len(LADDER) - 1)]


def _at_least(priority, minimum):
    if priority == 'P1+':
        return priority
    if priority == 'UNSCORED':
        # A strong signal is enough to act on even before CVSS/EPSS exist
        return minimum
    return minimum if LADDER.index(minimum) > LADDER.index(priority) else priority


_SIGNAL_LABELS = {
    'public_exploit': 'public exploit',
    'epss_rising': 'rising EPSS',
    'ssvc_poc': 'CISA SSVC proof-of-concept',
}


def apply_minimums(priority, signals, policy=None):
    """
    signals: {"public_exploit": bool, "epss_rising": bool, "ssvc_poc": bool}
    Returns (priority, notes) where notes explain any policy raise for the reason text.
    """
    policy = policy or _policy
    notes = []
    for key, minimum in policy['minimum_priority'].items():
        if minimum and signals.get(key):
            raised = _at_least(priority, minimum)
            if raised != priority:
                notes.append(f"raised to {raised} by policy ({_SIGNAL_LABELS[key]})")
                priority = raised
    return priority, notes


def host_escalation(priority, internet_facing, criticality, policy=None):
    """
    Finding-level priority: the CVE priority raised for the host it sits on.
    Returns (priority, note or '').
    """
    policy = policy or _policy
    rules = policy['host_escalation']
    levels = 0
    why = []
    if internet_facing and rules['internet_facing']:
        levels += rules['internet_facing']
        why.append('internet-facing')
    if criticality and rules['criticality'].get(criticality):
        levels += rules['criticality'][criticality]
        why.append(f'{criticality} criticality')
    raised = raise_priority(priority, levels)
    if raised == priority:
        return priority, ''
    return raised, f"raised {priority} -> {raised} by policy ({', '.join(why)})"


def due_date(priority, start=None, policy=None):
    """ISO date by which the policy's SLA says to fix this priority, or '' when there is no SLA."""
    policy = policy or _policy
    days = policy['sla_days'].get(priority)
    if days is None:
        return ''
    return ((start or date.today()) + timedelta(days=days)).isoformat()
