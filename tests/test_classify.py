import pytest

from scripts.helpers import PRIORITY_LABELS, classify, to_float

CVSS_T = 6.0
EPSS_T = 0.2


@pytest.mark.parametrize("cvss, epss, kev, attacked, expected", [
    # Known exploitation always wins, even with low or missing scores
    (2.0, 0.01, True, False, 'P1+'),
    (2.0, 0.01, False, True, 'P1+'),
    ("", None, True, False, 'P1+'),
    # The four CVSS x EPSS quadrants
    (9.8, 0.9, False, False, 'P1'),
    (9.8, 0.01, False, False, 'P2'),
    (3.1, 0.9, False, False, 'P3'),
    (3.1, 0.01, False, False, 'P4'),
    # Thresholds are inclusive
    (6.0, 0.2, False, False, 'P1'),
    # Missing data is reported, not dropped (previously raised TypeError and vanished)
    ("", 0.9, False, False, 'UNSCORED'),
    (9.8, None, False, False, 'UNSCORED'),
    (None, None, "", "", 'UNSCORED'),
])
def test_classify(cvss, epss, kev, attacked, expected):
    assert classify(cvss, epss, kev, attacked, CVSS_T, EPSS_T) == expected


def test_every_code_has_a_label():
    codes = {'P1+', 'P1', 'P2', 'P3', 'P4', 'UNSCORED'}
    assert codes == set(PRIORITY_LABELS)


@pytest.mark.parametrize("value, expected", [
    (7.5, 7.5), ("7.5", 7.5), (0, 0.0), ("", None), (None, None), ("N/A", None), (True, None),
])
def test_to_float(value, expected):
    assert to_float(value) == expected
