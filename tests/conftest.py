import pytest

from scripts import helpers


@pytest.fixture(autouse=True)
def reset_kev_cache():
    """Each test starts with an empty CISA KEV cache."""
    helpers._kev_cache = None
    yield
    helpers._kev_cache = None
