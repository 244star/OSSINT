import pytest

from webapp.server import RequestRateLimiter


def test_rate_limiter_allows_limit_then_rejects_until_window_expires():
    limiter = RequestRateLimiter(limit=2, window=10)
    assert limiter.allow("client", now=100)
    assert limiter.allow("client", now=101)
    assert not limiter.allow("client", now=102)
    assert limiter.allow("client", now=110)


def test_rate_limiter_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        RequestRateLimiter(limit=0)
    with pytest.raises(ValueError):
        RequestRateLimiter(window=0)
