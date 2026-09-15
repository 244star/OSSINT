import base64

from webapp.server import _basic_auth_valid


def _header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def test_basic_auth_accepts_matching_credentials():
    assert _basic_auth_valid(_header("analyst", "secret"), "analyst", "secret")


def test_basic_auth_rejects_wrong_or_malformed_credentials():
    assert not _basic_auth_valid(_header("analyst", "wrong"), "analyst", "secret")
    assert not _basic_auth_valid("Basic not-base64", "analyst", "secret")
    assert not _basic_auth_valid(None, "analyst", "secret")
