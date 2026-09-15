import json
import time

from ossint.cache import Cache
from ossint.models import Confidence, Finding, Identifier, IdentifierType


def make_finding():
    return Finding(
        source="test-source",
        identifier=Identifier(IdentifierType.EMAIL, "jane@example.com"),
        confidence=Confidence.VERIFIED,
        url="https://example.com",
        details={"note": "hi"},
        pivots=[Identifier(IdentifierType.USERNAME, "janedoe")],
    )


class TestCache:
    def test_miss_on_empty_cache(self, tmp_path):
        cache = Cache(path=tmp_path / "cache.json")
        assert cache.get("some:key", ttl=3600) is None

    def test_set_then_get_round_trips(self, tmp_path):
        cache = Cache(path=tmp_path / "cache.json")
        f = make_finding()
        cache.set("email:jane@example.com", [f.to_dict()])
        result = cache.get("email:jane@example.com", ttl=3600)
        assert result is not None
        restored = Finding.from_dict(result[0])
        assert restored.source == f.source
        assert restored.identifier == f.identifier
        assert restored.pivots[0] == f.pivots[0]

    def test_expired_entry_returns_none(self, tmp_path):
        cache = Cache(path=tmp_path / "cache.json")
        cache.set("k", [{"x": 1}])
        # ttl=0 means "expired immediately" for any positive age
        time.sleep(0.01)
        assert cache.get("k", ttl=0.001) is None

    def test_ttl_zero_always_disabled(self, tmp_path):
        cache = Cache(path=tmp_path / "cache.json")
        cache.set("k", [{"x": 1}])
        assert cache.get("k", ttl=0) is None

    def test_persists_to_disk(self, tmp_path):
        path = tmp_path / "cache.json"
        cache = Cache(path=path)
        cache.set("k", [{"x": 1}])
        assert path.exists()
        on_disk = json.loads(path.read_text())
        assert "k" in on_disk

    def test_creates_parent_directory_and_persists_atomically(self, tmp_path):
        path = tmp_path / "nested" / "cache.json"
        Cache(path=path).set("k", [{"x": 1}])
        assert json.loads(path.read_text())["k"]["value"] == [{"x": 1}]

    def test_reloads_from_disk_across_instances(self, tmp_path):
        path = tmp_path / "cache.json"
        Cache(path=path).set("k", [{"x": 1}])
        second = Cache(path=path)
        assert second.get("k", ttl=3600) == [{"x": 1}]

    def test_clear_empties_cache(self, tmp_path):
        cache = Cache(path=tmp_path / "cache.json")
        cache.set("k", [{"x": 1}])
        cache.clear()
        assert cache.get("k", ttl=3600) is None

    def test_corrupt_cache_file_starts_fresh(self, tmp_path):
        path = tmp_path / "cache.json"
        path.write_text("{not valid json")
        cache = Cache(path=path)
        assert cache.get("anything", ttl=3600) is None
