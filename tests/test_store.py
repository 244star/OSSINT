import json

from ossint.graph import CorrelationGraph
from ossint.models import Identifier, IdentifierType
from webapp.store import ReportStore


def test_create_persists_source_stats_and_delete_removes_report(tmp_path):
    store = ReportStore(tmp_path)
    report_id = store.create(
        Identifier(IdentifierType.EMAIL, "jane@example.com"),
        CorrelationGraph(),
        {"github": {"queries": 1, "findings": 0}},
    )

    saved = json.loads((tmp_path / f"{report_id}.json").read_text())
    assert saved["source_stats"]["github"]["queries"] == 1
    assert store.delete(report_id)
    assert store.load(report_id) is None


def test_load_returns_none_for_corrupt_report(tmp_path):
    store = ReportStore(tmp_path)
    (tmp_path / "0123456789ab.json").write_text("{invalid", encoding="utf-8")
    assert store.load("0123456789ab") is None
