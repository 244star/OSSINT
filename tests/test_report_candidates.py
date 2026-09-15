from webapp.server import prepare_report


def test_report_groups_platform_candidates_and_linked_accounts():
    data = {
        "id": "0123456789ab",
        "seed": "username:jane",
        "created": 0,
        "graph": {
            "identifiers": [
                {"key": "username:jane", "type": "username", "value": "jane", "score": 2},
            ],
            "findings": [
                {"source": "web:github.com", "identifier": {
                    "key": "username:jane", "value": "jane"},
                 "confidence": "likely", "url": "https://github.com/jane", "details": {}},
                {"source": "web:instagram.com", "identifier": {
                    "key": "username:jane", "value": "jane"},
                 "confidence": "likely", "url": "https://instagram.com/jane", "details": {}},
            ],
            "pivots": [],
        },
    }
    report = prepare_report(data)
    assert {group["platform"] for group in report["platform_groups"]} == {
        "github.com", "instagram.com"}
    assert report["linked_accounts"] == [{
        "identifier": "jane",
        "platforms": ["github.com", "instagram.com"],
    }]
