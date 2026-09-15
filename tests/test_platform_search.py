from ossint.orchestrator import PLATFORM_DOMAINS, Orchestrator


def test_all_platform_mode_creates_one_dork_source_per_platform():
    orchestrator = Orchestrator(platform="all")
    dork_sources = [source for source in orchestrator.sources
                    if source.name.startswith("serper:")]
    assert len(dork_sources) == len(PLATFORM_DOMAINS)
    assert {source.site for source in dork_sources} == set(PLATFORM_DOMAINS)
