import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from .models import Identifier, IdentifierType
from .normalizers import looks_like_domain, normalize_domain, normalize_email, normalize_phone
from .orchestrator import Orchestrator
from .reporting import render_markdown

try:
    from dotenv import load_dotenv
    load_dotenv()  # picks up .env in the current directory, if present
except ImportError:
    pass  # python-dotenv not installed — env vars still work if set some other way


_PHONE_PUNCTUATION = str.maketrans("", "", "+-.() \t")


def _looks_like_phone(raw: str) -> bool:
    """Digits plus common phone punctuation (spaces, dashes, parens, dots),
    with a plausible digit count — not just a bare numeric string."""
    stripped = raw.translate(_PHONE_PUNCTUATION)
    return stripped.isdigit() and 7 <= len(stripped) <= 15


def coerce(raw: str, forced_type: str | None = None) -> Identifier:
    raw = raw.strip()
    if forced_type:
        builders = {
            "email": normalize_email, "phone": normalize_phone,
            "domain": normalize_domain,
            "name": lambda v: Identifier(IdentifierType.NAME, v.title()),
            "username": lambda v: Identifier(IdentifierType.USERNAME, v.lower()),
        }
        return builders[forced_type](raw)
    if "@" in raw:
        return normalize_email(raw)
    if _looks_like_phone(raw):
        return normalize_phone(raw)
    if any(c in raw for c in " \t"):
        return Identifier(IdentifierType.NAME, raw.title())
    if looks_like_domain(raw):
        return normalize_domain(raw)
    return Identifier(IdentifierType.USERNAME, raw.lower())


def parse_args(argv: list) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m osint",
        description="Pivot an identifier (email, phone, name, username, or domain) "
                    "across OSINT sources and build a correlation report.",
    )
    p.add_argument("identifier", nargs="+",
                  help="the seed identifier, e.g. an email, phone number, name, username, or domain")
    p.add_argument("--type", choices=["email", "phone", "name", "username", "domain"],
                  default=None,
                  help="force how the identifier is interpreted instead of auto-detecting "
                       "(useful for ambiguous values like 'jane.doe')")
    p.add_argument("--max-depth", type=int, default=2,
                  help="how many pivot hops to follow from the seed (default: 2)")
    p.add_argument("--sources", default=None,
                  help="comma-separated list of source names to use, e.g. 'github,hibp' "
                       "(default: all enabled sources)")
    p.add_argument("--exclude-sources", default=None,
                  help="comma-separated list of source names to skip")
    p.add_argument("--platform", default=None,
                  help="restrict the search-engine dork source to a specific site, e.g. 'linkedin.com'")
    p.add_argument("--proxy", default=None,
                  help="proxy URL for outbound requests (overrides OSINT_PROXY env var)")
    p.add_argument("--output", default=None,
                  help="output file path prefix (default: 'report_<identifier-type>')")
    p.add_argument("--no-cache", action="store_true",
                  help="bypass the result cache for this run (same as OSINT_NO_CACHE=1)")
    p.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    return p.parse_args(argv)


def main(argv: list | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.no_cache:
        os.environ["OSINT_NO_CACHE"] = "1"

    try:
        ident = coerce(" ".join(args.identifier), args.type)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    include = set(args.sources.split(",")) if args.sources else None
    exclude = set(args.exclude_sources.split(",")) if args.exclude_sources else None

    orch = Orchestrator(max_depth=args.max_depth, proxy=args.proxy,
                        platform=args.platform, include_sources=include,
                        exclude_sources=exclude)
    graph = asyncio.run(orch.run(ident))

    prefix = args.output or f"report_{ident.type.value}"
    out = Path(f"{prefix}.md")
    out.write_text(render_markdown(graph))
    graph.save(f"{prefix}.gml")
    print(f"[+] report: {out}")
    print(f"[+] graph:  {prefix}.gml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
