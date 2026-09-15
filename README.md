# OSSINT

OSSINT searches public sources for relationships between emails, phone
numbers, usernames, names, and domains. Use it only for authorized
investigations and respect the terms and rate limits of every source.

## Installation

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Optional integrations are enabled when their dependencies and credentials are
available. Copy `.env.example` to `.env` and fill in only the services you
intend to use.

## Command line

```powershell
python -m ossint "jane.doe@example.com"
python -m ossint --type username jdoe --sources github,reddit
python -m ossint --max-depth 1 --output reports\jane "Jane Doe"
```

The CLI writes a Markdown report and a GML graph using the selected output
prefix. Use `--no-cache` to bypass cached source results for one run.

## Web application

```powershell
python run_web.py
```

Open <http://127.0.0.1:8000>. Reports are stored under `reports/`, which is
ignored by Git. The development server binds to localhost by default. Before
exposing it to a network, set `OSSINT_WEB_USERNAME` and
`OSSINT_WEB_PASSWORD`, or put an authenticated reverse proxy in front of it.
If only one credential is configured, requests fail closed with HTTP 503.

## Configuration

Supported environment variables are documented in `.env.example`, including:

- `HIBP_API_KEY` and `SERPER_API_KEY` for API-backed sources
- `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` for Telegram phone lookups
- `OSSINT_PROXY` for an outbound HTTP/SOCKS proxy
- `OSSINT_CACHE_PATH`, `OSSINT_CACHE_TTL`, and `OSSINT_NO_CACHE` for caching
- `OSSINT_WEB_USERNAME` and `OSSINT_WEB_PASSWORD` for optional web auth
- `OSSINT_WEB_RATE_LIMIT`, `OSSINT_WEB_RATE_WINDOW`, and
  `OSSINT_WEB_MAX_CONCURRENT` for inbound search limits

External CLI sources require `maigret` and/or `socialscan` on `PATH`.
Install those optional integrations with:

```powershell
python -m pip install -r requirements-optional.txt
```

## Testing

```powershell
python -m pytest -q
```

The test suite covers normalization, identifier coercion, confidence
classification, and cache persistence.
