from __future__ import annotations
import asyncio
import json
import shutil
import sys
from pathlib import Path

import httpx

from ..models import Confidence, Finding, Identifier, IdentifierType
from .base import Source


class MaigretSource(Source):
    """Username sweep across 3000+ sites via the `maigret` CLI (pipx install maigret)."""
    name = "maigret"
    handles = {IdentifierType.USERNAME}

    async def query(self, identifier: Identifier, client: httpx.AsyncClient):
        # Prefer a normal PATH installation, but also support the executable
        # installed into this project's virtual environment.
        executable = shutil.which("maigret")
        local_executable = Path(sys.executable).with_name("maigret.exe")
        if not executable and local_executable.is_file():
            executable = str(local_executable)
        if not executable:
            return []
        proc = await asyncio.create_subprocess_exec(
            executable, identifier.value, "--json", "-", "--timeout", "15",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        try:
            data = json.loads(out.decode() or "{}")
        except json.JSONDecodeError:
            return []
        findings = []
        for site, info in data.items():
            status = info.get("status", {})
            if status.get("status") == "Exist":
                f = Finding(source=f"maigret:{site}", identifier=identifier,
                            confidence=Confidence.VERIFIED,
                            url=status.get("url"), details=info)
                findings.append(f)
        return findings


class SocialscanSource(Source):
    """Email+username availability across ~15 major platforms via `socialscan`."""
    name = "socialscan"
    handles = {IdentifierType.EMAIL, IdentifierType.USERNAME}

    async def query(self, identifier: Identifier, client: httpx.AsyncClient):
        if not shutil.which("socialscan"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "socialscan", identifier.value, "--json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        try:
            data = json.loads(out.decode() or "[]")
        except json.JSONDecodeError:
            return []
        results = data if isinstance(data, list) else data.get("results", [])
        return [Finding(source=f"socialscan:{r.get('platform')}", identifier=identifier,
                        confidence=Confidence.VERIFIED if r.get("registered") else Confidence.UNSURE,
                        url=r.get("profile_url"), details=r)
                for r in results if r.get("registered")]
