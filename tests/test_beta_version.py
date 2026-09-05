"""Current Beta distribution identity remains consistent across public surfaces."""

from __future__ import annotations

import inspect
import tomllib
from pathlib import Path

from fetech.adapters.browser import BrowserAdapter
from fetech.adapters.reader import ReaderAdapter
from fetech.browser_worker import DEFAULT_USER_AGENT as WORKER_USER_AGENT
from fetech.config import Settings
from fetech.daemon import create_app
from fetech.search import HTTPSearchProvider
from fetech.version import DEFAULT_USER_AGENT, __version__

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.5.0b1"


def test_beta_distribution_identity_is_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    editable_fetech = [
        package
        for package in lock["package"]
        if package.get("name") == "fetech" and package.get("source") == {"editable": "."}
    ]

    assert project["version"] == EXPECTED_VERSION
    assert "Development Status :: 4 - Beta" in project["classifiers"]
    assert [package["version"] for package in editable_fetech] == [EXPECTED_VERSION]
    assert __version__ == EXPECTED_VERSION
    assert create_app().openapi()["info"]["version"] == EXPECTED_VERSION


def test_default_outbound_identity_matches_beta_version() -> None:
    assert DEFAULT_USER_AGENT.startswith(f"Fetech/{EXPECTED_VERSION} ")
    assert Settings.__dataclass_fields__["user_agent"].default == DEFAULT_USER_AGENT
    assert (
        inspect.signature(BrowserAdapter).parameters["user_agent"].default
        == DEFAULT_USER_AGENT
    )
    assert (
        inspect.signature(ReaderAdapter).parameters["user_agent"].default
        == DEFAULT_USER_AGENT
    )
    assert (
        inspect.signature(HTTPSearchProvider).parameters["user_agent"].default
        == DEFAULT_USER_AGENT
    )
    assert WORKER_USER_AGENT == DEFAULT_USER_AGENT
