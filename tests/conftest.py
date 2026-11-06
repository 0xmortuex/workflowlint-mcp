"""Shared helpers: real files in a temp dir, linted through the real code path."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
GOOD_REPO = os.path.join(FIXTURES, "good_repo")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
