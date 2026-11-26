from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable

import pytest
import yaml

from aof.platform import PlatformConfig, load_platform

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "refunds-assistant"


@pytest.fixture
def platform() -> PlatformConfig:
    return load_platform()


@pytest.fixture
def example(tmp_path: Path) -> Path:
    dest = tmp_path / "refunds-assistant"
    shutil.copytree(EXAMPLE, dest)
    return dest


@pytest.fixture
def edit_yaml() -> Callable[[Path, Callable[[dict], None]], None]:
    def _edit(path: Path, fn: Callable[[dict], None]) -> None:
        data = yaml.safe_load(path.read_text())
        fn(data)
        path.write_text(yaml.safe_dump(data, sort_keys=False))

    return _edit


def codes(findings) -> set[str]:
    return {f.code for f in findings if f.severity.value == "error"}
