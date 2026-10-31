import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
PROJECT_PATH = ROOT / "pyproject.toml"
AGENTS_PATH = ROOT / "AGENTS.md"

_RUN_STEP = re.compile(r"(?m)^[ \t]*(?:-[ \t]*)?run:[ \t]*(.+?)\s*$")
_REQUIRES_PYTHON = re.compile(r'(?m)^requires-python\s*=\s*"([^"]+)"')


def _agents_text() -> str:
    assert AGENTS_PATH.is_file(), "AGENTS.md is missing"
    return AGENTS_PATH.read_text()


def test_agents_md_quotes_every_ci_run_step() -> None:
    steps = _RUN_STEP.findall(CI_PATH.read_text())
    assert steps, "ci.yml has no run steps"
    agents = _agents_text()
    missing = [step for step in steps if step not in agents]
    assert missing == []


def test_agents_md_quotes_requires_python() -> None:
    match = _REQUIRES_PYTHON.search(PROJECT_PATH.read_text())
    assert match is not None, "pyproject.toml has no requires-python"
    assert match.group(1) in _agents_text()
