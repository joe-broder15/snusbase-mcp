import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
PROJECT_PATH = ROOT / "pyproject.toml"
AGENTS_PATH = ROOT / "AGENTS.md"

_REQUIRES_PYTHON = re.compile(r'(?m)^requires-python\s*=\s*"([^"]+)"')


def _agents_text() -> str:
    assert AGENTS_PATH.is_file(), "AGENTS.md is missing"
    return AGENTS_PATH.read_text()


def test_agents_md_quotes_every_ci_run_step() -> None:
    run_lines = [line.strip() for line in CI_PATH.read_text().splitlines() if "run:" in line]
    assert run_lines, "ci.yml has no run: line"
    agents = _agents_text()
    for line in run_lines:
        assert line.startswith("- run:"), line
        command = line.removeprefix("- run:").strip()
        assert command
        assert command in agents


def test_agents_md_quotes_requires_python() -> None:
    match = _REQUIRES_PYTHON.search(PROJECT_PATH.read_text())
    assert match is not None, "pyproject.toml has no requires-python"
    assert match.group(1) in _agents_text()
