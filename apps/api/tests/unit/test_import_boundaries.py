"""Smoke test for import-linter architectural boundaries.

This test invokes lint-imports via the venv binary and fails if any contract
is violated. It ensures pytest catches architectural drift even without the
full `uv run lint-imports` CLI step.

Note: The full `uv run lint-imports` check in CI is the authoritative gate.
This test is a belt-and-suspenders guard for local pytest runs.
"""

import subprocess
import sys
from pathlib import Path


def test_import_boundaries_clean() -> None:
    """Run lint-imports and assert all contracts pass."""
    # Use the lint-imports binary from the same venv that is running tests.
    venv_dir = Path(sys.executable).parent
    lint_imports_bin = venv_dir / "lint-imports"

    # apps/api root: this file is at apps/api/tests/unit/test_import_boundaries.py,
    # so the project root is three parents up.
    project_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(  # noqa: S603
        [str(lint_imports_bin)],
        capture_output=True,
        text=True,
        cwd=str(project_root),
    )
    if result.returncode != 0:
        pytest_fail_msg = (
            "import-linter found boundary violations:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        raise AssertionError(pytest_fail_msg)
