import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest


WORKER = Path(__file__).resolve().parents[1] / "wrapper" / "asf_file_worker.py"
HERMES_ROOT = Path.home() / ".hermes" / "hermes-agent"


@pytest.fixture(scope="function")
def users_tmp_workdir() -> Generator[Path, None, None]:
    """Create a temporary workdir under the user's home directory.

    This ensures the native Hermes file tools accept it (they reject /private/var
    paths on macOS). The directory is cleaned up after the test.
    """
    workdir = Path(tempfile.mkdtemp(dir=Path.home(), prefix="asf-test-"))
    try:
        yield workdir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_worker(workdir: Path, tool, args, **kwargs):
    env = os.environ.copy()
    env["ASF_HERMES_SANDBOX_WORKDIR"] = str(workdir)
    env["ASF_HERMES_AGENT_ROOT"] = str(HERMES_ROOT)
    proc = subprocess.run(
        [sys.executable, str(WORKER), json.dumps({"tool": tool, "args": args, "kwargs": kwargs})],
        cwd=workdir,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def native_dispatch(tool, args, **kwargs):
    sys.path.insert(0, str(HERMES_ROOT))
    import tools.file_tools  # type: ignore[import-not-found]  # noqa: F401
    from tools.registry import registry  # type: ignore[import-not-found]

    return json.loads(registry.dispatch(tool, args, **kwargs))


def test_worker_read_and_search_match_native_shape(users_tmp_workdir: Path):
    """Test that read_file and search_files from worker match native dispatch."""
    sample = users_tmp_workdir / "sample.txt"
    sample.write_text("alpha\nbeta\n", encoding="utf-8")

    worker_read = run_worker(users_tmp_workdir, "read_file", {"path": str(sample), "offset": 1, "limit": 1}, task_id="worker-read")
    native_read = native_dispatch("read_file", {"path": str(sample), "offset": 1, "limit": 1}, task_id="native-read")
    assert worker_read.keys() == native_read.keys()
    assert worker_read["content"] == native_read["content"]
    assert worker_read["total_lines"] == native_read["total_lines"]

    worker_search = run_worker(users_tmp_workdir, "search_files", {"pattern": "alpha", "path": str(users_tmp_workdir), "limit": 10}, task_id="worker-search")
    native_search = native_dispatch("search_files", {"pattern": "alpha", "path": str(users_tmp_workdir), "limit": 10}, task_id="native-search")
    assert worker_search.keys() == native_search.keys()
    assert worker_search["total_count"] == native_search["total_count"]
    assert worker_search["matches"][0].keys() == native_search["matches"][0].keys()


def test_worker_write_parity_with_native(users_tmp_workdir: Path):
    """Test write_file worker output has same shape as native and file is written."""
    inside = users_tmp_workdir / "inside.txt"

    # Run worker write
    worker_out = run_worker(users_tmp_workdir, "write_file", {"path": str(inside), "content": "hello world\n"})

    # Run native dispatch for the same operation
    native_out = native_dispatch("write_file", {"path": str(inside), "content": "hello world\n"})

    # Assert same keys/shape
    assert set(worker_out.keys()) == set(native_out.keys())
    assert worker_out["bytes_written"] == native_out["bytes_written"]

    # Assert file was actually written
    assert inside.exists()
    assert inside.read_text(encoding="utf-8") == "hello world\n"


def test_worker_write_outside_rejected(users_tmp_workdir: Path):
    """Test that writes outside WORKDIR are rejected."""
    outside = users_tmp_workdir.parent / "outside-worker-denied.txt"
    out = run_worker(users_tmp_workdir, "write_file", {"path": str(outside), "content": "no"})
    assert "error" in out
    assert "outside WORKDIR" in out["error"]
    assert not outside.exists()


def test_worker_patch_replace_parity_with_native(users_tmp_workdir: Path):
    """Test patch (replace mode) worker output has same shape as native."""
    path = users_tmp_workdir / "edit.txt"
    path.write_text("hello old\n", encoding="utf-8")

    # Run worker patch
    worker_out = run_worker(users_tmp_workdir, "patch", {
        "mode": "replace",
        "path": str(path),
        "old_string": "old",
        "new_string": "new"
    })

    # Reset file for native test
    path.write_text("hello old\n", encoding="utf-8")

    # Run native dispatch for the same operation
    native_out = native_dispatch("patch", {
        "mode": "replace",
        "path": str(path),
        "old_string": "old",
        "new_string": "new"
    })

    # Assert same keys/shape
    assert set(worker_out.keys()) == set(native_out.keys())
    assert worker_out["success"] is True
    assert "diff" in worker_out
    assert "files_modified" in worker_out

    # Assert the edit was applied
    assert path.read_text(encoding="utf-8") == "hello new\n"


def test_worker_patch_v4a_parity_with_native(users_tmp_workdir: Path):
    """Test patch (v4a mode) worker output has same shape as native."""
    path = users_tmp_workdir / "v4a_edit.txt"
    original_content = "line one\nline two\nline three\n"
    path.write_text(original_content, encoding="utf-8")

    patch_content = f"""*** Update File: {path}
@@ @@
-line two
+line TWO
"""

    # Run worker patch (v4a mode)
    worker_out = run_worker(users_tmp_workdir, "patch", {
        "mode": "patch",
        "patch": patch_content
    })

    # Reset file for native test
    path.write_text(original_content, encoding="utf-8")

    # Run native dispatch for the same operation
    native_out = native_dispatch("patch", {
        "mode": "patch",
        "patch": patch_content
    })

    # Assert same keys/shape
    assert set(worker_out.keys()) == set(native_out.keys())
    assert worker_out["success"] is True
    assert "diff" in worker_out
    assert "files_modified" in worker_out

    # Assert the edit was applied
    assert path.read_text(encoding="utf-8") == "line one\nline TWO\nline three\n"


def test_worker_patch_outside_rejected(users_tmp_workdir: Path):
    """Test that patch outside WORKDIR is rejected."""
    outside = users_tmp_workdir.parent / "outside-patch-denied.txt"
    outside.write_text("old\n", encoding="utf-8")
    out = run_worker(users_tmp_workdir, "patch", {
        "mode": "replace",
        "path": str(outside),
        "old_string": "old",
        "new_string": "new"
    })
    assert "outside WORKDIR" in out.get("error", "")
    assert outside.read_text(encoding="utf-8") == "old\n"


def test_worker_symlink_escape_rejected(users_tmp_workdir: Path):
    """Test that symlink escape attempts are rejected."""
    target = users_tmp_workdir.parent / "symlink-target.txt"
    target.write_text("old\n", encoding="utf-8")
    link = users_tmp_workdir / "link.txt"
    link.symlink_to(target)
    out = run_worker(users_tmp_workdir, "write_file", {"path": str(link), "content": "escape"})
    assert "error" in out
    assert "outside WORKDIR" in out["error"] or "symlink" in out["error"]
    assert target.read_text(encoding="utf-8") == "old\n"