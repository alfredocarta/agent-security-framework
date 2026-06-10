import json
import os
import subprocess
import sys
from pathlib import Path


WORKER = Path(__file__).resolve().parents[1] / "wrapper" / "asf_file_worker.py"
HERMES_ROOT = Path.home() / ".hermes" / "hermes-agent"


def run_worker(tmp_path, tool, args, **kwargs):
    env = os.environ.copy()
    env["ASF_HERMES_SANDBOX_WORKDIR"] = str(tmp_path)
    env["ASF_HERMES_AGENT_ROOT"] = str(HERMES_ROOT)
    proc = subprocess.run(
        [sys.executable, str(WORKER), json.dumps({"tool": tool, "args": args, "kwargs": kwargs})],
        cwd=tmp_path,
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


def test_worker_read_and_search_match_native_shape(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("alpha\nbeta\n", encoding="utf-8")

    worker_read = run_worker(tmp_path, "read_file", {"path": str(sample), "offset": 1, "limit": 1}, task_id="worker-read")
    native_read = native_dispatch("read_file", {"path": str(sample), "offset": 1, "limit": 1}, task_id="native-read")
    assert worker_read.keys() == native_read.keys()
    assert worker_read["content"] == native_read["content"]
    assert worker_read["total_lines"] == native_read["total_lines"]

    worker_search = run_worker(tmp_path, "search_files", {"pattern": "alpha", "path": str(tmp_path), "limit": 10}, task_id="worker-search")
    native_search = native_dispatch("search_files", {"pattern": "alpha", "path": str(tmp_path), "limit": 10}, task_id="native-search")
    assert worker_search.keys() == native_search.keys()
    assert worker_search["total_count"] == native_search["total_count"]
    assert worker_search["matches"][0].keys() == native_search["matches"][0].keys()


def test_worker_write_inside_workdir_succeeds_and_outside_rejected(tmp_path):
    inside = tmp_path / "inside.txt"
    out = run_worker(tmp_path, "write_file", {"path": str(inside), "content": "ok\n"})
    assert out["bytes_written"] == 3
    assert inside.read_text(encoding="utf-8") == "ok\n"

    outside = tmp_path.parent / "outside-worker-denied.txt"
    out = run_worker(tmp_path, "write_file", {"path": str(outside), "content": "no"})
    assert "error" in out
    assert "outside WORKDIR" in out["error"]
    assert not outside.exists()


def test_worker_patch_outside_and_symlink_escape_rejected(tmp_path):
    outside = tmp_path.parent / "outside-patch-denied.txt"
    outside.write_text("old\n", encoding="utf-8")
    out = run_worker(tmp_path, "patch", {"mode": "replace", "path": str(outside), "old_string": "old", "new_string": "new"})
    assert "outside WORKDIR" in out["error"]
    assert outside.read_text(encoding="utf-8") == "old\n"

    target = tmp_path.parent / "symlink-target.txt"
    target.write_text("old\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    out = run_worker(tmp_path, "write_file", {"path": str(link), "content": "escape"})
    assert "error" in out
    assert "outside WORKDIR" in out["error"] or "symlink" in out["error"]
    assert target.read_text(encoding="utf-8") == "old\n"


def test_worker_patch_inside_workdir_succeeds(tmp_path):
    path = tmp_path / "edit.txt"
    path.write_text("hello old\n", encoding="utf-8")
    out = run_worker(tmp_path, "patch", {"mode": "replace", "path": str(path), "old_string": "old", "new_string": "new"})
    assert out["success"] is True
    assert "diff" in out
    assert path.read_text(encoding="utf-8") == "hello new\n"
