from __future__ import annotations

import os
from pathlib import Path
from typing import MutableMapping

DEFAULT_SCRUB_ENV_VARS = frozenset(
    {
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROQ_API_KEY",
        "LANGFUSE_SECRET_KEY",
        "LANGFUSE_PUBLIC_KEY",
        "ASF_MASTER_KEY",
        "ASF_DASHBOARD_PASSWORD",
    }
)


def scrub_env_names(extra: str | None = None) -> set[str]:
    configured = extra if extra is not None else os.environ.get("ASF_SCRUB_ENV_VARS", "")
    names = set(DEFAULT_SCRUB_ENV_VARS)
    for item in configured.split(","):
        name = item.strip()
        if name:
            names.add(name)
    return names


def scrub_env(env: MutableMapping[str, str], extra: str | None = None) -> MutableMapping[str, str]:
    for name in scrub_env_names(extra):
        env.pop(name, None)
    return env


def scrubbed_environ(extra: str | None = None) -> dict[str, str]:
    return dict(scrub_env(os.environ.copy(), extra))


def persist_openrouter_key_file(env: MutableMapping[str, str], *, root: Path | None = None) -> None:
    """Move OPENROUTER_API_KEY out of child env and into an owner-only file for Stage 3.

    The child receives only ASF_OPENROUTER_API_KEY_FILE. The secret value is never re-exported.
    """
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        return
    if root is None:
        root = Path(os.environ.get("ASF_SECRET_DIR", Path.home() / ".cache" / "asf" / "secrets"))
    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    key_path = root / "openrouter_api_key"
    key_path.write_text(key, encoding="utf-8")
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    env["ASF_OPENROUTER_API_KEY_FILE"] = str(key_path)
