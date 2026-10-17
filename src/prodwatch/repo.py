"""Repo intake: accept a local path or git URL, return a working copy.

Also detects the repo's stack (languages, frameworks, Dockerfile, CI) so rules
can target what actually applies.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .models import StackInfo

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
    "dist", "build", ".next", ".eggs", "vendor", ".mypy_cache",
}
SOURCE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php"}


def is_url(source: str) -> bool:
    return re.match(r"^(https?://|git@|ssh://)", source.strip()) is not None


def ensure_repo(source: str, workdir: str | None = None) -> Path:
    """Return a local Path to the repo (cloning first if `source` is a URL)."""
    source = source.strip()
    if is_url(source):
        if shutil.which("git") is None:
            raise RuntimeError("git is not installed; cannot clone a URL")
        dest = Path(workdir or "/tmp") / "prodwatch-clone"
        if dest.exists():
            shutil.rmtree(dest)
        subprocess.run(
            ["git", "clone", "--depth", "1", source, str(dest)],
            check=True, capture_output=True, text=True,
        )
        return dest
    p = Path(source).expanduser().resolve()
    if not p.is_dir():
        raise ValueError(f"Not a directory: {source}")
    return p


def source_files(root: Path) -> list:
    """All source files worth analyzing, skipping deps/build/vendor dirs."""
    out = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix in SOURCE_EXTS:
            out.append(p)
    return sorted(out)


def read_text_safe(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _find_named(root: Path, names: set, maxdepth: int = 3) -> list:
    """Find files/dirs by name up to maxdepth levels deep (monorepo-aware)."""
    found = []
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if len(p.relative_to(root).parts) > maxdepth:
            continue
        if p.name in names:
            found.append(p)
    return sorted(found)


def detect_stack(root: Path) -> StackInfo:
    info = StackInfo()

    def manifests(*names: str) -> list:
        return [p for p in _find_named(root, set(names)) if p.is_file()]

    def blob(paths: list) -> str:
        text = ""
        for p in paths:
            text += read_text_safe(p) + "\n"
        return text.lower()

    # Python
    py = manifests("requirements.txt", "pyproject.toml", "setup.py", "Pipfile")
    if py:
        info.languages.append("python")
        deps = blob(py)
        for fw, keys in {
            "django": ["django"], "flask": ["flask"], "fastapi": ["fastapi"],
            "celery": ["celery"], "sqlalchemy": ["sqlalchemy"],
        }.items():
            if any(k in deps for k in keys):
                info.frameworks.append(fw)
        info.package_manager = "pip" if any(
            p.name == "requirements.txt" for p in py) else "poetry/pip"

    # Node
    pkgs = manifests("package.json")
    if pkgs:
        info.languages.append("javascript/typescript")
        info.package_manager = "npm"
        for p in pkgs:
            try:
                pkg = json.loads(read_text_safe(p))
            except (json.JSONDecodeError, AttributeError):
                continue
            deps = {**pkg.get("dependencies", {}),
                    **pkg.get("devDependencies", {})}
            for fw in ["express", "fastify", "nest", "next", "react", "koa",
                       "axios"]:
                if any(fw in d for d in deps) and fw not in info.frameworks:
                    info.frameworks.append(fw)

    if manifests("go.mod"):
        info.languages.append("go")
    if manifests("Cargo.toml"):
        info.languages.append("rust")
    if manifests("Gemfile"):
        info.languages.append("ruby")
    if manifests("pom.xml", "build.gradle"):
        info.languages.append("java")
    if manifests("composer.json"):
        info.languages.append("php")

    info.has_dockerfile = bool(manifests("Dockerfile"))
    info.has_ci = bool(_find_named(
        root, {".github", ".gitlab-ci.yml", "Jenkinsfile",
               ".circleci", "azure-pipelines.yml"}))
    for p in _find_named(root, {"app.py", "main.py", "server.py", "wsgi.py",
                                "server.js", "index.js", "app.js", "main.go"}):
        info.entry_points.append(p.relative_to(root).as_posix())
    return info
