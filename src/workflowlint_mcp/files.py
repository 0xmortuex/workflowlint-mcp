"""Sandboxed file access and workflow discovery.

Every path an agent supplies is resolved (symlinks included) and must stay inside the --dir
root. Files are size-capped and must be UTF-8.
"""

from __future__ import annotations

import os

from .errors import UserError, shorten

MAX_BYTES = 1_000_000
MAX_LINES = 20_000
MAX_FILES = 300


def _inside(root: str, path: str) -> bool:
    r, p = os.path.normcase(root), os.path.normcase(path)
    if p == r:
        return True
    try:
        return os.path.commonpath([r, p]) == r
    except ValueError:  # different drives on Windows
        return False


def real_path(path: str) -> str:
    """os.path.realpath, but a path the OS cannot resolve is a UserError. Python 3.10 on Windows raises a
    bare ValueError ("path too long") where newer versions raise OSError or return the path."""
    try:
        return os.path.realpath(path)
    except (OSError, ValueError) as e:
        raise UserError(f"{shorten(path)!r} cannot be resolved as a path ({type(e).__name__}: {shorten(str(e))})") from e


class Sandbox:
    def __init__(self, root: str) -> None:
        self.root = real_path(root)
        if not os.path.isdir(self.root):
            raise UserError(f"--dir {shorten(root)!r} is not a directory")

    def resolve(self, path: str) -> str:
        if not path or "\x00" in path:
            raise UserError("path is empty or contains a NUL byte")
        cand = path if os.path.isabs(path) else os.path.join(self.root, path)
        real = real_path(cand)
        if not _inside(self.root, real):
            raise UserError(
                f"{shorten(path)!r} is outside the directory this server is allowed to read ({self.root}). "
                "Start the server with --dir pointing at your project."
            )
        return real

    def read_text(self, path: str) -> tuple[str, str]:
        real = self.resolve(path)
        if not os.path.exists(real):
            raise UserError(f"File not found: {shorten(path)!r}. Relative paths are resolved against {self.root}.")
        if os.path.isdir(real):
            raise UserError(f"{shorten(path)!r} is a directory, not a file.")
        size = os.path.getsize(real)
        if size > MAX_BYTES:
            raise UserError(f"{shorten(path)!r} is {size} bytes; the limit is {MAX_BYTES}.")
        with open(real, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as e:
            raise UserError(f"{shorten(path)!r} is not valid UTF-8 text ({e.reason} at byte {e.start}).") from e
        if text.count("\n") + 1 > MAX_LINES:
            raise UserError(f"{shorten(path)!r} has more than {MAX_LINES} lines; refusing to analyze it.")
        return real, text

    def display(self, real: str) -> str:
        """Path relative to the root, with forward slashes, for output."""
        try:
            rel = os.path.relpath(real, self.root)
        except ValueError:
            return real
        return rel.replace("\\", "/")


def _yaml_files(directory: str) -> list[str]:
    try:
        names = sorted(os.listdir(directory))
    except OSError as e:
        raise UserError(f"cannot list {shorten(directory)!r}: {e.strerror or e}") from e
    return [os.path.join(directory, n) for n in names
            if n.lower().endswith((".yml", ".yaml")) and os.path.isfile(os.path.join(directory, n))]


def _composite_actions(root: str) -> list[str]:
    out: list[str] = []
    for name in ("action.yml", "action.yaml"):
        p = os.path.join(root, name)
        if os.path.isfile(p):
            out.append(p)
    actions = os.path.join(root, ".github", "actions")
    if os.path.isdir(actions):
        for dirpath, dirnames, filenames in os.walk(actions):
            dirnames.sort()
            for fn in sorted(filenames):
                if fn in ("action.yml", "action.yaml"):
                    out.append(os.path.join(dirpath, fn))
            if len(out) > MAX_FILES:
                break
    return out


def discover(sb: Sandbox, path: str) -> list[str]:
    """Real paths of the workflow / action files `path` refers to.

    A file is itself. A directory is searched for `.github/workflows/*.y*ml` (plus composite actions under
    `.github/actions` and a root `action.yml`); a directory named `workflows` or any directory holding
    YAML files directly is used as-is.
    """
    real = sb.resolve(path)
    if not os.path.exists(real):
        raise UserError(f"Not found: {shorten(path)!r}. Relative paths are resolved against {sb.root}.")
    if os.path.isfile(real):
        return [real]
    wf = os.path.join(real, ".github", "workflows")
    files: list[str]
    if os.path.isdir(wf):
        files = _yaml_files(wf) + _composite_actions(real)
    else:
        files = _yaml_files(real)
        if os.path.basename(real) == "workflows" and os.path.basename(os.path.dirname(real)) == ".github":
            files += _composite_actions(os.path.dirname(os.path.dirname(real)))
    safe = []
    for f in files:
        if not os.path.isfile(os.path.realpath(f)):
            continue
        sb.resolve(f)  # a symlink pointing outside the sandbox raises here
        safe.append(f)
    if not safe:
        raise UserError(
            f"No workflow files found under {shorten(path)!r}. Pass a workflow file, a repo root containing "
            ".github/workflows, or the workflows directory."
        )
    if len(safe) > MAX_FILES:
        raise UserError(f"{len(safe)} files found; the limit is {MAX_FILES}.")
    return safe


def repo_root(real_file: str) -> str | None:
    """The directory holding `.github` for a workflow or action file, if the file lives under one."""
    parts = real_file.replace("\\", "/").split("/")
    for i in range(len(parts) - 1, 0, -1):
        if parts[i] == ".github":
            return os.sep.join(parts[:i]) if os.sep != "/" else "/".join(parts[:i]) or "/"
    return None
