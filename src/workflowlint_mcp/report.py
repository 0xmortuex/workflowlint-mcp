"""Text formatting shared by the tools."""

from __future__ import annotations

import re

from .rules import Finding

MAX_OUTPUT = 60_000

_TOKEN_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_URL_CRED = re.compile(r"://[^/\s:@]+:[^/\s@]+@")
_SECRET_KEY_LINE = re.compile(
    r"^(\s*(?:-\s+)?[\w.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)[\w.-]*"
    r"\s*[:=]\s*)(?!\$\{\{)(?![\"']?(?:true|false|null|none|read|write)?[\"']?\s*$)(\S.{3,})$",
    re.I,
)


def redact(text: str) -> str:
    """Last line of defence: literal secrets that appear in file excerpts are replaced before output leaves
    the server. Values written as ${{ secrets.X }} are references, not values, and stay."""
    out = []
    for line in text.split("\n"):
        if len(line) < 4000:
            for rx in _TOKEN_PATTERNS:
                line = rx.sub("<redacted>", line)
            line = _URL_CRED.sub("://<redacted>@", line)
            m = _SECRET_KEY_LINE.match(line) if len(line) < 400 else None
            if m:
                line = m.group(1) + "<redacted>"
        else:
            line = line[:4000] + "...[line truncated]"
        out.append(line)
    return "\n".join(out)


def clip(text: str, limit: int = MAX_OUTPUT) -> str:
    window = redact(text[:limit + 2000])  # redact only what can be shown: bounds the regex work
    if len(text) <= limit:
        return window
    return window[:limit] + f"\n... [{len(text) - limit} more characters truncated]"


def format_findings(label: str, findings: list[Finding], note: str = "") -> str:
    counts = {"error": 0, "warning": 0, "info": 0}
    for f in findings:
        counts[f.severity] += 1
    head = (f"{label}: {len(findings)} finding(s) "
            f"({counts['error']} error, {counts['warning']} warning, {counts['info']} info)")
    if not findings:
        return head + ". Nothing to fix." + (f"\n{note}" if note else "")
    lines = [head, ""]
    for f in findings:
        lines.append(f"{f.file}:{f.line} [{f.rule}] {f.severity}: {f.message}")
        lines.append(f"    fix: {f.fix}")
    if note:
        lines += ["", note]
    lines += ["", "Suppress one finding with a `# workflowlint-ignore: <RULE-ID>` comment on the line above it "
              "(or at the end of that line)."]
    return clip("\n".join(lines))
