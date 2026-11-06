"""`${{ ... }}` expressions: finding them (quotes and all), the contexts they read, and which of
those contexts an attacker can write."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Expr:
    start: int  # offset of "${{"
    end: int  # offset just past "}}" (or end of text when unterminated)
    body: str
    closed: bool


def find_expressions(text: str) -> list[Expr]:
    """All `${{ ... }}` in text. A `}}` inside a single-quoted string literal does not end the expression
    (`${{ format('}}') }}`); '' is an escaped quote."""
    out: list[Expr] = []
    pos = 0
    n = len(text)
    while True:
        s = text.find("${{", pos)
        if s < 0:
            break
        i = s + 3
        in_str = False
        closed = False
        while i < n:
            c = text[i]
            if in_str:
                if c == "'":
                    if i + 1 < n and text[i + 1] == "'":
                        i += 2
                        continue
                    in_str = False
            elif c == "'":
                in_str = True
            elif c == "}" and i + 1 < n and text[i + 1] == "}":
                closed = True
                break
            i += 1
        end = i + 2 if closed else n
        out.append(Expr(s, end, text[s + 3:i], closed))
        pos = end
        if pos >= n:
            break
    return out


@dataclass
class Token:
    """A context reference such as github.event.issue.title, with bracket accessors normalized:
    `github.event.commits[0].message` -> ["github", "event", "commits", "*", "message"]."""
    parts: list[str]
    offset: int  # offset in the expression body

    @property
    def dotted(self) -> str:
        return ".".join(self.parts)


def _skip_string(body: str, i: int) -> int:
    n = len(body)
    i += 1
    while i < n:
        if body[i] == "'":
            if i + 1 < n and body[i + 1] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    return n


def _ident_start(c: str) -> bool:
    return c.isalpha() or c == "_"


def _ident_char(c: str) -> bool:
    return c.isalnum() or c in "_-"


def tokens(body: str) -> list[Token]:
    """Context references in an expression body, ignoring string literals, numbers and function calls."""
    out: list[Token] = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c == "'":
            i = _skip_string(body, i)
        elif c.isdigit():
            while i < n and (body[i].isalnum() or body[i] == "."):
                i += 1
        elif c == "." :
            # property access on a call result / bracket: skip the member name
            i += 1
            while i < n and (_ident_char(body[i]) or body[i] == "*"):
                i += 1
        elif _ident_start(c):
            start = i
            while i < n and _ident_char(body[i]):
                i += 1
            parts = [body[start:i]]
            while i < n:
                j = i
                while j < n and body[j] == " ":
                    j += 1
                if j < n and body[j] == "." and j + 1 < n and (_ident_char(body[j + 1]) or body[j + 1] == "*"):
                    k = j + 1
                    while k < n and (_ident_char(body[k]) or body[k] == "*"):
                        k += 1
                    parts.append(body[j + 1:k])
                    i = k
                elif i < n and body[i] == "[":
                    depth = 0
                    k = i
                    while k < n:
                        if body[k] == "'":
                            k = _skip_string(body, k)
                            continue
                        if body[k] == "[":
                            depth += 1
                        elif body[k] == "]":
                            depth -= 1
                            if depth == 0:
                                break
                        k += 1
                    inner = body[i + 1:k].strip()
                    if len(inner) >= 2 and inner[0] == "'" and inner[-1] == "'" and "'" not in inner[1:-1]:
                        parts.append(inner[1:-1])
                    else:
                        parts.append("*")
                    i = min(k + 1, n)
                else:
                    break
            j = i
            while j < n and body[j] == " ":
                j += 1
            if j < n and body[j] == "(":
                continue  # function call
            out.append(Token(parts, start))
        else:
            i += 1
    return out


LITERALS = {"true", "false", "null", "nan", "infinity"}
CONTEXTS = ("github", "env", "vars", "job", "jobs", "steps", "runner", "secrets", "strategy", "matrix", "needs",
            "inputs")
FUNCTIONS = ("contains", "startsWith", "endsWith", "format", "join", "toJSON", "fromJSON", "hashFiles",
             "success", "always", "cancelled", "failure")


# Contexts whose value an outsider can choose. "error": text from an untrusted event payload.
# "warning": a value the person who triggers the run types (inputs) or a branch/tag name.
DANGEROUS: tuple[tuple[str, str], ...] = (
    ("github.event.issue.title", "error"),
    ("github.event.issue.body", "error"),
    ("github.event.pull_request.title", "error"),
    ("github.event.pull_request.body", "error"),
    ("github.event.pull_request.head.ref", "error"),
    ("github.event.pull_request.head.label", "error"),
    ("github.event.pull_request.head.repo.default_branch", "error"),
    ("github.event.pull_request.head.repo.description", "error"),
    ("github.event.pull_request.head.repo.homepage", "error"),
    ("github.event.comment.body", "error"),
    ("github.event.review.body", "error"),
    ("github.event.review_comment.body", "error"),
    ("github.event.discussion.title", "error"),
    ("github.event.discussion.body", "error"),
    ("github.event.pages.*.page_name", "error"),
    ("github.event.commits.*.message", "error"),
    ("github.event.commits.*.author.email", "error"),
    ("github.event.commits.*.author.name", "error"),
    ("github.event.head_commit.message", "error"),
    ("github.event.head_commit.author.email", "error"),
    ("github.event.head_commit.author.name", "error"),
    ("github.event.head_commit.committer.email", "error"),
    ("github.event.head_commit.committer.name", "error"),
    ("github.event.workflow_run.head_branch", "error"),
    ("github.event.workflow_run.display_title", "error"),
    ("github.event.workflow_run.head_commit.message", "error"),
    ("github.event.workflow_run.head_commit.author.email", "error"),
    ("github.event.workflow_run.head_commit.author.name", "error"),
    ("github.event.workflow_run.head_repository.description", "error"),
    ("github.event.workflow_run.pull_requests.*.head.ref", "error"),
    ("github.event.check_suite.head_branch", "error"),
    ("github.event.check_suite.head_commit.message", "error"),
    ("github.event.check_run.check_suite.head_branch", "error"),
    ("github.event.release.name", "error"),
    ("github.event.release.body", "error"),
    ("github.event.release.tag_name", "error"),
    ("github.event.client_payload.**", "error"),
    ("github.head_ref", "error"),
    ("github.ref_name", "warning"),
    ("github.event.inputs.*", "warning"),
    ("inputs.*", "warning"),
)


def _match(pattern: list[str], parts: list[str]) -> bool:
    if pattern[-1] == "**":
        head = pattern[:-1]
        return len(parts) > len(head) and all(p in ("*", q) or q == "*" for p, q in zip(head, parts, strict=False))
    if len(parts) < len(pattern):
        return False
    return all(p == "*" or q == "*" or p == q for p, q in zip(pattern, parts, strict=False))


def dangerous(token: Token) -> str | None:
    """Severity ("error"/"warning") when the token reads attacker-controlled text, else None."""
    low = [p.lower() for p in token.parts]
    for pat, sev in DANGEROUS:
        if _match(pat.split("."), low):
            return sev
    return None
