"""pin_actions_plan: which `uses:` need pinning, and (optionally) the commit SHA behind each tag.

Network rules, all enforced here and not reachable from tool arguments:
  - exactly one host is ever contacted: the host of the API base URL chosen when the server was started
    (api.github.com unless the operator passed --github-api-url, which tests use for a local fake server);
  - redirects are followed only to that same host;
  - owner, repo and ref are validated against a strict character set before they go into a URL;
  - every request has a timeout, results are cached per process, and the number of lookups per call is capped;
  - GITHUB_TOKEN (if set in the server's environment) is sent only as the Authorization header to that host
    and is never put in output or error messages.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from . import __version__
from .errors import UserError
from .model import Doc
from .rules import _all_uses, pin_severity, split_uses

DEFAULT_API = "https://api.github.com"
MAX_LOOKUPS = 60
TIMEOUT = 10.0
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_REF = re.compile(r"[A-Za-z0-9_./+-]{1,200}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _lookup_safe(bits: list[str], ref: str) -> bool:
    """Only plain owner/repo/ref names may be placed in a URL path: no dot segments, no empty segments."""
    if len(bits) < 2 or not _NAME.match(bits[0]) or not _NAME.match(bits[1]) or not _REF.match(ref):
        return False
    if bits[0] in (".", "..") or bits[1] in (".", ".."):
        return False
    return not (".." in ref or "//" in ref or ref.startswith("/") or ref.endswith("/") or ref.endswith(".lock"))


class PinError(Exception):
    pass


class RateLimited(PinError):
    pass


@dataclass
class PinItem:
    file: str
    line: int
    uses: str
    name: str
    ref: str
    severity: str
    kind: str


@dataclass
class Resolution:
    sha: str | None
    kind: str  # "tag", "branch", ""
    note: str = ""


def collect(docs: list[Doc]) -> list[PinItem]:
    items: list[PinItem] = []
    for doc in docs:
        for uses, _node, line in _all_uses(doc):
            sp = split_uses(uses)
            if sp is None:
                continue
            res = pin_severity(*sp)
            if res is not None:
                items.append(PinItem(doc.path, line, uses, sp[0], sp[1], res[0], res[1]))
    return items


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def validate_base_url(url: str) -> str:
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("https", "http") or not p.hostname:
        raise UserError(f"--github-api-url {url!r} is not an http(s) URL")
    if p.scheme == "http" and p.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise UserError("--github-api-url may only use plain http for localhost")
    return url.rstrip("/")


class GitHubClient:
    def __init__(self, base_url: str = DEFAULT_API, token: str | None = None, timeout: float = TIMEOUT) -> None:
        self.base = validate_base_url(base_url)
        p = urllib.parse.urlparse(self.base)
        self.host = p.netloc
        self.scheme = p.scheme
        self.prefix = p.path.rstrip("/")
        self._token = token
        self.has_token = bool(token)
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect())
        self.cache: dict[tuple[str, str, str], Resolution] = {}
        self.requests = 0

    def _get(self, path: str) -> tuple[int, dict[str, object]]:
        url = f"{self.scheme}://{self.host}{path}"
        for _hop in range(4):
            headers = {"Accept": "application/vnd.github+json", "User-Agent": f"workflowlint-mcp/{__version__}",
                       "X-GitHub-Api-Version": "2022-11-28"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            req = urllib.request.Request(url, headers=headers, method="GET")
            self.requests += 1
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    body = resp.read(2_000_000)
                    data = json.loads(body.decode("utf-8")) if body else {}
                    return resp.status, data if isinstance(data, dict) else {}
            except urllib.error.HTTPError as e:
                code = e.code
                hdrs = e.headers
                if code in (301, 302, 307, 308):
                    loc = urllib.parse.urlparse(urllib.parse.urljoin(url, hdrs.get("Location", "")))
                    if loc.netloc != self.host or loc.scheme != self.scheme:
                        raise PinError(f"GitHub redirected to another host ({loc.netloc or '?'}); refusing to follow") from e
                    url = f"{self.scheme}://{self.host}{loc.path}"
                    continue
                if code == 404:
                    return 404, {}
                if code in (403, 429) and hdrs.get("x-ratelimit-remaining") == "0" or code == 429:
                    reset = hdrs.get("x-ratelimit-reset")
                    when = ""
                    if reset and reset.isdigit():
                        when = " It resets at " + datetime.fromtimestamp(int(reset), timezone.utc).strftime(
                            "%Y-%m-%d %H:%M UTC") + "."
                    hint = "" if self._token else (" Unauthenticated requests get only 60 per hour: set GITHUB_TOKEN "
                                                   "in the environment the MCP server runs in to raise this to 5000.")
                    raise RateLimited("GitHub API rate limit reached." + when + hint) from e
                if code == 401:
                    raise PinError("GitHub rejected the GITHUB_TOKEN (401). Unset it or supply a valid token.") from e
                if code == 403:
                    raise PinError("GitHub returned 403 (forbidden) for this request.") from e
                raise PinError(f"GitHub API returned HTTP {code}.") from e
            except urllib.error.URLError as e:
                raise PinError(f"cannot reach {self.host}: {e.reason}") from e
            except TimeoutError as e:
                raise PinError(f"request to {self.host} timed out after {self.timeout:g}s") from e
            except (OSError, ValueError) as e:
                raise PinError(f"request to {self.host} failed: {type(e).__name__}") from e
        raise PinError("too many redirects")

    def resolve(self, name: str, ref: str) -> Resolution:
        bits = name.split("/")
        if not _lookup_safe(bits, ref):
            return Resolution(None, "", "owner/repo/ref contains characters that are not allowed in a lookup")
        owner, repo = bits[0], bits[1]
        key = (owner.lower(), repo.lower(), ref)
        if key in self.cache:
            return self.cache[key]
        base = f"{self.prefix}/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/git"
        refq = urllib.parse.quote(ref, safe="/")
        result: Resolution | None = None
        for kind, ns in (("tag", "tags"), ("branch", "heads")):
            status, data = self._get(f"{base}/ref/{ns}/{refq}")
            if status != 200:
                continue
            obj = data.get("object")
            if not isinstance(obj, dict):
                continue
            sha, typ = obj.get("sha"), obj.get("type")
            hops = 0
            while typ == "tag" and isinstance(sha, str) and hops < 4:
                status, tdata = self._get(f"{base}/tags/{sha}")
                tobj = tdata.get("object") if status == 200 else None
                if not isinstance(tobj, dict):
                    sha = None
                    break
                sha, typ = tobj.get("sha"), tobj.get("type")
                hops += 1
            if isinstance(sha, str) and _HEX40.match(sha):
                result = Resolution(sha, kind)
            else:
                result = Resolution(None, kind, "the API returned an unexpected object")
            break
        if result is None:
            result = Resolution(None, "", "no tag or branch with that name was found")
        self.cache[key] = result
        return result


def plan(docs: list[Doc], online: bool, client: GitHubClient | None) -> str:
    items = collect(docs)
    if not items:
        return "Every `uses:` is already pinned to a full commit SHA, local, or has nothing to pin. Nothing to do."
    groups: dict[tuple[str, str], list[PinItem]] = {}
    for it in items:
        groups.setdefault((it.name, it.ref), []).append(it)
    out = [f"{len(items)} reference(s) to {len(groups)} distinct action version(s) need pinning "
           f"({'online lookup via ' + client.host if online and client else 'offline plan'}).", ""]
    stopped: str | None = None
    lookups = 0
    for (name, ref), its in sorted(groups.items()):
        worst = min(its, key=lambda i: {"error": 0, "warning": 1, "info": 2}[i.severity])
        out.append(f"{name}@{ref}  [{worst.severity}, {worst.kind}]")
        for it in its:
            out.append(f"    {it.file}:{it.line}")
        if online and client is not None:
            if stopped is not None:
                out.append(f"    not looked up: {stopped}")
            elif lookups >= MAX_LOOKUPS:
                out.append(f"    not looked up: more than {MAX_LOOKUPS} distinct actions in one call")
            else:
                lookups += 1
                try:
                    res = client.resolve(name, ref)
                except RateLimited as e:
                    stopped = str(e)
                    out.append(f"    RATE LIMITED: {stopped}")
                    continue
                except PinError as e:
                    out.append(f"    lookup failed: {e}")
                    continue
                if res.sha:
                    out.append(f"    -> uses: {name}@{res.sha} # {ref}")
                else:
                    out.append(f"    lookup found nothing: {res.note}")
        else:
            owner_repo = "/".join(name.split("/")[:2])
            out.append(f"    resolve: git ls-remote https://github.com/{owner_repo} 'refs/tags/{ref}*' "
                       f"'refs/heads/{ref}' (for an annotated tag use the SHA on the line ending ^{{}})")
            out.append(f"    then:    uses: {name}@<40-hex> # {ref}")
    out += ["", "Before accepting a SHA, check it is reachable from the action's own default branch or release "
            "tags (commits from forks can be referenced by SHA too), and keep the `# vX.Y.Z` comment so "
            "Dependabot/Renovate can update the pin. Nothing was written to disk."]
    if online and client is not None:
        out.append(f"({client.requests} API request(s) made; token {'was' if client.has_token else 'was not'}"
                   " configured.)")
    return "\n".join(out)
