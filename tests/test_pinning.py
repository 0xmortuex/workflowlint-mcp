"""pin_actions_plan online mode against a local fake GitHub API, plus the network-safety properties."""

from __future__ import annotations

import socket

import pytest
from fakegh import SHA_MAIN, SHA_MOVED, SHA_V1, SHA_V2_COMMIT, FakeGitHub

from workflowlint_mcp import server
from workflowlint_mcp.errors import UserError
from workflowlint_mcp.model import load_doc
from workflowlint_mcp.pinning import GitHubClient, plan, validate_base_url

from conftest import write

TOKEN = "ghp_FAKETOKENFAKETOKENFAKETOKEN123456"


def docs_for(*uses: str):
    steps = "".join(f"      - uses: {u}\n" for u in uses)
    return [load_doc("w.yml", "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n" + steps)]


def test_resolves_tags_annotated_tags_and_branches():
    with FakeGitHub() as gh:
        client = GitHubClient(gh.url)
        out = plan(docs_for("acme/tool@v1", "acme/tool@v2", "acme/tool@main", "acme/tool/sub@v1"), True, client)
    assert f"uses: acme/tool@{SHA_V1} # v1" in out
    assert f"uses: acme/tool@{SHA_V2_COMMIT} # v2" in out  # annotated tag dereferenced to the commit
    assert f"uses: acme/tool@{SHA_MAIN} # main" in out
    assert out.count(f"{SHA_V1} # v1") == 2  # sub-path action resolves through the same repo


def test_unknown_ref_and_unknown_repo_are_reported_not_hidden():
    with FakeGitHub() as gh:
        out = plan(docs_for("acme/tool@v99", "nobody/nothing@v1"), True, GitHubClient(gh.url))
    assert out.count("lookup found nothing: no tag or branch with that name was found") == 2


def test_results_are_cached():
    with FakeGitHub() as gh:
        client = GitHubClient(gh.url)
        plan(docs_for("acme/tool@v1"), True, client)
        n = len(gh.requests)
        plan(docs_for("acme/tool@v1"), True, client)
        assert len(gh.requests) == n


def test_token_goes_only_to_the_configured_host_and_is_never_printed():
    with FakeGitHub() as gh:
        out = plan(docs_for("acme/tool@v1", "acme/tool@v2"), True, GitHubClient(gh.url, TOKEN))
        assert gh.requests and all(auth == f"Bearer {TOKEN}" for _, auth in gh.requests)
    assert TOKEN not in out and "ghp_" not in out
    assert "token was configured" in out
    with FakeGitHub() as gh:
        plan(docs_for("acme/tool@v1"), True, GitHubClient(gh.url))
        assert all(auth is None for _, auth in gh.requests)


def test_rate_limit_is_reported_honestly_and_stops_further_lookups():
    with FakeGitHub() as gh:
        out = plan(docs_for("rate/limited@v1", "zeta/tool@v1"), True, GitHubClient(gh.url))
        n_rate = [p for p, _ in gh.requests if p.startswith("/repos/rate/")]
    assert "RATE LIMITED" in out and "rate limit" in out.lower() and "GITHUB_TOKEN" in out
    assert "2030-01-01 00:00 UTC" in out
    assert "not looked up" in out  # the second action was not attempted after the limit
    assert len(n_rate) == 1


def test_rate_limit_message_with_token_does_not_suggest_one():
    with FakeGitHub() as gh:
        out = plan(docs_for("rate/limited@v1"), True, GitHubClient(gh.url, TOKEN))
    assert "RATE LIMITED" in out and "Unauthenticated" not in out and TOKEN not in out


def test_bad_token_message():
    with FakeGitHub() as gh:
        out = plan(docs_for("bad/token@v1"), True, GitHubClient(gh.url, TOKEN))
    assert "rejected the GITHUB_TOKEN" in out and TOKEN not in out


def test_redirect_to_another_host_is_refused_and_no_request_is_made_there():
    with FakeGitHub() as other:
        with FakeGitHub(other_host_port=other.port) as gh:
            out = plan(docs_for("evil/redirect@v1"), True, GitHubClient(gh.url, TOKEN))
        assert other.requests == []
    assert "refusing to follow" in out and TOKEN not in out


def test_redirect_within_the_same_host_is_followed():
    with FakeGitHub() as gh:
        out = plan(docs_for("old/name@v1"), True, GitHubClient(gh.url))
    assert f"uses: old/name@{SHA_MOVED} # v1" in out


def test_unreachable_host_is_a_clear_error():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    out = plan(docs_for("acme/tool@v1"), True, GitHubClient(f"http://127.0.0.1:{port}", timeout=5))
    assert "lookup failed: cannot reach 127.0.0.1" in out


@pytest.mark.parametrize("uses", ["acme/tool@v1?x=1", "acme/tool@v1#frag", "acme/tool@a b", "acme/tool@../../etc"])
def test_hostile_refs_never_reach_the_network(uses):
    # YAML-wise these are valid scalars; the client must refuse to build a URL from them.
    with FakeGitHub() as gh:
        client = GitHubClient(gh.url)
        res = client.resolve(uses.split("@")[0], uses.split("@", 1)[1])
        assert res.sha is None and "not allowed" in res.note
        assert gh.requests == []


def test_hostile_owner_names_never_reach_the_network():
    with FakeGitHub() as gh:
        client = GitHubClient(gh.url)
        for name in ("a b/c", "../x/y", "o/r?x", "a%2f/b", "/x"):
            assert client.resolve(name, "v1").sha is None
        assert gh.requests == []


@pytest.mark.parametrize("url", ["ftp://x", "http://example.com", "https://", "file:///etc/passwd", "javascript:1"])
def test_base_url_validation(url):
    with pytest.raises(UserError):
        validate_base_url(url)


def test_default_base_url_is_api_github_com():
    assert GitHubClient().host == "api.github.com"
    assert GitHubClient().scheme == "https"


def test_lookup_cap_per_call():
    with FakeGitHub() as gh:
        many = [f"acme/tool{i}@v1" for i in range(70)]
        out = plan(docs_for(*many), True, GitHubClient(gh.url))
    assert "more than 60 distinct actions" in out


def test_tool_online_flag_uses_server_configured_url(tmp_path):
    with FakeGitHub() as gh:
        write(str(tmp_path / ".github/workflows/a.yml"),
              "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: acme/tool@v1\n")
        server.configure(str(tmp_path), (), gh.url)
        out = server.pin_actions_plan(".", online=True)
        assert f"uses: acme/tool@{SHA_V1} # v1" in out
        n = len(gh.requests)
        offline = server.pin_actions_plan(".", online=False)
        assert len(gh.requests) == n and "git ls-remote" in offline
    server.configure(str(tmp_path))
