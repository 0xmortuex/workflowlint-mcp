"""MCP stdio test: launches the installed server as a real process, lists the tools, calls every one against
real files, and checks that instructive errors, the sandbox, the --disable flag, the hidden API-URL flag and
secret redaction all work end to end."""

import os
import subprocess
import sys

import pytest
from fakegh import SHA_V1, FakeGitHub

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "workflows_overview",
    "lint_workflows",
    "explain_triggers",
    "permissions_review",
    "job_graph",
    "pin_actions_plan",
    "fix_preview",
}

FAKE_SECRET = "hunter2-STDIO-FAKE-value"
WORKFLOW = f"""name: bad
on:
  issues:
    types: [opened]
  schedule:
    - cron: '0 * * * *'
env:
  DB_PASSWORD: {FAKE_SECRET}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: acme/tool@v1
      - run: echo "${{{{ github.event.issue.title }}}}"
      - run: echo ${{{{ secrets.DEPLOY_KEY }}}}
"""


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def _params(root, *extra, env=None):
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "workflowlint_mcp", "--dir", str(root), *extra],
        env={**os.environ, "PYTHONIOENCODING": "utf-8", **(env or {})},
    )


@pytest.mark.anyio
async def test_tools_and_a_full_session_over_stdio(tmp_path):
    _write(str(tmp_path / ".github/workflows/bad.yml"), WORKFLOW)
    async with stdio_client(_params(tmp_path)) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "workflowlint"
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        assert all(len(t.description or "") > 150 for t in tools)

        res = await session.call_tool("lint_workflows", {"path": "."})
        text = res.content[0].text
        assert not res.is_error
        assert "bad.yml:14 [GHA1003] error" in text
        assert "bad.yml:15 [GHA1007] error" in text
        assert "bad.yml:13 [GHA1001] warning" in text
        assert "bad.yml:6 [GHA1030]" in text
        assert "fix:" in text and FAKE_SECRET not in text

        res = await session.call_tool("workflows_overview", {"path": ".github/workflows"})
        assert "DEPLOY_KEY" in res.content[0].text and FAKE_SECRET not in res.content[0].text
        res = await session.call_tool("explain_triggers", {"path": ".github/workflows/bad.yml"})
        assert "next runs:" in res.content[0].text and "60 days" in res.content[0].text
        res = await session.call_tool("permissions_review", {"path": "."})
        assert "least-privilege suggestion" in res.content[0].text
        res = await session.call_tool("job_graph", {"path": "."})
        assert "Critical path" in res.content[0].text
        res = await session.call_tool("pin_actions_plan", {"path": "."})
        assert "acme/tool@v1" in res.content[0].text and "git ls-remote" in res.content[0].text
        res = await session.call_tool("fix_preview", {"path": ".github/workflows/bad.yml"})
        out = res.content[0].text
        assert "ISSUE_TITLE: ${{ github.event.issue.title }}" in out
        assert FAKE_SECRET not in out
        # fix_preview never writes
        with open(tmp_path / ".github/workflows/bad.yml", encoding="utf-8") as fh:
            assert fh.read() == WORKFLOW


@pytest.mark.anyio
async def test_online_pin_plan_through_the_server_flag_and_token_env(tmp_path):
    token = "ghp_STDIOFAKETOKENSTDIOFAKETOKEN1234"
    _write(str(tmp_path / ".github/workflows/bad.yml"), WORKFLOW)
    with FakeGitHub() as gh:
        params = _params(tmp_path, "--github-api-url", gh.url, env={"GITHUB_TOKEN": token})
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            res = await session.call_tool("pin_actions_plan", {"path": ".", "online": True})
            text = res.content[0].text
            assert not res.is_error
            assert f"uses: acme/tool@{SHA_V1} # v1" in text
            assert token not in text
            # the model cannot redirect the lookup: the tool has no URL parameter
            tool = next(t for t in (await session.list_tools()).tools if t.name == "pin_actions_plan")
            assert set(tool.input_schema["properties"]) == {"path", "online"}
        assert gh.requests and all(auth == f"Bearer {token}" for _, auth in gh.requests)


@pytest.mark.anyio
async def test_disable_flag_over_stdio(tmp_path):
    _write(str(tmp_path / "w.yml"), WORKFLOW)
    async with stdio_client(_params(tmp_path, "--disable", "GHA1001,GHA1021", "--disable", "gha1013")) as (r, w), \
            ClientSession(r, w) as session:
        await session.initialize()
        text = (await session.call_tool("lint_workflows", {"path": "w.yml"})).content[0].text
        assert "GHA1001" not in text and "GHA1021" not in text and "GHA1013" not in text
        assert "GHA1003" in text


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent(tmp_path):
    root = tmp_path / "proj"
    _write(str(root / "bad.yml"), "on: push\njobs: [oops\n")
    _write(str(tmp_path / "outside.yml"), "on: push\njobs: {}\n")
    async with stdio_client(_params(root)) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("lint_workflows", {"path": "nope.yml"})
        assert res.is_error and "Not found" in res.content[0].text
        res = await session.call_tool("lint_workflows", {"path": str(tmp_path / "outside.yml")})
        assert res.is_error and "outside the directory this server is allowed to read" in res.content[0].text
        res = await session.call_tool("fix_preview", {"path": "../outside.yml"})
        assert res.is_error and "outside the directory" in res.content[0].text
        res = await session.call_tool("fix_preview", {"path": "bad.yml"})
        assert res.is_error and "not valid YAML" in res.content[0].text
        res = await session.call_tool("lint_workflows", {"path": "bad.yml"})
        assert not res.is_error and "[GHA1000]" in res.content[0].text and "bad.yml:3" in res.content[0].text


def test_cli_rejects_unknown_rule_id(tmp_path):
    p = subprocess.run([sys.executable, "-m", "workflowlint_mcp", "--dir", str(tmp_path), "--disable", "GHA9999"],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "unknown rule id" in p.stderr


def test_cli_rejects_missing_dir(tmp_path):
    p = subprocess.run([sys.executable, "-m", "workflowlint_mcp", "--dir", str(tmp_path / "nope")],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "not a directory" in p.stderr


def test_cli_rejects_non_local_plain_http_api_url(tmp_path):
    p = subprocess.run([sys.executable, "-m", "workflowlint_mcp", "--dir", str(tmp_path), "--github-api-url",
                        "http://example.com"], capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "localhost" in p.stderr


def test_hidden_flag_is_not_advertised(tmp_path):
    p = subprocess.run([sys.executable, "-m", "workflowlint_mcp", "--help"], capture_output=True, text=True, timeout=60)
    assert "--dir" in p.stdout and "--disable" in p.stdout and "github-api-url" not in p.stdout
