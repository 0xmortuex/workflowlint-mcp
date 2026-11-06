# workflowlint-mcp

An MCP server that lets an AI **audit GitHub Actions workflows**: security and correctness findings with a
rule ID, severity, `file:line` (exact even inside multi-line `run: |` blocks) and a concrete fix, plus a cron
explainer with the next run times, a `needs` graph with critical path, a least-privilege permissions review,
a commit-SHA pin plan and a diff of the safe automatic fixes. It is read-only, offline by default, and needs
no external binary.

<!-- mcp-name: io.github.0xmortuex/workflowlint-mcp -->

**How it differs from what exists.** The GitHub Actions MCP servers I could find either wrap
[actionlint](https://lobehub.com/ja/mcp/hongkongkiwi-actionlint-mcp) (a Go binary you must install; it
checks syntax and shell, not supply-chain risk) or are hosted scanners such as
[github-actions-audit](https://github.com/unbearabledev/github-actions-audit) and
[github-actions-audit-mcp](https://glama.ai/mcp/servers/tylerscomic-lab/github-actions-audit-mcp), which
report findings but do not explain schedules, draw job graphs, review token permissions, or produce
patches. This server is pure Python (`mcp` + `pyyaml`), runs locally, and adds: a position-aware YAML model
(so `on:` is not the boolean `True`, `3.10` is flagged, anchors resolve, and every finding has a real line),
script-injection analysis that knows the dangerous `github.event.*` contexts, a built-in cron engine, a
`fix_preview` that proves each patch by re-linting it, and an opt-in online SHA resolver that talks to
`api.github.com` only.

## Install

Claude Code:

```bash
claude mcp add workflowlint -- uvx workflowlint-mcp --dir .
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "workflowlint": {
      "command": "uvx",
      "args": ["workflowlint-mcp", "--dir", "C:\\path\\to\\your\\repo"]
    }
  }
}
```

Without uv: `pip install workflowlint-mcp`, then run `workflowlint-mcp --dir /path/to/repo`.

| Flag | Meaning |
|------|---------|
| `--dir PATH` | Only files inside this directory can be read (default: the current directory). |
| `--disable IDS` | Comma-separated rule ids to turn off, e.g. `--disable GHA1013,GHA1021`. Repeatable. |

(There is also an undocumented `--github-api-url` flag that tests use to point the online pin lookup at a
local fake server. It is a server flag, not a tool argument, so a model cannot use it.)

Silence one finding in the file itself with a comment on the line above it (or at the end of the line):

```yaml
      # workflowlint-ignore: GHA1001, GHA1003
      - uses: some/action@v1
```

## Tools

| Tool | What it does |
|------|--------------|
| `workflows_overview(path)` | Workflows, triggers, jobs, runners, `needs`, permissions per job, every action with its version and whether it is SHA-pinned, environments, and the **names** of referenced secrets. Covers composite actions too. |
| `lint_workflows(path)` | 33 rules (GHA1001-GHA1033) with severity, `file:line` and a fix. See the table below. |
| `explain_triggers(path)` | When each workflow runs, in plain English. Cron expressions are explained with the next 5 run times in UTC from a built-in cron engine (including the day-of-month/day-of-week OR rule), plus notes on congestion, the 5-minute minimum, default-branch-only schedules and the 60-day inactivity shutdown. |
| `permissions_review(path)` | Effective `GITHUB_TOKEN` permissions per job (job-level replaces workflow-level), what each job appears to need (from known actions and `gh`/`git` commands), excess write access, missing permissions, and a least-privilege block to paste. |
| `job_graph(path)` | The `needs` graph as text and Mermaid, parallel waves, critical path, and a worst-case duration bound from `timeout-minutes`. Reports cycles. |
| `pin_actions_plan(path, online=false)` | Every `uses:` not pinned to a commit SHA, grouped, with how to pin it. With `online=true`, tags and branches are resolved to SHAs through `api.github.com` only. |
| `fix_preview(path)` | Unified diff of the safe fixes: read-only `permissions:` when every job is recognised as read-only, injectable expressions moved into step `env:`, `::set-output` replaced with `$GITHUB_OUTPUT`. Re-linted to prove the findings vanish. Never writes. |

`path` is a workflow file, a repository root containing `.github/workflows`, or the workflows directory,
relative to `--dir` or absolute inside it. Local composite actions (`.github/actions/**/action.yml`) are included.

## Try asking

- "Audit my GitHub Actions workflows and fix everything that is safe."
- "Is any workflow vulnerable to script injection or a pwn request?"
- "Which actions are not pinned to a commit SHA? Look the SHAs up." (`online=true`; set `GITHUB_TOKEN` to avoid the 60 requests/hour limit)
- "When does the nightly workflow run next? Why did it not run last week?"
- "What permissions does each job really need? Give me a least-privilege `permissions:` block."
- "Draw the job graph for the release workflow and tell me the critical path."
- "Review my reusable workflow call: do the inputs and secrets match?"

## Rules

| ID | Severity | Rule |
|----|----------|------|
| GHA1000 | error | file is not valid YAML (reported with its line instead of failing) |
| GHA1001 | error / warning / info | action is not pinned to a full commit SHA (third-party branch = error, third-party tag = warning, `actions/*` or `github/*` tag = info) |
| GHA1002 | error | `pull_request_target` / `workflow_run` checks out and runs untrusted PR code (pwn request) |
| GHA1003 | error | untrusted expression expanded inside `run:` or `github-script` (script injection) |
| GHA1004 | warning | no `permissions:` key, so the token gets the repository default (often write) |
| GHA1005 | error | `permissions: write-all` |
| GHA1006 | warning | `secrets: inherit` hands every secret to the called workflow |
| GHA1007 | warning / error | secret printed or interpolated into a command line |
| GHA1008 | warning | downloads and executes a script in one step (`curl \| bash`) |
| GHA1009 | warning / info | checkout leaves the token in `.git/config` while later steps run other code |
| GHA1010 | warning | self-hosted runner reachable from pull requests or other outsider events |
| GHA1011 | warning / error | deprecated workflow command (`set-output`, `save-state`, `set-env`, `add-path`) |
| GHA1012 | error | `ACTIONS_ALLOW_UNSECURE_COMMANDS` re-enables disabled commands |
| GHA1013 | info | job has no `timeout-minutes` (default is 360) |
| GHA1014 | info | deploy-like job without a concurrency group |
| GHA1015 | error | `needs:` names a job that does not exist |
| GHA1016 | error | `needs:` forms a cycle |
| GHA1017 | error | `if:` condition that is always true (`${{ x }} == y`) or silently lost (`if: !cancelled()`) |
| GHA1018 | error | unknown context in an expression |
| GHA1019 | warning | misspelled `github.*` / `github.event.*` property (partial table) |
| GHA1020 | error | matrix is empty or larger than 256 jobs |
| GHA1021 | info | runner label tracks `latest` |
| GHA1022 | error | call does not match the reusable workflow's inputs/secrets (same repository) |
| GHA1023 | error / warning | retired or deprecated action version (dated table) |
| GHA1024 | error | upload-artifact and download-artifact majors are incompatible |
| GHA1025 | warning | cache key has no content hash |
| GHA1026 | warning / info | `continue-on-error` hides failures |
| GHA1027 | error | structure problem: missing `runs-on`/`steps`/`jobs`, unknown keys, unknown events or permission scopes |
| GHA1028 | warning | unquoted version number loses its trailing zero (`python-version: 3.10`) |
| GHA1029 | error | invalid cron expression in `schedule` |
| GHA1030 | info | schedule at minute 0 or more often than every 5 minutes |
| GHA1031 | error | composite action `run:` step without `shell:` |
| GHA1032 | info | job is granted write access it does not appear to use |
| GHA1033 | error | duplicate mapping key |

The injection contexts checked by GHA1003 are the documented attacker-writable fields: issue, pull request,
discussion, comment and review titles and bodies; `pull_request.head.ref/label/repo.*`; commit messages and
author/committer names and emails (`head_commit`, `commits[*]`, `workflow_run.head_commit`); `head_branch`
and `display_title` of a workflow run; release name/body/tag; `client_payload.*`; `github.head_ref`. Workflow
inputs and `github.ref_name` are reported as warnings (the person who starts the run chooses them).

## Security

- **Read-only.** No tool writes a file or runs a command. `fix_preview` and `pin_actions_plan` return text.
- **Sandboxed.** Every path is resolved (symlinks included) and must stay inside `--dir`. Files are capped at
  1 MB and 20,000 lines and must be UTF-8.
- **YAML is parsed safely.** Only PyYAML's composer is used (no object construction, no tags executed). Alias
  expansion is capped at 100,000 nodes and 20 MB of text, nesting at 60 levels, so alias bombs become a
  finding, not a hang.
- **Secrets: names only.** Findings and overviews show `secrets.NAME`, never a value. As a last line of
  defence every output passes through a redactor that masks well-known token formats, `://user:pass@` URLs and
  `password: literal` lines, so a literal secret in a diff context line is not repeated to the model.
- **The network is off by default.** `pin_actions_plan(online=true)` contacts exactly one host,
  `api.github.com` (validated owner/repo/ref characters, 10 s timeout, redirects only to the same host, at most
  60 lookups per call, results cached). If `GITHUB_TOKEN` is set in the server's environment it is sent only
  as the `Authorization` header to that host and is never printed. Rate limits are reported honestly with the
  reset time.

## Limits you should know about

- It reads files; it cannot see repository settings (default token permissions, branch protection, whether the
  repository is public). Findings about those are review prompts.
- The retired-action table, the `ubuntu-latest` mapping and the `github.event` property table are snapshots
  (the output says "as of 2025-12" where it matters). Newer deprecations are not in them.
- The permissions inference knows a few dozen popular actions and `gh`/`git` commands. When a job uses
  anything else it says the inference is partial and does not guess.
- Reusable-workflow checks cover callees in the same repository only.

## Development

```bash
uv sync --extra test
uv run pytest
uv run ruff check src tests && uv run mypy --strict src
```

MIT licensed.
