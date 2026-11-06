# Changelog

## 0.1.0

First release.

- Seven tools: `workflows_overview`, `lint_workflows`, `explain_triggers`, `permissions_review`, `job_graph`,
  `pin_actions_plan`, `fix_preview`.
- 33 rules (GHA1001-GHA1033) plus GHA1000 for invalid YAML.
- Position-aware YAML model on PyYAML's composer: `on` stays a string, only `true`/`false` are booleans,
  anchors/aliases/merge keys resolve, exact line numbers inside `run: |` blocks.
- Built-in cron engine (POSIX day-of-month/day-of-week OR rule) with plain-English explanations.
- Opt-in online SHA resolution against `api.github.com` only.
- `# workflowlint-ignore:` comments, `--disable` flag, `--dir` sandbox, secret redaction on every output.
