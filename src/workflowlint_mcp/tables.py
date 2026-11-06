"""Reference tables. They are snapshots of public GitHub documentation and changelogs; each says when it was
compiled so an agent knows how far to trust it."""

from __future__ import annotations

# ---------------------------------------------------------------------------------------------------------
# Retired / deprecated action majors.

RETIRED_AS_OF = "2025-12 (covers deprecations announced through late 2025; newer ones are not listed)"

# action -> (highest affected major, severity, why)
RETIRED_ACTIONS: dict[str, tuple[int, str, str]] = {
    "actions/upload-artifact": (3, "error", "v1-v3 were retired in January 2025 and now fail the job"),
    "actions/download-artifact": (3, "error", "v1-v3 were retired in January 2025 and now fail the job"),
    "actions/upload-pages-artifact": (2, "error", "v1-v2 depend on the retired upload-artifact v3"),
    "actions/deploy-pages": (3, "error", "v1-v3 depend on the retired artifact backend"),
    "actions/cache": (2, "error", "v1-v2 were retired in early 2025 (the cache service backend changed)"),
    "actions/checkout": (3, "warning", "v1-v3 run on the deprecated Node 12/16 runtimes"),
    "actions/setup-node": (3, "warning", "v1-v3 run on the deprecated Node 12/16 runtimes"),
    "actions/setup-python": (4, "warning", "v1-v4 run on the deprecated Node 12/16 runtimes"),
    "actions/setup-java": (3, "warning", "v1-v3 run on the deprecated Node 12/16 runtimes"),
    "actions/setup-go": (4, "warning", "v1-v4 run on the deprecated Node 12/16 runtimes"),
    "actions/setup-dotnet": (3, "warning", "v1-v3 run on the deprecated Node 12/16 runtimes"),
    "actions/github-script": (6, "warning", "v1-v6 run on the deprecated Node 12/16 runtimes"),
    "actions/labeler": (4, "warning", "v1-v4 run on deprecated Node runtimes"),
    "actions/stale": (7, "warning", "v1-v7 run on deprecated Node runtimes"),
    "actions/configure-pages": (3, "warning", "v1-v3 run on deprecated Node runtimes"),
    "github/codeql-action": (2, "error", "v1 and v2 were deprecated (v2 in January 2025)"),
    "docker/build-push-action": (4, "warning", "v1-v4 run on deprecated Node runtimes"),
    "docker/setup-buildx-action": (2, "warning", "v1-v2 run on deprecated Node runtimes"),
    "docker/setup-qemu-action": (2, "warning", "v1-v2 run on deprecated Node runtimes"),
    "docker/login-action": (2, "warning", "v1-v2 run on deprecated Node runtimes"),
    "docker/metadata-action": (4, "warning", "v1-v4 run on deprecated Node runtimes"),
    "codecov/codecov-action": (3, "warning", "v1-v3 use the deprecated uploader"),
    "aws-actions/configure-aws-credentials": (3, "warning", "v1-v3 run on deprecated Node runtimes"),
    "softprops/action-gh-release": (1, "warning", "v1 runs on a deprecated Node runtime"),
    "peaceiris/actions-gh-pages": (3, "warning", "v1-v3 run on deprecated Node runtimes"),
}

# Archived / unmaintained: any version.
ARCHIVED_ACTIONS: dict[str, str] = {
    "actions/create-release": "archived and unmaintained; use `gh release create` or softprops/action-gh-release",
    "actions/upload-release-asset": "archived and unmaintained; use `gh release upload`",
    "actions/setup-ruby": "removed; use ruby/setup-ruby",
    "actions/setup-elixir": "archived; use erlef/setup-beam",
    "actions/hub": "archived",
}

# ---------------------------------------------------------------------------------------------------------
# Runner labels

LATEST_LABELS = {
    "ubuntu-latest": "ubuntu-24.04",
    "windows-latest": "windows-2025",
    "macos-latest": "macos-15",
}
RUNNER_LABELS_AS_OF = "2025-12"

# ---------------------------------------------------------------------------------------------------------
# Structure

WORKFLOW_KEYS = ("name", "run-name", "on", "permissions", "env", "defaults", "concurrency", "jobs")
JOB_KEYS = ("name", "permissions", "needs", "if", "runs-on", "snapshot", "environment", "concurrency", "outputs",
            "env", "defaults", "steps", "timeout-minutes", "strategy", "continue-on-error", "container",
            "services", "uses", "with", "secrets")
STEP_KEYS = ("id", "if", "name", "uses", "run", "working-directory", "shell", "with", "env", "continue-on-error",
             "timeout-minutes")
PERMISSION_SCOPES = ("actions", "attestations", "checks", "contents", "deployments", "discussions", "id-token",
                     "issues", "models", "packages", "pages", "pull-requests", "repository-projects",
                     "security-events", "statuses")
EVENTS = ("branch_protection_rule", "check_run", "check_suite", "create", "delete", "deployment",
          "deployment_status", "discussion", "discussion_comment", "fork", "gollum", "issue_comment", "issues",
          "label", "merge_group", "milestone", "page_build", "public", "pull_request", "pull_request_review",
          "pull_request_review_comment", "pull_request_target", "push", "registry_package", "release",
          "repository_dispatch", "schedule", "status", "watch", "workflow_call", "workflow_dispatch",
          "workflow_run")
# Events a stranger can trigger (from a fork, an issue, a comment, ...).
OUTSIDER_EVENTS = {"pull_request", "pull_request_target", "issue_comment", "issues", "pull_request_review",
                   "pull_request_review_comment", "discussion", "discussion_comment", "fork", "watch",
                   "workflow_run", "label", "milestone"}

# ---------------------------------------------------------------------------------------------------------
# github context (partial table, used to catch typos)

GITHUB_KEYS = ("action", "action_path", "action_ref", "action_repository", "action_status", "actor", "actor_id",
               "api_url", "base_ref", "env", "event", "event_name", "event_path", "graphql_url", "head_ref", "job",
               "job_workflow_sha", "path", "ref", "ref_name", "ref_protected", "ref_type", "repository",
               "repository_id", "repository_owner", "repository_owner_id", "repositoryurl", "retention_days",
               "run_attempt", "run_id", "run_number", "secret_source", "server_url", "sha", "token",
               "triggering_actor", "workflow", "workflow_ref", "workflow_sha", "workspace")

EVENT_KEYS = ("action", "after", "base_ref", "before", "changes", "check_run", "check_suite", "client_payload",
              "comment", "commits", "compare", "created", "deleted", "deployment", "deployment_status",
              "discussion", "enterprise", "forced", "forkee", "head_commit", "inputs", "installation", "issue",
              "label", "master_branch", "member", "milestone", "number", "organization", "pages", "pull_request",
              "pusher", "release", "repository", "requested_action", "review", "review_comment", "ref", "ref_type",
              "sender", "starred_at", "status", "workflow", "workflow_job", "workflow_run", "merge_group",
              "description", "pusher_type", "repositories", "marketplace_purchase", "alert")

EVENT_SUBKEYS: dict[str, tuple[str, ...]] = {
    "pull_request": (
        "url", "id", "node_id", "html_url", "diff_url", "patch_url", "issue_url", "number", "state", "locked",
        "title", "user", "body", "created_at", "updated_at", "closed_at", "merged_at", "merge_commit_sha",
        "assignee", "assignees", "requested_reviewers", "requested_teams", "labels", "milestone", "draft",
        "commits_url", "review_comments_url", "review_comment_url", "comments_url", "statuses_url", "head", "base",
        "_links", "author_association", "auto_merge", "active_lock_reason", "merged", "mergeable", "rebaseable",
        "mergeable_state", "merged_by", "comments", "review_comments", "maintainer_can_modify", "commits",
        "additions", "deletions", "changed_files"),
    "issue": (
        "url", "repository_url", "labels_url", "comments_url", "events_url", "html_url", "id", "node_id", "number",
        "title", "user", "labels", "state", "locked", "assignee", "assignees", "milestone", "comments",
        "created_at", "updated_at", "closed_at", "author_association", "active_lock_reason", "body", "reactions",
        "timeline_url", "performed_via_github_app", "state_reason", "pull_request", "draft", "closed_by"),
    "head_commit": ("id", "tree_id", "distinct", "message", "timestamp", "url", "author", "committer", "added",
                    "removed", "modified"),
    "comment": ("url", "html_url", "issue_url", "id", "node_id", "user", "created_at", "updated_at",
                "author_association", "body", "reactions", "performed_via_github_app", "pull_request_review_id",
                "path", "position", "line", "commit_id", "diff_hunk", "in_reply_to_id", "original_position",
                "original_line", "start_line", "side", "subject_type", "pull_request_url", "original_commit_id"),
    "release": ("url", "assets_url", "upload_url", "html_url", "id", "author", "node_id", "tag_name",
                "target_commitish", "name", "draft", "prerelease", "created_at", "published_at", "assets",
                "tarball_url", "zipball_url", "body", "immutable"),
    "workflow_run": (
        "id", "name", "node_id", "head_branch", "head_sha", "path", "run_number", "event", "status", "conclusion",
        "workflow_id", "check_suite_id", "check_suite_node_id", "url", "html_url", "pull_requests", "created_at",
        "updated_at", "actor", "triggering_actor", "run_attempt", "run_started_at", "jobs_url", "logs_url",
        "check_suite_url", "artifacts_url", "cancel_url", "rerun_url", "previous_attempt_url", "workflow_url",
        "head_commit", "repository", "head_repository", "display_title", "referenced_workflows"),
}

# ---------------------------------------------------------------------------------------------------------
# What a job needs from GITHUB_TOKEN, by action (partial; heuristics). Each value maps scope -> level.

ACTION_NEEDS: dict[str, dict[str, str]] = {
    "actions/checkout": {"contents": "read"},
    "actions/setup-node": {}, "actions/setup-python": {}, "actions/setup-go": {}, "actions/setup-java": {},
    "actions/setup-dotnet": {}, "actions/cache": {}, "actions/upload-artifact": {},
    "actions/download-artifact": {}, "astral-sh/setup-uv": {}, "pnpm/action-setup": {},
    "docker/setup-buildx-action": {}, "docker/setup-qemu-action": {}, "dtolnay/rust-toolchain": {},
    "actions/upload-pages-artifact": {}, "actions/configure-pages": {},
    "actions/deploy-pages": {"pages": "write", "id-token": "write"},
    "github/codeql-action/init": {"security-events": "write", "contents": "read", "actions": "read"},
    "github/codeql-action/analyze": {"security-events": "write", "contents": "read", "actions": "read"},
    "github/codeql-action/upload-sarif": {"security-events": "write", "contents": "read"},
    "actions/dependency-review-action": {"contents": "read", "pull-requests": "write"},
    "actions/stale": {"issues": "write", "pull-requests": "write"},
    "actions/labeler": {"contents": "read", "pull-requests": "write"},
    "actions/first-interaction": {"issues": "write", "pull-requests": "write"},
    "peaceiris/actions-gh-pages": {"contents": "write"},
    "softprops/action-gh-release": {"contents": "write"},
    "ncipollo/release-action": {"contents": "write"},
    "pypa/gh-action-pypi-publish": {"id-token": "write"},
    "aws-actions/configure-aws-credentials": {"id-token": "write"},
    "google-github-actions/auth": {"id-token": "write"},
    "azure/login": {"id-token": "write"},
    "actions/attest-build-provenance": {"id-token": "write", "attestations": "write", "contents": "read"},
    "actions/attest": {"id-token": "write", "attestations": "write"},
    "dependabot/fetch-metadata": {},
    "codecov/codecov-action": {},
    "peter-evans/create-pull-request": {"contents": "write", "pull-requests": "write"},
}

# Actions we know well enough to call a job's needs "conclusive".
KNOWN_SIMPLE = set(ACTION_NEEDS)

# Shell commands that imply a permission: (regex fragment, scope, level)
COMMAND_NEEDS: tuple[tuple[str, str, str], ...] = (
    (r"\bgit\s+push\b", "contents", "write"),
    (r"\bgh\s+release\s+(create|upload|edit|delete)\b", "contents", "write"),
    (r"\bgh\s+pr\s+merge\b", "contents", "write"),
    (r"\bgh\s+pr\s+merge\b", "pull-requests", "write"),
    (r"\bgh\s+pr\s+(comment|edit|review|close|reopen|create|ready)\b", "pull-requests", "write"),
    (r"\bgh\s+issue\s+(comment|edit|close|reopen|create|lock)\b", "issues", "write"),
    (r"\bgh\s+workflow\s+run\b", "actions", "write"),
    (r"\bgh\s+run\s+(cancel|rerun)\b", "actions", "write"),
)

# The effective set when `permissions: write-all`, and the repo-default sets, in scope order.
ALL_SCOPES = PERMISSION_SCOPES
