"""Bad workflows. A line ending in `#@GHA1003` (comma separated for several rules) is where that rule must
report. The test asserts every marked (rule, line) is found and that no other line gets a finding of a
marked rule."""

from __future__ import annotations

SHA_CO = "11bd71901bbe5b1630ceea73d27597364c9af683"
SHA_UP = "ea165f8d65b6e75b540449e92b4886f43607fa02"
SHA_PY = "a26af69be951a213d495a4c3e4e4022e16d87065"
SHA_GS = "60a0d83039c74a4aee543508d2ffcb1c3799cdea"
SHA_CA = "5a3ec84eff668545956fd18022155c47e93e2684"
CO = f"actions/checkout@{SHA_CO}"
TOP = "on: push\npermissions: {}\n"


def wf(steps: str, top: str = TOP, job: str = "", runs_on: str = "ubuntu-24.04") -> str:
    return (top + "jobs:\n  j:\n    runs-on: " + runs_on + "\n    timeout-minutes: 5\n" + job
            + "    steps:\n" + steps)


# (name, text, file name)
CASES: list[tuple[str, str, str]] = []


def add(name: str, text: str, filename: str = ".github/workflows/w.yml") -> None:
    CASES.append((name, text, filename))


# ---- GHA1001 pinning
add("pin_tag_third_party", wf("      - uses: foo/bar@v1 #@GHA1001\n"))
add("pin_branch_third_party", wf("      - uses: foo/bar@main #@GHA1001\n"))
add("pin_branch_official", wf("      - uses: actions/checkout@main #@GHA1001\n"))
add("pin_official_tag_info", wf("      - uses: actions/checkout@v4 #@GHA1001\n"))
add("pin_no_version", wf("      - uses: foo/bar #@GHA1001\n"))
add("pin_docker_tag", wf("      - uses: docker://alpine:3.20 #@GHA1001\n"))
add("pin_reusable_tag", TOP + "jobs:\n  call:\n    uses: org/repo/.github/workflows/x.yml@v2 #@GHA1001\n")

# ---- GHA1002 pwn requests
add("pwn_pr_target_head_sha",
    wf(f"      - uses: {CO}\n        with:\n          ref: ${{{{ github.event.pull_request.head.sha }}}} #@GHA1002\n"
       "      - run: make test\n", top="on: pull_request_target\npermissions: {}\n"))
add("pwn_workflow_run_head_branch",
    wf(f"      - uses: {CO}\n        with:\n          ref: ${{{{ github.event.workflow_run.head_branch }}}} #@GHA1002\n"
       "      - run: npm ci\n", top="on:\n  workflow_run:\n    workflows: [CI]\npermissions: {}\n"))
add("pwn_gh_pr_checkout",
    wf("      - run: gh pr checkout ${{ github.event.number }} #@GHA1002\n",
       top="on: pull_request_target\npermissions: {}\n"))
add("pwn_refs_pull_merge",
    wf(f"      - uses: {CO}\n        with:\n          ref: refs/pull/${{{{ github.event.number }}}}/merge #@GHA1002\n"
       "      - run: make\n", top="on: pull_request_target\npermissions: {}\n"))
add("pwn_head_repo",
    wf(f"      - uses: {CO}\n        with:\n          repository: ${{{{ github.event.pull_request.head.repo.full_name }}}} #@GHA1002\n"
       "      - run: make\n", top="on: pull_request_target\npermissions: {}\n"))
add("pwn_head_ref_expression",
    wf(f"      - uses: {CO}\n        with:\n          ref: ${{{{ github.head_ref }}}} #@GHA1002\n"
       "      - run: ./build.sh\n", top="on: pull_request_target\npermissions: {}\n"))
add("pwn_workflow_run_artifact",
    wf("      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
       "        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
       .replace("      - uses: actions", "      - uses: actions"),  # keep step first line for the marker below
       top="on:\n  workflow_run:\n    workflows: [CI]\npermissions: {}\n").replace(
        "download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n",
        "download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 #@GHA1002\n"))

# ---- GHA1003 script injection
add("inj_issue_title", wf('      - run: echo "${{ github.event.issue.title }}" #@GHA1003\n'))
add("inj_pr_body_block",
    wf("      - run: |\n          echo start\n          echo \"${{ github.event.pull_request.body }}\" #@GHA1003\n"))
add("inj_head_ref", wf("      - run: git checkout ${{ github.head_ref }} #@GHA1003\n"))
add("inj_head_commit_message", wf("      - run: echo ${{ github.event.head_commit.message }} #@GHA1003\n"))
add("inj_comment_body", wf("      - run: echo ${{ github.event.comment.body }} #@GHA1003\n"))
add("inj_inputs_workflow_dispatch",
    wf("      - run: echo ${{ inputs.name }} #@GHA1003\n", top="on: workflow_dispatch\npermissions: {}\n"))
add("inj_github_event_inputs", wf("      - run: echo ${{ github.event.inputs.name }} #@GHA1003\n"))
add("inj_github_script",
    wf(f"      - uses: actions/github-script@{SHA_GS}\n        with:\n          script: |\n"
       "            const t = \"${{ github.event.issue.title }}\"; #@GHA1003\n"))
add("inj_bracket_syntax", wf("      - run: echo ${{ github.event['issue']['title'] }} #@GHA1003\n"))
add("inj_nested_quotes",
    wf("      - run: echo ${{ format('}}{0}', github.event.issue.title) }} #@GHA1003\n"))
add("inj_client_payload", wf("      - run: echo ${{ github.event.client_payload.cmd }} #@GHA1003\n"))
add("inj_third_line_of_block",
    wf("      - run: |\n          set -e\n          echo ok\n          echo \"$X ${{ github.event.issue.body }}\" #@GHA1003\n"))
add("inj_workflow_run_commit_message",
    wf("      - run: echo ${{ github.event.workflow_run.head_commit.message }} #@GHA1003\n"))
add("inj_commits_index", wf("      - run: echo ${{ github.event.commits[0].message }} #@GHA1003\n"))
add("inj_pwsh",
    wf("      - shell: pwsh\n        run: Write-Host \"${{ github.event.issue.title }}\" #@GHA1003\n",
       runs_on="windows-2022"))
add("inj_anchor_alias",
    wf("      - &step\n        run: echo \"${{ github.event.issue.title }}\" #@GHA1003\n      - *step\n"))
add("inj_composite_action_input",
    "name: x\ninputs:\n  who:\n    default: a\nruns:\n  using: composite\n  steps:\n"
    "    - run: echo ${{ inputs.who }} #@GHA1003\n      shell: bash\n", "action.yml")
add("inj_ref_name", wf("      - run: echo ${{ github.ref_name }} #@GHA1003\n"))
add("inj_review_comment", wf("      - run: echo '${{ github.event.review.body }}' #@GHA1003\n"))

# ---- GHA1004 / 1005 permissions
add("perm_missing", "on: push\njobs: #@GHA1004\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n"
    "    steps:\n      - run: echo hi\n")
add("perm_write_all_workflow", wf("      - run: echo hi\n", top="on: push\npermissions: write-all #@GHA1005\n"))
add("perm_write_all_job", wf("      - run: echo hi\n", job="    permissions: write-all #@GHA1005\n"))

# ---- GHA1006 / 1007 / 1008
add("secrets_inherit",
    TOP + "jobs:\n  call:\n    uses: org/repo/.github/workflows/x.yml@0123456789abcdef0123456789abcdef01234567\n"
    "    secrets: inherit #@GHA1006\n")
add("secret_echo", wf("      - run: echo ${{ secrets.TOKEN }} #@GHA1007\n"))
add("secret_cmdline", wf('      - run: |\n          curl -H "Authorization: ${{ secrets.TOKEN }}" https://example.test #@GHA1007\n'))
add("secret_echo_redirect", wf('      - run: echo "T=${{ secrets.TOKEN }}" >> "$GITHUB_ENV" #@GHA1007\n'))
add("curl_pipe_bash", wf("      - run: curl -fsSL https://example.test/i.sh | bash #@GHA1008\n"))
add("wget_pipe_sudo_bash", wf("      - run: wget -qO- https://example.test/i.sh | sudo bash #@GHA1008\n"))
add("bash_process_substitution", wf("      - run: bash <(curl -s https://example.test/i.sh) #@GHA1008\n"))
add("curl_pipe_continuation",
    wf("      - run: |\n          curl -fsSL https://example.test/i.sh \\\n            | bash #@GHA1008@-1\n"))
add("pwsh_iex", wf("      - shell: pwsh\n        run: irm https://example.test/i.ps1 | iex #@GHA1008\n",
                  runs_on="windows-2022"))

# ---- GHA1009 / 1010
add("persist_creds_artifact",
    wf(f"      - uses: {CO} #@GHA1009\n      - uses: actions/upload-artifact@{SHA_UP}\n        with:\n          path: .\n"))
add("persist_creds_third_party",
    wf(f"      - uses: {CO} #@GHA1009\n      - uses: codecov/codecov-action@{SHA_CA} # v5\n"))
add("self_hosted_on_pr", wf("      - run: make\n", top="on: pull_request\npermissions: {}\n",
                           runs_on="self-hosted #@GHA1010"))
add("self_hosted_label_list", wf("      - run: make\n", top="on: [pull_request_target]\npermissions: {}\n",
                                runs_on="[self-hosted, linux] #@GHA1010"))

# ---- GHA1011 / 1012
add("deprecated_set_output", wf('      - run: echo "::set-output name=v::1" #@GHA1011\n'))
add("deprecated_set_env", wf('      - run: echo "::set-env name=A::1" #@GHA1011\n'))
add("deprecated_add_path", wf('      - run: echo "::add-path::/x" #@GHA1011\n'))
add("deprecated_save_state", wf('      - run: echo "::save-state name=a::1" #@GHA1011\n'))
add("unsecure_commands", "on: push\npermissions: {}\nenv:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true #@GHA1012\n"
    "jobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\n")

# ---- GHA1013 / 1014
add("no_timeout", TOP + "jobs:\n  j: #@GHA1013\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo hi\n")
add("deploy_no_concurrency",
    TOP + "jobs:\n  deploy: #@GHA1014\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: ./deploy.sh\n")

# ---- GHA1015 / 1016 needs
add("needs_unknown",
    TOP + "jobs:\n  a:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    needs: nope #@GHA1015\n"
    "    steps:\n      - run: echo\n")
add("needs_cycle",
    TOP + "jobs:\n  a:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    needs: b\n    steps:\n      - run: echo\n"
    "  b:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    needs: a #@GHA1016\n    steps:\n      - run: echo\n")
add("needs_self",
    TOP + "jobs:\n  a:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    needs: [a] #@GHA1016\n"
    "    steps:\n      - run: echo\n")

# ---- GHA1017 / 1018 / 1019
add("if_mixed_text", wf("      - run: echo hi\n        if: ${{ github.ref }} == 'refs/heads/main' #@GHA1017\n"))
add("if_leading_bang", wf("      - run: echo hi\n        if: !cancelled() #@GHA1017\n"))
add("ctx_unknown", wf("      - run: echo ${{ gihub.sha }} #@GHA1018\n"))
add("ctx_misspelled_event_key", wf("      - run: echo ${{ github.event.pull_request.titel }} #@GHA1019\n"))
add("ctx_misspelled_github_key", wf("      - run: echo ${{ github.evnt.number }} #@GHA1019\n"))
add("ctx_unknown_in_if", wf("      - run: echo hi\n        if: githb.event_name == 'push' #@GHA1018\n"))

# ---- GHA1020 / 1021
add("matrix_too_large",
    wf("      - run: echo\n", job="    strategy:\n      matrix: #@GHA1020\n        a: [" + ",".join(
        str(i) for i in range(17)) + "]\n        b: [" + ",".join(str(i) for i in range(17)) + "]\n"))
add("matrix_empty_dimension",
    wf("      - run: echo\n", job="    strategy:\n      matrix:\n        os: [] #@GHA1020\n"))
add("runner_latest", wf("      - run: echo\n", runs_on="ubuntu-latest #@GHA1021"))
add("runner_latest_windows", wf("      - run: echo\n", runs_on="windows-latest #@GHA1021"))

# ---- GHA1023 / 1024 / 1025 / 1026
add("retired_upload_artifact_v3", wf("      - uses: actions/upload-artifact@v3 #@GHA1023\n"))
add("retired_via_sha_comment", wf(f"      - uses: actions/cache@{SHA_CA} # v2 #@GHA1023\n"))
add("retired_checkout_v3", wf("      - uses: actions/checkout@v3 #@GHA1023\n"))
add("archived_create_release", wf("      - uses: actions/create-release@v1 #@GHA1023\n"))
add("artifact_mismatch",
    wf("      - uses: actions/upload-artifact@v4\n        with:\n          path: x\n"
       "      - uses: actions/download-artifact@v3 #@GHA1024\n"))
add("cache_key_no_hash",
    wf(f"      - uses: actions/cache@{SHA_CA} # v4\n        with:\n          path: ~/.cache\n"
       "          key: ${{ runner.os }}-pip #@GHA1025\n"))
add("continue_on_error_job", wf("      - run: echo\n", job="    continue-on-error: true #@GHA1026\n"))
add("continue_on_error_step", wf("      - run: make lint\n        continue-on-error: true #@GHA1026\n"))

# ---- GHA1027 structure
add("struct_no_runs_on", TOP + "jobs:\n  j: #@GHA1027\n    timeout-minutes: 5\n    steps:\n      - run: echo\n")
add("struct_job_key_typo",
    TOP + "jobs:\n  j: #@GHA1027\n    runs_on: ubuntu-24.04 #@GHA1027\n    timeout-minutes: 5\n"
    "    steps:\n      - run: echo\n")
add("struct_step_neither", wf("      - name: nothing #@GHA1027\n"))
add("struct_step_both", wf("      - run: echo #@GHA1027\n        uses: foo/bar@v1\n"))
add("struct_unknown_permission", "on: push\npermissions:\n  contnts: read #@GHA1027\njobs:\n  j:\n"
    "    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: echo\n")
add("struct_unknown_event", wf("      - run: echo\n", top="on: pusj #@GHA1027\npermissions: {}\n"))
add("struct_top_level_typo", "on: push\npermission: {} #@GHA1027\njobs:\n  j:\n    runs-on: ubuntu-24.04\n"
    "    timeout-minutes: 5\n    steps:\n      - run: echo\n")
add("struct_no_jobs", "on: push #@GHA1027\n")

# ---- GHA1028 float versions
add("float_python_version",
    wf(f"      - uses: actions/setup-python@{SHA_PY} # v5\n        with:\n          python-version: 3.10 #@GHA1028\n"))
add("float_matrix_version",
    wf("      - run: echo\n", job="    strategy:\n      matrix:\n        python: [3.8, 3.10] #@GHA1028\n"))

# ---- GHA1029 / 1030 cron
add("cron_invalid", wf("      - run: echo\n", top="on:\n  schedule:\n    - cron: '61 * * * *' #@GHA1029\npermissions: {}\n"))
add("cron_wrong_field_count", wf("      - run: echo\n", top="on:\n  schedule:\n    - cron: '* * * *' #@GHA1029\npermissions: {}\n"))
add("cron_top_of_hour", wf("      - run: echo\n", top="on:\n  schedule:\n    - cron: '0 * * * *' #@GHA1030\npermissions: {}\n"))
add("cron_too_frequent", wf("      - run: echo\n", top="on:\n  schedule:\n    - cron: '*/2 * * * *' #@GHA1030\npermissions: {}\n"))

# ---- GHA1031 / 1032 / 1033
add("composite_no_shell",
    "name: x\nruns:\n  using: composite\n  steps:\n    - run: echo hi #@GHA1031\n", "action.yml")
add("unused_write_permission",
    "on: push\npermissions: #@GHA1032\n  contents: write\njobs:\n  j:\n    runs-on: ubuntu-24.04\n"
    f"    timeout-minutes: 5\n    steps:\n      - uses: {CO}\n        with:\n          persist-credentials: false\n"
    "      - run: make test\n")
add("duplicate_key", wf("      - run: echo\n", job="    timeout-minutes: 6 #@GHA1033\n"))
