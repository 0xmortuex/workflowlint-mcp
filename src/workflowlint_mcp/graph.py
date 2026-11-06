"""job_graph: the `needs:` graph, its waves of parallelism and its critical path."""

from __future__ import annotations

from collections import deque

from .model import Doc, Job


def _matrix_size(job: Job) -> int | None:
    st = job.strategy
    m = st.get("matrix") if st is not None else None
    if m is None or not m.is_map:
        return None
    total = 1
    dims = 0
    for k, v in m.items.items():
        if k in ("include", "exclude") or not v.is_seq:
            continue
        dims += 1
        total *= max(len(v.seq), 1)
    inc = m.get("include")
    if inc is not None and inc.is_seq:
        total = (total if dims else 0) + len(inc.seq)
    return total


def analyze(doc: Doc) -> tuple[dict[str, list[str]], list[str], dict[str, int], bool]:
    """(dependencies, topological order, level per job, has_cycle). Iterative, so huge graphs are fine."""
    ids = {j.id for j in doc.jobs}
    deps = {j.id: [n.text for n in j.needs if n.text in ids] for j in doc.jobs}
    users: dict[str, list[str]] = {u: [] for u in deps}
    indeg = {u: len(set(d)) for u, d in deps.items()}
    for u, ds in deps.items():
        for d in set(ds):
            users[d].append(u)
    queue = deque(u for u, n in indeg.items() if n == 0)
    order: list[str] = []
    level: dict[str, int] = {}
    while queue:
        u = queue.popleft()
        order.append(u)
        level[u] = 1 + max((level[d] for d in deps[u]), default=-1)
        for v in users[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                queue.append(v)
    cyclic = len(order) != len(deps)
    for u in deps:
        level.setdefault(u, 0)
    return deps, order, level, cyclic


def render(doc: Doc) -> str:
    if doc.kind != "workflow" or not doc.jobs:
        return f"{doc.path}: no jobs."
    deps, order, level, cyclic = analyze(doc)
    jobs = {j.id: j for j in doc.jobs}
    out = [f"== {doc.path}"]
    if cyclic:
        out.append("  WARNING: the needs graph has a cycle (rule GHA1016); levels below are approximate.")
    waves: dict[int, list[str]] = {}
    for u, lvl in level.items():
        waves.setdefault(lvl, []).append(u)
    out.append("  Needs graph:")
    for j in doc.jobs:
        dj = deps[j.id]
        extra = _matrix_size(j)
        out.append(f"    {j.id}" + (f" x{extra} matrix legs" if extra and extra > 1 else "")
                   + (f" <- {', '.join(dj)}" if dj else "  (starts immediately)"))
    out.append("  Waves (jobs in one wave can run at the same time, runner capacity permitting):")
    for lvl in sorted(waves):
        out.append(f"    wave {lvl + 1}: {', '.join(waves[lvl])}")
    width = max(len(v) for v in waves.values())
    out.append(f"  Maximum parallelism: {width} job(s) at once (plus matrix legs).")

    def timeout(u: str) -> int:
        t = jobs[u].timeout
        return int(t.value) if t is not None and isinstance(t.value, int) else 360

    for by_timeout in (False, True):
        score: dict[str, tuple[int, int]] = {}
        prev: dict[str, str | None] = {}
        for u in order:
            best_d: str | None = None
            best_s = (0, 0)
            for d in deps[u]:
                if score[d] > best_s:
                    best_s, best_d = score[d], d
            w = (timeout(u), 1) if by_timeout else (1, timeout(u))
            score[u] = (best_s[0] + w[0], best_s[1] + w[1])
            prev[u] = best_d
        if not score:
            continue
        end = max(score, key=lambda k: score[k])
        chain: list[str] = []
        cur: str | None = end
        while cur is not None:
            chain.append(cur)
            cur = prev[cur]
        chain.reverse()
        if by_timeout:
            out.append(f"  Worst-case duration bound (sum of timeout-minutes, 360 when unset): {score[end][0]} min via "
                       + " -> ".join(chain))
        else:
            out.append(f"  Critical path ({score[end][0]} job(s) deep): " + " -> ".join(chain))
    out.append("  Mermaid:")
    out.append("    ```mermaid")
    out.append("    graph LR")
    for j in doc.jobs:
        if not deps[j.id]:
            out.append(f"      {_m(j.id)}")
        for dep in deps[j.id]:
            out.append(f"      {_m(dep)} --> {_m(j.id)}")
    out.append("    ```")
    return "\n".join(out)


def _m(job_id: str) -> str:
    safe = "".join(c if c.isalnum() else "_" for c in job_id)
    return f"{safe}[\"{job_id.replace(chr(34), chr(39))}\"]"
