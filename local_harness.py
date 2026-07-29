#!/usr/bin/env python3
"""
local_harness.py — run the full job end-to-end with NO GitHub access.

Swaps _github_request for an in-memory fake and feeds detections from the
fixture XML (or, with --live, from the real Qualys API while GitHub stays
fake). Simulates four consecutive daily runs:

  day 1  baseline        -> per-vuln issues created + first summary
  day 2  spread          -> new asset joins one QID, new endpoint on another
                            (exercises update path + fingerprint)
  day 3  disappearance   -> the critical QID drops out (absence marking)
  day 4  grace elapsed   -> closure-review flag (grace forced to 0)

Then asserts the invariants:
  * no finding issue was ever closed
  * everything closed carries the summary marker
  * exactly one summary is open at the end
  * QID is the primary key (one finding issue per QID)

Rendered issue bodies land in ./local_out/ for eyeballing table formatting.

Usage, from the repo root:
    python scripts/local_harness.py            # fully offline
    python scripts/local_harness.py --live     # real Qualys pull, fake GitHub
                                               # (needs QUALYS_* env vars)
"""

import os
import re
import sys
import pathlib
import argparse
import xml.etree.ElementTree as ET
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Dummy env so the module imports; overridden by real vars if already set.
for var, val in {
    "QUALYS_BASE_URL": "https://qualys.invalid",
    "QUALYS_USERNAME": "harness",
    "QUALYS_PASSWORD": "harness",
    "GITHUB_TOKEN": "harness",
    "GITHUB_REPO": "local/harness",
}.items():
    os.environ.setdefault(var, val)

import qualys_qds_to_github as m  # noqa: E402

OUT = ROOT / "local_out"


# --------------------------------------------------------------------------- #
# Fake GitHub — implements exactly the API surface _github_request touches
# --------------------------------------------------------------------------- #
class FakeResponse:
    def __init__(self, payload=None, status=200):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.headers = {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"fake GitHub returned HTTP {self.status_code}")


class FakeGitHub:
    def __init__(self):
        self.issues = {}          # number -> {title, body, labels:set, state}
        self.comments = defaultdict(list)
        self.next_number = 1
        self.calls = []

    def request(self, method, path, **kw):
        self.calls.append((method, path))
        body = kw.get("json") or {}
        params = kw.get("params") or {}

        if re.fullmatch(r"/repos/[^/]+/[^/]+/issues", path):
            if method == "GET":
                if int(params.get("page", 1)) > 1:
                    return FakeResponse([])
                label = params.get("labels")
                state = params.get("state", "open")
                out = [
                    {
                        "number": n,
                        "title": i["title"],
                        "body": i["body"],
                        "state": i["state"],
                        "labels": [{"name": l} for l in sorted(i["labels"])],
                    }
                    for n, i in sorted(self.issues.items())
                    if i["state"] == state and (not label or label in i["labels"])
                ]
                return FakeResponse(out)
            if method == "POST":
                n = self.next_number
                self.next_number += 1
                self.issues[n] = {
                    "title": body.get("title", ""),
                    "body": body.get("body", ""),
                    "labels": set(body.get("labels", [])),
                    "state": "open",
                }
                return FakeResponse({"number": n})

        mnum = re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)", path)
        if mnum and method == "PATCH":
            issue = self.issues[int(mnum.group(1))]
            for field in ("title", "body", "state"):
                if field in body:
                    issue[field] = body[field]
            return FakeResponse({})

        mcom = re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)/comments", path)
        if mcom and method == "POST":
            self.comments[int(mcom.group(1))].append(body.get("body", ""))
            return FakeResponse({})

        mlab = re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)/labels", path)
        if mlab and method == "POST":
            self.issues[int(mlab.group(1))]["labels"].update(body.get("labels", []))
            return FakeResponse({})

        mdel = re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)/labels/(.+)", path)
        if mdel and method == "DELETE":
            issue = self.issues[int(mdel.group(1))]
            if mdel.group(2) in issue["labels"]:
                issue["labels"].discard(mdel.group(2))
                return FakeResponse({})
            return FakeResponse({}, status=404)  # absent label — ignored by caller

        raise AssertionError(f"fake GitHub has no route for {method} {path}")

    # ---- reporting -------------------------------------------------------- #
    def dump(self, tag):
        OUT.mkdir(exist_ok=True)
        for n, issue in sorted(self.issues.items()):
            (OUT / f"{tag}-issue-{n:03d}.md").write_text(
                f"# [{issue['state']}] {issue['title']}\n"
                f"labels: {sorted(issue['labels'])}\n\n{issue['body']}\n"
                + "".join(f"\n> comment: {c}\n" for c in self.comments[n])
            )

    def table(self):
        rows = [
            (n, i["state"], ",".join(sorted(i["labels"])), i["title"][:70])
            for n, i in sorted(self.issues.items())
        ]
        width = max(len(r[2]) for r in rows) if rows else 6
        lines = [f"{'#':>3}  {'STATE':6}  {'LABELS':{width}}  TITLE"]
        for n, state, labels, title in rows:
            lines.append(f"{n:>3}  {state:6}  {labels:{width}}  {title}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Detection feeds per simulated day
# --------------------------------------------------------------------------- #
def fixture_detections():
    xml = (ROOT / "tests" / "fixtures" / "qualys_sample.xml").read_text()
    return list(m._parse_detections(ET.fromstring(xml)))


def day_feeds(base):
    """Return the per-day detection lists derived from the baseline pull."""
    # Day 2: QID 38170 appears on db1 too, and gains endpoint 8443 on web1.
    spread = list(base)
    web1_38170 = next(d for d in base if d["qid"] == "38170")
    spread.append(dict(web1_38170, endpoint="8443/tcp", qds=79))
    db1 = next(d for d in base if d["asset_key"].startswith("dns:db1"))
    spread.append(dict(web1_38170, asset_key=db1["asset_key"],
                       host_id=db1["host_id"], host_label=db1["host_label"],
                       ip=db1["ip"], os=db1["os"], qds=71,
                       first_found="2026-07-29T01:00:00Z"))
    # Day 3 & 4: the critical QID drops out entirely (rebuild, not yet rescanned).
    without_crit = [d for d in spread if d["qid"] != "91234"]
    return {1: base, 2: spread, 3: without_crit, 4: without_crit}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="pull day 1 from the real Qualys API (GitHub stays fake)")
    args = ap.parse_args()

    fake = FakeGitHub()
    m._github_request = fake.request          # the only GitHub touchpoint

    base = list(m.qualys_pull()) if args.live else fixture_detections()
    if not base:
        sys.exit("No detections in the baseline feed — nothing to simulate.")
    feeds = day_feeds(base)

    for day in (1, 2, 3, 4):
        if day == 4:
            m.ABSENCE_GRACE_DAYS = 0          # fast-forward the grace period
        m.qualys_pull = lambda d=feeds[day]: iter(d)
        print(f"\n=== simulated run: day {day} ===")
        m.main()
        fake.dump(f"day{day}")

    print("\n=== final issue state ===")
    print(fake.table())

    # ---- invariants -------------------------------------------------------- #
    findings = {n: i for n, i in fake.issues.items() if m.KEY_RE.search(i["body"])}
    summaries = {n: i for n, i in fake.issues.items() if m.SUMMARY_MARKER in i["body"]}

    assert findings, "no finding issues were created"
    assert all(i["state"] == "open" for i in findings.values()), \
        "INVARIANT BROKEN: a finding issue was closed"
    closed = [i for i in fake.issues.values() if i["state"] == "closed"]
    assert all(m.SUMMARY_MARKER in i["body"] for i in closed), \
        "INVARIANT BROKEN: something closed without the summary marker"
    assert sum(1 for i in summaries.values() if i["state"] == "open") == 1, \
        "INVARIANT BROKEN: expected exactly one open summary"
    qids = [m.KEY_RE.search(i["body"]).group(1) for i in findings.values()]
    assert len(qids) == len(set(qids)), \
        "INVARIANT BROKEN: more than one finding issue per QID"
    review = [n for n, i in fake.issues.items()
              if m.REVIEW_LABEL in i["labels"]]
    assert review, "expected the absent critical to be flagged for closure review"

    print(f"\nALL INVARIANTS HOLD — {len(findings)} finding issues (all open), "
          f"{len(summaries)} summaries ({len(summaries) - 1} superseded), "
          f"issue #{review[0]} awaiting human closure review.")
    print(f"Rendered bodies: {OUT}/")


if __name__ == "__main__":
    main()
