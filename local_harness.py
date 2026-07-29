#!/usr/bin/env python3
"""
local_harness.py — run the full job end-to-end with NO GitHub access.

GitHub is replaced by an in-memory fake; nothing is written anywhere except
rendered issue bodies under ./local_out/. Two modes:

  python scripts/local_harness.py
      Fully offline: fixture Qualys data, includes a synthetic "spread" day
      to exercise the update path.

  python scripts/local_harness.py --live [--qds-min 90] [--max-qids 10] [--redact]
      REAL Qualys pull (needs QUALYS_* env vars), fake GitHub. The scenario is
      derived from whatever the pull returns, so it works on any estate:

        run 1  baseline           create per-vuln issues + first summary
        run 2  identical re-pull  IDEMPOTENCY CHECK: asserts zero creates and
                                  zero updates — proves fingerprints/markers
                                  are stable against your real data
        run 3  top QID dropped    absence marking (simulated rebuild)
        run 4  still absent       closure-review flag (grace forced to 0)

      Also reports SERVICE-TAG COVERAGE: what fraction of affected assets
      resolve to svc:/dns:/nb:/id: keys. High id: means poor rebuild
      continuity — those are the assets to tag in Qualys.

Real-data cautions (live mode):
  * ./local_out/ then contains real hostnames, IPs and vulnerability detail.
    The directory is created 0700 and is git/cursor-ignored; delete it when
    done, or pass --redact to pseudonymise hostnames/IPs in the dumps.
  * Use the least-privileged Qualys account that works; --qds-min 90 and
    --max-qids keep the first run small.
"""

import argparse
import os
import re
import sys
import pathlib
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "local_out"

ap = argparse.ArgumentParser()
ap.add_argument("--live", action="store_true",
                help="pull the baseline from the real Qualys API (GitHub stays fake)")
ap.add_argument("--qds-min", type=int, default=None,
                help="override QDS_MIN for this run (e.g. 90 for criticals only)")
ap.add_argument("--max-qids", type=int, default=None,
                help="cap the baseline to the N worst QIDs (keeps first live runs small)")
ap.add_argument("--redact", action="store_true",
                help="pseudonymise hostnames/IPs in dumped issue bodies")
args = ap.parse_args()

# Env must be set before the module import reads it.
if args.qds_min is not None:
    os.environ["QDS_MIN"] = str(args.qds_min)
for var, val in {
    "QUALYS_BASE_URL": "https://qualys.invalid",
    "QUALYS_USERNAME": "harness",
    "QUALYS_PASSWORD": "harness",
    "GITHUB_TOKEN": "harness",
    "GITHUB_REPO": "local/harness",
}.items():
    os.environ.setdefault(var, val)

if args.live and os.environ["QUALYS_BASE_URL"].startswith("https://qualys.invalid"):
    sys.exit("--live needs real QUALYS_BASE_URL / QUALYS_USERNAME / QUALYS_PASSWORD "
             "in the environment (inject from your keychain or password-manager CLI; "
             "don't type the password inline).")

import qualys_qds_to_github as m  # noqa: E402

# The prod per-run creation cap would break the idempotency check on large
# estates (leftovers create on run 2). Uncap for simulation.
m.MAX_ISSUES_PER_RUN = 10 ** 9


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
        self.issues = {}
        self.comments = defaultdict(list)
        self.next_number = 1

    def request(self, method, path, **kw):
        body = kw.get("json") or {}
        params = kw.get("params") or {}

        if re.fullmatch(r"/repos/[^/]+/[^/]+/issues", path):
            if method == "GET":
                if int(params.get("page", 1)) > 1:
                    return FakeResponse([])
                label = params.get("labels")
                state = params.get("state", "open")
                return FakeResponse([
                    {"number": n, "title": i["title"], "body": i["body"],
                     "state": i["state"],
                     "labels": [{"name": l} for l in sorted(i["labels"])]}
                    for n, i in sorted(self.issues.items())
                    if i["state"] == state and (not label or label in i["labels"])
                ])
            if method == "POST":
                n = self.next_number
                self.next_number += 1
                self.issues[n] = {"title": body.get("title", ""),
                                  "body": body.get("body", ""),
                                  "labels": set(body.get("labels", [])),
                                  "state": "open"}
                return FakeResponse({"number": n})

        if (x := re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)", path)) and method == "PATCH":
            issue = self.issues[int(x.group(1))]
            for field in ("title", "body", "state"):
                if field in body:
                    issue[field] = body[field]
            return FakeResponse({})

        if (x := re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)/comments", path)) and method == "POST":
            self.comments[int(x.group(1))].append(body.get("body", ""))
            return FakeResponse({})

        if (x := re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)/labels", path)) and method == "POST":
            self.issues[int(x.group(1))]["labels"].update(body.get("labels", []))
            return FakeResponse({})

        if (x := re.fullmatch(r"/repos/[^/]+/[^/]+/issues/(\d+)/labels/(.+)", path)) and method == "DELETE":
            labels = self.issues[int(x.group(1))]["labels"]
            if x.group(2) in labels:
                labels.discard(x.group(2))
                return FakeResponse({})
            return FakeResponse({}, status=404)

        raise AssertionError(f"fake GitHub has no route for {method} {path}")

    def findings(self):
        return {n: i for n, i in self.issues.items() if m.KEY_RE.search(i["body"])}

    def dump(self, tag, redact=None):
        OUT.mkdir(exist_ok=True)
        os.chmod(OUT, 0o700)
        for n, issue in sorted(self.issues.items()):
            text = (f"# [{issue['state']}] {issue['title']}\n"
                    f"labels: {sorted(issue['labels'])}\n\n{issue['body']}\n"
                    + "".join(f"\n> comment: {c}\n" for c in self.comments[n]))
            if redact:
                text = redact(text)
            (OUT / f"{tag}-issue-{n:03d}.md").write_text(text)

    def table(self, redact=None):
        rows = [(n, i["state"], ",".join(sorted(i["labels"])),
                 (redact(i["title"]) if redact else i["title"])[:70])
                for n, i in sorted(self.issues.items())]
        width = max((len(r[2]) for r in rows), default=6)
        lines = [f"{'#':>3}  {'STATE':6}  {'LABELS':{width}}  TITLE"]
        lines += [f"{n:>3}  {s:6}  {l:{width}}  {t}" for n, s, l, t in rows]
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Baseline feeds and real-data helpers
# --------------------------------------------------------------------------- #
def fixture_detections():
    xml = (ROOT / "tests" / "fixtures" / "qualys_sample.xml").read_text()
    return list(m._parse_detections(ET.fromstring(xml)))


def limit_to_top_qids(dets, n):
    worst = defaultdict(int)
    for d in dets:
        worst[d["qid"]] = max(worst[d["qid"]], d["qds"])
    keep = {q for q, _ in sorted(worst.items(), key=lambda kv: -kv[1])[:n]}
    return [d for d in dets if d["qid"] in keep]


def coverage_report(dets):
    """Service-tag coverage across unique assets — the rebuild-continuity metric."""
    label_by_key = {d["asset_key"]: d["host_label"] for d in dets}
    counts = Counter(k.split(":", 1)[0] for k in label_by_key)
    total = len(label_by_key)
    print(f"\n=== asset identity coverage ({total} unique assets) ===")
    meaning = {"svc": "service tag (survives rebuild)",
               "dns": "DNS fallback (survives if hostnames are stable)",
               "nb": "NetBIOS fallback",
               "id": "Qualys asset id (CHURNS on rebuild)"}
    for kind in ("svc", "dns", "nb", "id"):
        if counts.get(kind):
            print(f"  {kind:>4}: {counts[kind]:>5}  ({counts[kind]/total:5.1%})  {meaning[kind]}")
    if counts.get("id"):
        offenders = [v for k, v in label_by_key.items() if k.startswith("id:")][:5]
        print(f"  -> tag these in Qualys to gain continuity: {', '.join(offenders)}"
              + (" ..." if counts["id"] > 5 else ""))


def build_redactor(dets):
    """Consistent pseudonyms for hostnames/IPs so dumps can be shared.
    Logical service names (svc:*) are left readable."""
    mapping = {}
    hosts, ips = set(), set()
    for d in dets:
        for v in (d["host_label"], d["ip"]):
            (ips if re.fullmatch(r"[\d.]+", v or "") else hosts).add(v)
        if d["asset_key"].split(":", 1)[0] in ("dns", "nb"):
            hosts.add(d["asset_key"].split(":", 1)[1])
    for i, h in enumerate(sorted(filter(None, hosts)), 1):
        mapping[h] = f"host-{i:03d}"
    for i, ip in enumerate(sorted(filter(None, ips)), 1):
        mapping[ip] = f"ip-{i:03d}"

    def redact(text):
        for real, fake in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(real, fake)
        return text

    return redact


# --------------------------------------------------------------------------- #
# Scenario
# --------------------------------------------------------------------------- #
def main():
    fake = FakeGitHub()
    m._github_request = fake.request      # the only GitHub touchpoint

    base = list(m.qualys_pull()) if args.live else fixture_detections()
    if not base:
        sys.exit("Baseline feed is empty — nothing to simulate. "
                 "(Live: check QDS_MIN and the API account's asset visibility.)")
    if args.max_qids:
        base = limit_to_top_qids(base, args.max_qids)

    coverage_report(base)
    redact = build_redactor(base) if args.redact else None

    # Generic scenario derived from the baseline — works on any estate.
    top_qid = max(base, key=lambda d: d["qds"])["qid"]
    dropped = [d for d in base if d["qid"] != top_qid]
    runs = [("baseline", base),
            ("idempotency (identical re-pull)", base)]
    if not args.live:
        spread = list(base)
        seed = base[0]
        spread.append(dict(seed, endpoint="9443/tcp"))
        runs.append(("spread (synthetic endpoint)", spread))
    runs += [(f"absence (QID {top_qid} dropped)", dropped),
             ("closure-review flag (grace elapsed)", dropped)]

    snapshot = None
    for i, (label, feed) in enumerate(runs, 1):
        if label.startswith("closure-review"):
            m.ABSENCE_GRACE_DAYS = 0
        m.qualys_pull = lambda f=feed: iter(f)
        print(f"\n=== run {i}: {label} ===")
        m.main()
        fake.dump(f"run{i}", redact)

        if label == "baseline":
            snapshot = {n: (v["body"], len(fake.comments[n]))
                        for n, v in fake.findings().items()}
        elif label.startswith("idempotency"):
            now = {n: (v["body"], len(fake.comments[n]))
                   for n, v in fake.findings().items()}
            assert now == snapshot, (
                "IDEMPOTENCY BROKEN: identical data changed finding issues — "
                "a fingerprint or marker is unstable against this data")
            print("    idempotency holds: identical pull produced no finding changes")

    print(f"\n=== final issue state ===\n{fake.table(redact)}")

    findings = fake.findings()
    closed = [i for i in fake.issues.values() if i["state"] == "closed"]
    open_summaries = [i for i in fake.issues.values()
                      if m.SUMMARY_MARKER in i["body"] and i["state"] == "open"]
    qids = [m.KEY_RE.search(i["body"]).group(1) for i in findings.values()]

    assert all(i["state"] == "open" for i in findings.values()), \
        "INVARIANT BROKEN: a finding issue was closed"
    assert all(m.SUMMARY_MARKER in i["body"] for i in closed), \
        "INVARIANT BROKEN: something closed without the summary marker"
    assert len(open_summaries) == 1, "INVARIANT BROKEN: expected one open summary"
    assert len(qids) == len(set(qids)), "INVARIANT BROKEN: duplicate issue per QID"
    assert any(m.REVIEW_LABEL in i["labels"] for i in fake.issues.values()), \
        "expected the dropped QID to be flagged for closure review"

    print(f"\nALL INVARIANTS HOLD — {len(findings)} finding issues (all open), "
          f"{len(closed)} superseded summaries, idempotency verified.")
    print(f"Rendered bodies: {OUT}/"
          + ("" if redact else
             "  [contains real asset/vuln detail in --live mode — delete when done, "
             "or re-run with --redact]" if args.live else ""))


if __name__ == "__main__":
    main()
