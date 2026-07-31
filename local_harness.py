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
import time
import re
import sys
import pathlib
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

def _find_root(start):
    """Locate the repo root by looking for the job module itself.

    Works whether this harness lives in scripts/ or sits directly at the repo
    root — never assume a fixed depth, because that silently resolves to the
    parent directory and then hunts for .env in the wrong place.
    """
    here = pathlib.Path(start).resolve()
    for candidate in (here.parent, *here.parents):
        if (candidate / "qualys_qds_to_github.py").exists():
            return candidate
    return here.parent          # fall back to the script's own directory


ROOT = _find_root(__file__)
sys.path.insert(0, str(ROOT))
OUT = ROOT / "local_out"

ap = argparse.ArgumentParser()
ap.add_argument("--live", action="store_true",
                help="pull the baseline from the real Qualys API (GitHub stays fake)")
ap.add_argument("--qds-min", type=int, default=None,
                help="override QDS_MIN for this run (e.g. 90 for criticals only)")
ap.add_argument("--max-qids", type=int, default=None,
                help="cap the baseline to the N worst QIDs (keeps first live runs small)")
ap.add_argument("--runs", type=int, default=0,
                help="limit the simulation to the first N daily runs "
                     "(e.g. --runs 1 for a single day, 2 summaries)")
ap.add_argument("--redact", action="store_true",
                help="pseudonymise hostnames/IPs in dumped issue bodies")
ap.add_argument("-v", "--verbose", action="store_true",
                help="DEBUG logging, including urllib3 connection detail")
ap.add_argument("--check-env", action="store_true",
                help="parse the env file, report what resolved (passwords masked), exit")
ap.add_argument("--env-file", default=".env",
                help="file of KEY=VALUE credential lines to load (default: .env). "
                     "Already-exported variables always win.")
args = ap.parse_args()


def _expected_env_keys():
    """Derive recognised variable names from the job module's SOURCE (read as
    text, so no import ordering problem). Deriving beats maintaining a second
    list here — the duplicate went stale the moment the tag variables were
    added, and warned about names that were perfectly valid."""
    try:
        src = (ROOT / "qualys_qds_to_github.py").read_text(encoding="utf-8")
    except OSError:
        return set()
    return set(re.findall(r'env\(\s*"([A-Z][A-Z0-9_]*)"', src))


EXPECTED_ENV_KEYS = _expected_env_keys()

# Curly quotes, as inserted by GUI editors with smart-quote substitution on.
_SMART_QUOTES = str.maketrans({"\u201c": '"', "\u201d": '"',
                              "\u2018": "'", "\u2019": "'"})
_VALID_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _load_dotenv(path, check=False):
    """Minimal stdlib .env loader — dev harness only.

    Deliberately NOT used by qualys_qds_to_github.py: the job must take its
    config from the process environment alone, so that in CI the ONLY source of
    credentials is repo secrets. If the job read .env files, a stray committed
    .env could silently override them.

    Never overrides an already-set variable, so a keychain/password-manager
    injection takes precedence over the file.

    Tolerates the ways GUI editors mangle files: UTF-8 BOM, CRLF, smart quotes,
    stray whitespace. Anything it still cannot parse is reported rather than
    silently skipped — a credential file that half-loads is worse than one that
    fails loudly.
    """
    f = pathlib.Path(path)
    if not f.is_absolute():
        f = ROOT / f
    if not f.exists():
        if check:
            print(f"Repo root resolved to: {ROOT}")
            print(f"No env file at {f}")
            print("Create it there, or pass --env-file /absolute/path/to/.env")
        return

    mode = f.stat().st_mode
    if mode & 0o077:
        print(f"WARNING: {f} is readable beyond your user account "
              f"(mode {mode & 0o777:o}). Run: chmod 600 {f}", file=sys.stderr)

    # utf-8-sig transparently strips a BOM if present.
    text = f.read_text(encoding="utf-8-sig")

    loaded, skipped, report = [], [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            skipped.append((lineno, "no '=' on this line"))
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().translate(_SMART_QUOTES)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]

        if not _VALID_KEY.match(key):
            skipped.append((
                lineno,
                f"malformed variable name {key!r} — often an invisible "
                f"character from a GUI editor",
            ))
            continue
        if key not in EXPECTED_ENV_KEYS:
            # Environment variable names are case-sensitive, so 'tag_include'
            # is silently a DIFFERENT variable from 'TAG_INCLUDE' and the job
            # never sees it. Catch that specifically — it is by far the most
            # common form of this mistake.
            match = next((k for k in EXPECTED_ENV_KEYS if k.lower() == key.lower()),
                         None)
            if match:
                print(f"ERROR: {f.name} line {lineno}: {key!r} should be "
                      f"{match!r} — environment variable names are "
                      f"case-sensitive, so {key!r} is never read.",
                      file=sys.stderr)
                sys.exit(2)
            skipped.append((lineno, f"unrecognised variable {key!r} — typo? "
                                    f"(recognised names are derived from the "
                                    f"job's own env() calls)"))
            # still set it; the warning is enough
        if key in os.environ:
            report.append((key, "already set in shell — file value ignored"))
            continue
        os.environ[key] = val
        loaded.append(key)
        masked = (val[:4] + "…" + f"({len(val)} chars)") if "PASSWORD" in key or "TOKEN" in key else val
        report.append((key, masked))

    if loaded:
        print(f"Loaded {len(loaded)} variable(s) from {f.name}: {', '.join(loaded)}")
    for lineno, why in skipped:
        print(f"WARNING: {f.name} line {lineno}: {why}", file=sys.stderr)

    if check:
        print(f"\nRepo root resolved to: {ROOT}")
        print(f"=== parsed from {f} ===")
        for key, shown in report:
            print(f"  {key:<20} {shown}")
        missing = [k for k in ("QUALYS_BASE_URL", "QUALYS_USERNAME", "QUALYS_PASSWORD")
                   if k not in os.environ or not os.environ[k]]
        if missing:
            print(f"\nMISSING/EMPTY: {', '.join(missing)} — --live will refuse to run.")
        else:
            print("\nAll three Qualys variables resolved. --live is ready.")
        sys.exit(0)


_load_dotenv(args.env_file, check=args.check_env)

# Env must be set before the module import reads it.
if args.qds_min is not None:
    os.environ["QDS_MIN"] = str(args.qds_min)
for var, val in {
    "QUALYS_BASE_URL": "https://qualys.invalid",
    "QUALYS_USERNAME": "harness",
    "QUALYS_PASSWORD": "harness",
    "GITHUB_TOKEN": "harness",
    "GITHUB_REPO": "local/harness",
    "TAG_INCLUDE": "Env: PROD",
    "TAG_EXCLUDE": "FPS-bootmgmt,Bastions,bootmgmt,DESKTOP",
    "DESKTOP_TAG": "DESKTOP",
}.items():
    os.environ.setdefault(var, val)

if args.live and os.environ["QUALYS_BASE_URL"].startswith("https://qualys.invalid"):
    sys.exit("--live needs real QUALYS_BASE_URL / QUALYS_USERNAME / QUALYS_PASSWORD "
             "in the environment (inject from your keychain or password-manager CLI; "
             "don't type the password inline).")

import qualys_qds_to_github as m  # noqa: E402
import datetime as _dt  # noqa: E402


class _ClockDate(_dt.date):
    """date.today() under our control, so each simulated run is its own day."""
    current = _dt.date.today()

    @classmethod
    def today(cls):
        return cls.current


class _FakeDatetime:
    """Stand-in for the job's `datetime` module: only date.today() is faked."""
    date = _ClockDate
    datetime = _dt.datetime
    timedelta = _dt.timedelta
    timezone = _dt.timezone


def _set_clock(day_offset):
    _ClockDate.current = _dt.date.today() + _dt.timedelta(days=day_offset)
    return _ClockDate.current

if args.verbose:
    import logging
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("urllib3").setLevel(logging.DEBUG)
    m.log.setLevel(logging.DEBUG)

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
    """Parse the fixture, then split it the way the SERVER-side tag filters
    would: the desk1 host stands in for tag 'Desktop' (excluded from the
    estate scope, sole member of the desktop scope)."""
    xml = (ROOT / "tests" / "fixtures" / "qualys_sample.xml").read_text()
    dets = list(m._parse_detections(ET.fromstring(xml)))
    estate = [d for d in dets if not d["host_label"].startswith("desk")]
    desktop = [d for d in dets if d["host_label"].startswith("desk")]
    return estate, desktop


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

    desktop_feed = []
    if args.live:
        print(f"Pulling live from {os.environ['QUALYS_BASE_URL']} "
              f"as {os.environ['QUALYS_USERNAME']} (QDS_MIN={os.environ.get('QDS_MIN', '70')})")
        print("Contacting Qualys — first page can take minutes on a large "
              "estate; progress is logged per page.\n")
        t0 = time.monotonic()
        base = list(m.qualys_pull())
        print(f"\nPull complete: {len(base)} detections in "
              f"{time.monotonic() - t0:.1f}s")
        desktop_feed = list(m.qualys_pull(tag_include=m.DESKTOP_TAG,
                                          tag_exclude=""))
        print(f"Desktop scope: {len(desktop_feed)} detections")
    else:
        base, desktop_feed = fixture_detections()
    if not base:
        sys.exit(
            "Baseline feed is empty — nothing to simulate.\n"
            "Diagnose it with:  python scripts/check_connectivity.py --sample\n"
            "That pulls an UNFILTERED sample and shows the QDS distribution, "
            "which separates the three causes:\n"
            "  * no detections at all      -> API account cannot see assets\n"
            "  * detections but no QDS     -> TruRisk/QDS not enabled (Qualys case)\n"
            "  * QDS present, all below 70 -> the threshold is simply too high")
    if args.max_qids:
        base = limit_to_top_qids(base, args.max_qids)

    coverage_report(base)
    redact = build_redactor(base) if args.redact else None

    # Generic scenario derived from the baseline — works on any estate.
    top_qid = max(base, key=lambda d: d["qds"])["qid"]
    dropped = [d for d in base if d["qid"] != top_qid]
    # (label, feed, day offset) — the clock advances so summaries carry
    # distinct dates and the absence grace period elapses for real rather
    # than being forced to zero.
    runs = [("baseline", base, 0),
            ("idempotency (identical re-pull)", base, 1)]
    day = 2
    if not args.live:
        spread = list(base)
        seed = base[0]
        spread.append(dict(seed, endpoint="9443/tcp"))
        runs.append(("spread (synthetic endpoint)", spread, day))
        day += 1
    runs.append((f"absence (QID {top_qid} dropped)", dropped, day))
    runs.append(("closure-review (grace period elapsed)", dropped,
                 day + m.ABSENCE_GRACE_DAYS + 1))

    if args.runs:
        runs = runs[:max(1, args.runs)]
        print(f"(limited to {len(runs)} run(s) via --runs)")

    m.datetime = _FakeDatetime          # job now reads the controlled clock
    snapshot = None
    for i, (label, feed, offset) in enumerate(runs, 1):
        stamped = _set_clock(offset)
        m.qualys_pull = (
            lambda tag_include=None, tag_exclude=None, f=feed:
            iter(desktop_feed if tag_include == m.DESKTOP_TAG else f)
        )
        print(f"\n=== run {i} of {len(runs)} — simulated date {stamped} — {label} ===")
        m.main()
        fake.dump(f"run{i}", redact)

        if label == "baseline":
            snapshot = {n: (v["body"], len(fake.comments[n]))
                        for n, v in fake.findings().items()}
        elif label.startswith("idempotency") and snapshot is not None:
            now = {n: (v["body"], len(fake.comments[n]))
                   for n, v in fake.findings().items()}
            assert now == snapshot, (
                "IDEMPOTENCY BROKEN: identical data changed finding issues — "
                "a fingerprint or marker is unstable against this data")
            print("    idempotency holds: identical pull produced no finding changes")

    print(f"\n=== final issue state ===\n{fake.table(redact)}")

    findings = fake.findings()
    closed = [i for i in fake.issues.values() if i["state"] == "closed"]
    summaries = {n: i for n, i in fake.issues.items()
                 if m.SUMMARY_MARKER_PREFIX in i["body"]}
    qids = [m.KEY_RE.search(i["body"]).group(1) for i in findings.values()]

    assert all(i["state"] == "open" for i in findings.values()), \
        "INVARIANT BROKEN: a finding issue was closed"
    assert all(m.SUMMARY_MARKER_PREFIX in i["body"] for i in closed), \
        "INVARIANT BROKEN: something closed without the summary marker"
    for scope in ("estate", "desktop"):
        n_open = sum(1 for i in summaries.values()
                     if i["state"] == "open"
                     and m._summary_marker(scope) in i["body"])
        assert n_open == 1, (f"INVARIANT BROKEN: expected exactly one open "
                             f"{scope} summary, got {n_open}")
    assert len(qids) == len(set(qids)), "INVARIANT BROKEN: duplicate issue per QID"
    if len(runs) >= 5:
        assert any(m.REVIEW_LABEL in i["labels"] for i in fake.issues.values()), \
            "expected the dropped QID to be flagged for closure review"

    # Desktop-only QIDs are summary-only: never a finding issue.
    estate_qids = {d["qid"] for d in base}
    desktop_only = {d["qid"] for d in desktop_feed} - estate_qids
    finding_qids = {q.removeprefix("qid:") for q in qids}
    assert not (finding_qids & desktop_only), \
        "INVARIANT BROKEN: a desktop-only QID has a finding issue"
    desk_open = next(i for i in summaries.values()
                     if i["state"] == "open"
                     and m._summary_marker("desktop") in i["body"])
    assert "DESKTOP ASSETS" in desk_open["title"], \
        "desktop summary title is not clearly marked"

    print(f"\nALL INVARIANTS HOLD — {len(findings)} finding issue(s), all open.")
    print(f"  {len(runs)} simulated daily runs x 2 scopes (estate + desktop) = "
          f"{len(runs) * 2} summaries;")
    print(f"  {len(closed)} superseded and closed, 2 left open (today's, one per "
          f"scope). In production this is ONE run per day: one estate summary "
          f"and one desktop summary published, yesterday's pair closed.")
    print("  Idempotency verified: an identical re-pull changed no finding issue.")
    print(f"Rendered bodies: {OUT}/"
          + ("" if redact else
             "  [contains real asset/vuln detail in --live mode — delete when done, "
             "or re-run with --redact]" if args.live else ""))


if __name__ == "__main__":
    main()
