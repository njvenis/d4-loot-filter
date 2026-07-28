#!/usr/bin/env python3
"""
qualys_qds_to_github.py

Interim alerting: pull High/Critical vulnerability detections from Qualys VMDR
(by QDS threshold) and raise ONE GitHub issue per vulnerability (QID), listing
all affected assets. Issues are updated as the asset set changes and closed
only when no assets remain at/above the threshold. Idempotent, daily-scheduled,
fully decoupled from Google SecOps — retire once QDS ingestion is fixed there.

Grouping model
--------------
* Issue grain = QID (vulnerability), not host:QID. Each issue carries a table
  of affected assets with per-host QDS (QDS is detection-specific, so the same
  QID can score differently across hosts). The issue's severity band comes
  from the MAX QDS across its assets.
* Dedup key is "qid:<QID>", embedded as a hidden marker in the issue body,
  alongside a fingerprint of the asset set and the affected host-id list.
* Each run reconciles:
    - QID not yet tracked                  -> open a new issue
    - QID tracked, assets/QDS unchanged    -> leave untouched
    - QID tracked, assets/QDS changed      -> update title+body, comment with
                                              what changed, sync severity label
    - QID absent from the pull             -> record absence, then label as a
                                              closure CANDIDATE after the grace
                                              period. Never closed by this job.
* Secondary-rate-limit aware; MAX_ISSUES_PER_RUN caps new-issue creation so a
  large first run drains over several days (updates are not capped — they are
  bounded by the number of open issues).

Everything is configured via environment variables — see README.md.
"""

import os
import sys
import re
import time
import hashlib
import datetime
import logging
import xml.etree.ElementTree as ET

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("qualys-qds-github")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and not val:
        log.error("Missing required environment variable: %s", name)
        sys.exit(2)
    return val


QUALYS_BASE_URL = env("QUALYS_BASE_URL", required=True).rstrip("/")
QUALYS_USERNAME = env("QUALYS_USERNAME", required=True)
QUALYS_PASSWORD = env("QUALYS_PASSWORD", required=True)

GITHUB_TOKEN = env("GITHUB_TOKEN", required=True)
GITHUB_REPO = env("GITHUB_REPO", required=True)  # "owner/repo"

QDS_MIN = int(env("QDS_MIN", "70"))              # 70 = Highs (70-89) + Criticals (90-100)
QDS_MAX = int(env("QDS_MAX", "100"))
STATUSES = env("STATUSES", "Active,New,Re-Opened")  # open detections only

# Stable identity: assets are rebuilt and inherit new Qualys asset IDs, so the
# asset ID must never form part of a finding's identity. Resolve each instance
# to its logical service from Qualys asset tags instead.
SERVICE_TAG_PREFIX = env("SERVICE_TAG_PREFIX", "service:")

# Absence is not remediation. A rebuilt-but-not-yet-rescanned asset is UNKNOWN,
# not clean. This job NEVER closes an issue: it labels a QID that has stayed
# absent beyond the grace period as a closure *candidate* and leaves the
# decision to a human. Grace period should comfortably exceed the scan cycle.
ABSENCE_GRACE_DAYS = int(env("ABSENCE_GRACE_DAYS", "14"))
ABSENT_LABEL = env("ABSENT_LABEL", "qds-absent")
REVIEW_LABEL = env("REVIEW_LABEL", "qds-closure-review")

ISSUE_LABEL = env("ISSUE_LABEL", "qualys-qds")
MAX_ISSUES_PER_RUN = int(env("MAX_ISSUES_PER_RUN", "50"))
MAX_ASSETS_IN_BODY = int(env("MAX_ASSETS_IN_BODY", "50"))
TRACK_ABSENCE = env("TRACK_ABSENCE", "true").lower() == "true"
DRY_RUN = env("DRY_RUN", "false").lower() == "true"

MAX_HOSTS_IN_MARKER = 2000   # beyond this, per-host diffs are skipped

QUALYS_HEADERS = {"X-Requested-With": "qualys-qds-github"}
GITHUB_API = "https://api.github.com"
GITHUB_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

KEY_RE = re.compile(r"qualys-qds-key:\s*(\S+)")
HASH_RE = re.compile(r"qualys-qds-assets-hash:\s*([0-9a-f]+)")
# Stable service/asset keys, not host ids — may contain letters, dots, hyphens.
ASSETS_RE = re.compile(r"qualys-qds-assets:\s*(.*?)\s*-->")
ABSENT_RE = re.compile(r"qualys-qds-absent-since:\s*(\d{4}-\d{2}-\d{2})")


# --------------------------------------------------------------------------- #
# Qualys: Host List Detection API (with QDS) + pagination
# --------------------------------------------------------------------------- #
def qualys_pull():
    """Yield per-detection dicts for all open detections at/above QDS_MIN."""
    url = f"{QUALYS_BASE_URL}/api/2.0/fo/asset/host/vm/detection/"
    params = {
        "action": "list",
        "show_qds": "1",
        "show_qds_factors": "1",
        "qds_min": str(QDS_MIN),
        "qds_max": str(QDS_MAX),
        "status": STATUSES,
        "show_results": "0",
        "show_tags": "1",
        "truncation_limit": "1000",
    }

    session = requests.Session()
    session.auth = (QUALYS_USERNAME, QUALYS_PASSWORD)
    session.headers.update(QUALYS_HEADERS)

    page = 0
    conflict_retries = 0

    while url:
        resp = session.get(url, params=params, timeout=300)
        if resp.status_code == 409:
            # Qualys concurrency limit — back off and retry the SAME request
            # (same url + params; never advance the page or drop the query).
            conflict_retries += 1
            if conflict_retries > 10:
                raise RuntimeError("Qualys 409 concurrency limit persisted after 10 retries")
            log.warning(
                "Qualys concurrency limit (409); sleeping 30s (retry %d/10)",
                conflict_retries,
            )
            time.sleep(30)
            continue
        resp.raise_for_status()
        conflict_retries = 0
        page += 1
        log.info("Fetched Qualys detections page %d", page)

        root = ET.fromstring(resp.content)
        _raise_on_qualys_error(root)
        yield from _parse_detections(root)

        # Follow pagination: <RESPONSE><WARNING><URL>next</URL></WARNING>
        # Qualys pagination URLs carry the full query string, so params are
        # only sent on the first request.
        next_url = root.findtext("./RESPONSE/WARNING/URL")
        url = next_url.strip() if next_url else None
        params = None


def _raise_on_qualys_error(root):
    """Qualys can return HTTP 200 with an error body (SIMPLE_RETURN, or a
    RESPONSE carrying CODE/TEXT). Fail loudly instead of treating it as an
    empty result set."""
    if root.tag == "SIMPLE_RETURN" or root.find("./RESPONSE/CODE") is not None:
        code = root.findtext("./RESPONSE/CODE") or "?"
        text = root.findtext("./RESPONSE/TEXT") or "unknown Qualys error"
        raise RuntimeError(f"Qualys API error {code}: {text}")


def _text(elem, path, default=""):
    return (elem.findtext(path) or default).strip()


def _host_tags(host):
    """Qualys nests tags under TAGS/TAG or TAG_LIST/TAG depending on version."""
    names = []
    for path in ("./TAGS/TAG/NAME", "./TAG_LIST/TAG/NAME"):
        names.extend((e.text or "").strip() for e in host.findall(path))
    return [n for n in names if n]


def _asset_key(tags, dns, netbios, host_id):
    """Stable, rebuild-surviving identity for an instance.

    Preference order: logical service tag -> DNS -> NetBIOS -> asset id.
    Only the last of these breaks on rebuild, so coverage of the service tag
    directly determines how well continuity holds. Commas are stripped because
    the key list is comma-delimited inside the issue marker.
    """
    for t in tags:
        if t.lower().startswith(SERVICE_TAG_PREFIX.lower()):
            svc = t[len(SERVICE_TAG_PREFIX):].strip().lower().replace(",", "")
            if svc:
                return f"svc:{svc}"
    if dns:
        return f"dns:{dns.lower().replace(',', '')}"
    if netbios:
        return f"nb:{netbios.lower().replace(',', '')}"
    return f"id:{host_id}"   # last resort — will churn on rebuild


def _parse_detections(root):
    for host in root.findall("./RESPONSE/HOST_LIST/HOST"):
        host_id = _text(host, "ID")
        ip = _text(host, "IP")
        dns = _text(host, "DNS")
        netbios = _text(host, "NETBIOS")
        os_name = _text(host, "OS")
        host_label = dns or netbios or ip or host_id
        tags = _host_tags(host)
        asset_key = _asset_key(tags, dns, netbios, host_id)

        for det in host.findall("./DETECTION_LIST/DETECTION"):
            qds_elem = det.find("QDS")
            if qds_elem is None or not (qds_elem.text or "").strip():
                continue  # no QDS on this detection; skip
            qds_value = int(qds_elem.text.strip())
            qds_sev = (qds_elem.get("severity") or "").upper() or (
                "CRITICAL" if qds_value >= 90 else "HIGH"
            )

            factors = []
            for f in det.findall("./QDS_FACTORS/QDS_FACTOR"):
                name = f.get("name", "")
                fval = (f.text or "").strip()
                if name and fval:
                    factors.append(f"{name}={fval}")

            yield {
                "asset_key": asset_key,
                "host_id": host_id,
                "host_label": host_label,
                "ip": ip,
                "dns": dns,
                "os": os_name,
                "qid": _text(det, "QID"),
                "type": _text(det, "TYPE"),
                "severity": _text(det, "SEVERITY"),
                "qds": qds_value,
                "qds_severity": qds_sev,
                "qds_factors": factors,
                "status": _text(det, "STATUS"),
                "first_found": _text(det, "FIRST_FOUND_DATETIME"),
                "last_found": _text(det, "LAST_FOUND_DATETIME"),
            }


# --------------------------------------------------------------------------- #
# Grouping: one record per QID, assets nested
# --------------------------------------------------------------------------- #
def group_by_qid(detection_iter):
    """Return {key: group} where key = 'qid:<QID>' and group carries the
    affected-asset map keyed on STABLE asset identity (service tag where
    available), not the Qualys asset id.

    Consequences of the stable key:
      * a rebuilt instance matches its predecessor instead of looking like a
        new asset plus a remediated one;
      * first_found is the earliest across every instance of that service, so
        the age clock survives rebuilds and MTTR means something;
      * multiple live instances of one service collapse to the worst-scoring
        one, which is also what makes multi-port detections collapse.
    """
    groups = {}
    for d in detection_iter:
        key = f"qid:{d['qid']}"
        g = groups.setdefault(key, {
            "key": key,
            "qid": d["qid"],
            "type": d["type"],
            "severity": d["severity"],
            "max_qds": 0,
            "qds_severity": "HIGH",
            "qds_factors": [],
            "assets": {},  # stable asset_key -> asset dict
        })
        prev = g["assets"].get(d["asset_key"])
        if prev is None or d["qds"] > prev["qds"]:
            g["assets"][d["asset_key"]] = {
                "asset_key": d["asset_key"],
                "host_label": d["host_label"],
                "ip": d["ip"],
                "os": d["os"],
                "qds": d["qds"],
                "qds_severity": d["qds_severity"],
                # keep the earliest first_found seen for this asset key
                "first_found": min(
                    filter(None, [d["first_found"], prev["first_found"] if prev else None]),
                    default="",
                ),
                "last_found": d["last_found"],
            }
        elif d["first_found"] and (
            not prev["first_found"] or d["first_found"] < prev["first_found"]
        ):
            # A lower-scoring instance can still carry the earliest sighting.
            prev["first_found"] = d["first_found"]
        if d["qds"] > g["max_qds"]:
            g["max_qds"] = d["qds"]
            g["qds_severity"] = d["qds_severity"]
            g["qds_factors"] = d["qds_factors"]
    return groups


def assets_fingerprint(group):
    """Hash of the affected-asset set + per-asset QDS, used to detect real
    change. Because the keys are stable service identities rather than Qualys
    asset ids, a rebuild does NOT alter this fingerprint — which is the whole
    point: no spurious 'asset added / asset removed' churn every rebuild."""
    parts = sorted(f"{hid}={a['qds']}" for hid, a in group["assets"].items())
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# GitHub helpers
# --------------------------------------------------------------------------- #
def _github_request(method, path, **kwargs):
    """Request with primary + secondary rate-limit handling."""
    url = path if path.startswith("http") else f"{GITHUB_API}{path}"
    for attempt in range(6):
        resp = requests.request(method, url, headers=GITHUB_HEADERS, timeout=60, **kwargs)
        if resp.status_code in (403, 429):
            retry_after = resp.headers.get("Retry-After")
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if retry_after:
                wait = int(retry_after)
            elif remaining == "0":
                reset = int(resp.headers.get("X-RateLimit-Reset", "0"))
                wait = max(reset - int(time.time()), 1)
            else:
                wait = 2 ** attempt  # secondary limit, exponential backoff
            log.warning("GitHub rate limited (%s); waiting %ss", resp.status_code, wait)
            time.sleep(min(wait, 120))
            continue
        return resp
    resp.raise_for_status()
    return resp


def existing_open_issues():
    """Return {key: {number, hash, hosts}} for open issues carrying our label.
    `hosts` is a set of host ids from the marker, or None if unavailable."""
    tracked = {}
    page = 1
    while True:
        resp = _github_request(
            "GET",
            f"/repos/{GITHUB_REPO}/issues",
            params={"labels": ISSUE_LABEL, "state": "open", "per_page": 100, "page": page},
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        for issue in batch:
            if "pull_request" in issue:  # the issues endpoint also returns PRs
                continue
            body = issue.get("body") or ""
            key_m = KEY_RE.search(body)
            if not key_m:
                continue
            hash_m = HASH_RE.search(body)
            assets_m = ASSETS_RE.search(body)
            absent_m = ABSENT_RE.search(body)
            assets = (
                {a for a in assets_m.group(1).split(",") if a}
                if assets_m else None
            )
            tracked[key_m.group(1)] = {
                "number": issue["number"],
                "hash": hash_m.group(1) if hash_m else None,
                "assets": assets,
                "absent_since": absent_m.group(1) if absent_m else None,
                "labels": {l["name"] for l in issue.get("labels", [])},
                "body": body,
            }
        page += 1
    return tracked


def build_issue(group):
    sev = group["qds_severity"]
    assets = sorted(group["assets"].values(), key=lambda a: -a["qds"])
    n = len(assets)
    plural = "s" if n != 1 else ""
    title = (
        f"[Qualys QDS {sev}] QID {group['qid']} — "
        f"{n} affected asset{plural} (max QDS {group['max_qds']})"
    )

    shown = assets[:MAX_ASSETS_IN_BODY]
    rows = "\n".join(
        f"| {a['asset_key']} | {a['host_label']} | {a['ip']} "
        f"| {a['qds']} ({a['qds_severity']}) "
        f"| {a['first_found'] or 'n/a'} | {a['last_found'] or 'n/a'} |"
        for a in shown
    )
    overflow = (
        f"\n\n_...and {n - len(shown)} more asset{'s' if n - len(shown) != 1 else ''} "
        f"— see Qualys for the full list._"
        if n > len(shown) else ""
    )

    factors = "\n".join(f"  - {f}" for f in group["qds_factors"]) or "  - (none returned)"

    asset_keys = sorted(group["assets"])
    if len(asset_keys) <= MAX_HOSTS_IN_MARKER:
        assets_marker = f"<!-- qualys-qds-assets: {','.join(asset_keys)} -->"
    else:
        assets_marker = "<!-- qualys-qds-assets unavailable: asset count exceeds marker cap -->"

    body = f"""**QID:** {group['qid']}  |  **Type:** {group['type']}  |  **Qualys severity:** {group['severity']}
**Max QDS:** {group['max_qds']} ({sev})  |  **Affected assets:** {n}

| Service / asset | Current instance | IP | QDS | First found | Last found |
|---|---|---|---|---|---|
{rows}{overflow}

**QDS contributing factors** (worst-scoring instance)
{factors}

---
_Raised automatically from Qualys VMDR (QDS >= {QDS_MIN}), grouped by vulnerability and keyed on logical service rather than asset id, so rebuilt instances retain continuity. Interim alerting pending SecOps QDS ingestion._
<!-- qualys-qds-key: {group['key']} -->
<!-- qualys-qds-assets-hash: {assets_fingerprint(group)} -->
{assets_marker}
"""
    labels = [ISSUE_LABEL, f"qds-{sev.lower()}"]
    return title, body, labels


def _add_label(number, label):
    _github_request(
        "POST", f"/repos/{GITHUB_REPO}/issues/{number}/labels",
        json={"labels": [label]},
    )


def _remove_label(number, label):
    # 404 when the label is not applied — harmless, and not worth a pre-check.
    _github_request(
        "DELETE", f"/repos/{GITHUB_REPO}/issues/{number}/labels/{label}"
    )


def _sync_severity_label(number, sev):
    """Keep exactly one qds-<band> label without touching human-added labels."""
    want = f"qds-{sev.lower()}"
    other = "qds-high" if want == "qds-critical" else "qds-critical"
    # Add the wanted label (no-op if already present); remove the other band
    # (404 if absent — ignored). Neither is fatal if it fails.
    _github_request(
        "POST", f"/repos/{GITHUB_REPO}/issues/{number}/labels", json={"labels": [want]}
    )
    _github_request("DELETE", f"/repos/{GITHUB_REPO}/issues/{number}/labels/{other}")


def create_issue(group):
    title, body, labels = build_issue(group)
    if DRY_RUN:
        log.info("[dry-run] would create issue: %s", title)
        return
    resp = _github_request(
        "POST",
        f"/repos/{GITHUB_REPO}/issues",
        json={"title": title, "body": body, "labels": labels},
    )
    resp.raise_for_status()
    log.info("Created issue #%s: %s", resp.json()["number"], title)


def update_issue(number, group, prev):
    title, body, _labels = build_issue(group)
    n = len(group["assets"])
    if DRY_RUN:
        log.info("[dry-run] would update issue #%s -> %s", number, title)
        return

    _github_request(
        "PATCH",
        f"/repos/{GITHUB_REPO}/issues/{number}",
        json={"title": title, "body": body},
    ).raise_for_status()
    _sync_severity_label(number, group["qds_severity"])

    if prev.get("assets") is not None:
        current = set(group["assets"])
        added = current - prev["assets"]
        removed = prev["assets"] - current
        bits = []
        if added:
            names = [group["assets"][h]["host_label"] for h in sorted(added)[:5]]
            more = f" (+{len(added) - 5} more)" if len(added) > 5 else ""
            bits.append(f"**{len(added)} new asset(s):** {', '.join(names)}{more}")
        if removed:
            bits.append(
                f"**{len(removed)} asset(s) no longer detected** — note this is "
                f"not confirmation of remediation; an asset awaiting rescan is "
                f"unknown, not clean"
            )
        change = "; ".join(bits) if bits else "per-asset QDS scores changed"
    else:
        change = "asset list or QDS scores changed"

    comment = f"Updated: {change}. Now {n} affected asset(s), max QDS {group['max_qds']}."
    if prev.get("absent_since"):
        clear_absence(number, prev.get("labels", set()))
        comment += (
            f" This vulnerability has reappeared after being absent since "
            f"{prev['absent_since']} — absence tracking cleared."
        )
    _github_request(
        "POST", f"/repos/{GITHUB_REPO}/issues/{number}/comments", json={"body": comment}
    ).raise_for_status()
    log.info("Updated issue #%s (%s)", number, change)


def mark_absent(number, body, today, labels):
    """Record the first run in which a tracked QID dropped out of the pull.

    Absence is NOT remediation: in a rebuild-in-place estate an asset that has
    been rebuilt but not yet rescanned reports nothing, so the vulnerability
    silently disappears and returns on the next scan. This function records the
    observation and nothing else — it never changes issue state.
    """
    if DRY_RUN:
        log.info("[dry-run] would mark issue #%s absent as of %s", number, today)
        return
    new_body = body.rstrip() + f"\n<!-- qualys-qds-absent-since: {today} -->\n"
    _github_request(
        "PATCH", f"/repos/{GITHUB_REPO}/issues/{number}", json={"body": new_body}
    ).raise_for_status()
    if ABSENT_LABEL not in labels:
        _add_label(number, ABSENT_LABEL)
    _github_request(
        "POST",
        f"/repos/{GITHUB_REPO}/issues/{number}/comments",
        json={"body":
              f"Not present in the latest Qualys data. This is **not** treated "
              f"as remediation — an asset awaiting rescan is unknown, not "
              f"clean. The issue stays open. If it is still absent after "
              f"{ABSENCE_GRACE_DAYS} days it will be labelled "
              f"`{REVIEW_LABEL}` for a human to review and close."},
    ).raise_for_status()
    log.info("Marked issue #%s absent as of %s", number, today)


def flag_for_closure_review(number, key, days, labels):
    """Surface a long-absent QID as a closure *candidate*.

    This job does not close issues. Closure is a human decision: someone must
    confirm the affected assets were actually rescanned and came back clean,
    rather than inferring it from silence. Applied once — the label's presence
    is the idempotency guard.
    """
    if REVIEW_LABEL in labels:
        return False
    if DRY_RUN:
        log.info("[dry-run] would flag issue #%s for closure review", number)
        return False
    _add_label(number, REVIEW_LABEL)
    _github_request(
        "POST",
        f"/repos/{GITHUB_REPO}/issues/{number}/comments",
        json={"body":
              f"Absent from Qualys for {days} days (grace period "
              f"{ABSENCE_GRACE_DAYS}). **Candidate for closure — human review "
              f"required.** Before closing, confirm the affected assets have "
              f"actually been rescanned since the vulnerability was last seen; "
              f"absence alone is not evidence of remediation. This job will not "
              f"close the issue."},
    ).raise_for_status()
    log.info("Flagged issue #%s for closure review (absent %d days)", number, days)
    return True


def clear_absence(number, labels):
    """A QID has reappeared — drop the absence labels. The absent-since marker
    is cleared by build_issue simply not emitting it."""
    if DRY_RUN:
        return
    for label in (ABSENT_LABEL, REVIEW_LABEL):
        if label in labels:
            _remove_label(number, label)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    log.info(
        "Pulling Qualys detections QDS %d-%d, statuses [%s]", QDS_MIN, QDS_MAX, STATUSES
    )
    groups = group_by_qid(qualys_pull())
    total_assets = sum(len(g["assets"]) for g in groups.values())
    log.info(
        "Qualys returned %d distinct QIDs at/above threshold across %d asset detections",
        len(groups), total_assets,
    )

    existing = existing_open_issues()
    log.info("Found %d open issues already tracked", len(existing))

    # --- create new QID issues (worst-first, capped) ---
    to_create = [g for k, g in groups.items() if k not in existing]
    to_create.sort(
        key=lambda g: (g["qds_severity"] != "CRITICAL", -g["max_qds"], -len(g["assets"]))
    )
    created = 0
    for g in to_create:
        if created >= MAX_ISSUES_PER_RUN:
            log.warning(
                "Hit MAX_ISSUES_PER_RUN (%d); %d remaining will be created next run",
                MAX_ISSUES_PER_RUN, len(to_create) - created,
            )
            break
        create_issue(g)
        created += 1

    # --- update tracked QID issues whose asset set / scores changed, or
    #     which are reappearing after a period of absence ------------------
    updated = 0
    for key, g in groups.items():
        prev = existing.get(key)
        if not prev:
            continue
        changed = prev["hash"] != assets_fingerprint(g)
        returning = prev.get("absent_since") is not None
        if changed or returning:
            # `returning` alone still triggers a rewrite: build_issue omits the
            # absent-since marker, which is how the timer gets cleared.
            update_issue(prev["number"], g, prev)
            updated += 1

    # --- absence handling ---------------------------------------------------
    # This job NEVER closes an issue. Absence is recorded, and a long-absent
    # QID is labelled as a closure candidate for a human to act on.
    today = datetime.date.today()
    marked_absent = 0
    flagged = 0
    if TRACK_ABSENCE:
        if not groups and existing:
            # Safety valve: an empty pull alongside open issues almost always
            # means a broken pull (auth/params/subscription), not mass
            # remediation. Do not mark or flag anything.
            log.warning(
                "Qualys returned 0 detections but %d issues are open; "
                "skipping absence handling this run as a safety measure",
                len(existing),
            )
        else:
            for key, meta in existing.items():
                if key in groups:
                    continue
                labels = meta.get("labels", set())
                since = meta.get("absent_since")
                if since is None:
                    mark_absent(meta["number"], meta["body"], today.isoformat(), labels)
                    marked_absent += 1
                    continue
                try:
                    since_date = datetime.date.fromisoformat(since)
                except ValueError:
                    log.warning(
                        "Issue #%s has an unparseable absent-since marker (%r); "
                        "resetting the timer",
                        meta["number"], since,
                    )
                    mark_absent(meta["number"], meta["body"], today.isoformat(), labels)
                    continue
                days = (today - since_date).days
                if days >= ABSENCE_GRACE_DAYS:
                    if flag_for_closure_review(meta["number"], key, days, labels):
                        flagged += 1

    log.info(
        "Done. created=%d updated=%d unchanged=%d marked_absent=%d "
        "flagged_for_review=%d (issues are never closed automatically)",
        created, updated, len(groups) - len(to_create) - updated,
        marked_absent, flagged,
    )


if __name__ == "__main__":
    main()
