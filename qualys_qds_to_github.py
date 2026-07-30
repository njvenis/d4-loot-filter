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


def _validate_base_url(raw):
    """QUALYS_BASE_URL must be the API SERVER only — scheme + host.

    Pasting a full endpoint URL is an easy mistake, and the failure is
    baffling: the code appends its own path, so a base already carrying
    '?action=list' produces 'action=list/api/2.0/...' and Qualys replies
    'parameter action has invalid value'. Catch it here instead.
    """
    from urllib.parse import urlparse

    cleaned = (raw or "").strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or not parsed.netloc:
        log.error(
            "QUALYS_BASE_URL must be an https URL for your Qualys POD, e.g. "
            "https://qualysapi.qg2.apps.qualys.com — got %r", raw,
        )
        sys.exit(2)
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        log.error(
            "QUALYS_BASE_URL must be the API server ONLY — no path, no query "
            "string. Got %r.\n"
            "  Use:  https://%s\n"
            "  The endpoint path and parameters are added by this script; "
            "including them here produces the confusing Qualys error "
            "'parameter action has invalid value'.",
            raw, parsed.netloc,
        )
        sys.exit(2)
    return cleaned


QUALYS_BASE_URL = _validate_base_url(env("QUALYS_BASE_URL", required=True))
QUALYS_USERNAME = env("QUALYS_USERNAME", required=True)
QUALYS_PASSWORD = env("QUALYS_PASSWORD", required=True)

GITHUB_TOKEN = env("GITHUB_TOKEN", required=True)
GITHUB_REPO = env("GITHUB_REPO", required=True)  # "owner/repo"

QDS_MIN = int(env("QDS_MIN", "70"))              # 70 = Highs (70-89) + Criticals (90-100)
QDS_MAX = int(env("QDS_MAX", "100"))
STATUSES = env("STATUSES", "Active,New,Re-Opened")  # open detections only

# Split timeouts. A single total timeout makes an unreachable host (IP
# allow-listing silently dropping packets, no route from the runner) look
# exactly like a slow large pull until the whole window expires. A short
# connect timeout surfaces that in seconds; the long read timeout still allows
# genuinely big responses.
CONNECT_TIMEOUT = int(env("QUALYS_CONNECT_TIMEOUT", "15"))
# Generous by default: Qualys builds the ENTIRE page server-side before sending
# a single byte, and with stream=True this timeout measures the gap between
# bytes — so on a large subscription the wait for first byte is the whole
# generation time. Too short a value here reads as "connection timed out" when
# nothing is actually wrong.
READ_TIMEOUT = int(env("QUALYS_READ_TIMEOUT", "900"))

# Detections per page. Lower = faster first byte per page and far less likely
# to time out, at the cost of more round trips. Reduce this before raising the
# read timeout — it attacks the cause rather than the symptom.
TRUNCATION_LIMIT = env("QUALYS_TRUNCATION_LIMIT", "1000")

# ---- scoping filters (server-side) ----------------------------------------
# NOTE: the criteria were specified in QQL (tags.name:"..."), but this v2 XML
# API does not accept QQL. Tag criteria map exactly onto the endpoint's tag
# parameters. Deliberately NO freshness/check-in filter: the API's closest
# proxy (vm_processed_after) keys on data-processing time, not agent check-in,
# and would make live assets vanish — poisoning the absence signals the
# closure-review queue depends on.
TAG_INCLUDE = env("TAG_INCLUDE", "Env: PROD")
TAG_EXCLUDE = env("TAG_EXCLUDE", "FPS-bootmgmt,Bastions,bootmgmt,Desktop")

# Desktop assets: excluded from findings entirely (not tracked internally),
# but reported in their own clearly-titled daily summary with no child tickets.
DESKTOP_TAG = env("DESKTOP_TAG", "Desktop")
DESKTOP_SUMMARY = env("DESKTOP_SUMMARY", "true").lower() == "true"

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
SUMMARY_LABEL = env("SUMMARY_LABEL", "qds-summary")
SUMMARY_MARKER_PREFIX = "<!-- qualys-qds-summary"


def _summary_marker(scope):
    """Scope-specific marker so the estate and desktop summaries supersede
    independently — today's desktop summary must never close the estate one."""
    return f"<!-- qualys-qds-summary:{scope} -->"

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
def _detection_params(tag_include, tag_exclude):
    """Build the Host List Detection query, translating the QQL-style intent
    into this endpoint's native parameters:

      tags.name:"X" (include)      -> use_tags=1&tag_set_by=name&tag_set_include=X
      not tags.name:"Y" (exclude)  -> tag_set_exclude=Y (selector 'any': having
                                      ANY excluded tag drops the asset)
    """
    params = {
        "action": "list",
        "show_qds": "1",
        "show_qds_factors": "1",
        "qds_min": str(QDS_MIN),
        "qds_max": str(QDS_MAX),
        "status": STATUSES,
        "show_results": "0",
        "show_tags": "1",
        "truncation_limit": TRUNCATION_LIMIT,
    }
    if tag_include or tag_exclude:
        params["use_tags"] = "1"
        params["tag_set_by"] = "name"
        if tag_include:
            params["tag_include_selector"] = "any"
            params["tag_set_include"] = tag_include
        if tag_exclude:
            params["tag_exclude_selector"] = "any"
            params["tag_set_exclude"] = tag_exclude
    return params


def qualys_pull(tag_include=None, tag_exclude=None):
    """Yield per-detection dicts for open detections at/above QDS_MIN within
    the tag scope. Defaults to the estate scope (TAG_INCLUDE / TAG_EXCLUDE);
    pass explicit values for other scopes (e.g. the Desktop summary pull)."""
    tag_include = TAG_INCLUDE if tag_include is None else tag_include
    tag_exclude = TAG_EXCLUDE if tag_exclude is None else tag_exclude
    url = f"{QUALYS_BASE_URL}/api/2.0/fo/asset/host/vm/detection/"
    params = _detection_params(tag_include, tag_exclude)
    log.info(
        "Scope: include tags [%s], exclude tags [%s]",
        tag_include or "-", tag_exclude or "-",
    )

    session = requests.Session()
    session.auth = (QUALYS_USERNAME, QUALYS_PASSWORD)
    session.headers.update(QUALYS_HEADERS)

    page = 0
    conflict_retries = 0

    while url:
        log.info(
            "Requesting page %d from Qualys (connect timeout %ds, read timeout "
            "%ds) — large estates can take several minutes for the first page",
            page + 1, CONNECT_TIMEOUT, READ_TIMEOUT,
        )
        started = time.monotonic()
        log.info(
            "  (Qualys builds the full page before sending; expect no output "
            "until generation completes)"
        )
        try:
            resp = session.get(
                url,
                params=params,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                stream=True,
            )
        except requests.exceptions.ConnectTimeout:
            raise RuntimeError(
                f"Could not connect to Qualys within {CONNECT_TIMEOUT}s. This is "
                f"usually network reachability, not credentials — check whether "
                f"the Qualys API is IP allow-listed (Users -> Setup -> Security) "
                f"and whether this host's egress IP is permitted."
            ) from None
        except requests.exceptions.ReadTimeout:
            raise RuntimeError(
                f"Connected to Qualys, but no data arrived within {READ_TIMEOUT}s "
                f"(page {page + 1}, truncation_limit={TRUNCATION_LIMIT}). Qualys "
                f"builds the whole page before sending anything, so this is "
                f"usually generation time on a large subscription rather than a "
                f"broken connection. In order of preference:\n"
                f"  1. Smaller pages:  QUALYS_TRUNCATION_LIMIT=200\n"
                f"  2. Narrower scope: QDS_MIN=90 (criticals only)\n"
                f"  3. More patience:  QUALYS_READ_TIMEOUT=1800\n"
                f"Combining 1 and 2 is usually enough."
            ) from None
        except requests.exceptions.SSLError as exc:
            raise RuntimeError(
                f"TLS failure talking to Qualys: {exc}. Usually QUALYS_BASE_URL "
                f"is wrong (it must be your POD hostname, e.g. "
                f"https://qualysapi.qg2.apps.qualys.com — not an IP), or a "
                f"TLS-inspecting proxy is in the path."
            ) from None
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                f"Could not reach Qualys: {exc}. Check QUALYS_BASE_URL, DNS, and "
                f"any proxy; if the host is correct, this is usually IP "
                f"allow-listing (Users -> Setup -> Security) blocking this "
                f"machine's egress IP."
            ) from None
        if resp.status_code == 409:
            # Blocked by a subscription limit. Qualys tells us which, and how
            # long to wait — honour that rather than guessing. Retry the SAME
            # request (same url + params; never advance the page or drop the
            # query). Concurrency errors take precedence over rate-limit ones.
            q = _quota(resp)
            conflict_retries += 1
            if conflict_retries > 10:
                raise RuntimeError(
                    f"Qualys kept returning 409 after 10 retries "
                    f"(concurrency {q['conc_running']}/{q['conc_limit']}, "
                    f"rate remaining {q['remaining']}). Another integration is "
                    f"likely consuming this subscription's API quota; stagger "
                    f"the schedule or ask Qualys Support to review the limits."
                )
            concurrent = (
                q["conc_running"] is not None and q["conc_limit"] is not None
                and q["conc_running"] >= q["conc_limit"]
            )
            wait = q["to_wait"] if q["to_wait"] is not None else 30
            wait = max(1, min(wait, 300))
            log.warning(
                "Qualys 409 (%s limit); waiting %ds as instructed by Qualys "
                "(retry %d/10)",
                "concurrency" if concurrent else "rate",
                wait, conflict_retries,
            )
            time.sleep(wait)
            continue
        resp.raise_for_status()
        conflict_retries = 0
        page += 1
        _log_quota(_quota(resp), page)

        # Stream so a multi-megabyte page reports progress rather than sitting
        # silent. Without this, "no output" is ambiguous between working and hung.
        chunks, received, next_mark = [], 0, 2_000_000
        first_byte = None
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            if first_byte is None:
                first_byte = time.monotonic() - started
                log.info(
                    "  first byte after %.1fs (server-side generation time)",
                    first_byte,
                )
            chunks.append(chunk)
            received += len(chunk)
            if received >= next_mark:
                log.info("  ...page %d: %.1f MB received", page, received / 1e6)
                next_mark += 2_000_000
        content = b"".join(chunks)
        elapsed = time.monotonic() - started

        root = ET.fromstring(content)
        _raise_on_qualys_error(root)

        stats = {}
        detections = list(_parse_detections(root, stats))
        hosts = stats["hosts"]
        log.info(
            "Page %d complete: %d hosts, %d detections at/above threshold, "
            "%.1f MB in %.1fs (%.1fs waiting, %.1fs transferring)",
            page, hosts, len(detections), received / 1e6, elapsed,
            first_byte or 0.0, elapsed - (first_byte or 0.0),
        )
        if first_byte and first_byte > READ_TIMEOUT * 0.6:
            log.warning(
                "Generation took %.0fs of a %ds read timeout — lower "
                "QUALYS_TRUNCATION_LIMIT (currently %s) before this starts "
                "failing intermittently",
                first_byte, READ_TIMEOUT, TRUNCATION_LIMIT,
            )
        if stats["detections"]:
            log.info(
                "  of %d detection(s) on this page: %d carried QDS, %d did not",
                stats["detections"], stats["with_qds"], stats["without_qds"],
            )
        if hosts and not detections:
            if stats["detections"] and not stats["with_qds"]:
                log.error(
                    "Page %d: %d detections returned but NONE carried a <QDS> "
                    "element. The subscription is not returning QDS — either "
                    "TruRisk/QDS is not enabled on it, or this API account "
                    "cannot see it. The whole job depends on QDS; raise it with "
                    "Qualys Support. Run scripts/check_connectivity.py --sample "
                    "to confirm.",
                    page, stats["detections"],
                )
            elif not stats["detections"]:
                log.warning(
                    "Page %d: %d host(s) returned but zero detections. Either "
                    "qds_min=%d filtered everything server-side, or the API "
                    "account's asset scope has no matching findings.",
                    page, hosts, QDS_MIN,
                )
        yield from detections

        # Follow pagination: <RESPONSE><WARNING><URL>next</URL></WARNING>
        # Qualys pagination URLs carry the full query string, so params are
        # only sent on the first request.
        next_url = root.findtext("./RESPONSE/WARNING/URL")
        url = next_url.strip() if next_url else None
        params = None
        if url:
            log.info("More results available — following pagination to page %d", page + 1)
        else:
            log.info("Pagination complete after %d page(s)", page)


def _quota(resp):
    """Qualys exposes subscription quota on every response (all APIs except
    session login/logout). Documented headers:
      X-RateLimit-Limit / -Window-Sec / -Remaining / -ToWait-Sec
      X-Concurrency-Limit-Limit / -Running
    """
    h = resp.headers

    def num(name):
        try:
            return int(h[name])
        except (KeyError, TypeError, ValueError):
            return None

    return {
        "limit": num("X-RateLimit-Limit"),
        "window": num("X-RateLimit-Window-Sec"),
        "remaining": num("X-RateLimit-Remaining"),
        "to_wait": num("X-RateLimit-ToWait-Sec"),
        "conc_limit": num("X-Concurrency-Limit-Limit"),
        "conc_running": num("X-Concurrency-Limit-Running"),
    }


def _log_quota(q, page):
    bits = []
    if q["remaining"] is not None and q["limit"] is not None:
        bits.append(f"rate {q['remaining']}/{q['limit']} left"
                    + (f" per {q['window']}s" if q["window"] else ""))
    if q["conc_running"] is not None and q["conc_limit"] is not None:
        bits.append(f"concurrency {q['conc_running']}/{q['conc_limit']}")
    if bits:
        log.info("  quota after page %d: %s", page, "; ".join(bits))
    if q["remaining"] is not None and q["limit"] and q["remaining"] <= max(1, q["limit"] // 10):
        log.warning(
            "Qualys rate limit nearly exhausted (%d of %d remaining) — other "
            "integrations may be sharing this subscription's quota",
            q["remaining"], q["limit"],
        )


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


def _parse_detections(root, stats=None):
    """Yield detections. `stats` (optional dict) is updated in place so the
    caller can distinguish 'no detections returned' from 'detections returned
    but none carried QDS' — those have completely different fixes."""
    if stats is None:
        stats = {}
    for key in ("hosts", "detections", "with_qds", "without_qds"):
        stats.setdefault(key, 0)

    for host in root.findall("./RESPONSE/HOST_LIST/HOST"):
        stats["hosts"] += 1
        host_id = _text(host, "ID")
        ip = _text(host, "IP")
        dns = _text(host, "DNS")
        netbios = _text(host, "NETBIOS")
        os_name = _text(host, "OS")
        host_label = dns or netbios or ip or host_id
        tags = _host_tags(host)
        asset_key = _asset_key(tags, dns, netbios, host_id)

        for det in host.findall("./DETECTION_LIST/DETECTION"):
            stats["detections"] += 1
            qds_elem = det.find("QDS")
            if qds_elem is None or not (qds_elem.text or "").strip():
                stats["without_qds"] += 1
                continue  # no QDS on this detection; skip
            stats["with_qds"] += 1
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

            port = _text(det, "PORT")
            protocol = _text(det, "PROTOCOL")
            endpoint = f"{port}/{protocol.lower()}" if port and protocol else (port or "")

            yield {
                "asset_key": asset_key,
                "endpoint": endpoint,
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
        endpoints = set(prev["endpoints"]) if prev else set()
        if d.get("endpoint"):
            endpoints.add(d["endpoint"])
        if prev is None or d["qds"] > prev["qds"]:
            g["assets"][d["asset_key"]] = {
                "asset_key": d["asset_key"],
                "host_label": d["host_label"],
                "ip": d["ip"],
                "os": d["os"],
                "qds": d["qds"],
                "qds_severity": d["qds_severity"],
                "endpoints": endpoints,
                # keep the earliest first_found seen for this asset key
                "first_found": min(
                    filter(None, [d["first_found"], prev["first_found"] if prev else None]),
                    default="",
                ),
                "last_found": d["last_found"],
            }
        else:
            # Lower-scoring instance: still contributes its endpoints and can
            # carry the earliest sighting.
            prev["endpoints"] = endpoints
            if d["first_found"] and (
                not prev["first_found"] or d["first_found"] < prev["first_found"]
            ):
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
    parts = sorted(
        f"{hid}={a['qds']}@{';'.join(sorted(a['endpoints']))}"
        for hid, a in group["assets"].items()
    )
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


def _pre_table(headers, rows):
    """Aligned fixed-width text table for use inside a code fence.

    Rendered monospaced by GitHub, so columns stay aligned however wide the
    window — the 'preformatted table' the team reads."""
    data = [list(headers)] + [[str(c) for c in r] for r in rows]
    widths = [max(len(row[i]) for row in data) for i in range(len(headers))]

    def fmt(row):
        return "  ".join(str(c).ljust(w) for c, w in zip(row, widths)).rstrip()

    sep = "  ".join("-" * w for w in widths)
    return "\n".join([fmt(headers), sep] + [fmt(r) for r in rows])


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
    table = _pre_table(
        ("SERVICE/ASSET", "INSTANCE", "IP", "ENDPOINTS", "QDS", "FIRST FOUND", "LAST FOUND"),
        [
            (
                a["asset_key"],
                a["host_label"],
                a["ip"],
                ",".join(sorted(a["endpoints"])) or "-",
                f"{a['qds']} ({a['qds_severity']})",
                a["first_found"] or "n/a",
                a["last_found"] or "n/a",
            )
            for a in shown
        ],
    )
    overflow = (
        f"\n_...and {n - len(shown)} more asset{'s' if n - len(shown) != 1 else ''} "
        f"— see Qualys for the full list._"
        if n > len(shown) else ""
    )
    table_block = "```\n" + table + "\n```" + overflow

    factors = "\n".join(f"  - {f}" for f in group["qds_factors"]) or "  - (none returned)"

    asset_keys = sorted(group["assets"])
    if len(asset_keys) <= MAX_HOSTS_IN_MARKER:
        assets_marker = f"<!-- qualys-qds-assets: {','.join(asset_keys)} -->"
    else:
        assets_marker = "<!-- qualys-qds-assets unavailable: asset count exceeds marker cap -->"

    body = f"""**QID:** {group['qid']}  |  **Type:** {group['type']}  |  **Qualys severity:** {group['severity']}
**Max QDS:** {group['max_qds']} ({sev})  |  **Affected assets:** {n}

{table_block}

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


def find_open_summaries(scope):
    """Open issues carrying the summary label AND this scope's marker."""
    resp = _github_request(
        "GET",
        f"/repos/{GITHUB_REPO}/issues",
        params={"labels": SUMMARY_LABEL, "state": "open", "per_page": 100},
    )
    resp.raise_for_status()
    out = []
    for issue in resp.json():
        if "pull_request" in issue:
            continue
        body = issue.get("body") or ""
        if _summary_marker(scope) in body:
            out.append((issue["number"], body))
    return out


def _close_summary_issue(number, body, superseded_by):
    """The ONLY closure path in this job, by design.

    Finding issues are never closed by automation — closing a finding asserts
    remediation, and that judgement belongs to a human. A daily summary is the
    job's own report artifact, not a finding, so closing yesterday's when
    today's is published is housekeeping, not a remediation claim. The marker
    check makes it structurally impossible to route a finding through this
    path: no marker, no close, regardless of labels.
    """
    if SUMMARY_MARKER_PREFIX not in (body or ""):
        log.error(
            "Refusing to close issue #%s: summary marker missing — "
            "this job never closes finding issues",
            number,
        )
        return False
    if DRY_RUN:
        log.info("[dry-run] would close superseded summary #%s", number)
        return False
    _github_request(
        "POST",
        f"/repos/{GITHUB_REPO}/issues/{number}/comments",
        json={"body": f"Superseded by today's summary: #{superseded_by}."},
    ).raise_for_status()
    _github_request(
        "PATCH", f"/repos/{GITHUB_REPO}/issues/{number}", json={"state": "closed"}
    ).raise_for_status()
    log.info("Closed superseded summary #%s", number)
    return True


def build_summary(groups, existing, today, scope="estate"):
    """The day's report for one scope. Estate: everything tracked, with links
    to per-vuln issues and the absent section. Desktop: informational only —
    Desktop assets are not tracked internally, so no per-vuln issues exist and
    the title says so unmistakably."""
    desktop = scope == "desktop"
    ordered = sorted(
        groups.values(),
        key=lambda g: (g["qds_severity"] != "CRITICAL", -g["max_qds"], -len(g["assets"])),
    )
    ncrit = sum(1 for g in ordered if g["qds_severity"] == "CRITICAL")
    nhigh = len(ordered) - ncrit
    nassets = sum(len(g["assets"]) for g in ordered)

    rows = []
    for g in ordered:
        meta = existing.get(g["key"])
        first = min(
            filter(None, (a["first_found"] for a in g["assets"].values())),
            default="n/a",
        )
        endpoints = sum(len(a["endpoints"]) for a in g["assets"].values())
        rows.append((
            g["qid"],
            g["qds_severity"],
            g["max_qds"],
            len(g["assets"]),
            endpoints or "-",
            first,
            "not tracked" if desktop else (
                f"#{meta['number']}" if meta else "new this run"),
        ))
    table = _pre_table(
        ("QID", "BAND", "MAX QDS", "ASSETS", "ENDPOINTS", "FIRST FOUND", "ISSUE"),
        rows,
    ) if rows else "(nothing currently tracked at/above threshold)"

    absent_rows = []
    for key, meta in sorted(existing.items()):
        if key in groups or not key.startswith("qid:"):
            continue
        absent_rows.append((
            key.removeprefix("qid:"),
            f"#{meta['number']}",
            meta.get("absent_since") or today,
            "yes" if REVIEW_LABEL in meta.get("labels", set()) else "not yet",
        ))
    absent_block = ""
    if absent_rows and not desktop:
        absent_table = _pre_table(
            ("QID", "ISSUE", "ABSENT SINCE", "CLOSURE REVIEW"), absent_rows
        )
        absent_block = (
            "\n**Tracked but absent from the latest pull** — not confirmed "
            "remediated; closure remains a human decision:\n\n```\n"
            + absent_table + "\n```\n"
        )

    if desktop:
        title = f"Qualys QDS daily summary — DESKTOP ASSETS — {today}"
        headline = (
            f"**Desktop assets at/above threshold (QDS >= {QDS_MIN}):** "
            f"{len(ordered)} vulnerabilities ({ncrit} critical, {nhigh} high) "
            f"across {nassets} assets"
        )
        scope_note = (
            "\n**Desktop assets are not tracked internally** — this summary is "
            "informational only and **no per-vulnerability tickets are "
            "raised** for anything listed here.\n"
        )
    else:
        title = f"Qualys QDS daily summary — {today}"
        headline = (
            f"**Tracked at/above threshold (QDS >= {QDS_MIN}):** "
            f"{len(ordered)} vulnerabilities ({ncrit} critical, {nhigh} high) "
            f"across {nassets} assets"
        )
        scope_note = ""
    body = f"""**Date:** {today}
{headline}
{scope_note}

```
{table}
```
{absent_block}
---
_Published daily; yesterday's summary for this scope is closed as superseded — the only closure this job ever performs. Finding closure is a human decision._
{_summary_marker(scope)}
"""
    return title, body


def publish_summary(groups, existing, today, scope="estate"):
    """Create today's summary issue for one scope, then close that scope's
    previous open summaries as superseded. Publish-then-close, so a failure
    between the two steps leaves an extra open summary (self-corrects next
    run) rather than no summary."""
    title, body = build_summary(groups, existing, today, scope)
    previous = find_open_summaries(scope)
    if DRY_RUN:
        log.info(
            "[dry-run] would publish summary '%s' and close %d superseded",
            title, len(previous),
        )
        return
    labels = [SUMMARY_LABEL] + (["qds-desktop"] if scope == "desktop" else [])
    resp = _github_request(
        "POST",
        f"/repos/{GITHUB_REPO}/issues",
        json={"title": title, "body": body, "labels": labels},
    )
    resp.raise_for_status()
    new_number = resp.json()["number"]
    log.info("Published %s daily summary issue #%s", scope, new_number)
    for number, prev_body in previous:
        _close_summary_issue(number, prev_body, new_number)


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

    # --- daily summary (single rolling issue, rewritten each run) ---------
    if not groups and existing:
        log.warning("Skipping summary update this run (empty-pull safety)")
    else:
        publish_summary(groups, existing, today.isoformat(), scope="estate")

    # --- desktop summary: separate pull, informational only, no findings ---
    if DESKTOP_SUMMARY:
        log.info(
            "Desktop pass: pulling assets tagged '%s' (no per-vuln issues "
            "will be raised for these)", DESKTOP_TAG,
        )
        desktop_groups = group_by_qid(
            qualys_pull(tag_include=DESKTOP_TAG, tag_exclude="")
        )
        log.info(
            "Desktop pass: %d distinct QIDs across %d asset detections",
            len(desktop_groups),
            sum(len(g["assets"]) for g in desktop_groups.values()),
        )
        publish_summary(desktop_groups, {}, today.isoformat(), scope="desktop")

    log.info(
        "Done. created=%d updated=%d unchanged=%d marked_absent=%d "
        "flagged_for_review=%d (issues are never closed automatically)",
        created, updated, len(groups) - len(to_create) - updated,
        marked_absent, flagged,
    )


if __name__ == "__main__":
    main()
