"""Unit tests for the grouping, fingerprint and issue-rendering logic.

These cover the parts most likely to break silently: per-QID grouping,
worst-instance collapse, change detection, and the hidden markers the
idempotency depends on.
"""
import copy

import pytest

import qualys_qds_to_github as m


def det(host_id, qid, qds, asset_key=None, endpoint="", tags=None, **kw):
    base = dict(
        asset_key=asset_key or f"id:{host_id}",
        endpoint=endpoint,
        tags=tags or [],
        flag_matches=sorted({m._FLAG_LOOKUP[(tg or "").lower()]
                             for tg in (tags or [])
                             if (tg or "").lower() in m._FLAG_LOOKUP}),
        host_id=host_id, host_label=f"host{host_id}", ip=f"10.0.0.{host_id}",
        dns=f"host{host_id}", os="Ubuntu", qid=qid, type="Confirmed",
        severity="4", qds=qds,
        qds_severity="CRITICAL" if qds >= 90 else "HIGH",
        qds_factors=[f"EPSS={qds/100}"], status="Active",
        first_found="2026-06-01", last_found="2026-07-21",
    )
    base.update(kw)
    return base


@pytest.fixture
def groups():
    return m.group_by_qid(iter([
        det("1", "100", 78),                      # same host, two ports:
        det("1", "100", 91, qds_factors=["EPSS=0.9", "exploit=public"]),
        det("2", "100", 74),
        det("3", "200", 85),
    ]))


def test_groups_by_qid_not_by_host(groups):
    assert set(groups) == {"qid:100", "qid:200"}


def test_multi_port_instances_collapse_to_worst_per_host(groups):
    g = groups["qid:100"]
    assert len(g["assets"]) == 2
    assert g["assets"]["id:1"]["qds"] == 91


def test_band_follows_max_qds_across_assets(groups):
    g = groups["qid:100"]
    assert g["max_qds"] == 91
    assert g["qds_severity"] == "CRITICAL"
    assert g["qds_factors"] == ["EPSS=0.9", "exploit=public"]


def test_issue_title_and_labels(groups):
    title, _body, labels = m.build_issue(groups["qid:100"])
    assert "QID 100" in title and "2 affected assets" in title
    assert "max QDS 91" in title and "CRITICAL" in title
    assert labels == ["qualys-qds", "qds-critical"]

    title2, _b, labels2 = m.build_issue(groups["qid:200"])
    assert "1 affected asset (max QDS 85)" in title2   # singular
    assert labels2 == ["qualys-qds", "qds-high"]


def test_markers_round_trip_through_the_regexes(groups):
    g = groups["qid:100"]
    _t, body, _l = m.build_issue(g)
    assert m.KEY_RE.search(body).group(1) == "qid:100"
    assert m.HASH_RE.search(body).group(1) == m.assets_fingerprint(g)
    assert set(m.ASSETS_RE.search(body).group(1).split(",")) == {"id:1", "id:2"}
    # a freshly built body must never carry an absence marker
    assert m.ABSENT_RE.search(body) is None


def test_absent_marker_parses_when_present():
    body = "x\n<!-- qualys-qds-absent-since: 2026-07-01 -->\n"
    assert m.ABSENT_RE.search(body).group(1) == "2026-07-01"


# --------------------------------------------------------------------------- #
# Rebuild continuity — assets are rebuilt and inherit new Qualys asset ids.
# Identity must survive that, or the age clock resets every rebuild cycle.
# --------------------------------------------------------------------------- #
def test_service_tag_takes_precedence_over_ephemeral_identifiers():
    tags = ["env:prod", "service:payments-api", "owner:core"]
    assert m._asset_key(tags, "i-0a3f92b", "NB", "9911") == "svc:payments-api"


def test_asset_key_falls_back_through_dns_then_id():
    assert m._asset_key([], "web1.example", "NB1", "77") == "dns:web1.example"
    assert m._asset_key([], "", "NB1", "77") == "nb:nb1"
    assert m._asset_key([], "", "", "77") == "id:77"


def test_rebuild_with_new_asset_id_does_not_change_the_fingerprint():
    """The whole point: same service, new Qualys asset id -> same finding."""
    before = m.group_by_qid(iter([
        det("500", "300", 88, asset_key="svc:payments-api",
            first_found="2026-01-05", last_found="2026-07-01"),
    ]))["qid:300"]
    after = m.group_by_qid(iter([
        det("999", "300", 88, asset_key="svc:payments-api",
            first_found="2026-07-20", last_found="2026-07-22"),
    ]))["qid:300"]

    assert m.assets_fingerprint(before) == m.assets_fingerprint(after)
    assert list(after["assets"]) == ["svc:payments-api"]


def test_earliest_first_found_survives_across_instances():
    """Age clock must reflect the oldest sighting, not the newest rebuild."""
    g = m.group_by_qid(iter([
        det("1", "400", 75, asset_key="svc:api", first_found="2026-02-01"),
        det("2", "400", 95, asset_key="svc:api", first_found="2026-01-01"),
        det("3", "400", 80, asset_key="svc:api", first_found="2026-03-01"),
    ]))["qid:400"]
    assert g["assets"]["svc:api"]["first_found"] == "2026-01-01"
    assert g["assets"]["svc:api"]["qds"] == 95


def test_fingerprint_is_stable_but_detects_change(groups):
    g = groups["qid:100"]
    fp = m.assets_fingerprint(g)

    assert m.assets_fingerprint(copy.deepcopy(g)) == fp        # stable

    drift = copy.deepcopy(g)
    drift["assets"]["id:2"]["qds"] = 90
    assert m.assets_fingerprint(drift) != fp                   # QDS drift

    added = copy.deepcopy(g)
    added["assets"]["id:9"] = dict(g["assets"]["id:2"], asset_key="id:9")
    assert m.assets_fingerprint(added) != fp                   # new asset

    removed = copy.deepcopy(g)
    del removed["assets"]["id:2"]
    assert m.assets_fingerprint(removed) != fp                 # remediated


def test_asset_table_overflow_is_capped(groups, monkeypatch):
    big = copy.deepcopy(groups["qid:100"])
    for i in range(10, 30):
        big["assets"][f"id:{i}"] = dict(big["assets"]["id:2"], asset_key=f"id:{i}", host_label=f"host{i}")
    monkeypatch.setattr(m, "MAX_ASSETS_IN_BODY", 5)
    _t, body, _l = m.build_issue(big)
    assert body.count("10.0.0.") == 5
    assert "more asset" in body


def test_qualys_error_body_raises_rather_than_looking_empty():
    import xml.etree.ElementTree as ET
    err = ET.fromstring(
        "<SIMPLE_RETURN><RESPONSE><CODE>1905</CODE>"
        "<TEXT>Bad parameter</TEXT></RESPONSE></SIMPLE_RETURN>"
    )
    with pytest.raises(RuntimeError, match="1905"):
        m._raise_on_qualys_error(err)


def test_1904_error_carries_tag_guidance():
    import xml.etree.ElementTree as ET
    err = ET.fromstring(
        "<SIMPLE_RETURN><RESPONSE><CODE>1904</CODE>"
        "<TEXT>none of the scannable assets match selected tags</TEXT>"
        "</RESPONSE></SIMPLE_RETURN>"
    )
    with pytest.raises(RuntimeError, match="TAG SCOPE"):
        m._raise_on_qualys_error(err)


def test_detection_without_qds_is_skipped():
    import xml.etree.ElementTree as ET
    xml = ET.fromstring("""
    <RESPONSE_ROOT><RESPONSE><HOST_LIST><HOST>
      <ID>1</ID><IP>10.0.0.1</IP><DNS>h1</DNS>
      <DETECTION_LIST>
        <DETECTION><QID>1</QID></DETECTION>
        <DETECTION><QID>2</QID><QDS severity="HIGH">80</QDS></DETECTION>
      </DETECTION_LIST>
    </HOST></HOST_LIST></RESPONSE></RESPONSE_ROOT>""")
    out = list(m._parse_detections(xml))
    assert [d["qid"] for d in out] == ["2"]


# --------------------------------------------------------------------------- #
# Closure is a human decision. These guard against autonomous closing being
# reintroduced by a well-meaning refactor.
# --------------------------------------------------------------------------- #
def test_module_exposes_no_generic_close_function():
    assert not hasattr(m, "close_issue")
    assert hasattr(m, "_close_summary_issue")   # the sole, guarded exception


def test_closure_exists_only_inside_the_summary_close_path():
    """One closure call site in the whole module, and it lives in the function
    whose first act is to verify the summary marker. Findings cannot reach it."""
    import inspect
    module_src = inspect.getsource(m)
    fn_src = inspect.getsource(m._close_summary_issue)
    assert module_src.count('"state": "closed"') == 1
    assert '"state": "closed"' in fn_src
    assert "'state': 'closed'" not in module_src


def test_summary_close_refuses_bodies_without_the_marker():
    """A finding body routed at the close path is rejected before any API call
    (a network attempt against the dummy test host would raise)."""
    assert m._close_summary_issue(123, "some finding body, no marker", 999) is False
    assert m._close_summary_issue(124, "", 999) is False
    assert m._close_summary_issue(125, None, 999) is False


def test_absence_helpers_exist_instead():
    assert hasattr(m, "mark_absent")
    assert hasattr(m, "flag_for_closure_review")
    assert hasattr(m, "clear_absence")


# --------------------------------------------------------------------------- #
# Endpoints and the preformatted rendering
# --------------------------------------------------------------------------- #
def test_endpoints_aggregate_across_ports_on_one_asset():
    g = m.group_by_qid(iter([
        det("1", "500", 78, asset_key="svc:web", endpoint="443/tcp"),
        det("1", "500", 91, asset_key="svc:web", endpoint="8443/tcp"),
    ]))["qid:500"]
    a = g["assets"]["svc:web"]
    assert a["endpoints"] == {"443/tcp", "8443/tcp"}   # both survive the collapse
    assert a["qds"] == 91                               # worst instance still wins


def test_new_endpoint_changes_fingerprint():
    base = m.group_by_qid(iter([
        det("1", "500", 80, asset_key="svc:web", endpoint="443/tcp"),
    ]))["qid:500"]
    widened = m.group_by_qid(iter([
        det("1", "500", 80, asset_key="svc:web", endpoint="443/tcp"),
        det("1", "500", 80, asset_key="svc:web", endpoint="8443/tcp"),
    ]))["qid:500"]
    assert m.assets_fingerprint(base) != m.assets_fingerprint(widened)


def test_pre_table_alignment_and_separator():
    out = m._pre_table(("A", "LONGHEADER"), [("xxxx", "y"), ("z", "wwwww")])
    lines = out.splitlines()
    assert lines[0].startswith("A     LONGHEADER")     # padded to widest cell
    assert set(lines[1]) <= {"-", " "}                 # separator row
    assert lines[2].startswith("xxxx  y")


def test_issue_body_uses_code_fenced_table(groups):
    _t, body, _l = m.build_issue(groups["qid:100"])
    assert "```" in body
    assert "SERVICE/ASSET" in body and "ENDPOINTS" in body
    assert "|---|" not in body                          # no markdown table


# --------------------------------------------------------------------------- #
# Daily summary
# --------------------------------------------------------------------------- #
def test_summary_lists_tracked_and_absent(groups):
    existing = {
        "qid:100": {"number": 7, "hash": "x", "assets": None,
                    "absent_since": None, "labels": set(), "body": ""},
        "qid:999": {"number": 42, "hash": "y", "assets": None,
                    "absent_since": "2026-07-10",
                    "labels": {"qds-closure-review"}, "body": ""},
    }
    title, body = m.build_summary(groups, existing, "2026-07-29")
    assert "2026-07-29" in title
    assert "#7" in body                    # tracked QID links its issue
    assert "pending" in body               # qid:200 has no issue yet
    assert "1 NEW vulnerability today" in body
    assert "999" in body and "#42" in body # absent section present
    assert "2026-07-10" in body
    assert m._summary_marker("estate") in body
    assert "1 critical, 1 high" in body


def test_summary_handles_empty_estate():
    _t, body = m.build_summary({}, {}, "2026-07-29")
    assert "nothing currently tracked" in body


# --------------------------------------------------------------------------- #
# Scoping filters and the desktop summary
# --------------------------------------------------------------------------- #
def test_detection_params_translate_tag_criteria(monkeypatch):
    monkeypatch.setattr(m, "TAG_SET_BY", "name")
    params = m._detection_params("Env: PROD",
                                 "FPS-bootmgmt,Bastions,bootmgmt,Desktop")
    assert params["use_tags"] == "1" and params["tag_set_by"] == "name"
    assert params["tag_set_include"] == "Env: PROD"
    assert params["tag_set_exclude"] == "FPS-bootmgmt,Bastions,bootmgmt,Desktop"
    assert params["tag_exclude_selector"] == "any"   # ANY excluded tag drops the asset
    assert "vm_processed_after" not in params        # no freshness filter, by design


def test_tag_lists_are_normalised_but_inner_spaces_survive():
    params = m._detection_params(" Env: PROD ", "FPS-bootmgmt, Bastions ,bootmgmt,,Desktop")
    assert params["tag_set_include"] == "Env: PROD"     # inner space kept
    assert params["tag_set_exclude"] == "FPS-bootmgmt,Bastions,bootmgmt,Desktop"


def test_name_mode_is_the_default():
    params = m._detection_params("Env: PROD", "A,B")
    assert params["tag_set_by"] == "name"                   # module default


def test_id_mode_builds_the_lists(monkeypatch):
    monkeypatch.setattr(m, "TAG_SET_BY", "id")
    params = m._detection_params("12345", "67890, 67891 ,,67892")
    assert params["tag_set_by"] == "id"
    assert params["tag_set_include"] == "12345"
    assert params["tag_set_exclude"] == "67890,67891,67892" # normalised


def test_tag_list_builder():
    assert m._tag_list(" 101 ,202,, 303 ") == "101,202,303"
    assert m._tag_list("") == "" and m._tag_list(None) == ""
    assert m._tag_list("Env: PROD, X") == "Env: PROD,X"     # inner space kept


def test_id_mode_rejects_leftover_names(monkeypatch):
    monkeypatch.setattr(m, "TAG_SET_BY", "id")
    monkeypatch.setattr(m, "TAG_INCLUDE", "Env: PROD")      # a name, not an id
    monkeypatch.setattr(m, "TAG_EXCLUDE", "201,202")
    monkeypatch.setattr(m, "DESKTOP_TAG", "301")
    with pytest.raises(SystemExit):
        m._validate_tag_config()


def test_desktop_summary_requires_a_tag(monkeypatch):
    monkeypatch.setattr(m, "TAG_SET_BY", "id")
    monkeypatch.setattr(m, "TAG_INCLUDE", "101")
    monkeypatch.setattr(m, "TAG_EXCLUDE", "")
    monkeypatch.setattr(m, "DESKTOP_TAG", "")
    monkeypatch.setattr(m, "DESKTOP_SUMMARY", True)
    with pytest.raises(SystemExit):
        m._validate_tag_config()


def test_detection_params_without_tags():
    params = m._detection_params("", "")
    assert "use_tags" not in params
    assert "vm_processed_after" not in params


def test_desktop_summary_is_unmistakably_desktop(groups):
    title, body = m.build_summary(groups, {}, "2026-07-30", scope="desktop")
    assert "DESKTOP ASSETS" in title
    assert "not tracked internally" in body
    assert "no per-vulnerability tickets are raised" in body
    assert "not tracked" in body           # the ISSUE column
    assert m._summary_marker("desktop") in body
    assert m._summary_marker("estate") not in body


def test_summary_scopes_supersede_independently():
    """A desktop marker must not satisfy the estate scope's finder, and vice
    versa — otherwise publishing one scope closes the other's summary."""
    est = m._summary_marker("estate")
    desk = m._summary_marker("desktop")
    assert est != desk
    assert est.startswith(m.SUMMARY_MARKER_PREFIX)
    assert desk.startswith(m.SUMMARY_MARKER_PREFIX)
    # close guard accepts both scopes (they are summaries)...
    assert m._close_summary_issue(1, "finding body", 2) is False
    # ...but the scope markers do not match each other
    assert desk not in est and est not in desk


def test_query_encoding_keeps_commas_literal_exactly_once():
    """The docs' {tag1,tag2} samples use bare commas; %2C broke the call."""
    import requests as rq
    params = m._detection_params("12345", "67890,67891,67892")
    query = m._encode_query(params)
    assert "tag_set_exclude=67890,67891,67892" in query
    assert "%2C" not in query and "%252C" not in query
    # and requests must not re-encode the pre-built string
    url = rq.Request("GET", "https://x.example/api", params=query).prepare().url
    assert "67890,67891,67892" in url and "%2C" not in url


def test_pre_encoded_config_is_refused(monkeypatch):
    monkeypatch.setattr(m, "TAG_SET_BY", "name")
    monkeypatch.setattr(m, "TAG_INCLUDE", "101")
    monkeypatch.setattr(m, "TAG_EXCLUDE", "201%2C202")   # the classic mistake
    monkeypatch.setattr(m, "DESKTOP_TAG", "301")
    with pytest.raises(SystemExit):
        m._validate_tag_config()


# --------------------------------------------------------------------------- #
# The REAL qualys_pull signature.
#
# The local harness monkeypatches m.qualys_pull with a stub, so a green harness
# run proves nothing about the real function's parameters — a stale stub and a
# stale signature produce identical symptoms. Exercise the real one here.
# --------------------------------------------------------------------------- #
def _fake_http(monkeypatch, captured):
    XML = (b'<?xml version="1.0"?><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE>'
           b'<HOST_LIST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>')

    class Resp:
        status_code = 200
        headers = {}
        def raise_for_status(self): pass
        def iter_content(self, chunk_size=0): yield XML

    class Session:
        auth = None
        headers = {}
        def get(self, url, params=None, **kw):
            captured["params"] = params
            return Resp()

    monkeypatch.setattr(m.requests, "Session", lambda: Session())


def test_real_qualys_pull_accepts_scope_kwargs(monkeypatch):
    captured = {}
    _fake_http(monkeypatch, captured)
    list(m.qualys_pull(tag_include="301", tag_exclude=""))   # the desktop form
    assert "tag_set_include=301" in captured["params"]
    # an explicitly empty exclude must NOT fall back to the estate default
    assert "tag_set_exclude" not in captured["params"]


def test_real_qualys_pull_defaults_to_estate_scope(monkeypatch):
    from urllib.parse import parse_qs
    captured = {}
    _fake_http(monkeypatch, captured)
    list(m.qualys_pull())                                     # the estate form
    # Decode: names like "Env: PROD" are correctly percent-encoded on the wire
    # (only the list commas stay literal).
    q = parse_qs(captured["params"])
    assert q["tag_set_include"] == [m.TAG_INCLUDE]
    assert q["tag_set_exclude"] == [m.TAG_EXCLUDE]
    assert q["tag_set_by"] == ["name"]


# --------------------------------------------------------------------------- #
# One summary per scope per day: re-running must not spawn duplicates.
# --------------------------------------------------------------------------- #
def test_summary_body_carries_its_date():
    _t, body = m.build_summary({}, {}, "2026-07-30", scope="estate")
    assert m.SUMMARY_DATE_RE.search(body).group(1) == "2026-07-30"


def test_rerun_same_day_updates_in_place(monkeypatch, groups):
    """Second run on the same date must PATCH the existing summary, not POST a
    new one and close the old — otherwise repeated testing floods the repo."""
    calls = []
    _t, existing_body = m.build_summary(groups, {}, "2026-07-30", scope="estate")

    def fake_request(method, path, **kw):
        calls.append((method, path))
        class R:
            status_code = 200
            def json(self): return {"number": 99}
            def raise_for_status(self): pass
        return R()

    monkeypatch.setattr(m, "_github_request", fake_request)
    monkeypatch.setattr(m, "find_open_summaries", lambda scope: [(7, existing_body)])
    monkeypatch.setattr(m, "DRY_RUN", False)

    m.publish_summary(groups, {}, "2026-07-30", scope="estate")

    assert ("PATCH", f"/repos/{m.GITHUB_REPO}/issues/7") in calls   # in place
    assert not any(mth == "POST" and p.endswith("/issues") for mth, p in calls)
    assert not any("state" in str(c) for c in calls)      # nothing closed


def test_new_day_supersedes_yesterday(monkeypatch, groups):
    calls = []
    _t, yesterday = m.build_summary(groups, {}, "2026-07-29", scope="estate")

    def fake_request(method, path, **kw):
        calls.append((method, path, kw.get("json")))
        class R:
            status_code = 200
            def json(self): return {"number": 99}
            def raise_for_status(self): pass
        return R()

    monkeypatch.setattr(m, "_github_request", fake_request)
    monkeypatch.setattr(m, "find_open_summaries", lambda scope: [(7, yesterday)])
    monkeypatch.setattr(m, "DRY_RUN", False)

    m.publish_summary(groups, {}, "2026-07-30", scope="estate")

    assert any(mth == "POST" and p.endswith("/issues") for mth, p, _ in calls)
    assert any(j and j.get("state") == "closed" for _, _, j in calls)


# --------------------------------------------------------------------------- #
# FPS PROD flagging — informational only; never changes what is pulled.
# --------------------------------------------------------------------------- #
def test_flag_tags_detected_case_insensitively():
    g = m.group_by_qid(iter([
        det("1", "700", 91, asset_key="svc:a", tags=["fps-dc-prod"]),
        det("2", "700", 75, asset_key="svc:b", tags=["Something-Else"]),
        det("3", "700", 80, asset_key="svc:c", tags=["EKS-FPS_Prod"]),
    ]))["qid:700"]
    assert m.flagged_assets(g) == ["svc:a", "svc:c"]
    # per-tag lookup, and the DISPLAY casing from config is what is recorded
    assert m.flagged_assets(g, "FPS-DC-PROD") == ["svc:a"]
    assert m.flagged_assets(g, "EKS-FPS_Prod") == ["svc:c"]


def test_flag_survives_worst_instance_collapse():
    """A flagged lower-scoring instance must not lose its flag when a
    higher-scoring instance of the same asset wins."""
    g = m.group_by_qid(iter([
        det("1", "701", 95, asset_key="svc:a", tags=[]),
        det("1", "701", 70, asset_key="svc:a", tags=["FPS-DC-PROD"]),
    ]))["qid:701"]
    assert g["assets"]["svc:a"]["qds"] == 95
    assert m.flagged_assets(g, "FPS-DC-PROD") == ["svc:a"]


def test_estate_summary_has_one_column_per_flag_tag():
    g = m.group_by_qid(iter([
        det("1", "702", 91, asset_key="svc:a", tags=["FPS-DC-PROD"]),
        det("2", "702", 88, asset_key="svc:b", tags=["FPS-DC-PROD"]),
        det("3", "703", 80, asset_key="svc:c", tags=["EKS-FPS_Prod"]),
    ]))
    _t, body = m.build_summary(g, {}, "2026-07-30", scope="estate")
    for tag in m.FLAG_TAGS:
        assert tag.upper() in body                  # a column per tag
    header = next(l for l in body.splitlines() if l.startswith("QID"))
    assert header.index("FPS-DC-PROD") < header.index("EKS-FPS_PROD")


def test_desktop_summary_has_no_flag_columns():
    g = m.group_by_qid(iter([
        det("1", "704", 91, asset_key="svc:a", tags=["FPS-DC-PROD"]),
    ]))
    _t, body = m.build_summary(g, {}, "2026-07-30", scope="desktop")
    for tag in m.FLAG_TAGS:
        assert tag.upper() not in body
    header = next(l for l in body.splitlines() if l.startswith("QID"))
    assert header.split() == ["QID", "BAND", "MAX", "QDS", "ASSETS",
                              "ENDPOINTS", "FIRST", "FOUND", "ISSUE"]


def test_per_vuln_issue_names_the_matched_tag():
    g = m.group_by_qid(iter([
        det("1", "705", 91, asset_key="svc:a", tags=["EKS-FPS_Prod"]),
        det("2", "705", 75, asset_key="svc:b", tags=[]),
    ]))["qid:705"]
    _t, body, _l = m.build_issue(g)
    assert "EKS-FPS_Prod" in body


def test_flag_change_updates_the_fingerprint():
    plain = m.group_by_qid(iter([det("1", "706", 80, asset_key="svc:a", tags=[])]))["qid:706"]
    flagged = m.group_by_qid(iter([
        det("1", "706", 80, asset_key="svc:a", tags=["FPS-DC-PROD"])]))["qid:706"]
    other = m.group_by_qid(iter([
        det("1", "706", 80, asset_key="svc:a", tags=["EKS-FPS_Prod"])]))["qid:706"]
    assert m.assets_fingerprint(plain) != m.assets_fingerprint(flagged)
    assert m.assets_fingerprint(flagged) != m.assets_fingerprint(other)


# --------------------------------------------------------------------------- #
# Making new vulnerabilities obvious in the daily summary.
# --------------------------------------------------------------------------- #
def _two_qids():
    return m.group_by_qid(iter([
        det("1", "800", 95, asset_key="svc:a", tags=["FPS-DC-PROD"]),
        det("2", "801", 74, asset_key="svc:b"),
    ]))


def test_new_vulns_headline_section_and_row_marker():
    groups = _two_qids()
    tracked = {"qid:801": {"number": 5, "hash": "x", "assets": None,
                           "absent_since": None, "labels": set(), "body": ""}}
    _t, body = m.build_summary(groups, tracked, "2026-07-30", scope="estate")

    assert body.lstrip().startswith("**Date:") or "# 1 NEW vulnerability today" in body
    assert "— 1 CRITICAL" in body                  # severity called out up front
    assert "## NEW THIS RUN" in body               # its own section
    assert "### All tracked vulnerabilities" in body
    assert "** NEW **" in body                     # row marker in the main table
    assert body.index("## NEW THIS RUN") < body.index("### All tracked")


def test_quiet_day_says_so_explicitly():
    groups = _two_qids()
    tracked = {k: {"number": i, "hash": "x", "assets": None, "absent_since": None,
                   "labels": set(), "body": ""} for i, k in enumerate(groups, 1)}
    _t, body = m.build_summary(groups, tracked, "2026-07-30", scope="estate")
    assert "No new vulnerabilities today." in body
    assert "## NEW THIS RUN" not in body
    assert "** NEW **" not in body


def test_new_set_is_persisted_and_survives_a_same_day_rerun():
    groups = _two_qids()
    tracked = {"qid:801": {"number": 5, "hash": "x", "assets": None,
                           "absent_since": None, "labels": set(), "body": ""}}
    _t, first = m.build_summary(groups, tracked, "2026-07-30", scope="estate")
    assert m.SUMMARY_NEW_RE.search(first).group(1) == "qid:800"

    # Second run today: qid:800 now HAS an issue, so it is no longer "new" by
    # the plain test — but the carried-forward set must keep it flagged.
    now_tracked = dict(tracked, **{"qid:800": {"number": 9, "hash": "y",
                                               "assets": None, "absent_since": None,
                                               "labels": set(), "body": ""}})
    _t, second = m.build_summary(groups, now_tracked, "2026-07-30",
                                 scope="estate", prior_new={"qid:800"})
    assert "1 NEW vulnerability today" in second
    assert "** NEW **" in second


def test_desktop_summary_has_no_new_machinery():
    groups = _two_qids()
    _t, body = m.build_summary(groups, {}, "2026-07-30", scope="desktop")
    assert "NEW THIS RUN" not in body
    assert "** NEW **" not in body
    assert "NEW vulnerabilit" not in body
