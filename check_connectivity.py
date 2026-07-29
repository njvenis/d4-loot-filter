#!/usr/bin/env python3
"""
check_connectivity.py — isolate where the path to the Qualys API breaks.

Tests each layer in order and stops being useful to guess after the first
failure, because each layer has a different fix:

  1. Config      are the three QUALYS_* variables actually set
  2. Proxy       is a proxy in the path (env vars / macOS system config)
  3. DNS         does the POD hostname resolve
  4. TCP         can we open port 443 (the IP allow-list layer)
  5. TLS         does the handshake succeed, and who issued the cert
                 (a corporate CA here means TLS inspection)
  6. Auth        do the credentials work        -> /msp/about.php
  7. Endpoint    does the detection API respond -> truncation_limit=1
  8. QDS         does the subscription actually return QDS

Reads .env the same way local_harness.py does. Never prints the password.

    python scripts/check_connectivity.py
    python scripts/check_connectivity.py --env-file /path/to/.env
    python scripts/check_connectivity.py --egress    # also report public IP
"""

import argparse
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import pathlib
from urllib.parse import urlparse

import requests

CONNECT_TIMEOUT = 10
AUTH_TIMEOUT = 60

OK, BAD, WARN, INFO = "  PASS", "  FAIL", "  WARN", "  ..  "


def _find_root(start):
    here = pathlib.Path(start).resolve()
    for candidate in (here.parent, *here.parents):
        if (candidate / "qualys_qds_to_github.py").exists():
            return candidate
    return here.parent


ROOT = _find_root(__file__)


def load_env(path):
    f = pathlib.Path(path)
    if not f.is_absolute():
        f = ROOT / f
    if not f.exists():
        return
    for raw in f.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line[7:].lstrip() if line.startswith("export ") else line
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip("\"'")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) and k not in os.environ:
            os.environ[k] = v


def step(n, name):
    print(f"\n[{n}] {name}")


def fail(msg, hint=None):
    print(f"{BAD} {msg}")
    if hint:
        for line in hint.splitlines():
            print(f"       {line}")
    print("\nStopping here — later layers cannot be tested until this is fixed.")
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", default=".env")
    ap.add_argument("--sample", action="store_true",
                    help="pull an UNFILTERED sample and report the QDS "
                         "distribution — answers 'why is my feed empty?'")
    ap.add_argument("--egress", action="store_true",
                    help="also report this machine's public IP (makes an "
                         "outbound call to an external service)")
    args = ap.parse_args()
    load_env(args.env_file)

    # ---- 1. config --------------------------------------------------------
    step(1, "Configuration")
    base = os.environ.get("QUALYS_BASE_URL", "").rstrip("/")
    user = os.environ.get("QUALYS_USERNAME", "")
    pwd = os.environ.get("QUALYS_PASSWORD", "")
    missing = [k for k, v in
               (("QUALYS_BASE_URL", base), ("QUALYS_USERNAME", user),
                ("QUALYS_PASSWORD", pwd)) if not v]
    if missing:
        fail(f"missing: {', '.join(missing)}",
             "Set them in .env (see .env.example) or export them.\n"
             "Check with: python scripts/local_harness.py --check-env")
    parsed = urlparse(base)
    host = parsed.hostname
    port = parsed.port or 443
    print(f"{OK} base URL {base}")
    print(f"{OK} username {user}  (password {len(pwd)} chars, not shown)")
    if parsed.scheme != "https":
        fail(f"base URL scheme is {parsed.scheme!r}, must be https")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        fail(f"base URL contains a path/query: {base}",
             f"QUALYS_BASE_URL must be the API SERVER only.\n"
             f"  Use:  https://{parsed.netloc}\n"
             f"The endpoint path and parameters are added by the code. A base\n"
             f"URL that already contains '?action=list' produces the Qualys\n"
             f"error \"parameter action has invalid value\".")
    if re.fullmatch(r"[\d.]+", host or ""):
        fail(f"base URL is an IP ({host})",
             "Qualys certificates are issued to POD hostnames, so an IP will\n"
             "always fail TLS. Use e.g. https://qualysapi.qg2.apps.qualys.com\n"
             "(your POD is shown in the Qualys UI under Help -> About).")

    # ---- 2. proxy ---------------------------------------------------------
    step(2, "Proxy configuration")
    proxies = {k: v for k, v in os.environ.items()
               if k.lower() in ("http_proxy", "https_proxy", "no_proxy",
                                "all_proxy")}
    if proxies:
        for k, v in sorted(proxies.items()):
            print(f"{WARN} {k}={v}")
        print("       requests honours these. If the proxy cannot reach Qualys,")
        print("       or is not allow-listed by Qualys, that is your failure.")
    else:
        print(f"{OK} no proxy environment variables set")
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["scutil", "--proxy"], capture_output=True,
                                 text=True, timeout=5).stdout
            if re.search(r"HTTPSEnable\s*:\s*1", out):
                print(f"{WARN} macOS system HTTPS proxy is enabled "
                      f"(scutil --proxy) — Python does not always honour it")
        except Exception:
            pass

    if args.egress:
        step("2b", "Public egress IP")
        try:
            ip = requests.get("https://api.ipify.org", timeout=10).text.strip()
            print(f"{OK} this machine egresses as {ip}")
            print("       Compare against Qualys: Users -> Setup -> Security")
            print("       ('Allow connections from the following IPs only')")
        except Exception as exc:
            print(f"{WARN} could not determine egress IP ({exc})")

    # ---- 3. DNS -----------------------------------------------------------
    step(3, f"DNS resolution of {host}")
    t0 = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        fail(f"cannot resolve {host} ({exc})",
             "Check the POD hostname spelling, your DNS, and whether split-horizon\n"
             "DNS or a VPN is required to see it.")
    addrs = sorted({i[4][0] for i in infos})
    print(f"{OK} resolved in {(time.monotonic()-t0)*1000:.0f}ms -> {', '.join(addrs)}")

    # ---- 4. TCP -----------------------------------------------------------
    step(4, f"TCP connect to {host}:{port}")
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except socket.timeout:
        fail(f"timed out after {CONNECT_TIMEOUT}s",
             "Packets are being dropped rather than refused. This is the classic\n"
             "signature of IP allow-listing or a firewall silently discarding\n"
             "traffic. Check Qualys: Users -> Setup -> Security, and confirm this\n"
             "machine's egress IP is permitted (re-run with --egress).")
    except OSError as exc:
        fail(f"{exc}",
             "Connection refused or unreachable — routing, VPN, or local firewall.")
    tcp_ms = (time.monotonic() - t0) * 1000
    print(f"{OK} connected in {tcp_ms:.0f}ms")

    # ---- 5. TLS -----------------------------------------------------------
    step(5, "TLS handshake and certificate")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            proto = tls.version()
    except ssl.SSLCertVerificationError as exc:
        fail(f"certificate verification failed: {exc}",
             "Usually TLS inspection by a corporate proxy presenting its own CA.\n"
             "Point Python at the corporate CA bundle:\n"
             "  export REQUESTS_CA_BUNDLE=/path/to/corporate-ca.pem\n"
             "Do NOT disable verification as a workaround.")
    except Exception as exc:
        fail(f"TLS handshake failed: {exc}")
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    subject = dict(x[0] for x in cert.get("subject", ()))
    print(f"{OK} {proto}")
    print(f"       subject: {subject.get('commonName', '?')}")
    print(f"       issuer:  {issuer.get('organizationName', '?')} / "
          f"{issuer.get('commonName', '?')}")
    print(f"       expires: {cert.get('notAfter', '?')}")
    if not re.search(r"qualys", str(subject), re.I):
        print(f"{WARN} certificate does not look like Qualys — likely TLS "
              f"inspection in the path")

    # ---- 6. auth ----------------------------------------------------------
    step(6, "Authentication (/msp/about.php)")
    headers = {"X-Requested-With": "qualys-connectivity-check"}
    t0 = time.monotonic()
    try:
        r = requests.get(f"{base}/msp/about.php", auth=(user, pwd),
                         headers=headers,
                         timeout=(CONNECT_TIMEOUT, AUTH_TIMEOUT))
    except requests.exceptions.RequestException as exc:
        fail(f"request failed: {exc}")
    took = time.monotonic() - t0
    if r.status_code == 401:
        fail(f"HTTP 401 in {took:.1f}s",
             "TCP and TLS are fine, so this is genuinely the credentials:\n"
             "  - wrong username/password\n"
             "  - account lacks API access\n"
             "  - account locked from repeated failures\n"
             "  - correct credentials but WRONG POD (each POD is a separate\n"
             "    subscription). Identify yours at\n"
             "    https://www.qualys.com/platform-identification/ or via\n"
             "    Help -> About in the Qualys UI.")
    if r.status_code != 200:
        fail(f"HTTP {r.status_code} in {took:.1f}s\n{r.text[:300]}")
    ver = re.search(r"<VERSION>(.*?)</VERSION>", r.text or "")
    print(f"{OK} HTTP 200 in {took:.1f}s"
          + (f" — Qualys version {ver.group(1)}" if ver else ""))

    # Qualys returns subscription quota on every response (except session
    # login/logout). Worth surfacing: a shared subscription running near its
    # limits is a likely cause of intermittent 409s in the scheduled job.
    quota = {k: v for k, v in r.headers.items()
             if k.lower().startswith(("x-ratelimit", "x-concurrency"))}
    if quota:
        print("       subscription quota:")
        for k in sorted(quota):
            print(f"         {k}: {quota[k]}")
    else:
        print(f"{WARN} no quota headers returned — unusual; the subscription "
              f"may route through a gateway that strips them")

    # ---- 7 & 8. endpoint + QDS -------------------------------------------
    step(7, "Detection endpoint (truncation_limit=1)")
    params = {"action": "list", "show_qds": "1", "show_qds_factors": "1",
              "truncation_limit": "1", "show_results": "0", "show_tags": "1"}
    t0 = time.monotonic()
    try:
        r = requests.get(f"{base}/api/2.0/fo/asset/host/vm/detection/",
                         auth=(user, pwd), headers=headers, params=params,
                         timeout=(CONNECT_TIMEOUT, AUTH_TIMEOUT))
    except requests.exceptions.ReadTimeout:
        fail(f"no response within {AUTH_TIMEOUT}s for a single-detection page",
             "Auth works, so this is generation time or subscription load.\n"
             "The real pull will need QUALYS_TRUNCATION_LIMIT lowered and\n"
             "QUALYS_READ_TIMEOUT raised.")
    except requests.exceptions.RequestException as exc:
        fail(f"request failed: {exc}")
    took = time.monotonic() - t0
    if r.status_code == 409:
        fail(f"HTTP 409 — Qualys API concurrency limit reached",
             "Another integration is using the subscription's API slots.\n"
             "Retry shortly; the job handles this with backoff.")
    if r.status_code != 200:
        fail(f"HTTP {r.status_code} in {took:.1f}s\n{r.text[:300]}")
    body = r.text or ""
    if "<CODE>" in body:
        code = re.search(r"<CODE>(.*?)</CODE>", body)
        text = re.search(r"<TEXT>(.*?)</TEXT>", body)
        fail(f"Qualys returned an error body: "
             f"{code.group(1) if code else '?'} "
             f"{text.group(1) if text else ''}",
             "HTTP 200 with an error payload — usually parameter or\n"
             "entitlement problems on the API account.")
    print(f"{OK} HTTP 200 in {took:.1f}s, {len(body)/1000:.1f} KB")

    step(8, "QDS availability")
    if "<QDS" in body:
        qds = re.search(r"<QDS[^>]*>(\d+)</QDS>", body)
        print(f"{OK} QDS present in the response"
              + (f" (sample value {qds.group(1)})" if qds else ""))
    elif "<DETECTION>" in body:
        print(f"{WARN} detections returned but no QDS element")
        print("       The subscription may not have TruRisk/QDS enabled, or the")
        print("       API account cannot see it. Raise with Qualys support —")
        print("       the whole job depends on QDS being present.")
    else:
        print(f"{WARN} no detections in this 1-row sample — inconclusive")
        print("       Not necessarily a problem; try again with a wider scope.")

    if args.sample:
        step(9, "QDS distribution (unfiltered sample, 200 detections)")
        # Deliberately NO qds_min: we need to see what the subscription
        # actually returns before concluding anything about the threshold.
        params = {"action": "list", "show_qds": "1", "truncation_limit": "200",
                  "show_results": "0", "show_tags": "1",
                  "status": "Active,New,Re-Opened"}
        try:
            r = requests.get(f"{base}/api/2.0/fo/asset/host/vm/detection/",
                             auth=(user, pwd), headers=headers, params=params,
                             timeout=(CONNECT_TIMEOUT, 300))
            r.raise_for_status()
        except requests.exceptions.RequestException as exc:
            fail(f"sample request failed: {exc}")
        body = r.text or ""

        hosts = len(re.findall(r"<HOST>", body))
        dets = len(re.findall(r"<DETECTION>", body))
        scores = [int(x) for x in re.findall(r"<QDS[^>]*>(\d+)</QDS>", body)]
        tagged = len(re.findall(r"<TAG>", body))

        print(f"{INFO} {hosts} host(s), {dets} detection(s), "
              f"{len(scores)} with QDS, {tagged} asset tag(s)")

        if dets == 0:
            print(f"{BAD} No detections at all in this account's scope.")
            print("       Per the Host List Detection docs, visibility is")
            print("       role-dependent:")
            print("         Manager       - all hosts in the subscription")
            print("         Unit Manager  - hosts in the user's business unit")
            print("         Scanner/Reader- hosts in the USER'S OWN ACCOUNT only")
            print("         Auditor       - no VM-scanned hosts at all")
            print("       A least-privilege Reader with no asset groups assigned")
            print("       authenticates fine and returns nothing. Check the")
            print("       account's role and asset-group scope in Qualys.")
        elif not scores:
            print(f"{BAD} Detections returned, but NOT ONE carried a <QDS> element.")
            print("       The endpoint and parameters are correct, so this is")
            print("       entitlement: QDS/TruRisk is a VMDR capability. A classic")
            print("       VM subscription returns detections without QDS. Confirm")
            print("       the VMDR entitlement with Qualys — the job cannot work")
            print("       until QDS is returned.")
        else:
            bands = {
                "CRITICAL 90-100": sum(1 for s in scores if s >= 90),
                "HIGH     70-89": sum(1 for s in scores if 70 <= s < 90),
                "MEDIUM   40-69": sum(1 for s in scores if 40 <= s < 70),
                "LOW       1-39": sum(1 for s in scores if s < 40),
            }
            print(f"{OK} QDS present — range {min(scores)}-{max(scores)}")
            for band, n in bands.items():
                bar = "#" * min(40, n)
                print(f"       {band}: {n:>4}  {bar}")
            above = bands["CRITICAL 90-100"] + bands["HIGH     70-89"]
            if above == 0:
                print(f"{WARN} Nothing at or above QDS 70 in this sample.")
                print("       An empty feed at QDS_MIN=70 may simply be accurate.")
                print("       Confirm against the VMDR prioritisation view, and try")
                print("       QDS_MIN=40 to prove the pipeline end to end.")
            else:
                print(f"{OK} {above} detection(s) at/above QDS 70 in this sample "
                      f"— the job should find work at the default threshold")

    print("\nAll layers passed. Connectivity is not your problem —")
    print("run: python scripts/local_harness.py --live --qds-min 90")


if __name__ == "__main__":
    main()
