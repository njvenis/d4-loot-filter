#!/usr/bin/env python3
"""
diagnose_pull.py — why is the desktop call failing?

Reports what `qualys_pull` is ACTUALLY bound to (a function? a lambda? defined
where?), calls it both ways with a faked HTTP layer, and prints the full
traceback if either fails. Answers, without guesswork, which of these it is:

  * the job's own definition is stale        -> qualys_pull, wrong signature
  * a duplicate definition shadows the good  -> qualys_pull, unexpected line no.
  * something replaced it at runtime         -> <lambda> from another file
  * the job is fine                          -> both calls succeed here

Run from the repo root:  python scripts/diagnose_pull.py
"""

import inspect
import os
import pathlib
import re
import sys
import traceback

ROOT = pathlib.Path(__file__).resolve().parents[1]
if not (ROOT / "qualys_qds_to_github.py").exists():
    ROOT = pathlib.Path.cwd()
sys.path.insert(0, str(ROOT))

for var, val in {
    "QUALYS_BASE_URL": "https://qualys.invalid", "QUALYS_USERNAME": "diag",
    "QUALYS_PASSWORD": "diag", "GITHUB_TOKEN": "diag", "GITHUB_REPO": "o/r",
    "TAG_INCLUDE": "101", "TAG_EXCLUDE": "201,202", "DESKTOP_TAG": "301",
}.items():
    os.environ.setdefault(var, val)

import qualys_qds_to_github as m  # noqa: E402

print("=" * 72)
print("WHAT IS qualys_pull BOUND TO?")
print("=" * 72)
fn = m.qualys_pull
print(f"  repr           : {fn!r}")
print(f"  __qualname__   : {getattr(fn, '__qualname__', '?')}")
try:
    src_file = inspect.getsourcefile(fn)
    src_line = inspect.getsourcelines(fn)[1]
    print(f"  defined in     : {src_file}")
    print(f"  at line        : {src_line}")
except (OSError, TypeError):
    print("  defined in     : <source unavailable>")
print(f"  signature      : {inspect.signature(fn)}")

qualname = getattr(fn, "__qualname__", "")
if "<lambda>" in qualname or "<locals>" in qualname:
    print("\n  >>> This is NOT the job's function. Something replaced it at")
    print("      runtime (a monkeypatch in a harness/test). Fix the patch,")
    print("      not the job.")

print()
print("=" * 72)
print("DUPLICATE DEFINITIONS IN THE JOB FILE?")
print("=" * 72)
src = (ROOT / "qualys_qds_to_github.py").read_text(encoding="utf-8")
lines = src.splitlines()
defs = [i + 1 for i, l in enumerate(lines) if re.match(r"\s*def qualys_pull\b", l)]
assigns = [i + 1 for i, l in enumerate(lines) if re.match(r"\s*qualys_pull\s*=", l)]
print(f"  def qualys_pull on lines : {defs}")
print(f"  reassigned on lines      : {assigns or 'none'}")
for n in defs:
    print(f"    line {n}: {lines[n - 1].strip()}")
if len(defs) > 1:
    print("\n  >>> DUPLICATE: the LAST definition wins. Delete the stale one.")

print()
print("=" * 72)
print("CALLING IT BOTH WAYS (faked HTTP — no network)")
print("=" * 72)

XML = (b'<?xml version="1.0"?><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE>'
       b'<HOST_LIST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>')
captured = {}


class _Resp:
    status_code = 200
    headers = {}

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=0):
        yield XML


class _Session:
    auth = None
    headers = {}

    def get(self, url, params=None, **kw):
        captured["params"] = params
        return _Resp()


m.requests.Session = lambda: _Session()

for label, kwargs in (
    ("estate  qualys_pull()", {}),
    ("desktop qualys_pull(tag_include=DESKTOP_TAG, tag_exclude='')",
     {"tag_include": m.DESKTOP_TAG, "tag_exclude": ""}),
):
    print(f"\n--- {label}")
    try:
        list(m.qualys_pull(**kwargs))
        print(f"    OK")
        print(f"    params sent: {captured.get('params')}")
    except TypeError:
        print("    FAILED — full traceback:\n")
        traceback.print_exc()
        print("\n    Read the LAST line: the name before 'got an unexpected")
        print("    keyword argument' is what actually failed. If it is")
        print("    <lambda>, the job is innocent and a patch is at fault.")
    except Exception:
        print("    FAILED with a non-signature error (this is progress —")
        print("    the signature is fine):\n")
        traceback.print_exc()

print("\n" + "=" * 72)
print("If BOTH calls succeeded here but your run still fails, the failure is")
print("not in qualys_qds_to_github.py — run the same diagnosis on whatever")
print("script you are actually invoking.")
print("=" * 72)
