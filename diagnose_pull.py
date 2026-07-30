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

# Load the real .env first, so the tag values shown below are YOURS. Dummy
# placeholders are only a fallback for variables the file does not set.
_env_file = ROOT / ".env"
_from_file = set()
if _env_file.exists():
    for _raw in _env_file.read_text(encoding="utf-8-sig").splitlines():
        _line = _raw.strip()
        if not _line or _line.startswith("#"):
            continue
        _line = _line[7:].lstrip() if _line.startswith("export ") else _line
        if "=" not in _line:
            continue
        _k, _, _v = _line.partition("=")
        _k, _v = _k.strip(), _v.strip().strip("\"'")
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", _k) and _k not in os.environ:
            os.environ[_k] = _v
            _from_file.add(_k)

_DUMMIES = {
    "QUALYS_BASE_URL": "https://qualys.invalid", "QUALYS_USERNAME": "diag",
    "QUALYS_PASSWORD": "diag", "GITHUB_TOKEN": "diag", "GITHUB_REPO": "o/r",
    "TAG_INCLUDE": "101", "TAG_EXCLUDE": "201,202", "DESKTOP_TAG": "301",
}
_defaulted = set()
for var, val in _DUMMIES.items():
    if var not in os.environ:
        os.environ[var] = val
        _defaulted.add(var)

import qualys_qds_to_github as m  # noqa: E402

print("=" * 72)
print("CONFIG SOURCE")
print("=" * 72)
for _v in ("TAG_INCLUDE", "TAG_EXCLUDE", "DESKTOP_TAG"):
    _src = ("from .env" if _v in _from_file
            else "PLACEHOLDER (not set anywhere)" if _v in _defaulted
            else "from the shell environment")
    print(f"  {_v:<14} = {os.environ[_v]:<24} [{_src}]")
if _defaulted & {"TAG_INCLUDE", "TAG_EXCLUDE", "DESKTOP_TAG"}:
    print("\n  >>> Values marked PLACEHOLDER are this script's dummies, NOT your")
    print("      configuration. They are fine for a signature check but tell")
    print("      you nothing about your real tag scope.")

print()
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

print()
print("=" * 72)
print("HARNESS PATCH SITES (scripts/local_harness.py)")
print("=" * 72)
_harness = ROOT / "scripts" / "local_harness.py"
if not _harness.exists():
    print("  local_harness.py not found — skipping")
else:
    _hl = _harness.read_text(encoding="utf-8").splitlines()
    _sites = [i for i, l in enumerate(_hl) if re.match(r"\s*m\.qualys_pull\s*=", l)]
    if not _sites:
        print("  no 'm.qualys_pull = ...' patch found")
    for _i in _sites:
        _block = "\n".join(_hl[_i:_i + 4])
        _ok = "tag_include" in _block
        print(f"\n  line {_i + 1}: {'OK — accepts tag_include' if _ok else 'STALE — does NOT accept tag_include'}")
        for _n, _l in enumerate(_hl[_i:_i + 4], start=_i + 1):
            print(f"    {_n:>4}| {_l}")
        if not _ok:
            print("\n    >>> THIS is the failure. Replace with:")
            print("        m.qualys_pull = (")
            print("            lambda tag_include=None, tag_exclude=None, f=feed:")
            print("            iter(desktop_feed if tag_include == m.DESKTOP_TAG else f)")
            print("        )")
    if len(_sites) > 1:
        print(f"\n  >>> {len(_sites)} patch sites found. The LAST one executed wins —")
        print("      fixing only the first leaves the behaviour unchanged.")

print("\n" + "=" * 72)
print("If BOTH calls succeeded here but your run still fails, the failure is")
print("not in qualys_qds_to_github.py — run the same diagnosis on whatever")
print("script you are actually invoking.")
print("=" * 72)
