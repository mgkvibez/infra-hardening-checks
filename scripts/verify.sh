#!/usr/bin/env bash
# Release gate for hardencheck: run before every push that claims "done".
set -uo pipefail
fail() { echo "GATE FAILED: $1"; exit 1; }

echo "== check 1/5: install"
python3 -m pip install -q -e ".[dev]" || fail "install"

echo "== check 2/5: version consistency (pyproject vs module)"
pv=$(python3 - <<'PY'
import pathlib, re
try:
    import tomllib
    print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])
except ModuleNotFoundError:
    text = pathlib.Path("pyproject.toml").read_text()
    print(re.search(r'(?m)^version\s*=\s*"([^"]+)"', text).group(1))
PY
)
mv=$(python3 -c "import hardencheck;print(hardencheck.__version__)")
[ "$pv" = "$mv" ] || fail "pyproject says $pv, module says $mv"

echo "== check 3/5: test suite"
python3 -m pytest tests -q || fail "tests"

echo "== check 4/5: CLI smoke on the fixture corpus (expects exit 3)"
out=$(mktemp); err=$(mktemp)
python3 -m hardencheck.cli scan tests/fixtures --no-colour >"$out" 2>"$err"; code=$?
[ $code -eq 3 ] || fail "expected exit 3, got $code"
grep -q "HCD002" "$out" || fail "docker rules did not fire"
grep -q "No issues found by ruleset" <<<"$(python3 -m hardencheck.cli scan tests/fixtures/Dockerfile.good --no-colour)" || fail "clean file wording"
echo "smoke ok (exit 3, docker rules fired, clean file wording intact)"
python3 - "$out" "$err" <<'PY'
import os, sys
for p in sys.argv[1:]:
    os.unlink(p)
PY

echo "== check 5/5: the built wheel actually contains the package"
tmpd=$(mktemp -d)
blog=$(mktemp)
if ! python3 -m build --wheel --outdir "$tmpd" >"$blog" 2>&1; then
  echo "wheel build failed:"; tail -5 "$blog"; exit 1
fi
[ -n "$(ls -A "$tmpd" 2>/dev/null)" ] || { echo "wheel build produced nothing:"; tail -5 "$blog"; exit 1; }
python3 - "$tmpd" <<'PY'
import glob, shutil, sys, zipfile
matches = glob.glob(sys.argv[1] + "/*.whl")
if not matches:
    sys.exit("no wheel produced")
w = matches[0]
inside = [n for n in zipfile.ZipFile(w).namelist() if n.startswith("hardencheck/") and n.endswith(".py")]
shutil.rmtree(sys.argv[1], ignore_errors=True)
if len(inside) < 5:
    sys.exit("wheel has %d module file(s); the package is missing" % len(inside))
PY
[ $? -eq 0 ] || fail "wheel is missing the package; an editable install hides this"
echo "wheel contains the package"

echo "ALL CHECKS PASSED"
