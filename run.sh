#!/usr/bin/env bash
# CanaryGate — one command to run the whole thing locally.
#
#   ./run.sh                 start TargetLab + the website, open the browser
#   ./run.sh --no-browser    same, but print the URL instead of opening it
#   ./run.sh --doctor        check the install and print diagnostics, start nothing
#   ./run.sh --tests         run the full test suite with the demo environment set
#   ./run.sh --stop          stop a run started by this script (it records its PIDs)
#
# What it does, in order:
#   1. finds the project (wherever you copied it) and a usable Python 3.11–3.13
#   2. creates .venv and installs requirements if they are missing
#   3. starts the deliberately vulnerable TargetLab on 127.0.0.1 over HTTPS
#   4. exports CANARYGATE_TARGETLAB_CA and CANARYGATE_DB_PATH
#   5. starts the CanaryGate website and waits until it answers /api/health
#   6. opens http://127.0.0.1:8000/ui/
#
# Ctrl+C stops both servers. Nothing outside 127.0.0.1 is contacted.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

LAB_PORT="${LAB_PORT:-8765}"
UI_PORT="${UI_PORT:-8000}"
CERT="$ROOT/tests/fixtures/tls/targetlab-cert.pem"
KEY="$ROOT/tests/fixtures/tls/targetlab-key.pem"
DB="${CANARYGATE_DB_PATH:-$ROOT/.canarygate/canarygate.sqlite3}"
LOG_DIR="$ROOT/.canarygate/logs"
PID_FILE="$ROOT/.canarygate/run.pids"
OPEN_BROWSER=1
MODE="serve"

for arg in "$@"; do
  case "$arg" in
    --no-browser) OPEN_BROWSER=0 ;;
    --doctor)     MODE="doctor" ;;
    --tests)      MODE="tests" ;;
    --stop)       MODE="stop" ;;
    -h|--help)    awk 'NR>1 { if (/^#/) { sub(/^# ?/, ""); print } else { exit } }' \
                    "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- presentation
if [ -t 1 ]; then
  B=$'\033[1m'; DIM=$'\033[2m'; OK=$'\033[32m'; WARN=$'\033[33m'; BAD=$'\033[31m'; OFF=$'\033[0m'
else
  B=''; DIM=''; OK=''; WARN=''; BAD=''; OFF=''
fi
step()  { printf '\n%s▸ %s%s\n' "$B" "$*" "$OFF"; }
say()   { printf '   %s\n' "$*"; }
cmd()   { printf '   %s$ %s%s\n' "$DIM" "$*" "$OFF"; }
good()  { printf '   %s✓%s %s\n' "$OK" "$OFF" "$*"; }
warn()  { printf '   %s!%s %s\n' "$WARN" "$OFF" "$*"; }
die()   { printf '\n%s✗ %s%s\n' "$BAD" "$*" "$OFF" >&2; exit 1; }

# --------------------------------------------------------------- python lookup
find_python() {
  if [ -n "${CANARYGATE_PYTHON:-}" ] && [ -x "$CANARYGATE_PYTHON" ]; then
    echo "$CANARYGATE_PYTHON"; return 0
  fi
  # The project's own environment always wins: activation order in the shell must
  # not decide which interpreter runs the app (a conda env earlier on PATH would).
  if [ -x "$ROOT/.venv/bin/python" ]; then echo "$ROOT/.venv/bin/python"; return 0; fi
  local candidate
  for candidate in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; sys.exit(0 if (3,11) <= sys.version_info[:2] < (3,14) else 1)' 2>/dev/null; then
        command -v "$candidate"; return 0
      fi
    fi
  done
  return 1
}

PY="$(find_python || true)"

# ------------------------------------------------------------------- modes
if [ "$MODE" = "stop" ]; then
  if [ -f "$PID_FILE" ]; then
    while read -r pid; do
      [ -n "$pid" ] && kill "$pid" 2>/dev/null && say "stopped pid $pid"
    done < "$PID_FILE"
    rm -f "$PID_FILE"
    good "servers stopped"
  else
    say "nothing recorded in $PID_FILE — nothing to stop"
  fi
  exit 0
fi

if [ "$MODE" = "doctor" ]; then
  step "Project"
  say "root      $ROOT"
  say "commit    $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout')"
  say "branch    $(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '-')"
  step "Python"
  if [ -z "$PY" ]; then
    die "no Python 3.11–3.13 found. Install one, or set CANARYGATE_PYTHON=/path/to/python3.11"
  fi
  say "interpreter $PY"
  say "version     $("$PY" -V 2>&1)"
  "$PY" - <<'PYCHK' || warn "canarygate is imported from somewhere other than this checkout (see above)"
import pathlib, sys
import canarygate
where = pathlib.Path(canarygate.__file__).resolve()
print(f"   imported    {where}")
if "site-packages" in str(where):
    print("   WARNING: canarygate is loaded from site-packages, not the repository.")
    print("            An older `pip install` of a wheel can shadow your edits.")
    print(f"            Fix: {sys.executable} -m pip uninstall -y canarygate")
PYCHK
  step "Fixtures and ports"
  [ -f "$CERT" ] && good "test CA present: ${CERT#$ROOT/}" || warn "missing $CERT"
  [ -f "$KEY" ]  && good "test key present: ${KEY#$ROOT/}"  || warn "missing $KEY"
  for pair in "lab:$LAB_PORT" "ui:$UI_PORT"; do
    name="${pair%%:*}"; port="${pair##*:}"
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      say "port $port   in use (something is already listening)"
    else
      say "port $port   free"
    fi
  done
  step "Environment this shell is exporting"
  for name in CANARYGATE_TARGETLAB_CA CANARYGATE_DB_PATH; do
    if [ -n "${!name:-}" ]; then say "$name=${!name}"; else say "$name (unset)"; fi
  done
  say "Note: the test suite ignores these variables on purpose (tests/conftest.py),"
  say "      so \`--tests\` gives the same result whatever this shell exports."
  step "Quick check"
  if "$PY" -c "import fastapi, uvicorn, jinja2, httpx, yaml, pydantic" 2>/dev/null; then
    good "runtime dependencies import"
  else
    warn "dependencies missing — run ./run.sh once to install them"
  fi
  printf '\n'
  exit 0
fi

# ------------------------------------------------------------------ bootstrap
step "Project"
say "$ROOT"
if [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then
  warn "working tree has uncommitted changes — running them, not the last commit"
fi

if [ -z "$PY" ]; then
  die "no Python 3.11–3.13 found. Install one (https://www.python.org/downloads/),
   or point CANARYGATE_PYTHON at an interpreter:
   CANARYGATE_PYTHON=/home/ace/95/lrng/cl/python/canarygate/bin/python ./run.sh"
fi
say "python: $PY ($("$PY" -V 2>&1))"

if ! "$PY" -c "import fastapi, uvicorn, jinja2, httpx, yaml, pydantic" 2>/dev/null; then
  step "Installing dependencies (first run only)"
  if [ ! -x "$ROOT/.venv/bin/python" ]; then
    cmd "$PY -m venv .venv"
    "$PY" -m venv "$ROOT/.venv" || die "could not create .venv"
    PY="$ROOT/.venv/bin/python"
  fi
  cmd "$PY -m pip install -r requirements.txt"
  "$PY" -m pip install --quiet --upgrade pip >/dev/null 2>&1
  "$PY" -m pip install --quiet -r "$ROOT/requirements.txt" || die "pip install failed"
  good "dependencies installed"
fi

if ! "$PY" -c "import canarygate, pathlib, sys; sys.exit(0 if '$ROOT' in str(pathlib.Path(canarygate.__file__).resolve()) else 1)" 2>/dev/null; then
  warn "canarygate resolves outside this checkout; reinstalling it in place"
  cmd "$PY -m pip install --quiet -e ."
  "$PY" -m pip install --quiet -e "$ROOT" || die "editable install failed"
fi
good "canarygate imports from this checkout"

[ -f "$CERT" ] || die "test certificate not found: $CERT"
[ -f "$KEY" ]  || die "test key not found: $KEY"
mkdir -p "$LOG_DIR" "$(dirname "$DB")"
: > "$PID_FILE"
CLEANED=0
cleanup() {
  [ "$CLEANED" = "1" ] && return 0
  CLEANED=1
  printf '\n'
  step "Stopping"
  if [ -f "$PID_FILE" ]; then
    while read -r pid; do
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null && say "stopped pid $pid"
      fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
  fi
  good "done — the database keeps every stored run: $DB"
}
# Any exit stops what this script started: a failed start must not orphan a lab.
trap cleanup EXIT
trap 'exit 130' INT TERM

lab_healthy() {  # $1 = port
  "$PY" - "$1" "$CERT" <<'PYHEALTH' >/dev/null 2>&1
import json, ssl, sys, urllib.request
port, cert = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context(cafile=cert)
body = urllib.request.urlopen(f"https://127.0.0.1:{port}/health", timeout=2, context=ctx).read()
sys.exit(0 if json.loads(body).get("status") == "ok" else 1)
PYHEALTH
}

wait_for_http() {  # $1 = url, $2 = seconds
  local url="$1" limit="${2:-40}" waited=0
  while [ "$waited" -lt "$limit" ]; do
    if "$PY" - "$url" <<'PYWAIT' >/dev/null 2>&1
import sys, urllib.request
urllib.request.urlopen(sys.argv[1], timeout=2)
PYWAIT
    then return 0; fi
    sleep 0.5; waited=$((waited + 1))
  done
  return 1
}

# ------------------------------------------------------------------- TargetLab
step "TargetLab (the deliberately vulnerable lab, loopback only)"
if lab_healthy "$LAB_PORT"; then
  good "already running and healthy on https://127.0.0.1:$LAB_PORT — reusing it"
else
  cmd "$PY -m targetlab --port $LAB_PORT --tls-cert ${CERT#$ROOT/} --tls-key ${KEY#$ROOT/}"
  "$PY" -m targetlab --port "$LAB_PORT" --tls-cert "$CERT" --tls-key "$KEY" \
      >"$LOG_DIR/targetlab.log" 2>&1 &
  LAB_PID=$!
  echo "$LAB_PID" >> "$PID_FILE"
  waited=0
  until lab_healthy "$LAB_PORT"; do
    if ! kill -0 "$LAB_PID" 2>/dev/null; then break; fi
    sleep 0.3; waited=$((waited + 1))
    if [ "$waited" -ge 100 ]; then break; fi       # 30 s, generous on a cold disk
  done
  if ! lab_healthy "$LAB_PORT"; then
    warn "no health answer; last lines of $LOG_DIR/targetlab.log:"
    tail -n 15 "$LOG_DIR/targetlab.log" | sed 's/^/     /'
    die "TargetLab did not start on port $LAB_PORT (try LAB_PORT=8766 ./run.sh)"
  fi
  good "running on https://127.0.0.1:$LAB_PORT (pid $LAB_PID)"
fi

# ----------------------------------------------------------------------- tests
if [ "$MODE" = "tests" ]; then
  step "Tests (full suite)"
  say "the suite clears CANARYGATE_* per test, so this shell cannot change the verdict"
  cmd "$PY -m pytest -q"
  "$PY" -m pytest -q
  exit $?
fi

# -------------------------------------------------------------------- website
step "Configuration"
export CANARYGATE_TARGETLAB_CA="$CERT"
export CANARYGATE_DB_PATH="$DB"
cmd "export CANARYGATE_TARGETLAB_CA=${CERT#$ROOT/}"
cmd "export CANARYGATE_DB_PATH=${DB#$ROOT/}"
good "pinned test CA configured; database at ${DB#$ROOT/}"

step "CanaryGate website"
FREE_UI="$UI_PORT"
while (exec 3<>"/dev/tcp/127.0.0.1/$FREE_UI") 2>/dev/null; do
  warn "port $FREE_UI is busy, trying $((FREE_UI + 1))"
  FREE_UI=$((FREE_UI + 1))
  [ "$FREE_UI" -gt $((UI_PORT + 20)) ] && die "no free port near $UI_PORT (set UI_PORT=...)"
done
cmd "$PY -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port $FREE_UI"
"$PY" -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port "$FREE_UI" \
    >"$LOG_DIR/ui.log" 2>&1 &
UI_PID=$!
echo "$UI_PID" >> "$PID_FILE"
if ! wait_for_http "http://127.0.0.1:$FREE_UI/api/health" 40; then
  warn "the server did not answer; last lines of $LOG_DIR/ui.log:"
  tail -n 20 "$LOG_DIR/ui.log" | sed 's/^/     /'
  die "the website did not start (is $FREE_UI free? try UI_PORT=8010 ./run.sh)"
fi
good "running on http://127.0.0.1:$FREE_UI (pid $UI_PID)"

URL="http://127.0.0.1:$FREE_UI/ui/"
printf '\n%s──────────────────────────────────────────────────────────────%s\n' "$B" "$OFF"
printf '  %sCanaryGate is running%s\n' "$OK" "$OFF"
printf '  Landing page   http://127.0.0.1:%s/\n' "$FREE_UI"
printf '  Dashboard      %s\n' "$URL"
printf '  Assessment     http://127.0.0.1:%s/ui/assessment\n' "$FREE_UI"
printf '  API docs       http://127.0.0.1:%s/docs\n' "$FREE_UI"
printf '\n  In the assessment form: environment AssetVault / TargetLab, port %s\n' "$LAB_PORT"
printf '  Press "Run security assessment" and watch the live feed.\n'
printf '  Logs: %s\n' "${LOG_DIR#$ROOT/}"
printf '  Stop: Ctrl+C, or ./run.sh --stop from another terminal\n'
printf '%s──────────────────────────────────────────────────────────────%s\n\n' "$B" "$OFF"

if [ "$OPEN_BROWSER" = "1" ]; then
  if [ -n "${BROWSER:-}" ] && [ "${BROWSER}" != "none" ]; then
    "$BROWSER" "$URL" >/dev/null 2>&1 &
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then
    open "$URL" >/dev/null 2>&1 &
  elif command -v wslview >/dev/null 2>&1; then
    wslview "$URL" >/dev/null 2>&1 &
  else
    warn "no browser opener found — open the URL above yourself"
  fi
else
  say "--no-browser: open the URL above yourself"
fi

say "watching both processes; Ctrl+C stops them"
while true; do
  if ! kill -0 "$UI_PID" 2>/dev/null; then
    warn "the website stopped; last lines of $LOG_DIR/ui.log:"
    tail -n 20 "$LOG_DIR/ui.log" | sed 's/^/     /'
    break
  fi
  sleep 1
done
cleanup
