#!/bin/bash
# Runs hip-handler-client against njvack/gp-fake-gateway and checks that the
# gateway got the handler's HIP report, and that a failing handler fails
# session setup. Needs no root and no tun device.
#
#   tests/macos/hip-handler.sh CLIENT FAKEGP
set -u

CLIENT=${1:?usage: hip-handler.sh CLIENT FAKEGP}
FAKEGP=${2:?usage: hip-handler.sh CLIENT FAKEGP}
WORK=$(mktemp -d)
LISTEN=127.0.0.1:18543
CONTROL=127.0.0.1:18544
fails=0

unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy

cleanup() {
  [ -n "${GP_PID:-}" ] && kill "$GP_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "${WORK:?}"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
ctl() { curl -sf -X "$1" "http://$CONTROL$2" ${3:+-d "$3"}; }

"$FAKEGP" -listen "$LISTEN" -control "$CONTROL" -pin-file "$WORK/pin" >"$WORK/fakegp.out" 2>"$WORK/fakegp.log" &
GP_PID=$!
for _ in $(seq 10); do [ -s "$WORK/pin" ] && break; sleep 1; done
[ -s "$WORK/pin" ] || { echo "fakegp did not start"; cat "$WORK/fakegp.log"; exit 1; }
ctl PUT /config '{"hip_needed": true}' >/dev/null

handler_reports() {
  ctl GET /sessions | python3 -c 'import json, sys; print(sum(1 for s in json.load(sys.stdin) for r in (s["hip_reports"] or []) if "<host-name>hip-handler-client</host-name>" in r["report"]))'
}

if "$CLIENT" "$LISTEN" "$(cat "$WORK/pin")" >"$WORK/ok.log" 2>&1; then
  pass "session set up with the HIP report from the handler"
else
  fail "session setup with the handler failed"
fi
grep -h "^handler:" "$WORK/ok.log"
if [ "$(handler_reports)" -ge 1 ]; then pass "gateway received the handler's report"; else fail "gateway did not receive the handler's report"; fi
if grep -q "Trying to run HIP Trojan script" "$WORK/ok.log"; then fail "a HIP script ran"; else pass "no HIP script ran"; fi

if "$CLIENT" "$LISTEN" "$(cat "$WORK/pin")" fail >"$WORK/fail.log" 2>&1; then
  fail "session setup succeeded although the handler failed"
else
  pass "a failing handler fails session setup"
fi

if [ "$fails" -ne 0 ]; then
  for f in "$WORK"/*.log; do echo "--- $f"; tail -30 "$f"; done
  echo "$fails failure(s)"
  exit 1
fi
echo "all passed"
