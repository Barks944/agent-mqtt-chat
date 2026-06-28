#!/usr/bin/env bash
# End-to-end smoke test: two agents (alice, bob) on this host exchange a signed
# message in each direction through the real broker.
#
# Usage:
#   BROKER_HOST=your-broker.example.com \
#   BROKER_USER=agents BROKER_PASS='secret' \
#   [BROKER_PORT=8883] [TOPIC=agentmsg/chat] [BIN=./target/debug/agentmsg] \
#   scripts/e2e_smoke.sh
#
# Exits non-zero if either direction fails to deliver.
set -euo pipefail

BIN="${BIN:-./target/debug/agentmsg}"
[ -f "$BIN" ] || BIN="./target/debug/agentmsg.exe"
PORT="${BROKER_PORT:-8883}"
TOPIC="${TOPIC:-agentmsg/chat}"
: "${BROKER_HOST:?set BROKER_HOST}"
: "${BROKER_USER:?set BROKER_USER}"
: "${BROKER_PASS:?set BROKER_PASS}"

WORK="$(mktemp -d)"
ALICE="$WORK/alice"
BOB="$WORK/bob"
trap 'AGENTMSG_HOME="$ALICE" "$BIN" daemon stop >/dev/null 2>&1 || true;
      AGENTMSG_HOME="$BOB"   "$BIN" daemon stop >/dev/null 2>&1 || true;
      rm -rf "$WORK"' EXIT

a() { AGENTMSG_HOME="$ALICE" "$BIN" "$@"; }
b() { AGENTMSG_HOME="$BOB"   "$BIN" "$@"; }
jget() { python -c "import sys,json;print(json.load(sys.stdin)['data'])"; }

echo "== generate identities =="
a id generate alice >/dev/null
b id generate bob   >/dev/null
ATOK="$(a --json id token | jget)"
BTOK="$(b --json id token | jget)"

echo "== exchange identity tokens =="
a agent add "$BTOK" >/dev/null
b agent add "$ATOK" >/dev/null

echo "== configure both agents =="
for ag in a b; do
  $ag config set-broker "$BROKER_HOST" --port "$PORT" >/dev/null
  $ag config set-creds  "$BROKER_USER" "$BROKER_PASS" >/dev/null
  $ag config set-topic  "$TOPIC" >/dev/null
done

echo "== start daemons =="
a daemon start >/dev/null
b daemon start >/dev/null

echo "== wait for both to connect =="
for ag in a b; do
  for i in $(seq 1 20); do
    c="$($ag --json status | python -c "import sys,json;print(json.load(sys.stdin)['data'].get('connected'))" 2>/dev/null || echo None)"
    [ "$c" = "True" ] && break
    sleep 0.5
  done
  [ "$c" = "True" ] || { echo "FAIL: $ag did not connect (connected=$c)"; exit 1; }
done
echo "   both connected."

echo "== alice -> bob =="
a send "hello bob, this is alice" --to bob >/dev/null
GOT="$(timeout 15 bash -c 'AGENTMSG_HOME="'"$BOB"'" "'"$BIN"'" --json read --wait --ack --limit 5' \
       | python -c "import sys,json;d=json.load(sys.stdin)['data'];print(next((m['body'] for m in d if m['from']=='alice'),''))")"
echo "   bob received: '$GOT'"
[ "$GOT" = "hello bob, this is alice" ] || { echo "FAIL: bob did not receive alice's message"; exit 1; }

echo "== bob -> alice =="
b send "got it, alice" --to alice >/dev/null
GOT2="$(timeout 15 bash -c 'AGENTMSG_HOME="'"$ALICE"'" "'"$BIN"'" --json read --wait --ack --limit 5' \
        | python -c "import sys,json;d=json.load(sys.stdin)['data'];print(next((m['body'] for m in d if m['from']=='bob'),''))")"
echo "   alice received: '$GOT2'"
[ "$GOT2" = "got it, alice" ] || { echo "FAIL: alice did not receive bob's reply"; exit 1; }

echo
echo "PASS: bidirectional signed delivery through $BROKER_HOST works."
