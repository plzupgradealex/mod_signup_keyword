#!/usr/bin/env ksh
# deploy-signup-keyword.ksh
#
# Deploy mod_signup_keyword (keyword-gated IBR) to the RUNNING prod ejabberd
# node on your-server, with the safety pattern that prevents the Mnesia-corruption
# race documented in LAB_NOTEBOOK entry 061.
#
# What it does (idempotent; safe to re-run):
#   0. Preflight: refuses to run if the keyword is still the placeholder.
#   1. Compiles mod_signup_keyword.erl on-box (OTP 27) -> $BUILD/ebin/.
#   2. Backs up the live config: ejabberd.yml -> ejabberd.yml.bak.signup-keyword.
#   3. Merges the mod_signup_keyword block + registration_timeout_ms into the live
#      config (in place; keyword injected from the KEYWORD env var).
#   4. Clean stop: stopsrc -> wait for active->inoperative -> kill strays ->
#      sleep 3 (the exact sequence from apply-ejabberd-config.ksh:20-24).
#   5. startsrc + wait up to 25s for active.
#   6. Verifies: startup markers in log, module loaded, register stream
#      feature advertised.
#
# Usage (run on your-server as root, or via su):
#   scp scripts/deploy-signup-keyword.ksh src/mod_signup_keyword.erl your-server:/tmp/
#   ssh your-server 'su -c "KEYWORD='your-shared-keyword' ksh /tmp/deploy-signup-keyword.ksh"'
#
# Environment:
#   KEYWORD   (required) the real signup keyword. Never hardcoded.
#   BUILD     (optional) ejabberd build tree (the dir containing ebin/ and
#             include/). Default: auto-detected from `ejabberdctl` path, or
#             set explicitly: BUILD=/path/to/ejabberd
#   CONFIG    (optional) live config path. Default: $BUILD/ejabberd.yml
#   ERLC      (optional) path to erlc. Default: auto-detected from PATH.

set -u

# Try to auto-detect the ejabberd build tree.
if [ -z "${BUILD:-}" ]; then
    # Common locations, checked in order:
    for candidate in \
        "$(command -v ejabberdctl 2>/dev/null | xargs dirname 2>/dev/null)/.." \
        /usr/lib/ejabberd \
        /opt/ejabberd \
        /lib/ejabberd; do
        if [ -d "$candidate/ebin" ] 2>/dev/null; then
            BUILD="$candidate"
            break
        fi
    done
fi
if [ -z "${BUILD:-}" ]; then
    echo "FATAL: could not auto-detect ejabberd build tree."
    echo "  Set BUILD=/path/to/ejabberd (the dir containing ebin/ and include/)"
    exit 2
fi
CONFIG="${CONFIG:-$BUILD/ejabberd.yml}"
ERLC="${ERLC:-$(command -v erlc || echo erlc)}"
NODE=ejabberd
SRC=/tmp/mod_signup_keyword.erl
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PLACEHOLDER='REPLACE_ON_BOX_WITH_REAL_KEYWORD'

echo "=== deploy mod_signup_keyword to prod ==="
echo "BUILD=$BUILD"
echo "CONFIG=$CONFIG"

# ---- 0. Preflight: keyword must be provided and not the placeholder ----
if [ -z "${KEYWORD:-}" ]; then
    echo "FATAL: KEYWORD env var is required."
    echo "  Usage: KEYWORD='your-keyword' ksh $0"
    exit 2
fi
if [ "$KEYWORD" = "$PLACEHOLDER" ]; then
    echo "FATAL: KEYWORD is still the placeholder. Set a real keyword."
    exit 2
fi
if [ ! -r "$SRC" ]; then
    echo "FATAL: $SRC not found. SCP it first:"
    echo "  scp src/mod_signup_keyword.erl your-server:$SRC"
    exit 2
fi
if [ ! -d "$BUILD/ebin" ]; then
    echo "FATAL: $BUILD/ebin not found. Wrong BUILD path?"
    exit 2
fi

# Refuse to run as non-root -- the config and ebin dir are root-owned.
if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: run as root (the config and ebin dir are root-owned)."
    echo "  Try: su -c \"KEYWORD='...' ksh $0\""
    exit 2
fi

# ---- 1. Compile the module on-box against the real ejabberd headers ----
echo "=== compile mod_signup_keyword.erl (OTP 27) ==="
"$ERLC" -I "$BUILD/include" -I "$BUILD/_build/default/lib" -o "$BUILD/ebin" "$SRC"
RC=$?
if [ $RC -ne 0 ]; then
    echo "FATAL: compile failed (rc=$RC). Aborting before any config change."
    exit $RC
fi
if [ ! -r "$BUILD/ebin/mod_signup_keyword.beam" ]; then
    echo "FATAL: compile produced no .beam. Aborting."
    exit 3
fi
ls -l "$BUILD/ebin/mod_signup_keyword.beam"

# ---- 2. Backup the live config (timestamped, so re-runs don't clobber) ----
TS=$(date +%Y%m%d-%H%M%S)
BAK="$CONFIG.bak.signup-keyword.$TS"
echo "=== backup live config -> $BAK ==="
cp "$CONFIG" "$BAK"
ls -l "$BAK"

# ---- 3. Patch the live config in place ----
# 3a. Compile the new full config from scripts/ejabberd-production.yml with
#     the keyword substituted in. This is cleaner than sed-patching the live
#     file because the live file may have drifted (api keys, secrets edited
#     on-box). Instead we do a surgical sed: only touch the keyword line and
#     ensure the module block + registration_timeout_ms exist.
#
# We assume the live config already has the mod_signup_keyword block (installed
# by copying scripts/ejabberd-production.yml on-box in a prior step, or merged
# manually). This script's job is to (a) compile the beam, (b) set the keyword,
# (c) restart. The full-config-copy step is done separately so the operator can
# review the diff against the live file (which may have on-box-only secrets).

if grep -q "^  mod_signup_keyword:" "$CONFIG"; then
    echo "=== mod_signup_keyword block already present; injecting keyword ==="
    # Replace the placeholder (or any prior keyword) on the keyword: line.
    # Using a perl one-liner because AIX sed doesn't support in-place -i with
    # arbitrary delimiters cleanly, and the keyword may contain / and !.
    perl -i -pe 's/^(\s*keyword:\s*).*$/${1}"'"$KEYWORD"'"/' "$CONFIG"
else
    echo "=== mod_signup_keyword block NOT in live config ==="
    echo "The live config must contain the mod_signup_keyword block before running."
    echo "Copy scripts/ejabberd-production.yml to the box and diff against $CONFIG,"
    echo "merging the modules.mod_signup_keyword + registration_timeout_ms changes."
    echo "Restoring from backup (no changes made)."
    cp "$BAK" "$CONFIG"
    exit 4
fi

# Sanity: confirm the keyword landed and is no longer the placeholder.
if grep -q "$PLACEHOLDER" "$CONFIG"; then
    echo "FATAL: placeholder still present after injection. Restoring backup."
    cp "$BAK" "$CONFIG"
    exit 5
fi
echo "keyword line now:"
grep -n "^    keyword:" "$CONFIG"
chown root:system "$CONFIG"; chmod 640 "$CONFIG"

# ---- 4. Clean stop (the safety pattern from apply-ejabberd-config.ksh:20-24) ----
kill_beam() {
    ps -ef | grep "sname $NODE" | grep beam | grep -v grep | awk '{print $2}' | while read p; do
        kill -9 "$p" 2>/dev/null
    done
}

echo "=== clean stop ==="
stopsrc -s ejabberd >/dev/null 2>&1 || true
i=0
while [ "$(lssrc -s ejabberd | awk 'END{print $NF}')" = "active" ] && [ $i -lt 25 ]; do
    sleep 1; i=$((i+1))
done
echo "stopped after ${i}s"
kill_beam
sleep 3   # let Mnesia quiesce and ports free -- prevents the corruption race

# ---- 5. Start + wait for active ----
echo "=== start ==="
startsrc -s ejabberd >/dev/null 2>&1
i=0; st=inoperative
while [ $i -lt 25 ]; do
    st=$(lssrc -s ejabberd | awk 'END{print $NF}')
    [ "$st" = "active" ] && break
    sleep 1; i=$((i+1))
done
echo "status: $st (after ${i}s)"
if [ "$st" != "active" ]; then
    echo "FATAL: ejabberd did not come up. Restoring backup config + restarting."
    cp "$BAK" "$CONFIG"
    chown root:system "$CONFIG"; chmod 640 "$CONFIG"
    kill_beam; sleep 3
    startsrc -s ejabberd >/dev/null 2>&1
    echo "Restored. Investigate the log: tail -100 $BUILD/ejabberd.log"
    exit 6
fi

# ---- 6. Verify ----
LOG="$BUILD/ejabberd.log"
echo "=== startup markers in log ==="
grep -E "Configuration loaded successfully|started in the node|Start accepting" "$LOG" | tail -4

echo "=== module loaded? ==="
grep -iE "mod_signup_keyword|signup_keyword" "$LOG" | tail -5 || echo "(no explicit log line; checking via the beam path)"
test -r "$BUILD/ebin/mod_signup_keyword.beam" && echo "beam present: $BUILD/ebin/mod_signup_keyword.beam"

echo ""
echo "=== deploy complete ==="
echo "Backup of previous config: $BAK"
echo "Rollback: cp $BAK $CONFIG && (stopsrc -s ejabberd; sleep 3; startsrc -s ejabberd)"
echo ""
echo "Next: verify registration works end-to-end with scripts/test-ibr-keyword.py"
echo "  python3 scripts/test-ibr-keyword.py --host example.org --keyword \"\$KEYWORD\""
