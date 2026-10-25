#!/usr/bin/env bash
#
# Runs the official PostgreSQL regression suite twice:
#
#   * `baseline` — psql talks straight to the upstream server;
#   * `proxied`  — psql talks to the same server through `pregresql-proxy`.
#
# Both runs use identical client environments (only PGHOST/PGPORT differ) and
# the suite drops and recreates the `regression` database at the start of each
# run, so the two runs are independent.
#
# pg_regress deletes `regression.out`/`regression.diffs` when a run is clean, so
# the run's stdout is captured as well; that is what the comparison below uses.
set -uo pipefail

PGBINDIR=${PGBINDIR:-/usr/lib/postgresql/16/bin}
PG_REGRESS=${PG_REGRESS:-/usr/lib/postgresql/16/lib/pgxs/src/test/regress/pg_regress}
REGRESS_DIR=${REGRESS_DIR:-/pgtest-regress}
RESULTS=${RESULTS:-/results}
PGUSER=${PGUSER:-postgres}
export PGUSER
export PGPASSWORD=${PGPASSWORD:-postgres}

BASELINE_HOST=${BASELINE_HOST:-upstream}
BASELINE_PORT=${BASELINE_PORT:-5432}
PROXIED_HOST=${PROXIED_HOST:-proxy}
PROXIED_PORT=${PROXIED_PORT:-6432}

MAX_CONCURRENT_TESTS=${MAX_CONCURRENT_TESTS:-20}
MAX_CONNECTIONS=${MAX_CONNECTIONS:-20}

wait_for() {
    local label="$1" host="$2" port="$3"
    local tries=120
    printf 'waiting for %s at %s:%s ' "$label" "$host" "$port"
    until "$PGBINDIR/psql" -h "$host" -p "$port" -U "$PGUSER" -d postgres \
            -Atqc 'select 1' >/dev/null 2>&1; do
        tries=$((tries - 1))
        if [ "$tries" -le 0 ]; then
            echo " TIMEOUT"
            return 1
        fi
        printf '.'
        sleep 1
    done
    echo ' ready'
}

run_suite() {
    local label="$1" host="$2" port="$3"
    local out="$RESULTS/$label"

    rm -rf "$out"
    mkdir -p "$out"

    echo
    echo "==============================================================================="
    echo "pg_regress :: $label  (PGHOST=$host PGPORT=$port)"
    echo "==============================================================================="

    PGHOST="$host" PGPORT="$port" \
    "$PG_REGRESS" \
        --inputdir="$REGRESS_DIR" \
        --outputdir="$out" \
        --bindir="$PGBINDIR" \
        --dlpath="$REGRESS_DIR" \
        --schedule="$REGRESS_DIR/parallel_schedule" \
        --no-locale \
        --max-concurrent-tests="$MAX_CONCURRENT_TESTS" \
        --max-connections="$MAX_CONNECTIONS" \
        2>&1 | tee "$out/pg_regress.stdout"
    local rc=${PIPESTATUS[0]}
    echo "$rc" >"$out/exit_code"

    echo "pg_regress($label) exited with $rc"
    grep -E '^# [0-9]+ of|^# All ' "$out/pg_regress.stdout" | tail -1
    return 0
}

# Remove everything that legitimately varies between two identical runs: the
# host/port line, the order in which parallel groups happen to be scheduled, and
# per-test durations.
normalize() {
    sed -E \
        -e 's/^(# using postmaster on).*/\1 <host:port>/' \
        -e 's/^(# parallel group \([0-9]+ tests\):).*/\1 <order not compared>/' \
        -e 's/[[:space:]]+[0-9]+ ms$//' \
        -e 's/[[:space:]]+[0-9]+ s$//' \
        "$1"
}

wait_for upstream "$BASELINE_HOST" "$BASELINE_PORT" || exit 1
wait_for proxy "$PROXIED_HOST" "$PROXIED_PORT" || exit 1

run_suite baseline "$BASELINE_HOST" "$BASELINE_PORT"
run_suite proxied "$PROXIED_HOST" "$PROXIED_PORT"

echo
echo "==============================================================================="
echo "comparison"
echo "==============================================================================="

status=0

base="$RESULTS/baseline/pg_regress.stdout"
prox="$RESULTS/proxied/pg_regress.stdout"
if diff -u <(normalize "$base") <(normalize "$prox") >"$RESULTS/pg_regress.stdout.diff"; then
    echo "test-by-test status: IDENTICAL between the direct and the proxied run"
    rm -f "$RESULTS/pg_regress.stdout.diff"
else
    echo "test-by-test status: DIFFERS -> $RESULTS/pg_regress.stdout.diff"
    status=1
fi

# pg_regress removes these files only when a run had nothing to report.
base="$RESULTS/baseline/regression.diffs"
prox="$RESULTS/proxied/regression.diffs"
has_base=0; has_prox=0
[ -f "$base" ] && has_base=1
[ -f "$prox" ] && has_prox=1
if [ "$has_base" = "0" ] && [ "$has_prox" = "0" ]; then
    echo "unexpected output: NONE in either run (every test matched its expected output)"
elif [ "$has_base" != "$has_prox" ]; then
    echo "unexpected output: present in only one run (baseline=$has_base, proxied=$has_prox)"
    status=1
elif diff -u "$base" "$prox" >"$RESULTS/regression.diffs.diff" 2>&1; then
    echo "unexpected output: byte-identical between the two runs"
    rm -f "$RESULTS/regression.diffs.diff"
else
    echo "unexpected output: DIFFERS -> $RESULTS/regression.diffs.diff"
    status=1
fi

echo
for label in baseline proxied; do
    total=$(grep -cE '^(ok|not ok) ' "$RESULTS/$label/pg_regress.stdout" || true)
    failed=$(grep -cE '^not ok ' "$RESULTS/$label/pg_regress.stdout" || true)
    printf '%-8s %3s test file(s) run, %s differed from the expected output\n' \
        "$label" "$total" "$failed"
done

exit $status
