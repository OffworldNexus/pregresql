#!/usr/bin/env bash
#
# End-to-end validation:
#
#   1. build the proxy image and the PostgreSQL test image;
#   2. run the official PostgreSQL regression suite twice (direct and through
#      the proxy) and diff the results;
#   3. run the strict-mode demo client against the locked-down proxy.
#
# Usage: scripts/validate.sh [--keep]
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f docker/docker-compose.yml)
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

mkdir -p docker/results
# The tester runs as the same uid as the server process (999), and both write
# into this shared directory.
chmod 777 docker/results

echo "### building images"
"${COMPOSE[@]}" build

echo
echo "### starting the stack"
"${COMPOSE[@]}" up -d --remove-orphans

cleanup() {
    if [ "$KEEP" = "1" ]; then
        echo "### leaving the stack running (--keep)"
    else
        echo "### tearing the stack down"
        "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo
echo "### waiting for the regression suite to finish"
tester_id=$("${COMPOSE[@]}" ps -q tester)
if [ -z "$tester_id" ]; then
    echo "tester container did not start" >&2
    exit 1
fi
set +e
tester_rc=$(docker wait "$tester_id")
set -e
echo "tester exit code: $tester_rc"
docker logs "$tester_id" >docker/results/tester.log 2>&1 || true
echo "(full transcript in docker/results/tester.log)"

echo
echo "### regression summary"
for label in baseline proxied; do
    out="docker/results/$label/pg_regress.stdout"
    if [ -f "$out" ]; then
        total=$(grep -cE '^(ok|not ok) ' "$out" || true)
        bad=$(grep -cE '^not ok ' "$out" || true)
        summary=$(grep -E '^# (All [0-9]+ tests passed|[0-9]+ of [0-9]+ tests failed)' "$out" | tail -1)
        printf '%-8s %3s test file(s) run, %2s differed  -- %s\n' "$label" "$total" "$bad" "$summary"
    else
        echo "$label: no pg_regress output captured"
    fi
done

echo
if [ -f docker/results/pg_regress.stdout.diff ] || [ -f docker/results/regression.diffs.diff ]; then
    echo "### the proxied run differs from the direct run:"
    if [ -f docker/results/pg_regress.stdout.diff ]; then
        head -40 docker/results/pg_regress.stdout.diff
    fi
    if [ -f docker/results/regression.diffs.diff ]; then
        head -40 docker/results/regression.diffs.diff
    fi
    diff_rc=1
else
    echo "the direct and the proxied runs produced identical pass/fail results"
    diff_rc=0
fi

echo
echo "### TLS proxy check (client side TLS + required upstream TLS)"
tls_rc=1
tls_out=$("${COMPOSE[@]}" exec -T -e PGPASSWORD=postgres upstream \
    psql "sslmode=require host=proxy-tls port=6434 user=postgres dbname=postgres" \
    -Atc "select ssl from pg_stat_ssl where pid = pg_backend_pid()" 2>&1) || true
case "$tls_out" in
"t")
    echo "psql connected with sslmode=require and the upstream leg is encrypted too"
    tls_rc=0
    ;;
*)
    echo "TLS check failed: $tls_out"
    ;;
esac

echo
echo "### strict-mode demo client"
set +e
cargo run --quiet --example demo_client -- 15432 16433
demo_rc=$?
set -e

echo
if [ "$tester_rc" = "0" ] && [ "$diff_rc" = "0" ] && [ "$demo_rc" = "0" ] && [ "$tls_rc" = "0" ]; then
    echo "VALIDATION PASSED"
    exit 0
fi
echo "VALIDATION FAILED (tester=$tester_rc diff=$diff_rc demo=$demo_rc tls=$tls_rc)"
exit 1
