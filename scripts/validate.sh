#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
#  scripts/validate.sh  —  Week 12: Validation against test binaries
#  Runs the lifter against the provided Mach-O / ARM64 binaries
#  and compares key findings against expected results.
#
#  Usage:
#    ./scripts/validate.sh [path_to_lifter] [binary1] [binary2] ...
#
#  If no binaries are provided, the script compiles vuln.c and
#  vuln2.c using an available cross-compiler.
# ─────────────────────────────────────────────────────────

set -euo pipefail
LIFTER=${1:-./lifter}
TESTS_DIR="tests"
PASS=0; FAIL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${NC}$*${NC}"; }
ok()   { echo -e "${GREEN}  [PASS]${NC} $*"; ((PASS++)); }
fail() { echo -e "${RED}  [FAIL]${NC} $*"; ((FAIL++)); }
warn() { echo -e "${YELLOW}  [WARN]${NC} $*"; }

# ── Compile test binaries if possible ────────────────────
compile_tests() {
    local CC=""
    if command -v aarch64-linux-gnu-gcc &>/dev/null; then
        CC="aarch64-linux-gnu-gcc"
    elif clang --target=aarch64-linux-gnu -v 2>&1 | grep -q aarch64; then
        CC="clang --target=aarch64-linux-gnu"
    fi

    if [[ -z "$CC" ]]; then
        warn "No ARM64 cross-compiler found. Skipping compile step."
        warn "Provide pre-built ARM64 Mach-O binaries as arguments."
        return 1
    fi

    log "Compiling test binaries with: $CC"
    $CC -O0 -o "$TESTS_DIR/vuln_arm64"  "$TESTS_DIR/vuln.c"  && \
        log "  Built: $TESTS_DIR/vuln_arm64"
    $CC -O0 -o "$TESTS_DIR/vuln2_arm64" "$TESTS_DIR/vuln2.c" && \
        log "  Built: $TESTS_DIR/vuln2_arm64"
    return 0
}

# ── Run one binary and check output ──────────────────────
run_test() {
    local binary="$1"
    local label=$(basename "$binary")
    log "\n── Testing: $label ──"

    if [[ ! -f "$binary" ]]; then
        warn "Binary not found: $binary (skipping)"
        return
    fi

    # Run lifter; capture stderr (analysis output) and stdout (report)
    local report
    report=$("$LIFTER" "$binary" -f text 2>/tmp/lifter_diag) || true
    local diag
    diag=$(cat /tmp/lifter_diag)

    # Check 1: Tool did not crash
    if echo "$report" | grep -q "VERDICT"; then
        ok "$label: tool ran to completion"
    else
        fail "$label: tool did not produce a verdict"
        return
    fi

    # Check 2: Taint sources flagged
    if echo "$diag" | grep -qi "taint"; then
        ok "$label: taint source detected"
    else
        warn "$label: no taint source detected (expected for vuln binaries)"
    fi

    # Check 3: ROP gadgets
    if echo "$diag" | grep -qi "gadget"; then
        ok "$label: ROP gadget scan ran"
    else
        fail "$label: ROP gadget scan output missing"
    fi

    # Check 4: JSON output is valid JSON
    local json_out
    json_out=$("$LIFTER" "$binary" -f json 2>/dev/null) || true
    if echo "$json_out" | python3 -c "import sys,json; json.load(sys.stdin)" &>/dev/null; then
        ok "$label: JSON output is valid"
    else
        fail "$label: JSON output is malformed"
    fi

    # Check 5: Verdict present and non-empty
    local verdict
    verdict=$(echo "$json_out" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('verdict',''))" 2>/dev/null)
    if [[ -n "$verdict" ]]; then
        ok "$label: verdict field present — '$verdict'"
    else
        fail "$label: verdict field missing from JSON"
    fi
}

# ── Ghidra / objdump comparison note ─────────────────────
compare_note() {
    log "\n── Manual comparison guidance (Week 12) ──"
    log "  To cross-check against objdump:"
    log "    objdump -d <binary> | grep -E '(gets|strcpy|memcpy)'"
    log "  To cross-check against Ghidra:"
    log "    1. Import binary → Analyse → look for highlighted dangerous calls"
    log "    2. Compare with lifter taint sources"
    log ""
}

# ── Entry point ───────────────────────────────────────────
log "╔══════════════════════════════════════════════════╗"
log "║  Binary Code Lifter — Validation Suite (Week 12) ║"
log "╚══════════════════════════════════════════════════╝"

if [[ ! -x "$LIFTER" ]]; then
    echo "Error: lifter not found at '$LIFTER'. Run 'make' first."
    exit 1
fi

# Compile if no extra args given
if [[ $# -le 1 ]]; then
    compile_tests || true
    BINARIES=("$TESTS_DIR/vuln_arm64" "$TESTS_DIR/vuln2_arm64")
else
    shift  # remove lifter arg
    BINARIES=("$@")
fi

for b in "${BINARIES[@]}"; do
    run_test "$b"
done

compare_note

log "\n══════════════════════════════════════════════════"
log "  Results: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}"
log "══════════════════════════════════════════════════\n"

[[ $FAIL -eq 0 ]]
