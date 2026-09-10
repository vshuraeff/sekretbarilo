#!/usr/bin/env bash
#
# corpus-audit.sh - run `sekretbarilo audit` over a set of local repositories and summarise the
# result, so a detection change can be measured against the same corpus before and after.
#
# usage:
#   corpus-audit.sh <binary> <repos-file> <out-dir> [--config <toml>] [--trace-exemptions]
#   corpus-audit.sh --diff <a-out-dir> <b-out-dir>
#
# <repos-file> lists one local repository path per line; blank lines and lines starting with # are
# ignored. the run writes three tab-separated files into <out-dir>:
#
#   summary.tsv    repo, exit code, findings, files scanned
#   findings.tsv   repo, file, line, rule, masked match
#   per-rule.tsv   rule, findings
#
# raw/ keeps the unparsed output of every repository. audit exits 1 when it reports something and 2
# when the scan was incomplete, so a non-zero exit code in summary.tsv is data, not a failed run.

set -u

program=$(basename "$0")
tab=$(printf '\t')

usage() {
    printf 'usage: %s <binary> <repos-file> <out-dir> [--config <toml>] [--trace-exemptions]\n' "$program"
    printf '       %s --diff <a-out-dir> <b-out-dir>\n' "$program"
}

fail() {
    printf '%s: %s\n' "$program" "$1" >&2
    exit 2
}

absolute() {
    case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$PWD" "$1" ;;
    esac
}

# per-rule delta between two output directories, smallest delta first.
diff_mode() {
    a_dir=$1
    b_dir=$2
    for dir in "$a_dir" "$b_dir"; do
        [ -f "$dir/per-rule.tsv" ] || fail "no per-rule.tsv in $dir"
    done

    printf 'rule\t%s\t%s\tdelta\n' "$(basename "$a_dir")" "$(basename "$b_dir")"
    # the delta is printed without a sign, because sort -n reads a leading + as non-numeric.
    awk -F '\t' '
        FNR == 1 { next }
        NR == FNR { before[$1] = $2; seen[$1] = 1; next }
        { after[$1] = $2; seen[$1] = 1 }
        END {
            for (rule in seen) {
                left = (rule in before) ? before[rule] : 0
                right = (rule in after) ? after[rule] : 0
                printf "%s\t%d\t%d\t%d\n", rule, left, right, right - left
            }
        }
    ' "$a_dir/per-rule.tsv" "$b_dir/per-rule.tsv" | sort -t "$tab" -k4,4n -k1,1

    awk -F '\t' '
        FNR == 1 { next }
        NR == FNR { left += $2; next }
        { right += $2 }
        END { printf "TOTAL\t%d\t%d\t%d\n", left, right, right - left }
    ' "$a_dir/per-rule.tsv" "$b_dir/per-rule.tsv"
}

if [ "$#" -ge 1 ] && [ "$1" = "--help" ]; then
    usage
    exit 0
fi

if [ "$#" -ge 1 ] && [ "$1" = "--diff" ]; then
    [ "$#" -eq 3 ] || fail "--diff takes two output directories"
    diff_mode "$2" "$3"
    exit 0
fi

if [ "$#" -lt 3 ]; then
    usage >&2
    exit 2
fi

binary=$(absolute "$1")
repos_file=$(absolute "$2")
out_dir=$(absolute "$3")
shift 3

audit_args=(audit)
while [ "$#" -gt 0 ]; do
    case "$1" in
    --config)
        [ "$#" -ge 2 ] || fail "--config needs a path"
        audit_args+=(--config "$(absolute "$2")")
        shift 2
        ;;
    --trace-exemptions)
        audit_args+=(--trace-exemptions)
        shift
        ;;
    *) fail "unknown argument: $1" ;;
    esac
done

[ -x "$binary" ] || fail "not an executable: $binary"
[ -r "$repos_file" ] || fail "cannot read: $repos_file"
mkdir -p "$out_dir/raw" || fail "cannot create $out_dir/raw"

summary="$out_dir/summary.tsv"
findings="$out_dir/findings.tsv"
per_rule="$out_dir/per-rule.tsv"

printf 'repo\texit\tfindings\tfiles\n' >"$summary"
printf 'repo\tfile\tline\trule\tmatch\n' >"$findings"

while IFS= read -r repo || [ -n "$repo" ]; do
    case "$repo" in
    '' | \#*) continue ;;
    esac

    label=$(basename "$repo")
    slug=$(printf '%s' "$repo" | tr -c 'A-Za-z0-9._-' '_')
    log="$out_dir/raw/$slug.log"
    parsed="$out_dir/raw/$slug.tsv"

    if [ ! -d "$repo" ]; then
        printf '%s: no such directory: %s\n' "$program" "$repo" >&2
        printf '%s\t127\t0\t0\n' "$label" >>"$summary"
        continue
    fi

    (cd "$repo" && "$binary" "${audit_args[@]}") >"$log" 2>&1
    code=$?

    awk -v repo="$label" '
        /^  file: / { file = substr($0, 9); next }
        /^  line: / { line = substr($0, 9); next }
        /^  rule: / { rule = substr($0, 9); next }
        /^  match: / {
            printf "%s\t%s\t%s\t%s\t%s\n", repo, file, line, rule, substr($0, 10)
            next
        }
    ' "$log" >"$parsed"
    cat "$parsed" >>"$findings"

    count=$(awk 'END { print NR + 0 }' "$parsed")
    files=$(awk '/^\[AUDIT\] audit complete\./ {
        for (i = 1; i <= NF; i++) {
            if ($i == "scanned") { print $(i + 1); exit }
        }
    }' "$log")
    [ -n "$files" ] || files=0

    printf '%s\t%d\t%d\t%d\n' "$label" "$code" "$count" "$files" >>"$summary"
done <"$repos_file"

printf 'rule\tfindings\n' >"$per_rule"
awk -F '\t' 'NR > 1 { count[$4]++ } END { for (rule in count) printf "%s\t%d\n", rule, count[rule] }' \
    "$findings" | sort -t "$tab" -k2,2nr -k1,1 >>"$per_rule"

total=$(awk -F '\t' 'NR > 1 { total += $3 } END { print total + 0 }' "$summary")
repos=$(awk -F '\t' 'END { if (NR > 1) { print NR - 1 } else { print 0 } }' "$summary")
scanned=$(awk -F '\t' 'NR > 1 { files += $4 } END { print files + 0 }' "$summary")
printf 'corpus-audit: %s finding(s) over %s scanned file(s) in %s repositories -> %s\n' \
    "$total" "$scanned" "$repos" "$out_dir"
