#!/bin/bash


function show_usage() {
    echo "Usage: $0 -e|-s [-o outputdir] file_with_hashes.txt"
    echo '    -e, --extract  : extract hashes for easier cracking and stats'
    echo '    -s, --stats    : output stats from the base file and optionnaly cracked hashes'
    exit 0
}

function debug() {
    [[ "x$DEBUG" == "x1" ]] && echo "$@"
    echo -n ''
}

# configuration
DEBUG='0'
base_file='ntds_base_file.txt'


# function definitions
function l-keep-only-computer-accounts() {
    cat - | grep -E '^[^:]*\$(_history[0-9]*)?:[0-9]*:[0-9a-f]{32}:[0-9a-f]{32}:::( \(status=[a-zA-Z]*\))?$'
}
function l-remove-computer-accounts() {
    cat - | grep -E '^[^:$]*(_history[0-9]*)?:[0-9]*:[0-9a-f]{32}:[0-9a-f]{32}:::( \(status=[a-zA-Z]*\))?$'
}
function l-remove-history() {
    cat - | grep -vE '^[^:]*_history[0-9]*(\$)?:'
}
function l-remove-empty-lm() {
    cat - | grep -v 'aad3b435b51404eeaad3b435b51404ee'
}
function l-remove-empty-ntlm() {
    cat - | grep -v '31d6cfe0d16ae931b73c59d7e0c089c0'
}
function l-keep-only-empty-ntlm() {
    cat - | grep '31d6cfe0d16ae931b73c59d7e0c089c0'
}
function l-keep-only-enabled-accounts() {
    cat - | grep '(status=Enabled)$'
}
function l-keep-only-disabled-accounts() {
    cat - | grep '(status=Disabled)$'
}


# variable definitions
outdir="."

# argument parsing
# see: https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
POSITIONAL=()
while [[ $# -gt 0 ]] ; do
    key="$1"
    case $key in
        -h|--help)
        show_usage
        ;;
        -e|--extract)
        action='extract'
        shift # past argument
        ;;
        -s|--stats)
        action='stats'
        shift # past argument
        ;;
        -o|--output)
        outdir="$2"
        shift # past argument
        shift # past value
        ;;
        -d|--debug)
        DEBUG='1'
        shift # past argument
        ;;
        *)    # unknown option
        POSITIONAL+=("$1") # save it in an array for later
        shift # past argument
        ;;
    esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters


# Check parameters
hash_file="${POSITIONAL[0]}"
[[ -z "$hash_file" ]] && show_usage
[[ -z "$action" ]] && show_usage
# create output dir
mkdir -p "$outdir" 2>/dev/null
[[ -d "$outdir" ]] || ( echo "Unable to create output dir: $outdir" >&2 ; exit 1 )
# Extract known hash format
cat "$hash_file" | sed 's/^  *//;s/  *$//' | grep -E '^[^:]*:[0-9]*:[0-9a-f]{32}:[0-9a-f]{32}:::( \(status=[a-zA-Z]*\))?$' > "$outdir/$base_file"

if [[ "x$action" == "xstats" ]] ; then
    # Output statistics in CSV format
    echo 'Metric,Number'
    echo -n 'Number of total hashes,'
    cat "$outdir/$base_file" | wc -l
    echo -n 'Number of computer accounts,'
    cat "$outdir/$base_file" | l-keep-only-computer-accounts | l-remove-history | wc -l
    echo -n 'Number of user accounts,'
    cat "$outdir/$base_file" | l-remove-computer-accounts | l-remove-history | wc -l
    echo -n 'Number of user accounts enabled,'
    cat "$outdir/$base_file" | l-remove-computer-accounts | l-remove-history | grep '(status=Enabled)$' | wc -l
    echo -n 'Number of user accounts disabled,'
    cat "$outdir/$base_file" | l-remove-computer-accounts | l-remove-history | grep '(status=Disabled)$' | wc -l
    echo -n 'Number of user accounts with unknown status,'
    cat "$outdir/$base_file" | l-remove-computer-accounts | l-remove-history | grep -v -e '(status=Enabled)$' -e '(status=Disabled)$' | wc -l
    echo -n 'Number of user accounts with non-empty LM hash,'
    cat "$outdir/$base_file" | l-remove-computer-accounts | l-remove-history | l-remove-empty-lm | wc -l
    echo -n 'Number of user accounts with non-empty NTLM hash,'
    cat "$outdir/$base_file" | l-remove-computer-accounts | l-remove-history | l-remove-empty-ntlm | wc -l
    echo -n 'Number of user accounts with empty NTLM hash,'
    cat "$outdir/$base_file" | l-remove-computer-accounts | l-remove-history | l-keep-only-empty-ntlm | wc -l
    echo -n 'Number of distinct non-empty LM user hashes (including history),'
    cat "$outdir/$base_file" | l-remove-computer-accounts | cut -d: -f3 | l-remove-empty-lm | sort -u | wc -l
    echo -n 'Number of distinct non-empty NTLM user hashes (including history),'
    cat "$outdir/$base_file" | l-remove-computer-accounts | cut -d: -f4 | l-remove-empty-ntlm | sort -u | wc -l
    ls -1 "$outdir"/*.hash 2>/dev/null | while read fil ; do
        debug "parse $fil file"
        fil_show="${fil%.*}.show"
        debug "linked show file = $fil_show"
        if [[ -f "$fil_show" ]] ; then
            echo "$fil,$(($(wc -l "$fil_show"| grep -o "^[0-9]*")*100/$(wc -l "$fil" | grep -o "^[0-9]*"))) %"
        else
            echo "$fil,0 %"
        fi
    done
fi

if [[ "x$action" == "xextract" ]] ; then
    # Extract hashes
    ## extract LM
    cat "$outdir/$base_file" | cut -d: -f3 | sort -u > "$outdir/all_lm_3000.hash"
    cat "$outdir/$base_file" | l-remove-history | cut -d: -f1,3 | l-remove-empty-lm > "$outdir/users_lm_3000.hash"
    ## extract NTLM
    cat "$outdir/$base_file" | l-remove-computer-accounts | cut -d: -f4 | sort -u > "$outdir/all_ntlm_1000.hash"
    cat "$outdir/$base_file" | l-remove-computer-accounts | l-remove-history | cut -d: -f1,4 > "$outdir/users_ntlm_1000.hash"
    cat "$outdir/$base_file" | l-remove-computer-accounts | l-remove-history | grep '(status=Enabled)$' | cut -d: -f1,4 > "$outdir/users_enabled_ntlm_1000.hash"
fi



