#!/bin/bash


## Limitations
# * cleartext passwords for computer accounts could contain non-ascii characters,
#    so it is not possible to extract them for the moment.


function show_usage() {
    echo "Usage: $0 -e|-s [-o outputdir] file_with_hashes.txt"
    echo '  Mandatory argument:'
    echo '    -e, --extract  : extract hashes for easier cracking and stats'
    echo '    -s, --stats    : output stats from the base file and optionnaly cracked hashes'
    echo '  Optionnal argument:'
    echo '    -o, --output output_directory  : extract data into the supplied parameter'
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
function l_keep_only_ascii_charset() {
    cat - | tr -d -c '[ -~\n]'
}
function l_keep_only_computer_accounts() {
    cat - | grep -E '^[^:]*\$(_history[0-9]*)?:'
}
function l_remove_computer_accounts() {
    cat - | grep -v -E '^[^:]*\$(_history[0-9]*)?:'
}
function l_remove_history() {
    cat - | grep -v -E '^[^:]*_history[0-9]*(\$)?:'
}
function l_remove_empty_lm() {
    cat - | grep -v -F 'aad3b435b51404eeaad3b435b51404ee'
}
function l_remove_empty_ntlm() {
    cat - | grep -v -F '31d6cfe0d16ae931b73c59d7e0c089c0'
}
function l_keep_only_empty_ntlm() {
    cat - | grep -F '31d6cfe0d16ae931b73c59d7e0c089c0'
}
function l_keep_only_enabled_accounts() {
    cat - | grep -E '(status=Enabled)$'
}
function l_keep_only_disabled_accounts() {
    cat - | grep -E '(status=Disabled)$'
}
function l_keep_only_cleartext_passwords() {
    cat - | grep -E '^[^:]*:CLEARTEXT:'
}
function l_remove_cleartext_passwords() {
    cat - | grep -v -E '^[^:]*:CLEARTEXT:'
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
cat "$hash_file" | l_keep_only_ascii_charset | sed 's/^  *//;s/  *$//' | grep -E -e '^[^:]*:[0-9]*:[0-9a-f]{32}:[0-9a-f]{32}:::( \(status=[a-zA-Z]*\))?$' -e '^[^:]*:CLEARTEXT:' > "$outdir/$base_file"

if [[ "x$action" == "xstats" ]] ; then
    # Output statistics in CSV format
    echo 'Metric,Number'
    echo -n 'Number of total hashes,'
    cat "$outdir/$base_file" | wc -l
    echo -n 'Number of computer accounts,'
    cat "$outdir/$base_file" | l_keep_only_computer_accounts | l_remove_cleartext_passwords | l_remove_history | wc -l
    echo -n 'Number of user accounts,'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_remove_cleartext_passwords | l_remove_history | wc -l
    echo -n 'Number of user accounts enabled,'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_remove_cleartext_passwords | l_remove_history | grep '(status=Enabled)$' | wc -l
    echo -n 'Number of user accounts disabled,'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_remove_cleartext_passwords | l_remove_history | grep '(status=Disabled)$' | wc -l
    echo -n 'Number of user accounts with unknown status,'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_remove_cleartext_passwords | l_remove_history | grep -v -e '(status=Enabled)$' -e '(status=Disabled)$' | wc -l
    echo -n 'Number of user accounts with non-empty LM hash,'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_remove_cleartext_passwords | l_remove_history | l_remove_empty_lm | wc -l
    echo -n 'Number of user accounts with non-empty NTLM hash,'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_remove_cleartext_passwords | l_remove_history | l_remove_empty_ntlm | wc -l
    echo -n 'Number of user accounts with empty NTLM hash,'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_remove_cleartext_passwords | l_remove_history | l_keep_only_empty_ntlm | wc -l
    echo -n 'Number of distinct non-empty LM user hashes (including history),'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_remove_cleartext_passwords | cut -d: -f3 | l_remove_empty_lm | sort -u | wc -l
    echo -n 'Number of distinct non-empty NTLM user hashes (including history),'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_remove_cleartext_passwords | cut -d: -f4 | l_remove_empty_ntlm | sort -u | wc -l
    echo -n 'Number of cleartext passwords for user accounts,'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_keep_only_cleartext_passwords | wc -l
    echo -n 'Number of distinct cleartext passwords for user accounts,'
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_keep_only_cleartext_passwords | cut -d: -f3- | sort -u | wc -l
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
    cat "$outdir/$base_file" | l_remove_cleartext_passwords | cut -d: -f3 | sort -u | l_remove_empty_lm > "$outdir/all_lm_3000.hash"
    [[ ! -s "$outdir/all_lm_3000.hash" ]] && rm "$outdir/all_lm_3000.hash"
    cat "$outdir/$base_file" | l_remove_cleartext_passwords | l_remove_history | cut -d: -f1,3 | l_remove_empty_lm > "$outdir/users_lm_3000.hash"
    [[ ! -s "$outdir/users_lm_3000.hash" ]] && rm "$outdir/users_lm_3000.hash"
    ## extract NTLM
    cat "$outdir/$base_file" | l_remove_cleartext_passwords | l_remove_computer_accounts | cut -d: -f4 | sort -u > "$outdir/all_ntlm_1000.hash"
    [[ ! -s "$outdir/all_ntlm_1000.hash" ]] && rm "$outdir/all_ntlm_1000.hash"
    cat "$outdir/$base_file" | l_remove_cleartext_passwords | l_remove_computer_accounts | l_remove_history | cut -d: -f1,4 > "$outdir/users_ntlm_1000.hash"
    [[ ! -s "$outdir/users_ntlm_1000.hash" ]] && rm "$outdir/users_ntlm_1000.hash"
    cat "$outdir/$base_file" | l_remove_cleartext_passwords | l_remove_computer_accounts | l_remove_history | grep '(status=Enabled)$' | cut -d: -f1,4 > "$outdir/users_enabled_ntlm_1000.hash"
    [[ ! -s "$outdir/users_enabled_ntlm_1000.hash" ]] && rm "$outdir/users_enabled_ntlm_1000.hash"
    ## extract cleartext passwords of user accounts
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_keep_only_cleartext_passwords | cut -d: -f1,3- > "$outdir/users_cleartext_passwords.txt"
    [[ ! -s "$outdir/users_cleartext_passwords.txt" ]] && rm "$outdir/users_cleartext_passwords.txt"
    cat "$outdir/$base_file" | l_remove_computer_accounts | l_keep_only_cleartext_passwords | cut -d: -f3- | sort -u > "$outdir/cleartext_passwords.txt"
    [[ ! -s "$outdir/cleartext_passwords.txt" ]] && rm "$outdir/cleartext_passwords.txt"
fi



