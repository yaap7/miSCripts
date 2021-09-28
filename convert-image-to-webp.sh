#!/bin/bash

function show_usage() {
    echo "Usage: $0 [-q <quality>] <file.jpg> [<file.png> ...]"
    echo '  Optionnal argument:'
    echo '    -q, --quality <quality>: quality of images to save (default: 80%)'
    echo '    -r, --remove: remove old images'
    exit 1
}

# configuration
quality='80'
remove='0'

# argument parsing
# see: https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
POSITIONAL=()
while [[ $# -gt 0 ]] ; do
    key="$1"
    case $key in
        -h|--help)
        show_usage
        ;;
        -r|--remove)
        remove='1'
        shift # past argument
        ;;
        -q|--quality)
        quality="$2"
        shift # past argument
        shift # past value
        ;;
        *)    # unknown option
        POSITIONAL+=("$1") # save it in an array for later
        shift # past argument
        ;;
    esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

while [[ $# -gt 0 ]] ; do
	if file -i "${1}" | grep -q -e 'image/jpeg;' -e 'image/png' ; then
        ext="$(echo "${1}" | grep -o '\.[a-zA-Z]*$')"
        cwebp -quiet -q "${quality}" -o "${1%${ext}}.webp" "${1}"
        [[ "x$remove" == "x1" ]] && rm -f "${1}"
	else
		echo "image $1 not valid for optimisation (need jpeg or png images)" >&2
	fi
    shift
done

exit 0
