#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <file>" >&2
    exit 1
fi

file="$1"

if [[ ! -f "$file" ]]; then
    echo "Error: File not found: $file" >&2
    exit 1
fi

# Replace or remove selected Unicode characters in UTF-8 text.
perl -i -CSD -pe '
    s/\x{200B}//g;  # Zero Width Space: remove
    s/\x{200C}//g;  # Zero Width Non-Joiner: remove
    s/\x{200D}//g;  # Zero Width Joiner: remove
    s/\x{2060}//g;  # Word Joiner: remove
    s/\x{FEFF}//g;  # BOM / Zero Width No-Break Space: remove
    s/\x{00A0}/ /g; # No-Break Space: normal space
    s/\x{2009}/ /g; # Thin Space: normal space
    s/\x{202E}//g;  # Right-to-Left Override: remove
    s/\x{2014}/-/g; # Em dash: regular hyphen
' "$file"
