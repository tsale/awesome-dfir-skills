#!/bin/bash
# extract-table.sh - Extract full table definition from osquery schema file
# Usage: ./extract-table.sh <schema_file> <table_name>
# Output: Complete table definition including schema, implementation, and platform info

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="$1"
TABLE_NAME="$2"

if [ -z "$SCHEMA_FILE" ] || [ -z "$TABLE_NAME" ]; then
    echo "Usage: $0 <schema_file> <table_name>" >&2
    exit 1
fi

if [ ! -f "$SCHEMA_FILE" ]; then
    echo "Error: File not found: $SCHEMA_FILE" >&2
    exit 1
fi

# Detect format
FORMAT=$(bash "$SCRIPT_DIR/detect-format.sh" "$SCHEMA_FILE")

if [ "$FORMAT" = "platforms_array" ]; then
    # Format 1: platforms([...]) at end of table definition
    awk '/^[[:space:]]*table_name\("'"$TABLE_NAME"'"\)/ {p=1} p {print} p && /^[[:space:]]*platforms[[:space:]]*\(/ {inplat=1} p && inplat && /\)[[:space:]]*$/ {exit}' "$SCHEMA_FILE"
elif [ "$FORMAT" = "platform_markers" ]; then
    # Format 2: #platform marker before table definition
    awk '/^[[:space:]]*#/ { if (!p) hdr=$0; else exit } /^[[:space:]]*table_name\("'"$TABLE_NAME"'"\)/ { p=1; if (hdr!="") print hdr } p && /^[[:space:]]*table_name\("/ && !/^[[:space:]]*table_name\("'"$TABLE_NAME"'"\)/ { exit } p { print }' "$SCHEMA_FILE"
else
    echo "Error: Could not determine schema format" >&2
    exit 1
fi
