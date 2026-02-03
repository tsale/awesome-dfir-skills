#!/bin/bash
# detect-format.sh - Determine the schema format of an osquery schema file
# Usage: ./detect-format.sh <schema_file>
# Output: "platforms_array" or "platform_markers"

SCHEMA_FILE="$1"

if [ -z "$SCHEMA_FILE" ]; then
    echo "Usage: $0 <schema_file>" >&2
    exit 1
fi

if [ ! -f "$SCHEMA_FILE" ]; then
    echo "Error: File not found: $SCHEMA_FILE" >&2
    exit 1
fi

# Check for platforms([...]) format (Format 1)
if [ "$(grep -c 'platforms(\[' "$SCHEMA_FILE")" -gt 0 ]; then
    echo "platforms_array"
# Check for #platform marker format (Format 2)
elif [ "$(grep -cE '^#(darwin|linux|windows|linwin|macwin|posix|sleuthkit|utility|cross-platform)$' "$SCHEMA_FILE")" -gt 0 ]; then
    echo "platform_markers"
else
    echo "unknown"
    exit 1
fi
