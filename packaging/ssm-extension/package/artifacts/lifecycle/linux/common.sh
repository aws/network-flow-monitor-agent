#!/bin/bash
# Shared helper functions for NFM supervised extension lifecycle scripts.
# This file is meant to be sourced, not executed directly.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: common.sh is meant to be sourced, not executed directly." >&2
    exit 1
fi

check_kernel_version() {
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1,2)

    local major minor
    major=$(echo "$kernel_version" | cut -d. -f1)
    minor=$(echo "$kernel_version" | cut -d. -f2)

    if ! [[ "$major" =~ ^[0-9]+$ ]] || ! [[ "$minor" =~ ^[0-9]+$ ]]; then
        echo "Error: Unable to parse kernel version from '$(uname -r)'" >&2
        return 1
    fi

    if [ "$major" -gt 5 ]; then
        return 0
    elif [ "$major" -eq 5 ] && [ "$minor" -ge 8 ]; then
        return 0
    else
        echo "Error: This package requires Linux kernel 5.8 or later. Found ${major}.${minor}" >&2
        return 1
    fi
}

extract_json_value() {
    local key="$1"
    local file="$2"

    if [ -z "$key" ] || [ -z "$file" ] || [ ! -f "$file" ]; then
        return 0
    fi

    grep "\"${key}\"" "$file" 2>/dev/null | sed 's/.*"'"${key}"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}

map_systemd_state() {
    local state="$1"

    case "$state" in
        active)
            echo "active"
            ;;
        inactive)
            echo "inactive"
            ;;
        failed)
            echo "failed"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

extract_cargo_version() {
    local file="$1"

    if [ -z "$file" ] || [ ! -f "$file" ]; then
        return 0
    fi

    grep '^version[[:space:]]*=' "$file" | head -1 | sed 's/.*"[[:space:]]*\([^"]*\)[[:space:]]*".*/\1/'
}
