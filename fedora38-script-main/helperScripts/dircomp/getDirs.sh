#!/bin/bash

dirs=("/bin" "/etc" "/opt" "/sbin" "/usr" "/var")

getDirs() {
    local dir="$1"
    local out="$2"

    for item in "$dir"/*; do
        if [ -d "$item" ]; then
            echo "$item" >> "$out"
            getDirs "$item" "$out"
        elif [ -f "$item" ]; then
            echo "$item" >> "$out"
        fi
    done
}

for dir in "${dirs[@]}"; do
    if [ -d "$dir" ]; then
        out="${dir/\//}.txt"
        echo "Processing Dir: $dir"
        getDirs "$dir" "$out"
        echo "Output saved to: $out"
    else
        echo "Directory not found: $dir"
    fi
done
