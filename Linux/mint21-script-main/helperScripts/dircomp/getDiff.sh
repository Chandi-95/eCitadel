#!/bin/bash

# List of directories and corresponding base files
directories=("bin" "etc" "opt" "sbin" "usr" "var")

# Function to compare files line by line and generate output
compare_files() {
    local dir="$1"
    local base_file="$2"
    local current_file="$3"

    # Create arrays for each file's lines
    declare -a base_lines
    declare -a current_lines

    # Read lines from the base file into the array
    while IFS= read -r line; do
        base_lines+=("$line")
    done < "$base_file"

    # Read lines from the current file into the array
    while IFS= read -r line; do
        current_lines+=("$line")
    done < "$current_file"

    # Calculate lines in $dir.txt not in $dir_base.txt
    comm -23 <(sort "$current_file") <(sort "$base_file") > "helperScripts/dircomp/${dir}_notin_${dir}_base.txt"

    # Calculate lines in $dir_base.txt not in $dir.txt
    comm -13 <(sort "$current_file") <(sort "$base_file") > "helperScripts/dircomp/${dir}_base_notin_${dir}.txt"
}

# Loop through directories and compare files
for dir in "${directories[@]}"; do
    base_file="helperScripts/dircomp/${dir}_base.txt"
    current_file="helperScripts/dircomp/${dir}.txt"

    # Check if both files exist before comparing
    if [ -f "$base_file" ] && [ -f "$current_file" ]; then
        compare_files "$dir" "$base_file" "$current_file"
        echo "Differences saved to ${dir}_notin_${dir}_base.txt and ${dir}_base_notin_${dir}.txt"
    else
        echo "Files not found for directory: $dir"
    fi
done

