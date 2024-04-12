#!/bin/bash

#REFERENCE: https://askubuntu.com/questions/1309144/how-do-i-remove-all-snaps-and-snapd-preferably-with-a-single-command

remove_packages(){
    core_snaps=("snap-store" "gtk-common-themes" "gnome-system-monitor" "gnome-*" "core*" "snap-store" "snapd" "snapd-desktop-integration")
    #Find and remove all installed snaps (waits until later to remove core snaps bc they should be removed in certain order):
    installed_snaps=$(snap list | awk 'NR>1 {print $1}')
    for i in installed_snaps; do
        for j in core_snaps; do
            if [$i = $j]; then
                echo "$i\n$j"
            fi
        done
    done
    #Remove core snaps:
    for snap in "${core_snaps[@]}"; do
        snap remove "$snap"
    done
}

if command -v snap &> /dev/null
then
    echo "Snap is installed...removing packages..."
    remove_packages
else
    echo "Snap not installed"
fi