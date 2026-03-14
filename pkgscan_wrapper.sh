#!/bin/bash

if command -v paru &>/dev/null; then
    AUR_HELPER="paru"
elif command -v yay &>/dev/null; then
    AUR_HELPER="yay"
else
    echo "No AUR helper found (yay/paru)"
    exit 1
fi

if [[ "$1" != "-S" ]]; then
    exec $AUR_HELPER "$@"
fi

for pkg in "${@:2}"; do
    if ! pacman -Si "$pkg" &>/dev/null; then
        echo "=== pkgscan: AUR package '$pkg' detected ==="
        pkgscan "$pkg"
    else
        $AUR_HELPER -S "$pkg"
    fi
done
