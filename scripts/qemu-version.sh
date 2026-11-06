#!/bin/sh

set -eu

dir="$1"
pkgversion="$2"
version="$3"
nephrite_version="$4"

if [ -z "$pkgversion" ]; then
    cd "$dir"
    if [ -e .git ]; then
        pkgversion=$(git describe --match 'v*' --dirty --always) || :
    fi
fi

if [ -n "$pkgversion" ]; then
    fullversion="$nephrite_version ($pkgversion), based on QEMU $version"
else
    fullversion="$nephrite_version, based on QEMU $version"
fi

cat <<EOF
#define QEMU_PKGVERSION "$pkgversion"
#define QEMU_FULL_VERSION "$fullversion"
EOF
