#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# rez-icns.py OUTPUT: writes the Rez source of an 'icns' resource made of
# the nephrite_NxN.png images next to this script, which
# scripts/entitlement.sh appends to the macOS binaries with Rez.

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# icns element types that hold PNG images, and their sizes.
ELEMENTS = ((b'icp4', 16), (b'icp5', 32), (b'icp6', 64), (b'ic07', 128),
            (b'ic08', 256), (b'ic09', 512))


def main() -> None:
    elements = b''
    for kind, size in ELEMENTS:
        path = os.path.join(HERE, 'nephrite_%dx%d.png' % (size, size))
        with open(path, 'rb') as f:
            data = f.read()
        elements += kind + struct.pack('>I', 8 + len(data)) + data
    icns = b'icns' + struct.pack('>I', 8 + len(elements)) + elements
    lines = ["data 'icns' (-16455) {"]
    for i in range(0, len(icns), 16):
        row = icns[i:i + 16].hex().upper()
        lines.append('\t$"%s"' % ' '.join(row[j:j + 4]
                                         for j in range(0, len(row), 4)))
    lines.append('};')
    with open(sys.argv[1], 'w') as f:
        f.write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
