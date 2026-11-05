/*
 * QEMU version strings
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VERSION_H
#define QEMU_VERSION_H

/* qemu-version.h defines QEMU_PKGVERSION only if it is not empty.  */
#include "qemu-version.h"

#ifdef QEMU_PKGVERSION
#define QEMU_FULL_VERSION \
    NEPHRITE_VERSION " (" QEMU_PKGVERSION "), based on QEMU " QEMU_VERSION
#else
#define QEMU_PKGVERSION ""
#define QEMU_FULL_VERSION NEPHRITE_VERSION ", based on QEMU " QEMU_VERSION
#endif

#endif
