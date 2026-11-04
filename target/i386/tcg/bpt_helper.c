/*
 *  i386 breakpoint helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "helper-tcg.h"

G_NORETURN void HELPER(single_step)(CPUX86State *env)
{
#ifndef CONFIG_USER_ONLY
    raise_debug_exception(env, hw_breakpoint_hits(env, NULL) | DR6_BS, 0);
#else
    raise_exception(env, EXCP01_DB);
#endif
}

void HELPER(rechecking_single_step)(CPUX86State *env)
{
    if ((env->eflags & TF_MASK) != 0) {
        HELPER(single_step)(env);
    }
}
