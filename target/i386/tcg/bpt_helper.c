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

/*
 * The step after an instruction, branch telling whether it was a taken
 * branch: under VMX's monitor trap flag, which steps every instruction,
 * an MTF VM exit with TF's trap pending (Intel SDM 325462-093 Vol. 3C,
 * 28.5.2); else TF's single-step trap.
 */
static G_NORETURN void single_step(CPUX86State *env, bool branch)
{
#ifndef CONFIG_USER_ONLY
    if (x86_vmx_mtf(env)) {
        x86_vmx_mtf_step(env, x86_step_trap(env, branch));
    }
    raise_debug_exception(env, hw_breakpoint_hits(env, NULL) | DR6_BS, 0);
#else
    raise_exception(env, EXCP01_DB);
#endif
}

G_NORETURN void HELPER(single_step)(CPUX86State *env)
{
    single_step(env, false);
}

G_NORETURN void HELPER(branch_step)(CPUX86State *env)
{
    single_step(env, true);
}

void HELPER(rechecking_single_step)(CPUX86State *env)
{
    if ((env->eflags & TF_MASK) != 0 || x86_vmx_mtf(env)) {
        single_step(env, false);
    }
}

/*
 * MOV SS and POP SS suppress TF's trap (Intel SDM 325462-093 Vol. 3A,
 * 7.8.3), not the monitor trap flag's VM exit (Intel SDM 325462-093
 * Vol. 3C, 28.5.2).
 */
void HELPER(movss_step)(CPUX86State *env)
{
#ifndef CONFIG_USER_ONLY
    if (x86_vmx_mtf(env)) {
        x86_vmx_mtf_step(env, 0);
    }
#endif
}
