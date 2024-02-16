/********************************************************************************
* Copyright 2017-2022 Secure Thingz Ltd.
* All rights reserved.
*
* This source file and its use is subject to a Secure Thingz Embedded Trust
* License agreement. This source file may contain licensed source code from
* other third-parties and is subject to those license agreements as well.
*
* Permission to use, copy, modify, compile and distribute compiled binary of the
* source code for use as specified in the Embedded Trust license agreement is
* hereby granted provided that the this copyright notice and other third-party
* copyright notices appear in all copies of the source code.
*
* Distribution of Embedded Trust source code in any form is governed by the
* Embedded Trust license agreement. Use of the Secure Thingz name or trademark
* in any form is prohibited.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/
#include "sbm_memory.h"
#include "sbm_hal.h"
#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
#include <arm_cmse.h>

#include "secureApiInternal.h"

/*
 * The Secure stack (used when servicing Secure API calls) is defined in the
 * SoC-specific linker script.
 */
#pragma section = "SSTACK"
#define	SECURE_STACK_BASE	((uintptr_t)__section_begin("SSTACK"))
#define	SECURE_STACK_TOP	((uintptr_t)__section_end("SSTACK"))
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */


__noreturn void cpu_clear_memory_and_invoke_app(uint32_t sp,
    uint32_t entry_point)
{
#if !(defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
	/* Configure MSP and PSP on behalf of the application */
	__set_MSP(sp);
	__set_PSP(sp);
#else
    /*
     * Set up the TEE. On some SoCs where TrustZone configuration is
     * stored in NVM fuses, this function may cause a system reset in
     * the case where this is the first boot and fuses were updated from
     * their default state.
     */
    soc_enable_trustzone();

    /* The application is untrusted, so configure the NS stacks */
    __TZ_set_MSP_NS(sp);
    __TZ_set_PSP_NS(sp);

    /*
     * We rely on the Default-Out-Of-Reset states for the non-secure aliases
     * of PRIMASK, BASEPRI, FAULTMASK, MSPLIM, PSPLIM, and some bits in the
     * CONTROL register.
     */
#endif

    /* Clear ephemeral memory */
    if (SBM_EPHEMERAL_RAM_SIZE != 0) {
        /*
         * Linker script must ensure SBM_EPHEMERAL_RAM_SIZE is a
         * multiple of sizeof(uint32_t).
         */
        asm volatile(
                    "clear_ephemeral:                       \n"
                    "  stmia %[ephemeral_start]!, {%[zero]} \n"
                    "  subs  %[ephemeral_size], #4          \n"
                    "  bne   clear_ephemeral                \n"
                    :
                    : [zero] "r" (0u),
                      [ephemeral_start] "r" (SBM_EPHEMERAL_RAM_START),
                      [ephemeral_size] "r" (SBM_EPHEMERAL_RAM_SIZE)
                    : "cc", "memory");
    }

    asm volatile(
#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
                /* Set secure stack */
                "  msr   MSP, %[secure_stack_top]       \n"
                "  msr   MSPLIM, %[secure_stack_base]   \n"
#endif
                /* Clear all registers, except R0 - it holds the entrypoint */
                "  mov   r0, %[entry_point]             \n"
                "  movs  r1, #0                         \n"
                "  mov   r2, r1                         \n"
                "  mov   r3, r1                         \n"
                "  mov   r4, r1                         \n"
                "  mov   r5, r1                         \n"
                "  mov   r6, r1                         \n"
                "  mov   r7, r1                         \n"
                "  mov   r8, r1                         \n"
                "  mov   r9, r1                         \n"
                "  mov   r10, r1                        \n"
                "  mov   r11, r1                        \n"
                "  mov   r12, r1                        \n"
                "  mov   lr, r1                         \n"
                "  cpsie i                              \n"
#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
                "  bxns  r0                             \n"
#else
                "  bx    r0                             \n"
#endif
                :
                :
#if !(defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
                  [entry_point] "r" (entry_point)
#else
		  /*
		   * Must clear bit-0 of entry_point in order to effect entry
		   * to non-secure mode.
		   */
                  [entry_point] "r" (entry_point & ~1u),
                  [secure_stack_top] "r" (SECURE_STACK_TOP),
                  [secure_stack_base] "r" (SECURE_STACK_BASE)
#endif
                : "memory"
                );

	for (;;)
		;
	/*NOTREACHED*/
}

