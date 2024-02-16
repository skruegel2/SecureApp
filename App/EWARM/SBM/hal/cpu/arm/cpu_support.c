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

/*
 * Initialise the CPU. Not much to do on Cortex-M.
 */
void cpu_init(void)
{
#if defined(__ICACHE_PRESENT) && (__ICACHE_PRESENT != 0)
	SCB_EnableICache();
#endif
#if defined(__DCACHE_PRESENT) && (__DCACHE_PRESENT != 0)
	SCB_EnableDCache();
#endif

	/* Ensure firmware runs with interrupts enabled */
	__enable_irq();

#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
    /* Redirect all non-secure faults (including hardfaults) to a non-secure handler */
	__DSB(); /* Memory barrier before write */
#if (SBM_FORWARD_HARDFAULTS != 0)
	SCB->AIRCR = ((0x5FAUL << SCB_AIRCR_VECTKEY_Pos) | SCB_AIRCR_BFHFNMINS_Msk);
#else
	SCB->AIRCR = ((0x5FAUL << SCB_AIRCR_VECTKEY_Pos));
#endif
	__DSB(); /* Ensure completion of memory access */
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */
}

void cpu_quiesce(void)
{
	/* Ensure interrupts are disabled */
	__disable_irq();

#if defined(__DCACHE_PRESENT) && (__DCACHE_PRESENT != 0)
	SCB_DisableDCache();
#endif
#if defined(__ICACHE_PRESENT) && (__ICACHE_PRESENT != 0)
	SCB_DisableICache();
#endif
}

void cpu_reset(void)
{
	/* There's a generic reset API in CMSIS */
	NVIC_SystemReset();
	/*NOTREACHED*/

	/* But just in case it doesn't work ... */
	for (;;)
		;
	/*NOTREACHED*/
}

#if defined(__ICCARM__)
__weak void SysTick_Implementation(uint32_t *frame);
__weak void SysTick_Implementation(uint32_t *frame)
#elif defined(__GNUC__)
__attribute__ ((weak)) void SysTick_Implementation(uint32_t *frame);
__attribute__ ((weak)) void SysTick_Implementation(uint32_t *frame)
#else
void SysTick_Implementation(uint32_t *frame);
void SysTick_Implementation(uint32_t *frame)
#endif
{
	/* Invoke the SBM HAL's tick handler */
	hal_tick_isr(frame);
}

#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
/*
 * This is the SecureAPI trampoline, used when TrustZone is enabled.
 * Do not call this directly - it is intended to be invoked by the
 * assembly language call gate in cpu_secapi_callgate.s.
 */
secure_api_internal_return_t cpu_secure_api_trampoline(const unsigned int fidx,
													   const void *const in_buf,
													   const uint32_t in_len,
													   void *const out_buf);
secure_api_internal_return_t
cpu_secure_api_trampoline(const unsigned int fidx,
                          const void *const in_buf,
                          const uint32_t in_len,
                          void *const out_buf)
{
    /*
     * We need to work out which non-secure stack was used to invoke the
     * Secure API callgate so that we can access the out_len parameter.
     */
    uint32_t *out_len_ptr;

    if (__TZ_get_CONTROL_NS() & CONTROL_SPSEL_Msk)
        out_len_ptr = (uint32_t *)__TZ_get_PSP_NS();
    else
        out_len_ptr = (uint32_t *)__TZ_get_MSP_NS();

    /* Ensure the caller's stack is readable from non-secure mode */
    if (cmse_check_pointed_object(out_len_ptr, CMSE_NONSECURE) == NULL)
        return SECURE_API_INT_OUT_BUF_MISSING;

    /* Pass control to the regular Secure API entry point */
    return sbm_secure_api(fidx, in_buf, in_len, out_buf, *out_len_ptr);
}

/*
 * CPU-specific function to check if application has permission to access
 * the specified memory region.
 */
bool cpu_check_permission(const void *base_address, const uint32_t bytes,
                          bool can_write)
{
    /* const has been cast out of base_address as "cmse_check_address_range" does
     * not use const in its interface, however it does not modify the value that
     * base_address points to. */
    return cmse_check_address_range((void *)base_address, (size_t)bytes,
        CMSE_NONSECURE | (can_write ? CMSE_MPU_READWRITE : CMSE_MPU_READ)) != NULL;
}

#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */
