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

#ifndef SBM_HAL_CPU_H
#define SBM_HAL_CPU_H

#if !(defined(__ASSEMBLER__) || defined(__IAR_SYSTEMS_ASM__))
#if (NDRIVERS==0)
#include "soc_arm_cmsis.h"
#endif /* (NDRIVERS==0) */

/** \brief Disable interrupts
 * \return Previous interrupt mask
 */
static uint32_t cpu_critical_enter(void);
/** \brief Restore interrupts
 * \param mask Mask returned by previous call to cpu_critical_enter()
 */
static void cpu_critical_exit(uint32_t mask);

#if defined(__GNUC__)

static inline uint32_t cpu_critical_enter(void)
{
	uint32_t mask;

	__ASM volatile("" ::: "memory");

	/* Fetch the current mask and disable interrupts. */
	mask = __get_PRIMASK();
	__disable_irq();

	__ASM volatile("" ::: "memory");

	/* Caller receives a copy of the current mask */
	return mask;
}

static inline void cpu_critical_exit(uint32_t mask)
{
	__ASM volatile("" ::: "memory");

	/* Restore the previous interrupt mask */
	__set_PRIMASK(mask);

	__ASM volatile("" ::: "memory");
}

#else

#pragma inline=forced
static inline uint32_t cpu_critical_enter(void)
{
	uint32_t mask;

	/*
	 * The pair of 'asm memory clobber' statements here are a notification
	 * to the compiler to ensure it doesn't hang on to potentially volatile
	 * values in registers while we change the interrupt mask.
	 */
	asm("" ::: "memory");

	/* Fetch the current mask and disable interrupts. */
	mask = __get_PRIMASK();
	asm("cpsid i\n" ::: "memory");

	/* Caller receives a copy of the current mask */
	return mask;
}

#pragma inline=forced
static inline void cpu_critical_exit(uint32_t mask)
{
	/*
	 * The pair of 'asm memory clobber' statements here are a notification
	 * to the compiler to ensure it doesn't hang on to potentially volatile
	 * values in registers while we change the interrupt mask.
	 */
	asm("" ::: "memory");

	/* Restore the previous interrupt mask */
	__set_PRIMASK(mask);

	asm("" ::: "memory");
}

#endif /* defined(__GNUC__) */

/** Exception hooks */
typedef void (*exception_handler_t)(int irq, void *fault_pc);

/** Install an exception handler which will be invoked for any subsequent
 * CPU fault.
 *
 * \param[in] handler Pointer to the handler function.
 *
 * \return Opaque context
 */
extern void *cpu_push_exception_handler(exception_handler_t handler);

/** Uninstall a previously installed exception handler.
 *
 * \param[in] context Value returned from the most recent call to
 *                    cpu_push_exception_handler().
 */
extern void cpu_pop_exception_handler(void *context);

/** Set up MSP and ISP, clear ephmemeral RAM and invoke the application
 *
 * \param[in] sp The application's stack pointer
 * \param[in] entry_point The application's entry point
 *
 * Does not return.
 */
#if defined(__IAR_SYSTEMS_ICC__) && (__IAR_SYSTEMS_ICC__<9)
/* IAR only starts supporting `__attribute__` from V8. */
extern __noreturn void cpu_clear_memory_and_invoke_app(uint32_t sp, uint32_t entry_point);
#else
extern  void cpu_clear_memory_and_invoke_app(uint32_t sp, uint32_t entry_point) __attribute__((__noreturn__));
#endif


#endif /* !(defined(__ASSEMBLER__) || defined(__IAR_SYSTEMS_ASM__)) */

#endif /* SBM_HAL_CPU_H */
