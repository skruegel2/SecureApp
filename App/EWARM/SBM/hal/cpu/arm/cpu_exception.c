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

/** \file
 * \brief CPU Fault handler
 */

#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <LowLevelIOInterface.h>
#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
#include <arm_cmse.h>

#ifndef EXC_RETURN_S
#define EXC_RETURN_S               (0x00000040UL)     /* bit [6] stack used to push registers: 0=Non-secure 1=Secure          */
#endif

#ifndef EXC_RETURN_ES
#define EXC_RETURN_ES              (0x00000001UL)     /* bit [0] security state exception was taken to: 0=Non-secure 1=Secure */
#endif

#endif /* (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)) */
#include "sbm_memory.h"
#include "sbm_hal.h"


/*
 * Exception frame pushed onto the current stack when the CPU
 * takes an exception or interrupt.
 */
typedef struct {
	uint32_t r0, r1, r2, r3, r12;
	uint32_t lr;
	uint32_t pc;
	xPSR_Type xpsr;
} trapframe_t;

/*
 * Additional register state saved by the fault handler trampoline
 */
typedef struct {
#if (__ARM_ARCH_ISA_THUMB == 1)
	uint32_t r8, r9, r10, r11, r4, r5, r6, r7;
#else
	uint32_t r4, r5, r6, r7, r8, r9, r10, r11;
#endif
	uint32_t padding;	/* Keep stack 64-bit aligned */
	uint32_t excret;
} callee_saved_t;

/* Non-NULL if someone has hooked exceptions */
static exception_handler_t exception_handler SBM_PERSISTENT_RAM;

#ifndef NDEBUG
static void output_string(const void *buff, int len)
{
	/*
	 * Use low-level IO to display the string. This may go
	 * to a UART or perhaps to the user via semi-hosting.
	 */
	if (len > 0)
		__write(_LLIO_STDOUT, buff, len);
}
#endif

void *cpu_push_exception_handler(exception_handler_t handler)
{
	uint32_t c;
	void *rv;

	/*
	 * Make the supplied handler 'active'. The handler will gain control
	 * of the CPU in the event of a subsequent exception. Note that the
	 * only state preserved and passed to the handler is the exception
	 * number and the PC at the point where it fired.
	 */
	c = cpu_critical_enter();
	rv = (void *)(uintptr_t)exception_handler;
	exception_handler = handler;
	cpu_critical_exit(c);

	return rv;
}

void cpu_pop_exception_handler(void *context)
{
	/*
	 * Unstack the exception handler
	 */
	exception_handler = (exception_handler_t)(uintptr_t)context;
}

/*
 * Optionally allow some other code to examine the hardfault.
 */
#ifdef SBM_HAL_UNIT_TESTS
int hardfault_tests_hook(int irq, void *frame);
#endif
int hardfault_hook(int irq, void *frame);
int hardfault_hook(int irq, void *frame)
{
	trapframe_t *tf = frame;
	exception_handler_t handler;
	int rv;
#if defined(SCB_HFSR_FORCED_Msk)
	uint32_t hfsr, cfsr;
#endif

	/* If the exception is not expected, we're done here */
	if ((handler = exception_handler) == NULL)
		return 0;	/* Signal 'unrecoverable' fault */

#if defined(SCB_HFSR_FORCED_Msk)
	/* Fetch and clear latched fault status */
	hfsr = SCB->HFSR;
	cfsr = SCB->CFSR;
	SCB->HFSR = hfsr;
	SCB->CFSR = cfsr;

	/* Keep only the interesting bits */
	hfsr &= SCB_HFSR_FORCED_Msk;
	cfsr &= (
	    SCB_CFSR_MLSPERR_Msk |	/* MemManage status */
	    SCB_CFSR_MSTKERR_Msk |
	    SCB_CFSR_MUNSTKERR_Msk |
	    SCB_CFSR_DACCVIOL_Msk |
	    SCB_CFSR_IACCVIOL_Msk |
	    SCB_CFSR_LSPERR_Msk |	/* BusFault status */
	    SCB_CFSR_STKERR_Msk |
	    SCB_CFSR_UNSTKERR_Msk |
	    SCB_CFSR_IMPRECISERR_Msk |
	    SCB_CFSR_PRECISERR_Msk |
	    SCB_CFSR_IBUSERR_Msk |
	    SCB_CFSR_DIVBYZERO_Msk |	/* UsageFault status */
	    SCB_CFSR_UNALIGNED_Msk |
	    SCB_CFSR_NOCP_Msk |
	    SCB_CFSR_INVPC_Msk |
	    SCB_CFSR_INVSTATE_Msk |
	    SCB_CFSR_UNDEFINSTR_Msk
	    );

	/*
	 * If no faults are indicated, something is seriously awry.
	 * In this case, don't bother trying to recover.
	 */
	if (hfsr == 0 && cfsr == 0) {
#ifndef NDEBUG
		printf("hardfault: #%d, with no status!\n", irq);
#endif
		rv = 0;
	} else
#endif /* defined(SCB_HFSR_FORCED_Msk) */
	{

		/*
		 * Modify the trapframe so that the registered handler will
		 * regain control when the exception returns.
		 */
		tf->r0 = (uint32_t)irq;
		tf->r1 = tf->pc;
		tf->pc = (uint32_t)handler;
		rv = 1;
	}

	/* Signal to the caller that the fault is recoverable */
	return rv;
}

#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) && (SBM_FORWARD_HARDFAULTS != 0))
/*
 * MSPLIM_NS is only available on CPU cores with the Main Extension.
 * However, the CMSIS compiler headers don't always do the right thing
 * when targetting a Baseline core.
 */
#if (defined (__ARM_ARCH_8M_MAIN__ ) && (__ARM_ARCH_8M_MAIN__ == 1))
#define	Get_MSPLIM_NS()		__TZ_get_MSPLIM_NS()
#else
#define	Get_MSPLIM_NS()		0u
#endif

/** Check if we can bounce a Secure Fault back to the non-secure application.
 *
 * \param tf Trapframe saved on the stack by the Core on entry to the exception
 * \param cs Additional register state saved by the trampoline.
 * \param isr Current exception number.
 *
 * If the (Non-Secure) Application attempts to access a Secure region of memory,
 * the CPU will handle the resulting fault in Secure mode. This is not useful
 * as there is little SBM can do to deal with the situation.
 *
 * So if we are handling a fault which originated in Non-Secure mode then we
 * attempt to redirect control to the Non-Secure Hardfault handler.
 *
 * Great care is taken to avoid security issues.
 *
 * \retval true if the fault is redirected, otherwise false.
 */
static bool cpu_bounce_secure_fault(const trapframe_t *tf, callee_saved_t *cs, int isr)
{
	/*
	 * Validate EXC_RETURN
	 */
	if ((cs->excret & EXC_RETURN_S) != 0)
	{
		/* Exception occurred while running in Secure mode. */
		return false;
	}

	if ((cs->excret & EXC_RETURN_ES) == 0)
	{
		/*
		 * Somehow we're handling this in non-secure mode.
		 * This should never happen.
		 */
		return false;
	}

	if ((SCB->AIRCR & SCB_AIRCR_BFHFNMINS_Msk) != 0)
	{
		/*
		 * The easy way - pend a non-secure hardfault.
		 */
		SCB_NS->SHCSR |= SCB_SHCSR_HARDFAULTPENDED_Msk;
	}
	else
	{
		/* Secure hardfault occurred while running in non-secure mode.
		 * So far this use-case is not handled
		 * Just act as before, i.e. reset */
		return false;
	}

	return true;
}
#endif /* (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) && (SBM_FORWARD_HARDFAULTS != 0) */

/** Handle Cortex exceptions.
 *
 * Called from the low-level exception trampoline.
 *
 * \param tf Trapframe saved on the stack by the Core on entry to the exception
 * \param cs Additional register state saved by the trampoline.
 *
 * In most cases this function does not return since exeptions usually indicate
 * a serious problem. However, we need to filter out semi-hosting traps in case
 * no debugger is connected. In this case, we simply advance the PC beyond the
 * breakpoint instruction and return.
 */
void cpu_fault_handler(trapframe_t *tf, callee_saved_t *cs);
void cpu_fault_handler(trapframe_t *tf, callee_saved_t *cs)
{
	IPSR_Type ipsr;
	const uint16_t *pc;

	/* Fetch the interrupt number */
	ipsr.w = __get_IPSR();
	const int isr = (int)ipsr.b.ISR;

#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) && (SBM_FORWARD_HARDFAULTS != 0))
	/*
	 * TrustZone is enabled and active. A fault here indicates
	 * one of several events:
	 *
	 * - Any fault within SBM while servicing a Secure API call.
	 *   This is always fatal.
	 * - A Secure fault caused by the application attempting
	 *   to access a Secure memory region. We need to bounce
	 *   this back to the application's fault handler.
	 */ 
	if (cpu_bounce_secure_fault(tf, cs, isr) != false)
	{
		/* Returning here will bounce to the Non-Secure handler. */
		return;
	}
#endif /* (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) && (SBM_FORWARD_HARDFAULTS != 0)) */

	pc = (const uint16_t *)(uintptr_t)(tf->pc & ~0x1u);

	/*
	 * Semi-hosting candidates require special treatment
	 */
	switch ((IRQn_Type)(isr - 16)) {
	case HardFault_IRQn:
#if defined(SCB_HFSR_DEBUGEVT_Msk)
		if ((SCB->HFSR & SCB_HFSR_DEBUGEVT_Msk) == 0) {
			/* Not a debug event */
			break;
		}
		/*FALLTHROUGH*/

	case DebugMonitor_IRQn:
#endif
		/*
		 * CPU has likely hit a software breakpoint or semi-hosting
		 * call.
		 */
		if (*pc == 0xbeabu) {
			/*
			 * Just skip the instruction and return from
			 * the exception.
			 */
			tf->pc += 2u;
			return;
		}
		break;

	default:
		break;
	}

	/*
	 * Check if someone else wants to process the fault
	 */
	if (hardfault_hook(isr - 16, tf) == 0
#ifdef SBM_HAL_UNIT_TESTS
	    && hardfault_tests_hook(isr - 16, tf) == 0
#endif
	    ) {
#ifndef NDEBUG
		/* Genuine fatal exception. Dump some state to the console */
		static char buff[80] SBM_PERSISTENT_RAM;
		int i;

		i = snprintf(buff, sizeof(buff), "Fatal exception %d at PC %08p\r\n", isr, pc);
		if (i < 0) {
			/* No recovery possible, already inside exception handler */
			for (;;) {}
		}
		output_string(buff, i);
		i = snprintf(buff, sizeof(buff), "   r0 %08" PRIx32 ",  r1 %08" PRIx32
		    ",  r2 %08" PRIx32 ",  r3 %08" PRIx32 "\r\n",
		    tf->r0, tf->r1, tf->r2, tf->r3);
		if (i < 0) {
			/* No recovery possible, already inside exception handler */
			for (;;) {}
		}
		output_string(buff, i >= sizeof(buff) ? sizeof(buff) : i);
		i = snprintf(buff, sizeof(buff), "   r4 %08" PRIx32 ",  r5 %08" PRIx32
		    ",  r6 %08" PRIx32 ",  r7 %08" PRIx32 "\r\n",
		    cs->r4, cs->r5, cs->r6, cs->r7);
		if (i < 0) {
			/* No recovery possible, already inside exception handler */
			for (;;) {}
		}
		output_string(buff, i >= sizeof(buff) ? sizeof(buff) : i);
		i = snprintf(buff, sizeof(buff), "   r8 %08" PRIx32 ",  r9 %08" PRIx32
		    ", r10 %08" PRIx32 ", r11 %08" PRIx32 "\r\n",
		    cs->r8, cs->r9, cs->r10, cs->r11);
		if (i < 0) {
			/* No recovery possible, already inside exception handler */
			for (;;) {}
		}
		output_string(buff, i >= sizeof(buff) ? sizeof(buff) : i);
		i = snprintf(buff, sizeof(buff), "  r12 %08" PRIx32 ",  sp %08p"
		    ",  lr %08" PRIx32 ",  pc %08" PRIx32 "\r\n",
		    tf->r12, tf + 1, tf->lr, tf->pc);
		if (i < 0) {
			/* No recovery possible, already inside exception handler */
			for (;;) {}
		}
		output_string(buff, i >= sizeof(buff) ? sizeof(buff) : i);
		i = snprintf(buff, sizeof(buff), "  EXCRET %08" PRIx32 ", xPSR %08"
		    PRIx32 "\r\n",  cs->excret, tf->xpsr.w);
		if (i < 0) {
			/* No recovery possible, already inside exception handler */
			for (;;) {}
		}
		output_string(buff, i >= sizeof(buff) ? sizeof(buff) : i);

		/* No going back from here */
		for (;;) {}
#else

		/*
		 * In the non-debug case, reset.
		 *
		 * Add further code here if behaviour beyond a device reset is
		 * required when not forwarding hardfaults to the application.
		 */
		hal_reset();

#endif /* NDEBUG */
	}

	/*
	 * We're recovering from an exception. In all use-cases (so far)
	 * the PC in the trapframe has been adjusted to point to a function
	 * which will, eventually, longjmp() somewhere else. This greatly
	 * simplifies exception recovery since we avoid having to unwind
	 * interruptible instructions (such as PUSH/POP) in order to restore
	 * the stack pointer.
	 *
	 * In simple terms, ensure:
	 *   - The T (thumb) bit is set,
	 *   - Preserve the ISR/Exception number,
	 *   - Clear everything else.
	 */
	tf->xpsr.w = (tf->xpsr.w & xPSR_ISR_Msk) | xPSR_T_Msk;
}
