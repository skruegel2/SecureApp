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

/*
 * Monotonically incrementing counter of the number of 1mS periods
 * since the last reset. Valid until hal_quiesce() is called.
 */
static volatile hal_tick_value_t hal_ticker SBM_EPHEMERAL_RAM;

/** Initialise a 1mS timer for use by the HAL */
void hal_tick_init(void)
{
	/* No action required at the present time */
}

/** Return the current value of the SBM HAL tick counter
 *
 * Note that this cannot be used once the application has started.
 *
 * \return The number of 1mS ticks since the last reset.
 */
hal_tick_value_t hal_tick_get(void)
{
	return hal_ticker;
}

/** Block the caller for the number of milliseconds specified by \a ms
 *
 * \param ms Number of milliseconds to delay
 *
 * This is implemented as a busy-wait. Interrupts must be enabled
 * when invoked.
 */
void hal_tick_delay(hal_tick_value_t ms)
{
	ms += hal_ticker;

	while (ms > hal_ticker) {
		/* Spin-wait */
	}
}

/*
 * Allow the SysTick interrupt to be hooked by other code.
 * (Used by unit test framework)
 */
#if defined(__IAR_SYSTEMS_ICC__)
__weak void hal_tick_isr_hook(void *frame)
#elif defined(__GNUC__)
__attribute__ ((weak)) void hal_tick_isr_hook(void *frame)
#else
void hal_tick_isr_hook(void *frame)
#endif
{
	(void) frame;
}

/*
  Invoked at interrupt level 1000 times per second.
  */
void hal_tick_isr(void *frame)
{
	/* Update the tick counter */
	hal_ticker++;

	/* Call the optional hook routine */
	hal_tick_isr_hook(frame);
}
