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

#include "sbm_hal.h"
#include "oem.h"
#include "oem_board.h"
#include "oem_bsp.h"
#include "soc_arm_cmsis.h"

/*
 * Set up the target board
 */
void oem_init(void)
{
    /* Configure onboard LEDs */
    oem_board_led_init();

#if SBM_INCLUDE_CONSOLE != 0
	/* Configure UART(s), if necessary */
	oem_serial_init();
#endif /* SBM_INCLUDE_CONSOLE != 0 */
}

/*
 * Return the target board to a quiescent state
 */
void oem_quiesce(void)
{
	/* Revert GPIO pins for LEDs back to default state */
	oem_board_led_quiesce();

#if SBM_INCLUDE_CONSOLE != 0
	/* Quiesce UART(s), if necessary */
	oem_serial_quiesce();
#endif /* SBM_INCLUDE_CONSOLE != 0 */
}

/* oem_reset() is optional */

const char *oem_target_string(void)
{
    return OEM_TARGET_STRING;
}
