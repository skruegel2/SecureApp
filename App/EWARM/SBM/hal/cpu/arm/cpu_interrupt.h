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

#ifndef CPU_INTERRUPT_H
#define CPU_INTERRUPT_H

#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))

#include <stdbool.h>
/* To include SoC-specific CMSIS definitions */
#include "sbm_hal.h"

typedef enum interrupt_sec_level
{
    INTERRUPT_SECURE = 0,
    INTERRUPT_NON_SECURE = 1
} interrupt_sec_level_t;

/** Configure all interrupts as non-secure or secure
 *
 * \param nb_interrupts The maximum number of interrupts available on the device
 * \param sec_level Whether the interrupts are to be set as non-secure or secure
 *
 * \note The function doesn't check if \e nb_interrupts corresponds to the number
 *       of interrupts implemented on the target device.
 */
void cpu_interrupt_configure_all(uint32_t nb_interrupts, interrupt_sec_level_t sec_level);

#endif /* (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)) */

#endif /* CPU_INTERRUPT_H */
