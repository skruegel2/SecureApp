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

#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))

#include "cpu_interrupt.h"

void cpu_interrupt_configure_all(uint32_t nb_interrupts, interrupt_sec_level_t sec_level)
{
    /* NVIC->ITNS is an array of 32-bit registers */
    uint8_t num_full_registers = nb_interrupts / 32u;
    /* The number of bits to set in the last register if there are less than 32 */
    uint8_t num_extra_interrupts = nb_interrupts % 32u;
    uint32_t val = (INTERRUPT_NON_SECURE == sec_level) ? 0xFFFFFFFFu : 0;
   
    /* Set the full registers */
    for (uint32_t reg_idx = 0; reg_idx < num_full_registers; reg_idx++)
    {
        NVIC->ITNS[reg_idx] = val;
    }

    /* Set the remaining bits in the last register if there are any left */
    if(num_extra_interrupts)
    {
        /* Read the value of the last register */
        val = NVIC->ITNS[num_full_registers];

        /* Set the bits that might be remaining on the last register */
        for (uint8_t i = 0; i < num_extra_interrupts; i++)
        {
            /* Set only the bits needed */
            if (INTERRUPT_NON_SECURE == sec_level)
            {
                val |= (1UL << i);
            }
            else /* Clear only the bits needed */
            {
                val &= ~(1UL << i);
            }
        }
        /* Write back the value computed above */
        NVIC->ITNS[num_full_registers] = val;
    }
}
#endif /* (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)) */
