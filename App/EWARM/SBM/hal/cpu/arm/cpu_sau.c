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
 * \brief Simple driver for ARMv8M TrustZone SAU
 */

#include <assert.h>

#include "sbm_memory.h"
#include "sbm_hal.h"
#include "cpu_sau.h"
#include "memoryMap.h"

void cpu_sau_configure(const struct cpu_sau_config *sau, int nsau)
{
#if (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0))
	const uint32_t sregion = SAU->TYPE & SAU_TYPE_SREGION_Msk;
	uint32_t region;

	assert(nsau <= sregion);

	/*
	 * First, ensure SAU is disabled. Since ALLNS is clear, all memory
	 * will be Secure by default.
	 */
	SAU->CTRL = 0;

	/* Configure the required regions. */
	for (region = 0; region < nsau; region++, sau++)
	{
		/* Verify size and alignment of each entry. */
		assert((sau->base & ~SAU_RBAR_BADDR_Msk) == 0);
		assert(((sau->end + 1u) & ~SAU_RLAR_LADDR_Msk) == 0);

		/* Ensure the caller does not specify Secure regions here. */
		assert(sau->base < sau->end);
		assert(sau->end < SBM_PERSISTENT_RAM_START || sau->base > SBM_PERSISTENT_RAM_END);
#ifndef NDEBUG
		if (!sau->nsc)
		{
			const hal_mem_address_t sbm_end_address = sbm_slot.start_address + sbm_slot.size - 1;
			assert((sbm_slot.start_address > 0u && sau->end < sbm_slot.start_address) ||
			        sau->base > sbm_end_address);
		}
#endif /* NDEBUG */

		SAU->RNR = region;
		SAU->RBAR = sau->base & SAU_RBAR_BADDR_Msk;
		SAU->RLAR = (sau->end & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk | (sau->nsc ? SAU_RLAR_NSC_Msk : 0);
	}

	/* Disable any remaining regions. */
	while (region < sregion)
	{
		SAU->RNR = region++;
		SAU->RLAR = 0;
		SAU->RBAR = 0;
	}

	/* Enable the SAU */
	SAU->CTRL = SAU_CTRL_ENABLE_Msk;
#else
	(void) sau;
	(void) nsau;
#endif /* (defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)) */
}
