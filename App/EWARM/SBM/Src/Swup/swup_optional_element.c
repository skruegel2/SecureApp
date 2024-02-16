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
#include "swup_optional_element.h"

#include "swup_layout.h"

hal_mem_address_t swup_first_oe(uint32_t update_records)
{
	hal_mem_address_t oe_offset;

#if defined(SBM_HAL_FC_SIZE)
	if (update_records)
	{
		/* The image has a deprecated update status field. The initial padding is based
		   on the size of one Flash Counter record, which is SoC-specific. */
		const uint32_t alignment = SBM_HAL_FC_SIZE(1);
		const size_t padding_overshoot = SWUP_OFFSET_HEADER_OPTIONAL_ELEMENTS + alignment - 1U;
		const hal_mem_address_t fc_start = padding_overshoot & ~(alignment - 1U);

		/* Now account for the number of Flash Counters. */
		oe_offset = fc_start + SBM_HAL_FC_SIZE(update_records);
	}
	else
#endif /* SBM_HAL_FC_SIZE */
	{
		/* New-style image. Alignment is 32-bits. */
		const uint32_t alignment = sizeof(uint32_t);
		const size_t padding_overshoot = SWUP_OFFSET_HEADER_OPTIONAL_ELEMENTS + alignment - 1U;
		oe_offset = (hal_mem_address_t)(padding_overshoot & ~(alignment - 1U));
	}

	return oe_offset;
}
