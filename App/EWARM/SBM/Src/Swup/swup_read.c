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
#include "swup_read.h"

#include <string.h>
#include "memory_devices_and_slots.h"
#include "sbm_log_update_status.h"
#include "sbm_hal_mem.h"

#pragma inline=never
void swup_read(const memory_slot *update_slot,
               hal_mem_address_t offset_in_slot,
               hal_mem_address_t max_offset,
               void *dest,
               size_t bytes)
{
	hal_mem_result_t result;
	if (offset_in_slot > max_offset)
	{
		SBM_LOG_UPDATE_ERROR("swup_read offset is out of range (max 0x%" PRIxMEM_ADDR
		                     ", offset 0x%" PRIxMEM_ADDR ", bytes 0x%" PRIxSIZET ")\n",
		                     max_offset, offset_in_slot, bytes);
		result = HAL_MEM_PARAM_ERROR;
	}
	else
	{
		/* Note that hal_mem_read() performs range checking on the parameters */
		result = hal_mem_read(update_slot, offset_in_slot, dest, bytes);
		if (result != HAL_MEM_SUCCESS)
		{
			SBM_LOG_UPDATE_ERROR("hal_mem_read(slot: %s, offset: 0x%" PRIxMEM_ADDR
								", bytes: 0x%" PRIxSIZET ") failed with result %d\n",
								update_slot->name, offset_in_slot, bytes, (int)result);
		}
	}

	if (result != HAL_MEM_SUCCESS)
	{
		/* In case of failure, return a buffer with all bits set. */
		memset(dest, 0xffu, bytes);
	}
}
