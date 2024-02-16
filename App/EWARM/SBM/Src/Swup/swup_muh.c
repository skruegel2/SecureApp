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
#include "swup_muh.h"

#if MUH_READ_USE_FLASH_DRIVER != 0

#include <string.h>
#include "sbm_memory.h"
#include "swup_read.h"
#include "sbm_hal.h"
#include "memory_devices_and_slots.h"
#include "sbm_log_update_status.h"

pie_module_t        g_muh_buf        SBM_PERSISTENT_RAM;
hal_mem_address_t   g_muh_buf_origin SBM_PERSISTENT_RAM;

bool swup_read_mu_data(hal_mem_address_t offset,
                       void *dest,
                       size_t bytes,
                       hal_mem_address_t *origin_var)
{
	if (offset == *origin_var)
	{
		/* We already have it */
		return true;
	}

	bool result = (hal_mem_read(&app_status_slot, offset, dest, bytes) == HAL_MEM_SUCCESS);
	if (!result)
	{
		SBM_LOG_UPDATE_ERROR("SWUP MUH read failed for %zu bytes, offset %lu\n",
		                     bytes, (unsigned long)offset);
	}

	*origin_var = offset;

	return result;
}

void sbm_purge_cached_muh(void)
{
	memset(&g_muh_buf, 0xff, sizeof(g_muh_buf));
	g_muh_buf_origin = SWUP_INVALID_MUH_MUF_BUF;
}
#endif /* MUH_READ_USE_FLASH_DRIVER */
