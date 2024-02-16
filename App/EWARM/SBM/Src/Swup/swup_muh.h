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
#ifndef SWUP_MUH_H
#define SWUP_MUH_H

#include <stdbool.h>
#include "swup_eub.h"
#include "sbm_memory.h"

#if SBM_ALL_ACCESS_USE_FLASH_DRIVER != 0
#define MUH_READ_USE_FLASH_DRIVER 1
#endif /* SBM_ALL_ACCESS_USE_FLASH_DRIVER != 0 */

/** Where to find the MUH.
 *
 * This depends on whether we need to use hal_mem_read() to pull the MUH
 * into muh_buf, or we can read it directly.
 */
#if SBM_ALL_ACCESS_USE_FLASH_DRIVER != 0

/* We need to read in the MUH before processing it */
extern pie_module_t        g_muh_buf;

/* Offset (if any) from which muh_buf/myuh_buf has been read */
#define SWUP_INVALID_MUH_MUF_BUF ((uintptr_t)-1L)
extern hal_mem_address_t g_muh_buf_origin;

#define SWUP_READ_MUH() \
	swup_read_mu_data(0, &g_muh_buf, sizeof(g_muh_buf), &g_muh_buf_origin)

/** Read data from the module update header/footer into a buffer
 *
 * \param offset    Offset in device from which to read
 * \param dest      Pointer to RAM into which to read the data
 * \param bytes     Number of bytes to read
 * \returns true on success, false if unable
 */
bool swup_read_mu_data(hal_mem_address_t offset,
                       void *dest,
                       size_t bytes,
                       hal_mem_address_t *origin_var);

/** Clear cached MUH (and MUF) data */
void sbm_purge_cached_muh(void);
#endif

#if MUH_READ_USE_FLASH_DRIVER
#define PIEM ((const pie_module_t *)&g_muh_buf)
#else
#define PIEM ((const pie_module_t *)app_status_slot.start_address)
#endif

#endif /* SWUP_MUH_H */
