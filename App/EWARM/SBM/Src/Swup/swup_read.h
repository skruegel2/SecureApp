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
#ifndef SWUP_READ_H
#define SWUP_READ_H

#include <stddef.h>
#include "sbm_hal_mem.h"

/** Read a range of bytes from an update slot.
 *
 * This is essentially a wrapper around `hal_mem_read()`.
 *
 * \note Note that the routine has no return value. This is by design, for performance
 * reasons. In case of error, the destination buffer will be filled with 0xff
 * bytes, mimicking an erased Flash device. If logging is enabled, the error will
 * be logged to the console.
 *
 * \note Safe to call via Secure API iff logging is disabled (see sbm_log_disable()).
 *
 * \note DO NOT be tempted to force the compiler to `inline` this function.
 *       The various SWUP validation routines have been broken up in such
 *       a way as to minimise stack usage. This aim will be defeated if
 *       the function is inlined, increasing the potential for the stack
 *       to overflow when servicing Secure API calls.
 *
 * \pre update_slot != NULL
 * \pre dest != NULL
 * \pre max_offset < update_slot->size
 *
 * \param[in] update_slot The update slot to read from.
 * \param[in] offset_in_slot The offset of the first byte to read from the
 *                           update slot, relative to the start of the slot.
 * \param[in] max_offset     The maximum allowed value of \p offset_in_slot.
 *                           This should be set based on the length field
 *                           read from the SWUP header. This function will
 *                           perform range checking to ensure that \p offset_in_slot
 *                           does not access past the end of the SWUP based on
 *                           its length.
 * \param[out] dest The data read from the update slot is written here.
 *                  This is filled with 0xff if an error occurs.
 * \param[in] bytes The number of bytes to read from the update slot.
 */
#pragma inline=never
void swup_read(const memory_slot *update_slot,
               hal_mem_address_t offset_in_slot,
               hal_mem_address_t max_offset,
               void *dest,
               size_t bytes);

#ifdef SBM_PC_BUILD
#ifndef PRIxSIZET
#define	PRIxSIZET	PRIx64
#endif
#else
#define	PRIxSIZET	"zx"
#endif

#endif /* SWUP_READ_H */
