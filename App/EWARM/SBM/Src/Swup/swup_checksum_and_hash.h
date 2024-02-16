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
#ifndef SWUP_CHECKSUM_H
#define SWUP_CHECKSUM_H

#include <stdbool.h>
#include <stdint.h>
#include "sbm_hal_mem.h"

typedef uint8_t hash_t[32]; /**< Carries a hash. */

/** Calculate a simple 16-bit checksum.
 *
 * \param[in] acc Checksum accumulator (pass zero, unless summing multiple blocks).
 * \param[in] data Address of the buffer over which to calculate the checksum.
 * \param len Length of the buffer pointed to by \a data.
 *
 * \return Checksum.
 */
uint16_t swup_checksum(uint16_t acc, const void *const data, size_t len);

/** Perform a checksum and hash of a section of the specific Flash device.
 * We compute both hash and checksum in parallel (for locality of reference
 * to take advantage of the CPU's data cache, if available) after breaking
 * the operation into manageable chunks.
 *
 * \param slot  The memory slot to read from.
 * \param start Starting offset of the target chunk with the Flash device.
 * \param bytes Number of bytes to include in the sum/hash.
 * \param sum   The checksum result is written here.
 * \param hash  The hash result is written here.
 *
 * \return `true` on success, else `false`.
 *
 * \note Safe to call via Secure API.
 *
 * \note DO NOT be tempted to force the compiler to `inline` this function.
 *       The various SWUP validation routines have been broken up in such
 *       a way as to minimise stack usage. This aim will be defeated if
 *       the function is inlined, increasing the potential for the stack
 *       to overflow when servicing Secure API calls.
 */
bool swup_checksum_and_hash(const memory_slot *slot,
								   hal_mem_address_t start, size_t bytes,
								   uint16_t *sum, hash_t *hash);

#endif /* SWUP_CHECKSUM_H */
