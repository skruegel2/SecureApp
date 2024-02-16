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
#include "swup_checksum_and_hash.h"

#include "memory_devices_and_slots.h"
#include "sha256_wrapper.h"
#include "sbm_hal_mem.h"


/** Use the following structure to save context for the hash/checksum
    callback. */
struct swup_sum_and_hash_arg {
	const memory_slot *slot; /**< Memory slot containing the source data. */
	hal_mem_address_t start; /**< Offset within the slot of next chunk. */
	size_t bytes;            /**< Bytes remaining. */
	uint16_t sum;            /**< Accumulated checksum. */
	uint8_t buffer[16];      /**< Current data being summed/hashed. */
};

uint16_t swup_checksum(uint16_t acc, const void *const data, size_t len)
{
	const uint8_t *d = data;

	while (len--)
		acc += *d++;

	return acc;
}

/** Hash callback function.
 * This performs two tasks:
 *  - Fetch the next chunk of source data from the Flash device into a
 *    temporary buffer.
 *  - Calculate the chunk's checksum and fold it into the total sum.
 *
 * \param arg    Points to the state structure `swup_sum_and_hash_arg`.
 * \param pbytes The number of bytes loaded into the buffer is recorded here.
 *               EOF is indicated by the number of bytes returned being zero.
 *
 * \return A pointer to the buffer to be hashed on success, else `NULL`.
 *
 * \note Safe to call via Secure API.
 */
static const void *swup_hash_callback(void *arg, size_t *pbytes)
{
	struct swup_sum_and_hash_arg *a = arg;
	size_t bytes;

	/* Break up the source into buffer-sized chunks. */
	bytes = (a->bytes > sizeof a->buffer) ? sizeof a->buffer : a->bytes;

	if (bytes)
	{
		if (HAL_MEM_SUCCESS != hal_mem_read(a->slot, a->start, a->buffer, bytes))
			return NULL;

		a->start += bytes;
		a->bytes -= bytes;

		a->sum = swup_checksum(a->sum, a->buffer, bytes);
	}

	/* Inform the caller of the next chunk's details. */
	*pbytes = bytes;
	return a->buffer;
}

#pragma inline=never
bool swup_checksum_and_hash(const memory_slot *slot,
                            hal_mem_address_t start, size_t bytes,
                            uint16_t *sum, hash_t *hash)
{
	struct swup_sum_and_hash_arg a;

	/* Prepare the state structure with the starting parameters. */
	a.slot  = slot;
	a.start = start;
	a.bytes = bytes;
	a.sum = 0;

	if (!sha256_calc_hash_callback(swup_hash_callback, &a, (uint8_t *)hash))
		return false;

	*sum = a.sum;
	return true;
}
