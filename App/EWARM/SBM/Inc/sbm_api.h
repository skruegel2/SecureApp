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

#ifndef SRC_SBM_API_H_
#define SRC_SBM_API_H_

/** \file
 * \brief Various SBM internal functions - declarations.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sbm_hal.h"
#include "sbm_hal_mem.h"
#include "memory_devices_and_slots.h"

/** TLV internal structure. Typical type, length, value. */
typedef struct
{
	uint16_t t; /**< Type of data in this node. */
	uint16_t l; /**< Length of data in this node. */
	uint8_t v[]; /**< Node data. */
} tlv_node;

#define TLV_END_MARKER 0xFFFFU /**< Value in tlv_node.t to mark end. */

/** Dump a TLV list.
 *
 * Print the address, type and length of each node.
 *
 * Dumps data until either it reaches the length provided in
 * the \a data_size argument or the terminating node is reached.
 *
 * \param[in] data Address of first TLV node in the list.
 * \param data_size Length of buffer (zero to dump until terminating node is found).
 */
void tlv_dump(const void *const data, const size_t data_size);

/** Find a field of a given type in a data buffer.
 *
 * Walk the buffer until we find the tag we're seeking, we reach the
 * end or we find an end marker where the next "type" field would be.
 *
 * \param[in] data Address of buffer to search.
 * \param data_size Length of buffer to search (zero to search until terminator is found).
 * \param target Type of field to search for.
 * \param[out] field Address of a pointer to unit8_t to populate with address of data.
 * \param[out] f_len Address of a unit16_t to populate with length of data (may be NULL).
 *
 * \return Zero if target found, non-zero if not.
 *
 * If non-zero is returned the value of \a *field is
 * the address just beyond the end of the TLV list.
 */
int tlv_find_node(const void *const data, const uint16_t data_size,
				  const uint16_t target, const uint8_t **const field, uint16_t *const f_len);

/** Find a field of a given type on a memory device at the given offset.
 *
 * Walk the device until we find the tag we're seeking, we reach the
 * end or we find an end marker where the next "type" field would be.
 *
 * \param[in] slot Handle of the memory slot to search.
 * \param[in] start_offset Offset relative to the start of the slot to start searching from.
 * \param data_size Length of region to search (zero to search until terminator is found).
 * \param target Type of field to search for.
 * \param[out] field Address of a hal_mem_address_t to populate with offset of data (may be NULL).
 * \param[out] f_len Address of a uint16_t to populate with length of data (may be NULL).
 *
 * \return Zero if target found, non-zero if not.
 *
 * If non-zero is returned the value of \a *field is
 * the offset just beyond the end of the TLV list.
 */
int tlv_find_node_flash(const memory_slot *slot, hal_mem_address_t start_offset,
						const size_t data_size, const uint16_t target,
						hal_mem_address_t *const field, uint16_t *const f_len);

/** Copy a block of memory to a memory device.
 *
 * The blocks of memory targeted by the destination address
 * are programmed with, then verified against, the source buffer.
 *
 * It is the caller's resposibility to make sure the target
 * memory area has been erased before calling this function.
 *
 * \param slot The target memory slot
 * \param dst The destination address to which the copy is made.
 * \param src The address of the buffer to be copied.
 * \param length The length of the buffer to be copied.
 *
 * \return \c HAL_MEM_SUCCESS if the copy is successful,
 *            otherwise any other value if the copy failed (see hal_mem_result_t).
 */
hal_mem_result_t sbm_copy_to_flash(const memory_slot *slot, uintptr_t dst, const void *const src, const size_t length);

#endif /* SRC_SBM_API_H_ */
