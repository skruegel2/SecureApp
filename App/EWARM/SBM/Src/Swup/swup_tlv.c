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
#include "swup_tlv.h"

#include "memory_devices_and_slots.h"
#include "sbm_api.h"

/** Provide a service to read a TLV element from the update slot of the
 * specified Flash device.
 *
 * \param update_slot The update slot to read from.
 * \param max_offset The maximum offset to read from the SWUP, or 0 if
 *                   the SWUP size/max offset is unknown.
 * \param offset Starting offset of the TLV list.
 * \param size   If non-zero, this is the max size of the list.
 * \param target The ID of the target element.
 * \param field  If the target element is found, the offset of its value
 *               field is written here. Can be NULL.
 * \param f_len  If the target element is found, the length of its value
 *               field is written here. Can be NULL.
 *
 * \return `true` if the element was found, else `false` if not found or error.
 */
#pragma inline=never
bool swup_tlv_find_node(const memory_slot *update_slot, hal_mem_address_t max_offset,
                        hal_mem_address_t offset, size_t size, const uint16_t target,
                        hal_mem_address_t *field, uint16_t *f_len)
{
	if (max_offset != 0 && max_offset < (offset + size))
	{
		return false;
	}

	if (size == 0)
		size = max_offset;

	if (tlv_find_node_flash(update_slot, offset,
							size, target, field, f_len))
	{
		return false;
	}

	if (field)
	{
#ifndef NDEBUG
		/* If we know the length of the SWUP, perform some sanity checks. */
		if (max_offset && (max_offset < *field ||
			(f_len && max_offset < (*field + *f_len))))
		{
			return false;
		}
#endif /* NDEBUG */
	}

	return true;
}
