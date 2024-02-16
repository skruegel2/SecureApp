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
 * \brief Various SBM internal function implementations.
 */

#include <string.h>

#include "memoryMap.h"
#include "sbm_api.h"
#include "sbm_log.h"
#include "oem.h"
#include "swup_muh.h"

/* Flash programming and update processing gubbins */

#ifndef SBM_PC_BUILD
void tlv_dump(const void *const data, const size_t data_size)
{
	const tlv_node *const e = (const tlv_node *) ((uintptr_t) data + data_size);
	for (const tlv_node *f = (const tlv_node *) data;
		 (!data_size || f < e) && f->t != TLV_END_MARKER && f->l; ++f)
	{
		SBM_PRINTF_INFO("0x%p: 0x%04" PRIx16 ", 0x%04" PRIx16 " @ 0x%p\n", f, f->t, f->l, f->v);

		/* Bump address of next node by length of data in this one.
		   The loop increment will take care of the size of the node itself. */
		*((uint8_t **) &f) += (f->l + 3U) & ~3U;
	}
}

int tlv_find_node(const void *const data, const uint16_t data_size,
				  const uint16_t target, const uint8_t **const field, uint16_t *const f_len)
{
	const tlv_node *const e = (const tlv_node *) ((uintptr_t) data + data_size);
	const tlv_node *f = (const tlv_node *) data;
	for (; (!data_size || f < e) && f->t != TLV_END_MARKER && f->l; ++f)
	{
		if (target == f->t)
		{
			*field = f->v;
			if (f_len) *f_len = f->l;
			return 0;
		}

		/* Bump address of next node by length of data in this one.
		   The loop increment will take care of the size of the node itself. */
		*((uint8_t **) &f) += (f->l + 3U) & ~3U;
	}

	/* Degenerate case: if we've hit the end, our caller can make
	   use of the address just past the end of the TLV list. */

	*field = (uint8_t *) (((uintptr_t) f->v + 3U) & ~3U);

	return -1;
}
#endif /* SBM_PC_BUILD */

int tlv_find_node_flash(const memory_slot *slot, hal_mem_address_t start_offset,
						const size_t data_size, const uint16_t target,
						hal_mem_address_t *const field, uint16_t *const f_len)
{
	const hal_mem_address_t end_address = start_offset + data_size;
	tlv_node f;

	do
	{
		if (HAL_MEM_SUCCESS != hal_mem_read(slot, start_offset, &f, sizeof f))
			break;

		if (target == f.t)
		{
			if (field) *field = start_offset + sizeof f;
			if (f_len) *f_len = f.l;
			return 0;
		}

		if (TLV_END_MARKER == f.t)
			break;

		/* Bump address of next node by length of data in this one,
		   ensuring we maintain 32-bit alignment. */
		start_offset += (f.l + 3u) & ~3u;
	} while ((!data_size || start_offset < end_address) && f.l);

	/* Degenerate case: if we've hit the end, our caller can make
	   use of the address just past the end of the TLV list. */
	if (field) *field = start_offset + ((f.l + 3u) & ~3u);

	return -1;
}

hal_mem_result_t sbm_copy_to_flash(const memory_slot *slot, uintptr_t dst, const void *const src, const size_t length)
{
	hal_mem_result_t result = hal_mem_program(slot, (hal_mem_address_t)dst, src, length);
	if (HAL_MEM_SUCCESS != result)
		return result;

	return hal_mem_verify(slot, (hal_mem_address_t)dst, src, length);
}
