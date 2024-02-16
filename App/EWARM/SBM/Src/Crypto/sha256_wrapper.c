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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "benchmark.h"
#include "sha256_wrapper.h"
#include "sha.h"
#define ERROR(...)	do { (void) shaStatus; } while (0)

static bool sha256_calc_hash_callback_internal(sha256_callback_fn_t fn, void *arg,
												uint8_t *pHash)
{
	SHA256Context 	shaContext;
	int 			shaStatus;
	size_t			bytes;
	const void		*buff;

	if (shaSuccess != (shaStatus = SHA256Reset(&shaContext)))
	{
		ERROR("[e] SHA256Reset failed %d\n", shaStatus);
		return false;
	}

	for (;;)
	{
		buff = (fn)(arg, &bytes);
		if (buff == NULL || bytes == 0)
			break;

		if (shaSuccess != (shaStatus = SHA256Input(&shaContext, buff, bytes)))
		{
			ERROR("[e] SHA256Input failed %d\n", shaStatus);
			return false;
		}
	}

	if (shaSuccess != (shaStatus = SHA256FinalBits(&shaContext, 0, 0)) ||
		shaSuccess != (shaStatus = SHA256Result(&shaContext, pHash)))
	{
		ERROR("[e] SHA256FinalBits failed %d\n", shaStatus);
		return false;
	}

	return buff != NULL;
}

__weak bool sha256_calc_hash_callback(sha256_callback_fn_t fn, void *arg,
									  uint8_t *pHash)
{
	sbm_benchmark_procedure_start(BENCHMARK_CALCULATE_SHA256);
	const bool ret = sha256_calc_hash_callback_internal(fn, arg, pHash);
	sbm_benchmark_procedure_stop(BENCHMARK_CALCULATE_SHA256);
	return ret;
}

struct chunked_args {
	const sha256_hash_chunk_t *chunks;
	uint16_t nchunks;
	uint16_t idx;
};

static const void *chunked_callback(void *arg, size_t *pBytes)
{
	struct chunked_args *a = arg;

	if (a->idx >= a->nchunks)
	{
		*pBytes = 0;
		return a;	/* Returning any non-NULL pointer here is fine */
	}

	*pBytes = a->chunks[a->idx].length;
	return a->chunks[a->idx++].data;
}

__weak bool sha256_calc_hash_chunked(const sha256_hash_chunk_t *chunks,
									 unsigned int nchunks,
									 uint8_t *pHash)
{
	struct chunked_args a;

	a.chunks = chunks;
	a.nchunks = (uint16_t)nchunks;
	a.idx = 0;

	return sha256_calc_hash_callback(chunked_callback, &a, pHash);
}

__weak bool sha256_calc_hash(const void *pData,
							 uint32_t length,
							 uint8_t *pHash)
{
	sha256_hash_chunk_t chunk;

	chunk.data = pData;
	chunk.length = length;

	return sha256_calc_hash_chunked(&chunk, 1, pHash);
}
