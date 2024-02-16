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
#ifndef SWUP_OPTIONAL_ELEMENT_H
#define SWUP_OPTIONAL_ELEMENT_H

#include <stdint.h>
#include "sbm_hal_mem.h"
#include "ecies_crypto.h"
#include "tomcrypt_api.h"

/* Optional element tags */
#define OE_TAG_AES_GCM_HEADER 0x0001 /**< Node contains ECC NIST-256 public key and AES-GCM tag. */
#define OE_TAG_VERSION_NUMBER 0x8001 /**< Node contains version number. */

/** AES-GCM encryption header.
 *
 * Used to decrypt EUB encrypted details.
 */
typedef struct
{
	EccPublicKey key; /**< Public key. */
	AesTag tag; /**< Tag. */
} aes_gcm_header_t;

/** AES-GCM 128 encryption record.
 *
 * This is the decrypted format.
 */
typedef struct
{
	AesKey key; /**< Key. */
	AesGcmIv iv; /**< Initialisation vector. */
	AesTag tag; /**< Tag. */
} seer_aes_gcm_128_t;

/** Calculate the offset of the first optional element in a SWUP.
 *  For historical reasons (which will be removed soon) we must take steps to align things
 *  correctly here. If SBM_HAL_FC_SIZE is defined and \a update_records is non-zero,
 *  then there is additional padding before the optional elements to account for the
 *  deprecated update status field.
 *
 * \param[in] update_records The number of update records encoded in the SWUP.
 *
 * \return Offset to the first optional element following the SWUP header.
 *
 * \note Safe to call via Secure API.
 */
hal_mem_address_t swup_first_oe(uint32_t update_records);

#endif /* SWUP_OPTIONAL_ELEMENT_H */
