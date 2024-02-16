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
#include "swup_sbm_update_slot_contains_swup.h"

#include <string.h>
#include "sbm_memory.h"
#include "swup_uuid.h"
#include "swup_signature.h"
#include "swup_metadata.h"
#include "swup_layout.h"
#include "swup_status_error_code.h"
#include "swup_capability_defines.h"
#include "swup_supported_defines.h"
#include "swup_header_magic.h"
#include "swup_eub.h"
#include "swup_muh.h"
#include "swup_read.h"
#include "swup_optional_element.h"
#include "swup_public_key.h"
#include "swup_tlv.h"
#include "swup_oem.h"
#include "memoryMap.h"
#include "ecies_crypto.h"
#include "secureApiData.h"
#include "datastore.h"
#include "sbm_api.h"
#include "static.h"
#include "memory_devices_and_slots.h"
#include "sbm_log_update_status.h"

/** Perform cheap (computationally inexpensive) sanity checks of a potential
 * SWUP in the update slot, providing a quick Go/NoGo indication to minimise
 * startup time during system boot.
 *
 * \param[in] update_slot The update slot containing the SWUP to validate.
 * \param[out] max_offset If the SWUP is valid, then this is set to the offset of
 *                        the last byte of the SWUP based on its length. I.e. this is
 *                        equal to the SWUP length minus one.
 * \param[out] smd Pointer to a `swup_metadata_t` structure where offsets to some
 *                 key SWUP elements are written if the SWUP appears to be valid.
 * \param key_instance Pointer to where the instance number of the private
 *                     update key will be written (to be used to decrypt the
 *                     EUB encrypted details).
 *
 * \return `SWUP_STATUS_INITIAL` on success, or a `SWUP_STATUS_ERROR_CODE`
 *         indicating the nature of any detected error.
 *
 * \note Safe to call via Secure API iff logging is disabled (see sbm_log_disable()).
 *
 * \note DO NOT be tempted to force the compiler to `inline` this function.
 *       The various SWUP validation routines have been broken up in such
 *       a way as to minimise stack usage. This aim will be defeated if
 *       the function is inlined, increasing the potential for the stack
 *       to overflow when servicing Secure API calls.
 */
#pragma inline=never
STATIC unsigned int swup_validation_simple_checks(const memory_slot *update_slot, hal_mem_address_t *max_offset, swup_metadata_t *smd, uint8_t *const key_instance)
{
	union {
		/* Minimise stack usage by sharing memory across several objects which
		   are not required to be 'live' concurrently. */
		uint32_t u32;
		uuid_t uuid;
		EccPublicKey update_key;
	} u;
	uint32_t val32;
	uint16_t val16;

	/* Default the max. offset to the last byte in the update slot until
	 * the SWUP length has been read. */
	*max_offset = update_slot->size - 1;

	swup_read(update_slot, SWUP_OFFSET_HEADER_PREAMBLE_MAGIC, *max_offset, &val32, sizeof val32);
	if (val32 != SWUP_HEADER_MAGIC)
	{
		SBM_LOG_UPDATE_ERROR("header magic: 0x%" PRIx32 " expected 0x%" PRIx32 "\n",
				 val32, (uint32_t)SWUP_HEADER_MAGIC);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_MAGIC);
	}

	swup_read(update_slot, SWUP_OFFSET_HEADER_LAYOUT_VERSION, *max_offset, &val32, sizeof val32);
	if (val32 != SUPPORTED_LAYOUT_VERSION)
	{
		SBM_LOG_UPDATE_ERROR("layout version: 0x%" PRIx32 " expected 0x%x\n",
				 val32, SUPPORTED_LAYOUT_VERSION);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_LAYOUT);
	}

	/* Test SWUP capability flags against whatever this SBM can do */

	swup_read(update_slot, SWUP_OFFSET_HEADER_SWUP_CAPABILITY_FLAGS, *max_offset, &val32, sizeof val32);

#if SBM_SUPPORT_ENCRYPTED_UPDATES == 0
	if ((val32 & SWUP_CAP_ENC_MODE_MASK) != SWUP_CAP_ENC_MODE_NONE)
#else
	if ((val32 & SWUP_CAP_ENC_MODE_MASK) != SWUP_CAP_ENC_MODE_ECIES_AES_GCM)
#endif
	{
		SBM_LOG_UPDATE_ERROR("invalid encryption mode: 0x%" PRIx32 "\n",
				 val32 & SWUP_CAP_ENC_MODE_MASK);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_SWUP_ENC_MODE);
	}

	if ((val32 & SWUP_CAP_CIPHER_LAYOUT_MASK) != SWUP_CAP_HEAD_FOOT_CIPHER)
	{
		SBM_LOG_UPDATE_ERROR("invalid cipher layout: 0x%" PRIx32 "\n",
				 val32 & SWUP_CAP_CIPHER_LAYOUT_MASK);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_SWUP_CIPHER_LAYOUT);
	}

	if ((val32 & SWUP_CAP_CIPHER_SUITE_MASK) != SWUP_CAP_SHA_256_ECDSA_P_256)
	{
		SBM_LOG_UPDATE_ERROR("invalid cipher suite: 0x%" PRIx32 "\n",
				 val32 & SWUP_CAP_CIPHER_SUITE_MASK);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_CIPHER_SUITE);
	}

	const uint32_t update_records = SWUP_UPDATE_STATUS_RECORDS(val32);
	if (update_records != 0 && update_records != SUPPORTED_FLASH_COUNTERS)
	{
		SBM_LOG_UPDATE_ERROR("invalid number of update status records: 0x%"
				 PRIx32 "\n", SWUP_UPDATE_STATUS_RECORDS(val32));
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_COUNTERS);
	}

	const hal_mem_address_t swup_oe_offset = swup_first_oe(update_records);

	if (((val32 & SWUP_CAP_VERSION_SIZE_MASK) >> SWUP_CAP_VERSION_SIZE_SHIFT) != SUPPORTED_VERSION_SIZE)
	{
		SBM_LOG_UPDATE_ERROR("invalid version size: 0x%" PRIx32 "\n",
				 (val32 & SWUP_CAP_VERSION_SIZE_MASK) >> SWUP_CAP_VERSION_SIZE_SHIFT);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_VERSION);
	}

	/* Last ditch test: any "reserved" bits should be zero */

	if (val32 & SWUP_CAP_RESERVED)
	{
		SBM_LOG_UPDATE_ERROR("reserved capability bits set: 0x%" PRIx32 "\n", val32);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_RESERVED_CAPS);
	}

	/* Test EUB capability flags against whatever this SBM can do */

	swup_read(update_slot, SWUP_OFFSET_HEADER_EUB_CAPABILITY_FLAGS, *max_offset, &val32, sizeof val32);
	smd->eub_capability_flags = val32;

#if SBM_SUPPORT_ENCRYPTED_UPDATES == 0
	if ((val32 & COMMON_CAP_ENC_MODE_MASK) != COMMON_CAP_ENC_MODE_NONE)
#else
	if ((val32 & COMMON_CAP_ENC_MODE_MASK) != COMMON_CAP_ENC_MODE_AES_GCM_128)
#endif
	{
		SBM_LOG_UPDATE_ERROR("invalid EUB encryption mode: 0x%" PRIx32 "\n",
				 val32 & COMMON_CAP_ENC_MODE_MASK);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_ENC_MODE);
	}

	if (val32 & COMMON_CAP_ADV_ENC_OPTIONS_MASK)
	{
		SBM_LOG_UPDATE_ERROR("invalid EUB advanced encryption options: 0x%" PRIx32 "\n",
				 val32 & COMMON_CAP_ADV_ENC_OPTIONS_MASK);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_ENC_OPTIONS);
	}

	if ((val32 & COMMON_CAP_CIPHER_LAYOUT_MASK) != COMMON_CAP_FIXED_CIPHER_FIELDS)
	{
		SBM_LOG_UPDATE_ERROR("invalid cipher fields: 0x%" PRIx32 "\n",
				 val32 & COMMON_CAP_CIPHER_LAYOUT_MASK);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_CIPHER_LAYOUT);
	}

	if ((val32 & COMMON_CAP_PU_MASK) != (COMMON_CAP_SINGLE_PU_SIG | COMMON_CAP_SINGLE_PU_HASH))
	{
		SBM_LOG_UPDATE_ERROR("invalid cipher fields: 0x%" PRIx32 "\n", val32 & COMMON_CAP_PU_MASK);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_SWUP_EUB_PU);
	}

	/* Last ditch test: any "reserved" bits should be zero */

	if (val32 & COMMON_CAP_RESERVED)
	{
		SBM_LOG_UPDATE_ERROR("reserved EUB capability bits set: 0x%" PRIx32 "\n", val32);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_COMMON_RESERVED_CAPS);
	}

	/* Police the number of EUBs field. There must be at least one. */

	swup_read(update_slot, SWUP_OFFSET_HEADER_NUM_EUBS, *max_offset, &smd->num_eubs, sizeof smd->num_eubs);
	if (smd->num_eubs > SUPPORTED_EUBS || smd->num_eubs < 1U)
	{
		SBM_LOG_UPDATE_ERROR("invalid number of EUBs: 0x%" PRIx16 "\n", smd->num_eubs);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUBS);
	}

	/* Police the SWUP length field. While great precision is not required,
	   we should be able to deduce a more accurate minimum length */

	swup_read(update_slot, SWUP_OFFSET_HEADER_LENGTH_OF_SWUP, *max_offset, &val32, sizeof val32);

	if (val32 < (swup_oe_offset +
				 (smd->num_eubs * SWUP_OFFSET_EUB_CLEAR__SIZEOF) +
				 SWUP_OFFSET_HEADER_EPILOGUE__SIZEOF +
				 SWUP_OFFSET_FOOTER__SIZEOF) ||
		val32 > update_slot->size || (val32 & 3U))
	{
		SBM_LOG_UPDATE_ERROR("length too short, larger than the update slot or not "
				 "a multiple of 4: 0x%" PRIx32 "\n", val32);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_LENGTH);
	}

	/* With a reasonable-looking SWUP length field, set max_offset so that
	   all subsequent read operations can be policed to ensure they are within
	   the bounds of the SWUP image. */
	*max_offset = (hal_mem_address_t)val32;

	/* Police the layout */

	swup_read(update_slot, SWUP_OFFSET_HEADER_FOOTER_LENGTH, *max_offset, &val16, sizeof val16);
	if (val16 != SWUP_OFFSET_FOOTER__SIZEOF)
	{
		SBM_LOG_UPDATE_ERROR("footer length invalid: 0x%" PRIx16 " expected 0x%" PRIx16 "\n",
				 val16, (uint16_t)SWUP_OFFSET_FOOTER__SIZEOF);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_FOOTER_LEN);
	}

	/* We can calculate the length of the SWUP, minus footer. */
	smd->length_of_swup = val32 - (uint32_t)val16;

	swup_read(update_slot, SWUP_OFFSET_HEADER_EUB_CLEAR_START, *max_offset, &smd->layout, sizeof smd->layout);
	if (smd->layout.first_eub_start - smd->layout.epilogue_start != SWUP_OFFSET_HEADER_EPILOGUE__SIZEOF)
	{
		SBM_LOG_UPDATE_ERROR("epilogue length apparently invalid: 0x%" PRIx16 " expected 0x%" PRIx16 "\n",
				 smd->layout.first_eub_start - smd->layout.epilogue_start,
				 (uint16_t)SWUP_OFFSET_HEADER_EPILOGUE__SIZEOF);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EPILOGUE_LEN);
	}

	/* Police the identity */

	swup_read(update_slot, SWUP_OFFSET_HEADER_RANDOM, *max_offset, &u.u32, sizeof u.u32);
	if (INVALID_RANDOM(u.u32))
	{
		SBM_LOG_UPDATE_ERROR("header random invalid: 0x%" PRIx32 "\n", u.u32);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_HEADER_RANDOM);
	}

	swup_read(update_slot, smd->length_of_swup + SWUP_OFFSET_FOOTER_RANDOM, *max_offset, &val32, sizeof val32);
	if (INVALID_RANDOM(val32))
	{
		SBM_LOG_UPDATE_ERROR("footer random invalid: 0x%" PRIx32 "\n", val32);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_FOOTER_RANDOM);
	}

	if (u.u32 != val32)
	{
		SBM_LOG_UPDATE_ERROR("header/footer random mismatch: header 0x%" PRIx32
				 " footer 0x%" PRIx32 "\n", u.u32, val32);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_RANDOM);
	}

	if (smd->layout.eub_clear_details_start & 3U)
	{
		SBM_LOG_UPDATE_ERROR("misaligned start of EUB clear details: 0x%" PRIx16 "\n",
				 smd->layout.eub_clear_details_start);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_CD_ALIGNMENT);
	}

	if (smd->layout.eub_encrypted_details_start & 3U)
	{
		SBM_LOG_UPDATE_ERROR("misaligned start of EUB encrypted details: 0x%" PRIx16 "\n",
				 smd->layout.eub_encrypted_details_start);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_ED_ALIGNMENT);
	}

	if (smd->layout.epilogue_start & 3U)
	{
		SBM_LOG_UPDATE_ERROR("misaligned start of header epilogue: 0x%" PRIx16 "\n",
				 smd->layout.epilogue_start);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EPILOGUE_ALIGNMENT);
	}

	if (smd->layout.first_eub_start & 3U)
	{
		SBM_LOG_UPDATE_ERROR("misaligned start of EUBs: 0x%" PRIx16 "\n",
				 smd->layout.first_eub_start);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_ALIGNMENT);
	}

	/* Police the update UUID */

	swup_read(update_slot, SWUP_OFFSET_HEADER_UPDATE_UUID, *max_offset, u.uuid, sizeof u.uuid);
	if (!swup_uuid_valid(u.uuid))
	{
		SBM_LOG_UPDATE_ERROR("invalid SWUP update UUID\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_STATUS);
	}

	/* If the update UUID matches the installed UUID then this SWUP must
	   have been installed on a previous boot. */
#if MUH_READ_USE_FLASH_DRIVER
	if (!SWUP_READ_MUH())
	{
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_MUH_READ_ERROR);
	}
#endif

	const pie_module_sbm_exec_info_t *sei = (const pie_module_sbm_exec_info_t *)PIEM->header.sbm_exec_info;
	if (memcmp(sei->installed_uuid, u.uuid, sizeof(uuid_t)) == 0)
	{
		SBM_LOG_UPDATE_INFO("previously installed update found\n");
		return SWUP_STATUS_INSTALLED_PREVIOUS;
	}

	/* This SWUP appears to be "fresh" so we need to police it properly */

	/* Ensure the SWUP was created from the same Security World as our
	   provisioned data. */

	swup_read(update_slot, SWUP_OFFSET_HEADER_SECURITY_WORLD_UUID, *max_offset, u.uuid, sizeof u.uuid);
	const provisioning_summary *const provisioned_data_summary = datastore_provisioning_data_summary();
	if (memcmp(u.uuid, provisioned_data_summary->context_uuid, sizeof u.uuid))
	{
		SBM_LOG_UPDATE_ERROR("security ID mismatch\n");
		SBM_HEXDUMP_UPDATE_ERROR(u.uuid, sizeof u.uuid);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_SECURITY_ID);
	}

	swup_read(update_slot, SWUP_OFFSET_HEADER_SECURITY_WORLD_ITERATION, *max_offset, &val16, sizeof val16);
	if (val16 != provisioned_data_summary->iteration)
	{
		SBM_LOG_UPDATE_ERROR("security iteration mismatch 0x%" PRIx16 "\n", val16);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_SECURITY_ITERATION);
	}

	/* Check update key */

	swup_read(update_slot, SWUP_OFFSET_HEADER_UPDATE_KEY, *max_offset, u.update_key, sizeof u.update_key);
	if (!update_key_valid(u.update_key, key_instance))
	{
		SBM_LOG_UPDATE_ERROR("update key and private key mismatch\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_UPDATE_KEY);
	}

	/* The swup->gen_date_time and swup->source_device_id are
	   for transportation only and are neither used nor policed by the SBM. */

	/* Police optional elements. If we're carrying any encrypted
	   EUBs, the encryption details must be in here. */

	/* We currently only have at most a single OE in the list (and the terminator), which is
	   the encryption-tag. */
	u.u32 = (uint32_t)((hal_mem_address_t)smd->layout.eub_clear_details_start - swup_oe_offset);

#if SBM_SUPPORT_ENCRYPTED_UPDATES != 0
	/* Are there encrypted EUBs in here? */
	swup_read(update_slot, SWUP_OFFSET_HEADER_SWUP_CAPABILITY_FLAGS, *max_offset, &val32, sizeof val32);
	if ((val32 & SWUP_CAP_ENC_MODE_MASK) == SWUP_CAP_ENC_MODE_ECIES_AES_GCM)
	{
		if (!swup_tlv_find_node(update_slot, *max_offset, swup_oe_offset, (size_t)u.u32, OE_TAG_AES_GCM_HEADER, NULL, NULL))
		{
			SBM_LOG_UPDATE_ERROR("has no AES-GCM header\n");
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_AES_GCM);
		}
	}

	/* Since we're expecting an encrypted update, the encrypted details must be present. */
	if (smd->layout.eub_encrypted_details_start == 0)
	{
		SBM_LOG_UPDATE_ERROR("encrypted details start is zero.\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_ENCRYPTION_CONFIG_INCONSISTENT);
	}
#else
	/* Not supporting encryption updates: */
	if (swup_tlv_find_node(update_slot, *max_offset, swup_oe_offset, (size_t)u.u32, OE_TAG_AES_GCM_HEADER, NULL, NULL))
	{
		SBM_LOG_UPDATE_ERROR("has unexpected AES-GCM header.\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_ENCRYPTION_CONFIG_INCONSISTENT);
	}

	/* Not supporting encrypted updates, check "EUB Details (Encrypted)" is missing. */
	if (smd->layout.eub_encrypted_details_start != 0)
	{
		SBM_LOG_UPDATE_ERROR("unexpected encrypted EUB found.\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_ENCRYPTION_CONFIG_INCONSISTENT);
	}
#endif

	return SWUP_STATUS_INITIAL;
}

/** Perform a computationally expensive sanity check of the SWUP.
 * This involves computing a checksum and hash starting with the SWUP
 * header and covering all bytes up to, but not including, the epilogue
 * object. The computed hash is used to generate a signature via the OEM
 * validation key. The checksum, hash, and signature are compared with
 * the corresponding values stored in the SWUP epilogue object.
 *
 * \pre update_slot != NULL
 * \pre smd != NULL
 * \pre max_offset < update_slot->size
 *
 * \param[in] update_slot The update slot containing the SWUP to validate.
 * \param[in] max_offset The offset of the last byte of the SWUP. This
 *                       should be set based on the length of the SWUP.
 *                       If the length is unknown, then this should be
 *                       set to update_slot->size - 1.
 * \param[in] smd    Pointer to SWUP metadata extracted earlier.
 *
 * \return `SWUP_STATUS_INITIAL` on success, or a `SWUP_STATUS_ERROR_CODE`
 *         indicating the nature of any detected error.
 *
 * \note Safe to call via Secure API iff logging is disabled (see sbm_log_disable()).
 *
 * \note DO NOT be tempted to force the compiler to `inline` this function.
 *       The various SWUP validation routines have been broken up in such
 *       a way as to minimise stack usage. This aim will be defeated if
 *       the function is inlined, increasing the potential for the stack
 *       to overflow when servicing Secure API calls.
 */
#pragma inline=never
STATIC unsigned int swup_validation_check_header(const memory_slot *update_slot, hal_mem_address_t max_offset, const swup_metadata_t *smd)
{
	uint16_t calc_sum;
	hash_t calc_hash;
	union {
		/* Minimise stack usage by sharing memory across several objects which
		   are not required to be 'live' concurrently. The following values are
		   read from the SWUP, to be compared with our calculated values. */
		uint16_t sum;
		hash_t hash;
		sig_t sig;
	} u;

	/* Compute checksum and hash of the entire SWUP header. */
	if (!swup_checksum_and_hash(update_slot, 0, (size_t)smd->layout.epilogue_start,
								&calc_sum, &calc_hash))
	{
		SBM_LOG_UPDATE_ERROR("failed to checksum/hash header\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_FAILED_HEADER_HASH);
	}

	/* Fetch and compare the checksum stored in the SWUP epilogue. */
	swup_read(update_slot, smd->layout.epilogue_start + SWUP_OFFSET_HEADER_EPILOGUE_CHECKSUM,
			  max_offset, &u.sum, sizeof u.sum);
	if (calc_sum != u.sum)
	{
		SBM_LOG_UPDATE_ERROR("header checksum calculated 0x%" PRIx16 " expected 0x%" PRIx16 "\n",
				 calc_sum, u.sum);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_HEADER_CHECKSUM);
	}

	/* Fetch and compare the hash stored in the SWUP epilogue. */
	swup_read(update_slot, smd->layout.epilogue_start + SWUP_OFFSET_HEADER_EPILOGUE_HASH,
			  max_offset, &u.hash, sizeof u.hash);
	if (memcmp(u.hash, calc_hash, sizeof calc_hash))
	{
		SBM_LOG_UPDATE_ERROR("header hash mismatch\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_HEADER_HASH);
	}

	/* Fetch and validate the signature stored in the SWUP epilogue. */
	swup_read(update_slot, smd->layout.epilogue_start + SWUP_OFFSET_HEADER_EPILOGUE_SIGNATURE,
			  max_offset, &u.sig, sizeof u.sig);

	const pd_slot_t osvks = oem_swup_key_slot(KEY_PURPOSE_OEM_VALIDATION);
	if (osvks < 0)
	{
		SBM_LOG_UPDATE_ERROR("header signature (OEM validation) key not found\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_VALIDATION_KEY);
	}

	int8_t r = datastore_verify(osvks, calc_hash, sizeof calc_hash, u.sig, sizeof u.sig);
	if (r)
	{
		SBM_LOG_UPDATE_ERROR("header signature verification failed: %" PRId8 "\n", r);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_HEADER_SIGNATURE);
	}

	/* We could, at this point, validate the SWUP footer. However, strictly
	   speaking this is only necessary for SWUP transportation. For this reason,
	   the code to perform the validation is included here for reference
	   purposes but is not enabled by default (and comes with no guarantee that
	   it will compile). */
#if 0
	/* Compute checksum and hash of the entire SWUP. */
	if (!swup_checksum_and_hash(swup_update_handle, 0, (size_t)smd->length_of_swup,
								&calc_sum, &calc_hash))
	{
		SBM_LOG_UPDATE_ERROR("failed to checksum/hash footer\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_FAILED_FOOTER_HASH);
	}

	/* Fetch and compare the checksum stored in the SWUP footer. */
	swup_read(smd->length_of_swup + SWUP_OFFSET_FOOTER_CHECKSUM,
			  &u.sum, sizeof u.sum);
	if (calc_sum != u.sum)
	{
		SBM_LOG_UPDATE_ERROR("footer checksum calculated 0x%" PRIx16 " expected 0x%" PRIx16 "\n",
				 calc_sum, u.sum);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_FOOTER_CHECKSUM);
	}

	/* Fetch and compare the hash stored in the SWUP footer. */
	swup_read(smd->length_of_swup + SWUP_OFFSET_FOOTER_HASH,
			  &u.hash, sizeof u.hash);
	if (memcmp(u.hash, calc_hash, sizeof calc_hash))
	{
		SBM_LOG_UPDATE_ERROR("footer hash mismatch\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_FOOTER_HASH);
	}

	/* Fetch and validate the signature stored in the SWUP footer. */
	swup_read(smd->length_of_swup + SWUP_OFFSET_FOOTER_SIGNATURE,
			  &u.sig, sizeof u.sig);

	const pd_slot_t ostks = oem_swup_key_slot(KEY_PURPOSE_OEM_TRANSPORTATION);
	if (ostks < 0)
	{
		SBM_LOG_UPDATE_ERROR("footer signature (OEM transportation) key not found\n");
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_VALIDATION_KEY);
	}

	r = datastore_verify(ostks, calc_hash, sizeof calc_hash, u.sig, sizeof u.sig);
	if (r)
	{
		SBM_LOG_UPDATE_ERROR("footer signature verification failed: %" PRId8 "\n", r);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_FOOTER_SIGNATURE);
	}
#endif

	return SWUP_STATUS_INITIAL;
}
/** Sanity check of the EUB clear details.
 * This involves validating the EUB clear header fields and computing a checksum
 * and hash of the individual EUB payloads. The checksum and hash are compared
 * with the corresponding values stored in the EUB clear details object.
 *
 * \pre update_slot != NULL
 * \pre smd != NULL
 * \pre max_offset < update_slot->size
 *
 * \param[in] update_slot The update slot containing the SWUP to validate.
 * \param[in] max_offset The offset of the last byte of the SWUP. This
 *                       should be set based on the length of the SWUP.
 *                       If the length is unknown, then this should be
 *                       set to update_slot->size - 1.
 * \param[in] smd Pointer to a `swup_metadata_t` structure where offsets to some
 *                key SWUP elements are held, including EUB offset.
 *
 * \return `SWUP_STATUS_INITIAL` on success, or a `SWUP_STATUS_ERROR_CODE`
 *         indicating the nature of any detected error.
 *
 * \note Safe to call via Secure API iff logging is disabled (see sbm_log_disable()).
 *
 * \note DO NOT be tempted to force the compiler to `inline` this function.
 *       The various SWUP validation routines have been broken up in such
 *       a way as to minimise stack usage. This aim will be defeated if
 *       the function is inlined, increasing the potential for the stack
 *       to overflow when servicing Secure API calls.
 */
#pragma inline=never
static unsigned int swup_validation_check_clear_eubs(const memory_slot *update_slot,
                                                     hal_mem_address_t max_offset,
                                                     const swup_metadata_t *smd)
{
	hal_mem_address_t eub_clear_next;
	hash_t calc_hash;
	uint16_t calc_sum;
	uint32_t payload_start;
	union {
		uint32_t payload_length;
		uint32_t val32;
		uint16_t val16;
		hash_t hash;
	} u;

	eub_clear_next = (hal_mem_address_t)smd->layout.eub_clear_details_start;

	/* The first EUB's payload should agree with where the SWUP header says it should be */

	swup_read(update_slot, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_PAYLOAD_START,
			  max_offset, &u.val32, sizeof u.val32);
	if ((uint32_t)smd->layout.first_eub_start != u.val32)
	{
		SBM_LOG_UPDATE_ERROR("SWUP header says EUB at 0x%" PRIx16 ", EUB details says 0x%" PRIx32 "\n",
				 smd->layout.first_eub_start, u.val32);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_START);
	}

	for (unsigned int eub_idx = 0U; eub_idx < (unsigned int)smd->num_eubs; eub_idx++)
	{
		/* Software update is the only EUB type supported at v1.0 */

		swup_read(update_slot, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_CONTENT,
				  max_offset, &u.val16, sizeof u.val16);
		if (u.val16 != EUB_CONTENT_SW_UPDATE)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u content 0x%" PRIx16 "\n", eub_idx, u.val16);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_CONTENT);
		}

		/* Master module is the only update type supported at v1.0 */

		swup_read(update_slot, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_PARAMETERS,
				  max_offset, &u.val16, sizeof u.val16);
		if (u.val16 != EUB_PARAM_MASTER_MODULE)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u parameters 0x%" PRIx16 "\n", eub_idx, u.val16);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_PARAMETERS);
		}

		swup_read(update_slot, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_CAPABILITY_FLAGS,
				  max_offset, &u.val32, sizeof u.val32);
#if SBM_SUPPORT_ENCRYPTED_UPDATES == 0
		if ((u.val32 & COMMON_CAP_ENC_MODE_MASK) != COMMON_CAP_ENC_MODE_NONE)
#else
		if ((u.val32 & COMMON_CAP_ENC_MODE_MASK) != COMMON_CAP_ENC_MODE_AES_GCM_128)
#endif /* SBM_SUPPORT_ENCRYPTED_UPDATES == 0 */
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u invalid EUB encryption mode: 0x%" PRIx32 "\n",
					 eub_idx, u.val32 & COMMON_CAP_ENC_MODE_MASK);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_CD_CAP);
		}

		if (u.val32 & COMMON_CAP_ADV_ENC_OPTIONS_MASK)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u invalid EUB advanced encryption options: 0x%" PRIx32 "\n",
					 eub_idx, u.val32 & COMMON_CAP_ADV_ENC_OPTIONS_MASK);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_CD_CAP);
		}

		if ((u.val32 & COMMON_CAP_CIPHER_LAYOUT_MASK) != COMMON_CAP_FIXED_CIPHER_FIELDS)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u invalid cipher fields: 0x%" PRIx32 "\n",
					 eub_idx, u.val32 & COMMON_CAP_CIPHER_LAYOUT_MASK);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_CD_CAP);
		}

		if ((u.val32 & COMMON_CAP_PU_MASK) != (COMMON_CAP_SINGLE_PU_SIG | COMMON_CAP_SINGLE_PU_HASH))
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u invalid cipher fields: 0x%" PRIx32 "\n",
					 eub_idx, u.val32 & COMMON_CAP_PU_MASK);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_CD_PU);
		}

		/* Last ditch test: any "reserved" bits should be zero */

		if (u.val32 & COMMON_CAP_RESERVED)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u capability_flags 0x%" PRIx32 "\n",
					 eub_idx, u.val32);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_RESERVED);
		}

		/* Make sure the EUB doesn't need anything not identified in the SWUP header */

		if ((smd->eub_capability_flags & u.val32) != u.val32)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u capability_flags 0x%" PRIx32 " but SWUP header says 0x%" PRIx32 "\n",
					 eub_idx, u.val32, smd->eub_capability_flags);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_SWUP_EUB_CAP);
		}

		/* Verify the hardware SKU has the expected value. */

		swup_read(update_slot, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_HW_SKU,
				  max_offset, &u.val32, sizeof u.val32);
		if (u.val32 != SUPPORTED_HW_SKU)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u bogus hw_sku 0x%" PRIx32 "\n", eub_idx, u.val32);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_SKU);
		}

		/* Fetch start address of this EUB's payload. */
		swup_read(update_slot, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_PAYLOAD_START,
				  max_offset, &payload_start, sizeof payload_start);

		if (payload_start < (uint32_t)smd->layout.first_eub_start || payload_start >= smd->length_of_swup)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u bogus payload_start 0x%" PRIx32 "\n", eub_idx, payload_start);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_PAYLOAD);
		}

		if (payload_start & 3U)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u payload_start misaligned 0x%" PRIx32 "\n", eub_idx, payload_start);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_PAYLOAD);
		}

		/* The EUB must be big enough to hold a module header and footer
		   but not so big that it won't fit into the executable slot
		   (after we allow for the header being copied elsewhere) */

		swup_read(update_slot, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_PAYLOAD_LENGTH,
				  max_offset, &u.payload_length, sizeof u.payload_length);

		if (u.payload_length < sizeof(pie_module_t) + sizeof(pie_module_footer_t) ||
			u.payload_length - sizeof(pie_module_t) > exec_slot.size)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u bogus payload_length 0x%" PRIx32 "\n", eub_idx, u.payload_length);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_PAYLOAD_LEN);
		}

		if (u.payload_length & 3U)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u payload_length misaligned 0x%" PRIx32 "\n", eub_idx, u.payload_length);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_PAYLOAD_LEN);
		}

		/* Compute checksum and hash of the EUB payload. */
		if (!swup_checksum_and_hash(update_slot, payload_start, (size_t)u.payload_length,
									&calc_sum, &calc_hash))
		{
			SBM_LOG_UPDATE_ERROR("failed to checksum/hash header\n");
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_FAILED_EUB_HASH);
		}

		swup_read(update_slot, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_CHECKSUM,
				  max_offset, &u.val16, sizeof u.val16);
		if (calc_sum != u.val16)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u checksum calculated 0x%" PRIx16 " expected 0x%" PRIx16 "\n",
					 eub_idx, calc_sum, u.val16);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_CHECKSUM);
		}

		swup_read(update_slot, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_HASH,
				  max_offset, &u.hash, sizeof u.hash);
		if (memcmp(u.hash, calc_hash, sizeof calc_hash))
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u hash mismatch\n", eub_idx);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_HASH);
		}

		/* Check the optional elements. These HAVE to be intact as we cannot find
		   the start of any subsequent EUB details without finding the TLV terminator.

		   As there's an installable module in this EUB,
		   there must be at least a version number in here. */

		if ((eub_clear_next + SWUP_OFFSET_EUB_CLEAR_OPTIONAL_ELEMENTS) & 3U)
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u optional elements misaligned: 0x%" PRIxMEM_ADDR "\n",
			                     eub_idx, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_OPTIONAL_ELEMENTS);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_OE_ALIGNMENT);
		}

		hal_mem_address_t field_address;
		if (!swup_tlv_find_node(update_slot, max_offset, eub_clear_next + SWUP_OFFSET_EUB_CLEAR_OPTIONAL_ELEMENTS, 0,
								OE_TAG_VERSION_NUMBER, &field_address, &u.val16))
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u has no version number\n", eub_idx);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_MISSING_EUB_VERSION);
		}

		/* It must hold a 32-bit word */

		if ((size_t)u.val16 != sizeof(uint32_t))
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u version number has wrong size: 0x%" PRIx16 "\n", eub_idx, u.val16);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_VERSION_SIZE);
		}

		/* When we pull out the whole word, the top byte must be our supported version size */

		swup_read(update_slot, field_address, max_offset, &u.val32, sizeof u.val32);
		if ((u.val32 & 0xFF000000U) != (SUPPORTED_VERSION_SIZE << 24U))
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u has malformed version number: 0x%" PRIx32 "\n", eub_idx, u.val32);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_MALFORMED_EUB_VERSION);
		}

		/* Crank the address to the next EUB.
		   There must be an end marker or we cannot find the next EUB details.
		   Wherever we think the "value" of the end marker would be is the right place. */

		if (!swup_tlv_find_node(update_slot, max_offset, field_address + sizeof(uint32_t), 0,
								TLV_END_MARKER, &field_address, NULL))
		{
			SBM_LOG_UPDATE_ERROR("EUB CD %u has no end marker\n", eub_idx);
			return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_EUB_MISSING_END_MARKER);
		}

		eub_clear_next = field_address;
	}

	/* When we get to here, we should have landed on the encrypted
	   details (if there are any) or the epilogue (if there aren't) */

	u.val32 = smd->layout.eub_encrypted_details_start ?
		(uint32_t)smd->layout.eub_encrypted_details_start :
		(uint32_t)smd->layout.epilogue_start;

	if (eub_clear_next != (hal_mem_address_t)u.val32)
	{
		SBM_LOG_UPDATE_ERROR("End of EUB clear details at 0x%" PRIxMEM_ADDR " but should be at 0x%" PRIx32 "\n",
		                     eub_clear_next, u.val32);
		return SWUP_STATUS_ERROR_CODE(SWUP_STATUS_ERROR_BAD_EUB_END);
	}

	/* All is good. */

	return SWUP_STATUS_INITIAL;
}

unsigned int sbm_update_slot_contains_swup(const memory_slot *update_slot, hal_mem_address_t *max_offset, uint8_t *const key_instance)
{
	swup_metadata_t smd;
	unsigned int rv;

#if SBM_ENABLE_LOG_UPDATE_STATUS != 0 && SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO
	if (update_slot)
	{
		SBM_LOG_UPDATE_INFO("looking for an application image in update slot \"%s\"\n",
		                    update_slot->name);
	}
#endif /* SBM_ENABLE_LOG_UPDATE_STATUS != 0 && SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO */

	const memory_device *device = get_device_from_slot(update_slot);

	if (device->removable && !hal_mem_device_present(device))
	{
		SBM_LOG_UPDATE_INFO("The device \"%s\" containing update slot \"%s\" is not connected\n",
		                    device->name,
		                    update_slot->name);
		return SWUP_STATUS_ERROR;
	}

	rv = swup_validation_simple_checks(update_slot, max_offset, &smd, key_instance);
	if (rv != SWUP_STATUS_INITIAL)
		return rv;

	rv = swup_validation_check_header(update_slot, *max_offset, &smd);
	if (rv != SWUP_STATUS_INITIAL)
		return rv;

	return swup_validation_check_clear_eubs(update_slot, *max_offset, &smd);
}
