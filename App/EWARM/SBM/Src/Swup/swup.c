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
 * \brief Various SWUP manglement typedefs, macros and function definitions.
 */

#include "swup.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "swup_sbm_update_slot_contains_swup.h"
#include "swup_uuid.h"
#include "swup_layout.h"
#include "swup_capability_defines.h"
#include "swup_supported_defines.h"
#include "swup_header_magic.h"
#include "swup_eub.h"
#include "swup_read.h"
#include "swup_optional_element.h"
#include "swup_public_key.h"
#include "swup_tlv.h"
#include "swup_oem.h"
#include "swup_muh.h"
#include "dataStore.h"
#include "ecc.h"
#include "ecies_crypto.h"
#include "memoryMap.h"
#include "memory_devices_and_slots.h"
#include "oem.h"
#include "sbm_api.h"
#include "sbm_memory.h"
#include "sbm_hal.h"
#include "sbm_hal_mem.h"
#include "secureApiData.h"
#include "sha256_wrapper.h"
#include "sbm_log_update_status.h"

#define PIEM_EXPECTED_STATUS 0x5555AAAA /**< Expected value of pie_module_t.module_status. */

/* Permanently installed executable module field presence masks. */
/* Advance warning: these will be deprecated soon. */
#define PIEM_FIELD_HASH        1U /**< Payload hash is present. */
#define PIEM_FIELD_SIGNATURE   2U /**< Payload signature is present. */
#define PIEM_FIELD_CHECKSUM    4U /**< Payload checksum is present. */
#define PIEM_FIELD_RESERVED 0xF8U /**< Reserved bits should be zero. */

#define EXPECTED_IAVVCS_CAPABILITY UINT16_C(0x55AA) /**< Value expected in pie_module_sbm_exec_info_t.capability_indicator. */

/* Installed module capability flags and masks ... */
#define IAVVCS_CAP_MUF_SUPPLIED UINT16_C(1) /**< Bit 0: MUF supplied. */
#define IAVVCS_CAP_RESERVED_MASK UINT16_C(0xFFFE) /**< Reserved: must be all zero bits. */

/* Possible values of SBM_BOOT_INTEGRITY_CHECKING delivered by Security Manager ... */

#define SBM_BOOT_INTEGRITY_NONE 0 /**< Not supported. */
#define SBM_BOOT_INTEGRITY_CHECKSUM 1 /**< Verify checksum. */
#define SBM_BOOT_INTEGRITY_CRC 2 /* Not yet supported. */
#define SBM_BOOT_INTEGRITY_MAC 3 /* Not yet supported. */
#define SBM_BOOT_INTEGRITY_HASH 4 /**< Verify hash. */
#define SBM_BOOT_INTEGRITY_SIGNATURE 5 /**< Verify hash and signature. */

/* If this is not (pre-)defined use a wise default ... */

#ifndef SBM_BOOT_INTEGRITY_CHECKING
#define SBM_BOOT_INTEGRITY_CHECKING SBM_BOOT_INTEGRITY_SIGNATURE
#endif /* ifndef SBM_BOOT_INTEGRITY_CHECKING */

/* Police for unsupported options ... */

#if SBM_BOOT_INTEGRITY_CHECKING == SBM_BOOT_INTEGRITY_NONE || \
    SBM_BOOT_INTEGRITY_CHECKING == SBM_BOOT_INTEGRITY_CRC || \
    SBM_BOOT_INTEGRITY_CHECKING == SBM_BOOT_INTEGRITY_MAC
#error Boot integrity checking must be Checksum, Hash or Hash and signature
#endif

/** Find the module footer given the address of the corresponding PIE module.
 *
 * The supplied module header can be located in the MUH (in which case
 * the image is in the executable slot), or not (in which case the image
 * is assumed to follow the header).
 *
 * \param[in] pie_module Address of PIE module.
 * \param[out] footer Address of pointer to footer.
 *
 * \return `true` if the footer offset present in the module header is valid or `false` otherwise.
 * \note When \b true is returned, \a *footer is populated with the address of the footer.
 */
static bool find_footer_from_pie_module(const pie_module_t *const pie_module, const pie_module_footer_t **const footer)
{
	const uint32_t pie_module_footer_offset = pie_module->header.footer_offset;

	if (pie_module_footer_offset < offsetof(pie_module_t, image))
	{
		return false;
	}

	const uintptr_t pie_module_addr = (uintptr_t) pie_module;

	if (pie_module_addr == app_status_slot.start_address)
	{
		/* We're looking at an IAVVCS. Once the MUF has been
		   copied into the IAVVCS, the MUH's footer_offset no
		   longer tells us where it (the MUF) is.
		   The copy is in the header's sbm_exec_info ... */

		const pie_module_sbm_exec_info_t *const sei = (const pie_module_sbm_exec_info_t *) pie_module->header.sbm_exec_info;
		*footer = &sei->installed_muf;

		return true;
	}

	*footer = (pie_module_footer_t *) (pie_module_addr + pie_module_footer_offset);

	return true;
}

/* We have prior knowledge that this is the size
   of the module header at the start of the EUB */
#define EUB_MODULE_HEADER_SIZE 1024U
#define MAX_DECRYPT_SIZE EUB_MODULE_HEADER_SIZE
static_assert(sizeof(pie_module_t) <= MAX_DECRYPT_SIZE, "pie_module_t size > MAX_DECRYPT_SIZE");

/* The plain eub buffer is placed in the ephemeral RAM section because it
   is not referenced once the application is started and will be effaced
   beforehand anyway. */
static uint8_t plain_eub_buffer[MAX_DECRYPT_SIZE] SBM_EPHEMERAL_RAM;
static uint8_t plain_iavvcs_buffer[MAX_DECRYPT_SIZE] SBM_EPHEMERAL_RAM;

/** Establish the status of the module within the executable slot using
 * the specified PIEM.
 *
 * \note This function ignores the content of the MUH slot; it uses the
 * caller-provided PIEM instead.
 *
 * \pre piem != NULL
 *
 * \param[in] The PIEM to verify the executable slot with. This is assumed to be
 *            an IAVVCS, i.e. with the MUF written to the piem->sbm_exec_info area.
 * \return \b true if the module is good, \b false otherwise.
 *
 * \note Called during boot process and from a secure API context.<br>
 * When called from a secure API context, logging must be disabled (see sbm_log_disable()).
 */
static bool sbm_executable_slot_module_valid_with_iavvcs(const pie_module_t *const piem)
{
	assert(piem != NULL);

	if (piem->header.module_status != PIEM_EXPECTED_STATUS)
	{
		SBM_LOG_UPDATE_INFO("module_status 0x%" PRIx32 "\n", piem->header.module_status);
		return false;
	}

	/* The PIEMF is assumed to be already installed in the PIEM */
	const pie_module_sbm_exec_info_t *const sei   = (const pie_module_sbm_exec_info_t *)piem->header.sbm_exec_info;
	const pie_module_footer_t        *const piemf = &sei->installed_muf;

	if (INVALID_RANDOM(piem->header.header_random))
	{
		SBM_LOG_UPDATE_INFO("bogus header random 0x%" PRIx32 "\n", piem->header.header_random);
		return false;
	}

	if (piem->header.field_presence & PIEM_FIELD_RESERVED)
	{
		SBM_LOG_UPDATE_INFO("field presence 0x%" PRIx8 "\n", piem->header.field_presence);
		return false;
	}

	if (piem->header.num_signatures != 1U)
	{
		SBM_LOG_UPDATE_INFO("bogus num signatures 0x%" PRIx8 "\n",
				 piem->header.num_signatures);
		return false;
	}

	if (piem->header.footer_length != sizeof(pie_module_footer_t))
	{
		SBM_LOG_UPDATE_INFO("footer length 0x%" PRIx16 " expected 0x%x\n",
				 piem->header.footer_length, (unsigned int)sizeof(pie_module_footer_t));
		return false;
	}

	if (piem->header.header_random != piemf->footer_random)
	{
		SBM_LOG_UPDATE_INFO("footer random 0x%" PRIx32 " expected 0x%" PRIx32 "\n",
				 piemf->footer_random, piem->header.header_random);
		return false;
	}

	/* Sanity check of the installed UUID. */
	if (!swup_uuid_valid(sei->installed_uuid))
	{
		SBM_LOG_UPDATE_INFO("installed UUID is invalid\n");
		return false;
	}

	/* Do we have an IAVVCS or do we have and old style MUH? ... */

	if (sei->iavvcs_capability_indicator != EXPECTED_IAVVCS_CAPABILITY ||
		(sei->iavvcs_capability_flags & IAVVCS_CAP_RESERVED_MASK) ||
		!(sei->iavvcs_capability_flags & IAVVCS_CAP_MUF_SUPPLIED))
	{
		SBM_LOG_UPDATE_INFO("IAVVCS capability indicator/flags: 0x%" PRIx16 "/0x%" PRIx16 "\n",
				 sei->iavvcs_capability_indicator, sei->iavvcs_capability_flags);
		return false;
	}

#if SBM_BOOT_INTEGRITY_CHECKING > SBM_BOOT_INTEGRITY_NONE
	/* We must copy the PIEM from the MUH into a local buffer and zero the rest
	   of the buffer (to nobble the fabricated pie_module_sbm_exec_info_t
	   and anything following it) before calculating the checksum and hash.
	   This is to re-create the condition of the header when it was in a SWUP
	   so that the checksum and hash will be calculated as expected. */

	pie_module_t *const checked_piem = (pie_module_t *) plain_eub_buffer;
	checked_piem->header = piem->header;
	memset(checked_piem->header.sbm_exec_info, 0, sizeof plain_eub_buffer - sizeof piem->header);

#if SBM_BOOT_INTEGRITY_CHECKING == SBM_BOOT_INTEGRITY_CHECKSUM
	uint16_t lcs = swup_checksum(0, checked_piem, sizeof *checked_piem);
	lcs = swup_checksum(lcs, (void *) exec_slot.start_address, piem->header.footer_offset - sizeof *piem);
	/* This section only spans the version number but this
	   way of calculating the size is more general (i.e. future
	   proof) than sizeof *piemf->version_number ... */
	lcs = swup_checksum(lcs, piemf, (const uint8_t *) piemf->block_hash - (const uint8_t *) piemf);
	if (lcs != piemf->block_cs)
	{
		SBM_LOG_UPDATE_INFO("module footer checksum calculated 0x%" PRIx16 " expected 0x%" PRIx16 "\n",
				 lcs, piemf->block_cs);
		return false;
	}
#endif /* SBM_BOOT_INTEGRITY_CHECKING == SBM_BOOT_INTEGRITY_CHECKSUM */

#if SBM_BOOT_INTEGRITY_CHECKING >= SBM_BOOT_INTEGRITY_HASH
	const sha256_hash_chunk_t h_chunks[] = {
		{
			.data = checked_piem,
			.length = sizeof *checked_piem
		},
		{
			.data = (const void *) exec_slot.start_address,
			.length = piem->header.footer_offset - sizeof *piem
		},
		{
			.data = piemf,
			.length = (const uint8_t *) &piemf->block_hash[0] - (const uint8_t *) piemf
		}
	};

	hash_t h;
	if (!sha256_calc_hash_chunked(h_chunks, sizeof h_chunks / sizeof h_chunks[0], h))
	{
		SBM_LOG_UPDATE_INFO("module block hash calculation failed\n");
		return false;
	}
	if (memcmp(&piemf->block_hash[0], h, sizeof h))
	{
		SBM_LOG_UPDATE_INFO("module block hash mismatch\n");
		return false;
	}

#if SBM_BOOT_INTEGRITY_CHECKING == SBM_BOOT_INTEGRITY_SIGNATURE
	const pd_slot_t osvks = oem_swup_key_slot(KEY_PURPOSE_PU_VALIDATION);
	if (osvks < 0)
	{
		SBM_LOG_UPDATE_INFO("module block signature (OEM validation) key not found: %" PRId8 "\n", osvks);
		return false;
	}

	const int8_t r = datastore_verify(osvks, h, sizeof h,
									  piemf->block_sig, sizeof piemf->block_sig);
	if (r)
	{
		SBM_LOG_UPDATE_INFO("module block signature verification failed: %" PRId8 "\n", r);
		return false;
	}
#endif /* SBM_BOOT_INTEGRITY_CHECKING == SBM_BOOT_INTEGRITY_SIGNATURE */
#endif /* SBM_BOOT_INTEGRITY_CHECKING >= SBM_BOOT_INTEGRITY_HASH */
#endif /* SBM_BOOT_INTEGRITY_CHECKING >= SBM_BOOT_INTEGRITY_CHECKSUM */

	return true;
}

bool sbm_executable_slot_module_valid(void)
{
#if MUH_READ_USE_FLASH_DRIVER
	if (!SWUP_READ_MUH())
	{
		return false;
	}
#endif

	return sbm_executable_slot_module_valid_with_iavvcs(PIEM);
}

#if SBM_SUPPORT_ENCRYPTED_UPDATES != 0
/** Find address of private device update key.
 *
 * Find the private part of the device update key and yield its address.
 *
 * \param instance Instance number of required key.
 * \param[out] private_key Address of pointer to private key.
 *
 * \return \b true on sucess, \b false otherwise.
 * \note When \b true is returned, \a *private_key is populated with the address of the key.
 */
static bool find_private_update_key(const uint8_t instance, const private_key_t **private_key)
{
	/* Find the device update key slot */

	const pd_slot_t duks = find_update_key_slot(instance, KEY_CATEGORY_PRIVATE);
	if (duks < 0)
		return false;

	/* Extract the address of the private key */

	const int8_t dupk = datastore_private_key(duks, private_key);
	if (dupk)
	{
		SBM_LOG_UPDATE_ERROR("device update private key not found in slot 0x%" PRIx8
				   ": 0x%" PRIx8 "\n", duks, dupk);
		return false;
	}

	return true;
}
#endif /* SBM_SUPPORT_ENCRYPTED_UPDATES != 0 */

uint32_t sbm_swup_piem_version(void)
{
	const pie_module_t *const piem = (const pie_module_t *) app_status_slot.start_address;

	const pie_module_footer_t *piemf = NULL;
	const bool footer_found = find_footer_from_pie_module(piem, &piemf);
	(void) footer_found;
	assert(footer_found == true);
	assert(piemf != NULL);

	return piemf->version_number;
}

uint32_t sbm_swup_eub_version(const memory_slot *update_slot)
{
	hal_mem_address_t version_address;
	uint16_t eub_clear_start, version_len;
	uint32_t version;
	const size_t max_offset = update_slot->size - 1;

	swup_read(update_slot, SWUP_OFFSET_HEADER_EUB_CLEAR_START,
			  max_offset, &eub_clear_start, sizeof eub_clear_start);
	if ((hal_mem_address_t)eub_clear_start >= max_offset)
		return 0u;

	if (!swup_tlv_find_node(update_slot, max_offset, eub_clear_start + SWUP_OFFSET_EUB_CLEAR_OPTIONAL_ELEMENTS, 0,
							OE_TAG_VERSION_NUMBER, &version_address, &version_len))
	{
		return 0u;
	}

	if (version_len != sizeof(version))
		return 0u;

	swup_read(update_slot, version_address, max_offset, &version, sizeof version);

	return version;
}

#if SBM_VERSION_CHECKING > 0
#if (SBM_VERSION_CHECKING == 1)
/* Version number: WITHIN_MIN */
#error "WITHIN_MIN version checking not yet supported"
#elif (SBM_VERSION_CHECKING == 2)
/* Version number: GTR_EQU */
#define	SBM_VERSION_ROLLBACK(update,current)	(!((update) >= (current)))
#elif (SBM_VERSION_CHECKING == 3)
/* Version number: GTR */
#define	SBM_VERSION_ROLLBACK(update,current)	(!((update) > (current)))
#else
#error "Unsupported value for SBM_VERSION_CHECKING"
#endif /* (SBM_VERSION_CHECKING == ...) */
#endif /* SBM_VERSION_CHECKING > 0 */

bool sbm_swup_update_version_rollback(const memory_slot *update_slot)
{
#if SBM_VERSION_CHECKING > 0
	return SBM_VERSION_ROLLBACK(sbm_swup_eub_version(update_slot), sbm_swup_piem_version());
#else
	/* No version checking configured. */
	return false;
#endif /* SBM_VERSION_CHECKING > 0 */
}

unsigned int sbm_swup_install_module(const memory_slot *update_slot, hal_mem_address_t max_offset, const uint8_t key_instance)
{
	swup_layout_t layout;
	uint32_t val32;
	uint16_t num_eubs;
	hal_mem_result_t mem_result;

	swup_read(update_slot, SWUP_OFFSET_HEADER_EUB_CLEAR_START, max_offset, &layout, sizeof layout);
	swup_read(update_slot, SWUP_OFFSET_HEADER_NUM_EUBS, max_offset, &num_eubs, sizeof num_eubs);

#if SBM_SUPPORT_ENCRYPTED_UPDATES != 0
	/* Find the slot containing the key to decrypt the EUB encrypted details.
	   Note: at the moment we're assuming the EUB is encrypted. */
	const pd_slot_t osvks = oem_swup_key_slot(KEY_PURPOSE_OEM_VALIDATION);
	if (osvks < 0)
	{
		SBM_LOG_UPDATE_ERROR("OEM validation key not found\n");
		return SWUP_INSTALL_STATUS_FAILURE;
	}

	/* Find the slot containing the private key to decrypt the EUB encrypted details */

	const private_key_t *private_key;
	if (!find_private_update_key(key_instance, &private_key))
	{
		SBM_LOG_UPDATE_ERROR("Failed to find private update key\n");
		return SWUP_INSTALL_STATUS_FAILURE;
	}
	/* Locate the AES/GCM header with which to decrypt the EUB encrypted details */

	swup_read(update_slot, SWUP_OFFSET_HEADER_SWUP_CAPABILITY_FLAGS, max_offset, &val32, sizeof val32);
	const hal_mem_address_t swup_oe = swup_first_oe(SWUP_UPDATE_STATUS_RECORDS(val32));
	const size_t swup_oe_size = ((size_t)layout.eub_clear_details_start) - swup_oe;
	hal_mem_address_t aes_gcm_offset;
	if (!swup_tlv_find_node(update_slot, max_offset, swup_oe, swup_oe_size, OE_TAG_AES_GCM_HEADER, &aes_gcm_offset, NULL))
	{
		SBM_LOG_UPDATE_ERROR("has no AES-GCM header\n");
		return SWUP_INSTALL_STATUS_FAILURE;
	}

	/* We have its location, so read the header. */
	aes_gcm_header_t aes_gcm_header;
	swup_read(update_slot, aes_gcm_offset, max_offset, &aes_gcm_header, sizeof aes_gcm_header);

	/* Encrypted and plain text are the same size */
	const size_t eubed_size = (size_t)(layout.epilogue_start - layout.eub_encrypted_details_start);
	if (eubed_size > MAX_DECRYPT_SIZE)
	{
		SBM_LOG_UPDATE_ERROR("EUB encrypted details too large: 0x%" PRIxSIZET "\n", eubed_size);
		return SWUP_INSTALL_STATUS_FAILURE;
	}

	/* Decrypt the EUB encrypted details */

	if (!ecies_init())
	{
		SBM_LOG_UPDATE_ERROR("ecies_init() failed\n");
		return SWUP_INSTALL_STATUS_FAILURE;
	}

	/* The crypto buffers are placed in the ephemeral RAM section because
	   they are not referenced once the application is started and will be
	   effaced beforehand anyway. */
	static uint8_t cipher_text_buffer[MAX_DECRYPT_SIZE] SBM_EPHEMERAL_RAM;
	static uint8_t plain_seer_buffer[MAX_DECRYPT_SIZE] SBM_EPHEMERAL_RAM;

	/* Read the Encryption Record cipher text. */
	swup_read(update_slot, (hal_mem_address_t)layout.eub_encrypted_details_start,
			  max_offset, cipher_text_buffer, sizeof cipher_text_buffer);

	if (!ecies_decrypt(cipher_text_buffer, eubed_size,
					   private_key, &aes_gcm_header.key,
					   NULL, 0U, /* Not using AAD */
					   &aes_gcm_header.tag, plain_seer_buffer))
	{
		SBM_LOG_UPDATE_ERROR("EUB encrypted details decrypt failed\n");
		return SWUP_INSTALL_STATUS_FAILURE;
	}

	/* Check signature */

	hash_t h;
	if (!sha256_calc_hash(plain_seer_buffer, eubed_size - sizeof(sig_t), h))
	{
		SBM_LOG_UPDATE_ERROR("EUB encrypted details hash calculation failed\n");
		return SWUP_INSTALL_STATUS_FAILURE;
	}

	const sig_t *const sig = (const sig_t *) (plain_seer_buffer + eubed_size - sizeof *sig);
	const int8_t r = datastore_verify(osvks, h, sizeof h, (const uint8_t *) sig, sizeof *sig);
	if (r)
	{
		SBM_LOG_UPDATE_ERROR("EUB encrypted details signature verification failed: %" PRId8 "\n", r);
		return SWUP_INSTALL_STATUS_FAILURE;
	}

	/* We'll need to walk the encryption records when we have more than one encrypted EUB */

	const seer_aes_gcm_128_t *const seer = (const seer_aes_gcm_128_t *) plain_seer_buffer;
#endif /* SBM_SUPPORT_ENCRYPTED_UPDATES != 0 */

	/* Count the number of EUBs that have been verified by sbm_executable_slot_module_valid_with_iavvcs() */
	uint16_t num_verified_eubs = 0u;

	/* Find EUBs (possibly decrypting them) and, block by block, write them into flash */

	for (unsigned int i = 0U; i < num_eubs; ++i)
	{
		/* Note that we currently support just a single EUB (this is enforced
		   when checking the SWUP validity). The following code contains
		   hard-coded assumptions to this effect. When we do support more than
		   one EUB, we'll need to find the right set of details based on the
		   EUB index. */

		swup_read(update_slot, layout.eub_clear_details_start + SWUP_OFFSET_EUB_CLEAR_PAYLOAD_START,
		          max_offset, &val32, sizeof val32);
		hal_mem_address_t payload_start = (hal_mem_address_t)val32;

		/* Read the total length (header, binary and footer) of the EUB ... */
		swup_read(update_slot, layout.eub_clear_details_start + SWUP_OFFSET_EUB_CLEAR_PAYLOAD_LENGTH,
		          max_offset, &val32, sizeof val32);
		size_t payload_length = (size_t)val32;

		/* Find the length of the binary and footer which will be copied to the executable slot ... */
		const size_t exec_length = payload_length - EUB_MODULE_HEADER_SIZE;

		if (payload_length < EUB_MODULE_HEADER_SIZE || exec_length > exec_slot.size)
		{
			SBM_LOG_UPDATE_ERROR("EUB %u abnormal EUB payload length: 0x%" PRIx32 "\n", i,
					   (uint32_t) payload_length);
			return SWUP_INSTALL_STATUS_FAILURE;
		}

		/* Clear the MUH/IAVVCS ... */
		mem_result = hal_mem_erase(&app_status_slot, 0, EUB_MODULE_HEADER_SIZE);
		if (HAL_MEM_SUCCESS != mem_result)
		{
			SBM_LOG_UPDATE_ERROR("Failed to erase MUH (%u bytes), result: %d\n",
			                     EUB_MODULE_HEADER_SIZE,
			                     (int)mem_result);
			return SWUP_INSTALL_STATUS_BRICKED;
		}
		/* Clear enough of the executable slot to recieve the binary and footer ... */
		mem_result = hal_mem_erase(&exec_slot, 0, exec_length);
		if (HAL_MEM_SUCCESS != mem_result)
		{
			SBM_LOG_UPDATE_ERROR("Failed to erase EXEC at 0x%" PRIxPTR " (%u bytes), result: %d\n",
			                     exec_slot.start_address,
			                     (unsigned int)exec_length,
			                     (int)mem_result);
			return SWUP_INSTALL_STATUS_BRICKED;
		}
#if MUH_READ_USE_FLASH_DRIVER
		/* Invalidate our safe-read caches */
		sbm_purge_cached_muh();
#endif

		/* Deal with this EUB */

		uintptr_t exec_slot_offset = 0;

#if SBM_SUPPORT_ENCRYPTED_UPDATES != 0
		void *const decrypt_ctx = aes_gcm_chunked_init(&seer->key, &seer->iv,
													   NULL, 0U); /* Not using AAD */
		if (!decrypt_ctx)
		{
			SBM_LOG_UPDATE_ERROR("EUB %u aes_gcm_chunked_init() failed\n", i);
			return SWUP_INSTALL_STATUS_BRICKED;
		}
#endif /* SBM_SUPPORT_ENCRYPTED_UPDATES */

		pie_module_t *const iavvcs = (pie_module_t *) plain_iavvcs_buffer;

		/* Split the EUB payload into manageable chunks. */

		for (unsigned int block_no = 0U; payload_length; ++block_no)
		{
			size_t block_size = payload_length;
			if (block_size > MAX_DECRYPT_SIZE)
				block_size = MAX_DECRYPT_SIZE;

#if SBM_SUPPORT_ENCRYPTED_UPDATES != 0
			swup_read(update_slot, payload_start, max_offset, cipher_text_buffer, block_size);

			if (!aes_gcm_chunked_decrypt(decrypt_ctx, cipher_text_buffer,
				block_size, plain_eub_buffer))
			{
				aes_gcm_chunked_done(decrypt_ctx, NULL);
				SBM_LOG_UPDATE_ERROR("EUB %u aes_gcm_chunked_decrypt() failed\n", i);
				return SWUP_INSTALL_STATUS_BRICKED;
			}

#else /* SBM_SUPPORT_ENCRYPTED_UPDATES == 0 */
			swup_read(update_slot, payload_start, max_offset, plain_eub_buffer, block_size);
#endif /* SBM_SUPPORT_ENCRYPTED_UPDATES == 0 */

			/* The EUB contains 2 parts, a header and the executable code. */

			if (0U == block_no)
			{
				/* The first block contains the module update header and ought to be 1K long.
				   This was policed earlier. */

				/* Copy the update MUH into the IAVVCS ... */
				const pie_module_t *const piem = (const pie_module_t *) plain_eub_buffer;
				iavvcs->header = piem->header;
			}
			else
			{
				/* Everything else goes where you expect */

				mem_result = sbm_copy_to_flash(&exec_slot, exec_slot_offset, plain_eub_buffer, block_size);
				if (HAL_MEM_SUCCESS != mem_result)
				{
#if SBM_SUPPORT_ENCRYPTED_UPDATES != 0
					aes_gcm_chunked_done(decrypt_ctx, NULL);
#endif /* SBM_SUPPORT_ENCRYPTED_UPDATES != 0 */
					SBM_LOG_UPDATE_ERROR("EUB %u block 0x%x copy to flash failed with result: %d\n",
					           i, block_no, (int)mem_result);
					return SWUP_INSTALL_STATUS_BRICKED;
				}

				exec_slot_offset += block_size; /* Fill up the flash. */
			}

			payload_start += block_size; /* Address the next chunk of EUB. */
			payload_length -= block_size; /* How much we still need to do. */
		}

		/* Finish off the decryption */

#if SBM_SUPPORT_ENCRYPTED_UPDATES != 0
		AesTag tag;
		if (!aes_gcm_chunked_done(decrypt_ctx, &tag))
		{
			SBM_LOG_UPDATE_ERROR("EUB %u aes_gcm_chunked_done() failed\n", i);
			return SWUP_INSTALL_STATUS_BRICKED;
		}

		/* Validate the tag against the one in the encryption record */

		if (memcmp(tag, seer->tag, sizeof tag))
		{
			SBM_LOG_UPDATE_ERROR("EUB %u aes_gcm_chunked_done() tag mismatch\n", i);
			return SWUP_INSTALL_STATUS_BRICKED;
		}
#endif /* SBM_SUPPORT_ENCRYPTED_UPDATES != 0 */

		/* Finish populating the IAVVCS */

		pie_module_sbm_exec_info_t *const sei = (pie_module_sbm_exec_info_t *) iavvcs->header.sbm_exec_info;

		/* Read the UUID from the SWUP header */
		swup_read(update_slot, SWUP_OFFSET_HEADER_UPDATE_UUID,
				  max_offset, sei->installed_uuid, sizeof sei->installed_uuid);

		sei->iavvcs_capability_indicator = EXPECTED_IAVVCS_CAPABILITY;
		sei->iavvcs_capability_flags = IAVVCS_CAP_MUF_SUPPLIED;

		/* Make a copy of the MUF from the freshly decrypted executable slot ... */
		sei->installed_muf = *((pie_module_footer_t *) (exec_slot.start_address - sizeof(pie_module_t) + iavvcs->header.footer_offset));

#if SBM_SUPPORT_ENCRYPTED_UPDATES == 0
		const memory_device *device = get_device_from_slot(update_slot);
		if ((device != NULL) && device->removable)
		{
			if (sbm_executable_slot_module_valid_with_iavvcs(iavvcs))
			{
				num_verified_eubs++;
			}
			else
			{
				return SWUP_INSTALL_STATUS_BRICKED;
			}
		}
#endif /* SBM_SUPPORT_ENCRYPTED_UPDATES == 0 */

		/* Copy the IAVVCS into the MUH slot in the flash ... */
		if (HAL_MEM_SUCCESS != sbm_copy_to_flash(&app_status_slot,
		                                         0,
		                                         plain_iavvcs_buffer,
		                                         sizeof iavvcs->header + sizeof *sei))
		{
			SBM_LOG_UPDATE_ERROR("IAVVCS copy to flash failed\n");
			return SWUP_INSTALL_STATUS_BRICKED;
		}

		/* Check that the installed version number matches
		   that in the EUB details from the SWUP header */

		if (sbm_swup_piem_version() != sbm_swup_eub_version(update_slot))
		{
			SBM_LOG_UPDATE_ERROR("EUB %u version 0x%" PRIx32 " but installed module version number is 0x%" PRIx32 "\n",
			                     i, sbm_swup_piem_version(), sbm_swup_eub_version(update_slot));
		}
	}

	if (num_verified_eubs == num_eubs)
	{
		/* All installed EUBs have been verified by sbm_executable_slot_module_valid() */
		return SWUP_INSTALL_STATUS_SUCCESS_VERIFIED;
	}
	else
	{
		/* At least one EUB was not verified during installation. */
		return SWUP_INSTALL_STATUS_SUCCESS;
	}
}

/* We preserve the status of the update here
   so it can be collected by getUpdateInfo() */

static unsigned int sbm_swup_last_status SBM_PERSISTENT_RAM;

void sbm_swup_set_last_status(const unsigned int status)
{
	sbm_swup_last_status = status;
}

unsigned int sbm_swup_get_last_status(void)
{
	return sbm_swup_last_status;
}

void sbm_swup_get_last_installed_uuid(uuid_t uuid)
{
	/* This is only called from the secure API, when the application has already been
	 * loaded and muh_buf read, if used.
	 */
	const pie_module_sbm_exec_info_t *sei = (const pie_module_sbm_exec_info_t *)PIEM->header.sbm_exec_info;

	memcpy(uuid, sei->installed_uuid, sizeof(uuid_t));
}

bool sbm_swup_can_install_update(const memory_slot *update_slot)
{
	if (NULL == update_slot)
		return false;

	hal_mem_address_t max_offset;
	if (sbm_update_slot_contains_swup(update_slot, &max_offset, NULL) != SWUP_STATUS_INITIAL)
		return false;

	/* Note: No need to check validity of the exec slot here. We are only
	   invoked as a result of a Secure API call, which can only come from
	   an app in the exec slot. The app is running because we started it
	   *after* verifying that the exec slot was valid. */

	/* There's a module in the executable slot so we can
	   police the version of the update against it */

	if (sbm_swup_update_version_rollback(update_slot))
		return false; /* Version rollback attempt. */

	return true;
}

bool sbm_swup_get_executable_module_info(app_info_record *const info)
{
	/* Note: No need to check validity of the exec slot here. We are only
	   invoked as a result of a Secure API call, which can only come from
	   an app in the exec slot. The app is running because we started it
	   after* verifying that the exec slot was valid.

	 . This also means that the MUH is readable safely. */

	const pie_module_t *const piem = (const pie_module_t *) app_status_slot.start_address;

	const pie_module_footer_t *piemf;
	if (!find_footer_from_pie_module(piem, &piemf))
	{
		return false;
	}

	/* Write the relevant information */
	info->app_type = 0U; /* Always 0 for v1.10, there is only the master application */
	info->installed = 1U; /* Always 1 for v1.10, only the installed application */
	info->start_addr = (uint32_t) exec_slot.start_address;
	info->end_addr = info->start_addr + piem->header.footer_offset - sizeof *piem - 1U;
	info->app_version = piemf->version_number;

	return true;
}

void sbm_swup_init(void)
{
	/* Select flash driver for handling MUH slot */
#if MUH_READ_USE_FLASH_DRIVER
	sbm_purge_cached_muh();
#endif /* MUH_READ_USE_FLASH_DRIVER */
}

#ifdef SBM_PC_BUILD
void sbm_swup_quiesce(void)
{
	/* Nothing to do */
}
#endif
