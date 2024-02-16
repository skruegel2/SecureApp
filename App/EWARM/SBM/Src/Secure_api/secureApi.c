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
 * \brief Secure API function implementations.
 */

#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "secureApiInternal.h"
#include "secureApiReturnCodes.h"
#include "dataStore.h"
#include "bufferCheck.h"
#include "memoryMap.h"
#include "swup.h"
#include "sbm_memory.h"
#include "sbm_hal.h"
#include "sbm_hal_mem.h"
#if SBM_PROVISIONED_DATA_ENCRYPTED != 0
#include "sbm_hal_crypto.h"
#endif
#include "sbm_api.h"
#include "sbm_log.h"
#include "benchmark.h"
#include "memory_devices_and_slots.h"

/**
 * \brief The SBM version string. This, including the NUL terminator, must
 *        be no larger than SECURE_API_SBM_VER_STR_SIZE.
 */
#define SBM_VERSION "SBM_VERSION_ID"

/* This is only for the uECC_BYTES macro */

#if ((SBM_APPLICATION_INTERFACE_METHOD_STZ_INDIRECTION == 0) && (SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE == 0))
#error "The SBM Application Interface Method must be set"
#elif ((SBM_APPLICATION_INTERFACE_METHOD_STZ_INDIRECTION != 0) && (SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE != 0))
#error "Only one SBM Application Interface Method can be set"
#endif

#if defined(SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE) && (SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE != 0)
/*
 * Temporary storage for SecureAPI input parameters when SBM_APPLICATION_INTERFACE_METHOD is TRUSTZONE.
 * Once we've validated the input buffer points somewhere legal, we copy
 * the buffer here to prevent an interrupt-based attack vector.
 * All types used as input parameters must have an entry in this union.
 */
#define SECFUNC(it, i, o, a, f) it f;
static union {
#include "secureApiFunctionList.i"
} secure_api_input_params SBM_PERSISTENT_RAM;
/* #undef these because secureApiFunctionList.i is included again below */
#undef SECFUNC
#undef SECUREAPIFUNCTIONLIST_H
#endif /* defined(SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE) && (SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE != 0) */

static uint32_t updateSlotWriteIndex SBM_PERSISTENT_RAM;
static uint32_t updateSlotWriteSize SBM_PERSISTENT_RAM;
static const memory_slot *activeUpdateSlot SBM_PERSISTENT_RAM;

/** Perform initialisation of activeUpdateSlot if it is NULL.
 *
 * Default initialisation cannot be performed at the definition since
 * activeUpdateSlot is placed in SBM_PERSISTENT_RAM which is zero-initialised.
 */
static void default_init_active_update_slot(void)
{
#if NUM_UPDATE_SLOTS > 0
	if (!activeUpdateSlot)
	{
		activeUpdateSlot = &update_slots[0];
	}
#endif /* NUM_UPDATE_SLOTS > 0 */
}

/* Certificate API */

/** Implementation of getNumberOfDeviceCertificates(). */
static secure_api_internal_return_t sbm_getNumberOfDeviceCertificates(const void *const in_buf,
														   void *const out_buf)
{
	*(int8_t *) out_buf = datastore_count(SLOT_PURPOSE_IDENTITY_CERT | CERT_LEVEL_DEVICE,
										   *(const uint16_t *) in_buf,
										   SLOT_PURPOSE_MASK | CERT_LEVEL_MASK);

	return SECURE_API_INT_OK;
}

/** Implementation of getSlotNumberOfDeviceCertificate(). */
static secure_api_internal_return_t sbm_getSlotNumberOfDeviceCertificate(const void *const in_buf,
															  void *const out_buf)
{
	const slot_number_of_device_certificate_args *const p = in_buf;
	*(pd_slot_t *) out_buf = datastore_find(SLOT_PURPOSE_IDENTITY_CERT | CERT_LEVEL_DEVICE,
										 p->m_usage, p->m_instance,
										 SLOT_PURPOSE_MASK | CERT_LEVEL_MASK);

	return SECURE_API_INT_OK;
}

/** Implementation of getX509CertificateFromSlot(). */
static secure_api_internal_return_t sbm_getX509CertificateFromSlot(const void *const in_buf,
														void *const out_buf)
{
	const get_x509_certificate_from_slot_in_args *const p = in_buf;
	if (!buffer_check_app_permissions_ram(p->m_cert_len, sizeof *p->m_cert_len, true))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	if (p->m_buf == NULL)
	{
		/* Deliver size required */
		*p->m_cert_len = 0U; /* need size of certificate */
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	if (!buffer_check_app_permissions_ram(p->m_buf, p->m_len, false))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	*(int8_t *) out_buf = datastore_copy_data(p->m_slot, p->m_buf,
											  p->m_len, p->m_cert_len);

	return SECURE_API_INT_OK;
}

/** Implementation of getParentOfCertificate(). */
static secure_api_internal_return_t sbm_getParentOfCertificate(const void *const in_buf,
													void *const out_buf)
{
	*(pd_slot_t *) out_buf = datastore_parent(*(const pd_slot_t *) in_buf);

	return SECURE_API_INT_OK;
}

/* Key API */

/** Implementation of getNumberOfDKeys(). */
static secure_api_internal_return_t sbm_getNumberOfKeys(const void *const in_buf,
											 void *const out_buf)
{
	const number_of_keys_args *const p = in_buf;
	switch (SLOT_PURPOSE(p->m_key_type))
	{
		case SLOT_PURPOSE_IDENTITY_KEY:
		case SLOT_PURPOSE_TRUST_ANCHOR_KEY:
		case SLOT_PURPOSE_UPDATE_KEY:
			*(int8_t *) out_buf = datastore_count(p->m_key_type, p->m_key_usage,
                                                  SLOT_PURPOSE_MASK |
                                                  (KEY_CATEGORY(p->m_key_type) ? KEY_CATEGORY_MASK : 0) |
                                                  (KEY_ALGORITHM(p->m_key_type) ? KEY_ALGORITHM_MASK : 0) |
                                                  (KEY_CURVE(p->m_key_type) ? KEY_CURVE_MASK : 0));
			break;

		default:
			*(int8_t *) out_buf = 0;
			break;
	}

	return SECURE_API_INT_OK;
}

/** Implementation of getSlotNumberOfKeyForCertificate(). */
static secure_api_internal_return_t sbm_getSlotNumberOfKeyForCertificate(const void *const in_buf,
															  void *const out_buf)
{
	const slot_number_of_key_for_certificate_args *const p = in_buf;
	if (!buffer_check_app_permissions_ram(p->m_key_type, sizeof *p->m_key_type, true))
	{
		*(pd_slot_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	*(pd_slot_t *) out_buf = datastore_find_cert_key(p->m_slot, p->m_key_type);

	return SECURE_API_INT_OK;
}

/** Implementation of getSlotNumberOfKey(). */
static secure_api_internal_return_t sbm_getSlotNumberOfKey(const void *const in_buf,
												void *const out_buf)
{
	const slot_number_of_key_args *const p = in_buf;
	switch (SLOT_PURPOSE(p->m_key_type))
	{
		case SLOT_PURPOSE_IDENTITY_KEY:
		case SLOT_PURPOSE_TRUST_ANCHOR_KEY:
		case SLOT_PURPOSE_UPDATE_KEY:
			*(pd_slot_t *) out_buf = datastore_find(p->m_key_type, p->m_key_usage, p->m_instance,
												 SLOT_PURPOSE_MASK | KEY_CATEGORY_MASK |
												 (KEY_ALGORITHM(p->m_key_type) ? KEY_ALGORITHM_MASK : 0) |
												 (KEY_CURVE(p->m_key_type) ? KEY_CURVE_MASK : 0));
			break;

		default:
			*(pd_slot_t *) out_buf = SECURE_API_ERR_SLOT_TYPE_MISMATCH;
			break;
	}

	return SECURE_API_INT_OK;
}

/** Implementation of getDetailsOfKey(). */
static secure_api_internal_return_t sbm_getDetailsOfKey(const void *const in_buf,
											 void *const out_buf)
{
	const details_of_key_args *const p = in_buf;
	if (!buffer_check_app_permissions_ram(p->m_key_type, sizeof *p->m_key_type, true) ||
		!buffer_check_app_permissions_ram(p->m_key_usage, sizeof *p->m_key_usage, true) ||
		!buffer_check_app_permissions_ram(p->m_public_key, ECC_PUBLIC_KEY_SIZE, true))
	{
		*(pd_slot_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	*(pd_slot_t *) out_buf = datastore_key_details(p->m_slot, p->m_key_type,
												p->m_key_usage, p->m_public_key);

	return SECURE_API_INT_OK;
}

/** Implementation of signUsingKey(). */
static secure_api_internal_return_t sbm_signUsingKey(const void *const in_buf,
										  void *const out_buf)
{
	const sign_using_key_args *const p = in_buf;
	if (!buffer_check_app_permissions(p->m_hash, p->m_hlen) ||
	    !buffer_check_app_permissions_ram(p->m_sig_len, sizeof *p->m_sig_len, true))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	if (p->m_sig == NULL)
	{
		/* Deliver size required */
		*p->m_sig_len = 0U; /* need size of signature */
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	if (!buffer_check_app_permissions_ram(p->m_sig, *p->m_sig_len, true))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	*(int8_t *) out_buf = datastore_sign(p->m_slot, p->m_hash, p->m_hlen, p->m_sig, p->m_sig_len);

	return SECURE_API_INT_OK;
}

/** Implementation of verifyUsingKey(). */
static secure_api_internal_return_t sbm_verifyUsingKey(const void *const in_buf,
											void *const out_buf)
{
	const verify_using_key_args *const p = in_buf;
	if (!buffer_check_app_permissions(p->m_hash, p->m_hlen) ||
	    !buffer_check_app_permissions(p->m_sig, p->m_slen))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	*(int8_t *) out_buf = datastore_verify(p->m_slot, p->m_hash, p->m_hlen, p->m_sig, p->m_slen);

	return SECURE_API_INT_OK;
}

/** Implementation of generateSharedSecret(). */
static secure_api_internal_return_t sbm_generateSharedSecret(const void *const in_buf,
												  void *const out_buf)
{
	const generate_shared_secret_in_args *const p = in_buf;
	if (!buffer_check_app_permissions(p->m_public_key, ECC_PUBLIC_KEY_SIZE) ||
	    !buffer_check_app_permissions_ram(p->m_shared_secret, ECC_PRIVATE_KEY_SIZE, true))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	*(int8_t *) out_buf = datastore_shared_secret(p->m_slot, p->m_public_key, p->m_shared_secret);

	return SECURE_API_INT_OK;
}

/** Find the provisioning details.
 *
 * Track down the data slot containing the provisioning details.
 *
 * \return The address of the data if it's there, \c NULL if it's not.
 */
static const provisioning_details *obtain_provisioning_details(void)
{
    const pd_slot_t pds = datastore_find(SLOT_PURPOSE_PROVISION_INFO | PROVISIONING_DETAILS,
                                         0U, 0U, SLOT_PURPOSE_MASK | SLOT_SUBTYPE_MASK);
    if (pds < 0)
        return NULL; /* Slot not found */

    uint16_t pds_len;
    const provisioning_details *provisioned_data_details;
    if (datastore_slot_data(pds, (const void **) &provisioned_data_details, &pds_len))
        return NULL; /* Internal error */

    if (pds_len < sizeof *provisioned_data_details)
        return NULL; /* Slot doesn't contain enough data to be plausible */

    return provisioned_data_details;
}

/** Adjust the supplied buffer length to the desired buffer length and populate buffer.
 *
 * Adjust the supplied length unconditionaly. Fill the destination
 * buffer from the source if the original length is large enough.
 *
 * \param[out] dst Address of destination buffer.
 * \param[in] src Address of source buffer.
 * \param[in, out] supplied_len Address of a \c uint32_t initially holding the supplied buffer size.
 * \param desired_len The desired size of the buffer.
 *
 * \return Non-zero if upward adjustment is made to the supplied size, zero otherwise.
 */
static unsigned int fill_buffer(void *const dst, const void *const src, uint32_t *const supplied_len, const uint32_t desired_len)
{
    const uint32_t original = *supplied_len;
    *supplied_len = desired_len;
    if (desired_len <= original)
    {
        memcpy(dst, src, desired_len);
        return 0U;
    }

    return 1U;
}

/** Implementation of getSBMInformation(). */
static secure_api_internal_return_t sbm_getSBMInformation(const void *const in_buf,
                                               void *const out_buf)
{
    const get_sbm_info_in_args *const p = in_buf;

    /* Check string length pointers are in RAM */
    if (!buffer_check_app_permissions_ram(p->sbm_ver_length, sizeof(*p->sbm_ver_length), true) ||
        !buffer_check_app_permissions_ram(p->sbm_build_time_length, sizeof(*p->sbm_build_time_length), true) ||
        !buffer_check_app_permissions_ram(p->provisioned_ver_length, sizeof(*p->provisioned_ver_length), true) ||
        !buffer_check_app_permissions_ram(p->provisioned_time_length, sizeof(*p->provisioned_time_length), true) ||
        !buffer_check_app_permissions_ram(p->provisioning_machine_length, sizeof(*p->provisioning_machine_length), true))
    {
        *(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
        return SECURE_API_INT_OK;
    }

    /* Check string buffers are in RAM */
    if (!buffer_check_app_permissions_ram(p->sbm_ver, *p->sbm_ver_length, true) ||
        !buffer_check_app_permissions_ram(p->sbm_build_time, *p->sbm_build_time_length, true) ||
        !buffer_check_app_permissions_ram(p->provisioned_ver, *p->provisioned_ver_length, true) ||
        !buffer_check_app_permissions_ram(p->provisioned_time, *p->provisioned_time_length, true) ||
        !buffer_check_app_permissions_ram(p->provisioning_machine, *p->provisioning_machine_length, true))
    {
        *(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
        return SECURE_API_INT_OK;
    }

    /* For each field, populate the field length with the "new" length
       and copy the data if the supplied buffer is big enough.
       Keep a status as we go which is set to an error code
       if any supplied buffer is found to be too small.
       If we don't have data to copy into a buffer, set the buffer
       length to zero and populate the buffer with an empty string. */

    unsigned int size_increase = 0U; /* Set to error code if any buffer is too small */

    /* SBM information that can be enabled using specific flags */

    /* SBM version */
#if SBM_REPORT_SBM_VERSION != 0
    char sbm_ver[] = SBM_VERSION;
    size_increase |= fill_buffer(p->sbm_ver, sbm_ver, p->sbm_ver_length, strlen(sbm_ver) + 1U);
#else
    *p->sbm_ver_length = 0U;
    p->sbm_ver[0] = '\0';
#endif /* SBM_REPORT_SBM_VERSION != 0 */

    /* SBM build time */
#if SBM_REPORT_SBM_BUILD_TIME != 0
    char sbm_build_time[] = __DATE__" "__TIME__;
    size_increase |= fill_buffer(p->sbm_build_time, sbm_build_time, p->sbm_build_time_length, strlen(sbm_build_time) + 1U);
#else
    *p->sbm_build_time_length = 0U;
    p->sbm_build_time[0] = '\0';
#endif /* SBM_REPORT_SBM_BUILD_TIME != 0 */

    /* Find the provisioning details */

    const provisioning_details *const provisioned_data_details = obtain_provisioning_details();
    if (provisioned_data_details)
    {
        /* Provisioned version */
        size_increase |= fill_buffer(p->provisioned_ver, provisioned_data_details->context_uuid_iteration,
									 p->provisioned_ver_length,
									 strnlen((const char *) provisioned_data_details->context_uuid_iteration,
											 sizeof provisioned_data_details->context_uuid_iteration - 1U) + 1U);

        /* Provisoned time */
        size_increase |= fill_buffer(p->provisioned_time, provisioned_data_details->date_time,
									 p->provisioned_time_length,
									 strnlen((const char *) provisioned_data_details->date_time,
											 sizeof provisioned_data_details->date_time - 1U) + 1U);

        /* Provisioning machine */
        size_increase |= fill_buffer(p->provisioning_machine, provisioned_data_details->machine_uuid,
									 p->provisioning_machine_length,
									 strnlen((const char *) provisioned_data_details->machine_uuid,
											 sizeof provisioned_data_details->machine_uuid - 1U) + 1U);
    }
    else
    {
        /* Provisioning details aren't available so deposit empty
           strings in the buffers and set the buffer lengths to zero */

        p->provisioned_ver[0] = p->provisioned_time[0] = p->provisioning_machine[0] = '\0';
        *p->provisioned_ver_length = *p->provisioned_time_length = *p->provisioning_machine_length = 0U;
    }

	*(int8_t *) out_buf = size_increase ? SECURE_API_ERR_BUFFER_SIZE_INVALID : 0;

    return SECURE_API_INT_OK;
}

/** Implementation of getUpdateInfo(). */
static secure_api_internal_return_t sbm_getUpdateInfo(const void *const in_buf,
                                           void *const out_buf)
{
    /* Check the locations passed by the caller */
    const get_update_info_in_args *const p = in_buf;
    if (!buffer_check_app_permissions_ram(p->status, sizeof(*p->status), true) ||
        !buffer_check_app_permissions_ram(p->uuid_length, sizeof(*p->uuid_length), true) ||
        !buffer_check_app_permissions_ram(p->uuid, *p->uuid_length, true))
    {
        *(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
        return SECURE_API_INT_OK;
    }

    const uint16_t buf_len = *p->uuid_length;
    *p->uuid_length = sizeof(uuid_t);

    if (sizeof(uuid_t) > buf_len)
    {
        /* Return failure */
        *(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
    }
    else
    {
        /* Collect the status and UUID from preserved RAM */
        *p->status = sbm_swup_get_last_status();
        sbm_swup_get_last_installed_uuid(p->uuid);
        /* Return success */
        *(int8_t *) out_buf = SECURE_API_RETURN_SUCCESS;
    }

    return SECURE_API_INT_OK;
}

/** Implementation of getApplicationInfo(). */
static secure_api_internal_return_t sbm_getApplicationInfo(const void *const in_buf,
                                                void *const out_buf)
{
	/* Check the locations passed by the caller */
	const get_app_info_in_args *const p = in_buf;
	if (!buffer_check_app_permissions_ram(p->num_apps, sizeof(*p->num_apps), true) ||
	    !buffer_check_app_permissions_ram(p->app_info_records_length, sizeof(*p->app_info_records_length), true) ||
	    !buffer_check_app_permissions_ram(p->app_info_records, *p->app_info_records_length, true))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	/* Get the number of applications supported - always 1 for v1.10*/
	*p->num_apps = 1;

	/* If the caller has not allocated enough space in their buffer return failure */
	if ((*p->num_apps * sizeof(app_info_record)) > *p->app_info_records_length)
	{
		return SECURE_API_INT_IN_BUF_SIZE_ERROR;
	}

	if (sbm_swup_get_executable_module_info(&p->app_info_records[0]))
	{
		/* Return success */
		*(int8_t *) out_buf = SECURE_API_RETURN_SUCCESS;
	}
	else
	{
		/* Return failure */
		*(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
	}

	return SECURE_API_INT_OK;
}

/** Implementation of getUpdateSlotInfo(). */
static secure_api_internal_return_t sbm_getUpdateSlotInfo(const void *const in_buf,
														  void *const out_buf)
{
	/* Check the locations passed by the caller */
	const get_update_slot_info_in_args *const p = in_buf;
	if (!buffer_check_app_permissions_ram(p->update_slot_id, sizeof(*p->update_slot_id), true) ||
	    !buffer_check_app_permissions_ram(p->start_address, sizeof(*p->start_address), true) ||
	    !buffer_check_app_permissions_ram(p->slot_size, sizeof(*p->slot_size), true))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	default_init_active_update_slot();

	/* Write the data */
	if (NULL == activeUpdateSlot)
	{
		/* No update slot is supported */
		*p->update_slot_id = MEMORY_SLOT_ID_INVALID;
		*p->start_address  = UINT32_MAX;
		*p->slot_size      = 0U;
	}
	else
	{
		*p->update_slot_id = activeUpdateSlot->id;
		*p->start_address  = activeUpdateSlot->start_address;
		*p->slot_size      = activeUpdateSlot->size;
	}

	/* Return success */
	*(int8_t *) out_buf = SECURE_API_RETURN_SUCCESS;

	return SECURE_API_INT_OK;
}

/** Implementation of checkUpdateSlot(). */
static secure_api_internal_return_t sbm_checkUpdateSlot(const void *const in_buf,
                                             void *const out_buf)
{
	default_init_active_update_slot();

	if (NULL == activeUpdateSlot)
	{
		*(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
	}
	else
	{
		/* Check the update slot and write the return value */
		*(int8_t *) out_buf = sbm_swup_can_install_update(activeUpdateSlot) ?
		                          SECURE_API_RETURN_SUCCESS : SECURE_API_ERR_COMMAND_FAILED;
	}

	return SECURE_API_INT_OK;
}

/** Implementation of installUpdate(). */
static secure_api_internal_return_t sbm_installUpdate(const void *const in_buf,
                                                      void *const out_buf)
{
	default_init_active_update_slot();

	/* Check the update slot before resetting */
	if (activeUpdateSlot != NULL)
	{
		if (sbm_swup_can_install_update(activeUpdateSlot))
		{
			/* Currently this functionality could be carried out by the application by calling
			* checkUpdateSlot, then resetting. However, we have this API as well to allow us
			* an opportunity to tidy-up before resetting the device.
			* That tidy-up can be done here. */

			/* The update is valid so reset the device. */
			cpu_reset();
		}
	}

	/* Update not valid, tell the caller and return */
	*(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
	return SECURE_API_INT_OK;
}

/** Implementation of updateSlotBeginWrite(). */
static secure_api_internal_return_t sbm_updateSlotBeginWrite(const void *const in_buf,
                                               void *const out_buf)
{
	/* Check the location passed by the caller */
	const update_slot_begin_write_in_args *const p = in_buf;
	if (!buffer_check_app_permissions_ram(p->write_size, sizeof(*p->write_size), true))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	default_init_active_update_slot();

	/* Check the currently active update slot. */
	if (NULL == activeUpdateSlot)
	{
		*(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
		return SECURE_API_INT_OK;
	}

	/* Erase the update slot. */
	if (HAL_MEM_SUCCESS != hal_mem_erase(activeUpdateSlot, 0, activeUpdateSlot->size))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
		return SECURE_API_INT_OK;
	}

	/* Fetch the minimum write size of the Flash. */
	const memory_device *const device = get_device_from_slot(activeUpdateSlot);
	const memory_subregion *subregion = get_subregion_from_address(device, activeUpdateSlot->start_address);
	if (!subregion)
	{
		*(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
		return SECURE_API_INT_OK;
	}
	updateSlotWriteSize = subregion->min_write_size;

	/* Provide the minimum write size to the caller. */
	*p->write_size = updateSlotWriteSize;

	/* Set update slot index to zero. */
	updateSlotWriteIndex = 0;

	/* Return success */
	*(int8_t *) out_buf = SECURE_API_RETURN_SUCCESS;

	return SECURE_API_INT_OK;
}

/** Implementation of updateSlotEndWrite(). */
static secure_api_internal_return_t sbm_updateSlotEndWrite(const void *const in_buf,
                                               void *const out_buf)
{
	/* Prevent any further calls to updateSlotWrite(). */
	updateSlotWriteSize = 0;

	/* Some additional functionality may be required here in future. */

	/* Return success */
	*(int8_t *) out_buf = SECURE_API_RETURN_SUCCESS;

	return SECURE_API_INT_OK;
}

/** Implementation of updateSlotWrite(). */
static secure_api_internal_return_t sbm_updateSlotWrite(const void *const in_buf,
                                               void *const out_buf)
{
	/* Fetch the buffer details passed by the caller */
	const update_slot_write_in_args *const p = in_buf;

	/* Verify there has been a successful call to sbm_updateSlotBeginWrite() */
	if ((0 == updateSlotWriteSize) || (!activeUpdateSlot))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
		return SECURE_API_INT_OK;
	}

	/*
	 * Ensure the supplied buffer size is a multiple of the device write size
	 * and does not exceed the bounds of the update slot.
	 */
	if (p->bytes == 0 || (p->bytes % updateSlotWriteSize) != 0 ||
		p->bytes > activeUpdateSlot->size - updateSlotWriteIndex)
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_SIZE_INVALID;
		return SECURE_API_INT_OK;
	}

	if (!buffer_check_app_permissions_ram(p->buffer, p->bytes, false))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	/* Program the update slot. */
	if (HAL_MEM_SUCCESS != sbm_copy_to_flash(activeUpdateSlot,
	                                         updateSlotWriteIndex,
	                                         p->buffer,
	                                         p->bytes))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
		return SECURE_API_INT_OK;
	}

	/* Advance the update slot index. */
	updateSlotWriteIndex += p->bytes;

	/* Return success */
	*(int8_t *) out_buf = SECURE_API_RETURN_SUCCESS;

	return SECURE_API_INT_OK;
}

#if SBM_RECORD_BOOT_TIME != 0
/** Implementation of getSBMPerformance(). */
static secure_api_internal_return_t sbm_getSBMPerformance(const void *const in_buf,
														  void *const out_buf)
{
	/* Check the location passed by the caller */
	const get_sbm_performance_in_args *const p = in_buf;
	if (!buffer_check_app_permissions_ram(p->boot_time, sizeof *p->boot_time, true) ||
		!buffer_check_app_permissions_ram(p->sbm_size, sizeof *p->sbm_size, true) ||
		!buffer_check_app_permissions_ram(p->pd_size, sizeof *p->pd_size, true) ||
		!buffer_check_app_permissions_ram(p->watchdog_period, sizeof *p->watchdog_period, true) ||
		!buffer_check_app_permissions_ram(p->watchdog_max_period, sizeof *p->watchdog_max_period, true) ||
		!buffer_check_app_permissions_ram(p->watchdog_max_activity_start, sizeof *p->watchdog_max_activity_start, true) ||
		!buffer_check_app_permissions_ram(p->watchdog_max_activity_end, sizeof *p->watchdog_max_activity_end, true) ||
		!buffer_check_app_permissions_ram(p->sbm_stack_size, sizeof *p->sbm_stack_size, true) ||
		!buffer_check_app_permissions_ram(p->sbm_stack_used, sizeof *p->sbm_stack_used, true))
	{
		*(int8_t *) out_buf = SECURE_API_ERR_BUFFER_LOCATION_INVALID;
		return SECURE_API_INT_OK;
	}

	*p->boot_time = sbm_benchmark_boot_time();
	datastore_calculate_sizes(p->sbm_size, p->pd_size);
	/* The rest are unused for now ... */
	*p->watchdog_period = *p->watchdog_max_period =
		*p->watchdog_max_activity_start = *p->watchdog_max_activity_end =
		*p->sbm_stack_size = *p->sbm_stack_used = UINT32_C(0);

	/* Return success */
	*(int8_t *) out_buf = SECURE_API_RETURN_SUCCESS;

	return SECURE_API_INT_OK;
}
#else
#define sbm_getSBMPerformance NULL
#endif

/** Implementation of setActiveUpdateSlot(). */
static secure_api_internal_return_t sbm_setActiveUpdateSlot(const void *const in_buf,
															void *const out_buf)
{
	/* Check the ID passed by the caller */
	const set_active_update_slot_in_args *const p = in_buf;
	const memory_slot *slot = get_update_slot_from_id(p->slot_id);

	/* Check if slot is a valid update slot */
	if (!slot || slot->slot_type != UPDATE_SLOT_TYPE)
	{
		*(int8_t *) out_buf = SECURE_API_ERR_COMMAND_FAILED;
		return SECURE_API_INT_OK;
	}

	/* Set the slot as active */
	activeUpdateSlot = slot;

	/* Abort any write in progress */
	updateSlotWriteIndex = 0;
	updateSlotWriteSize  = 0;

	/* Return success */
	*(int8_t *) out_buf = SECURE_API_RETURN_SUCCESS;

	return SECURE_API_INT_OK;
}

#define SBM_API_ATTR_OVERLAP 1 /**< Input and output buffers may overlap. */
#define SECFUNC(it, i, o, a, f) { (uint8_t)(i), (uint8_t)(o), a, sbm_ ## f },
static const struct
{
	const uint8_t in_len;
	const uint8_t out_len;
	const uint16_t attr;
	secure_api_internal_return_t (*const addr)(const void *, void *);
} api_table[] = {
#include "secureApiFunctionList.i"
};

/** Secure API routing function.
 *
 * - Validate the function index.
 * - Validate the function address.
 * - Validate the function arguments against the attributes.
 * - Forward the call into the implementation.
 *
 * \param fidx Function number to be called.
 * \param[in] in_buf Address of input buffer.
 * \param in_len Length of input buffer.
 * \param[out] out_buf Address of output buffer.
 * \param out_len Length of output buffer.
 */
#if (SBM_APPLICATION_INTERFACE_METHOD_STZ_INDIRECTION != 0) && !defined(SBM_PC_BUILD)
static
#endif
secure_api_internal_return_t sbm_secure_api(const unsigned int fidx,
                                            const void *const in_buf,
                                            const uint32_t in_len,
                                            void *const out_buf,
                                            const uint32_t out_len)
{
	if (fidx >= sizeof api_table / sizeof api_table[0])
		return SECURE_API_INT_MISSING_FUNCTION;

	if (!api_table[fidx].addr)
		return SECURE_API_INT_UNIMPLEMENTED_FUNCTION;

	if (api_table[fidx].in_len != in_len)
		return SECURE_API_INT_IN_BUF_SIZE_ERROR;

	if (in_len && !buffer_check_app_permissions(in_buf, in_len))
		return SECURE_API_INT_IN_BUF_MISSING;

	if (api_table[fidx].out_len != out_len)
		return SECURE_API_INT_OUT_BUF_SIZE_ERROR;

	if (out_len && !buffer_check_app_permissions_ram(out_buf, out_len, true))
		return SECURE_API_INT_OUT_BUF_MISSING;

	if (in_len && out_len && ((api_table[fidx].attr & SBM_API_ATTR_OVERLAP) == 0))
	{
		/* Input and output and must not overlap */

		if ((uintptr_t)in_buf <= (uintptr_t)out_buf && (uintptr_t)out_buf < ((uintptr_t)in_buf + in_len))
			return SECURE_API_INT_BUF_OVERLAP;

		if ((uintptr_t)out_buf <= (uintptr_t)in_buf && (uintptr_t)in_buf < ((uintptr_t) out_buf + out_len))
			return SECURE_API_INT_BUF_OVERLAP;
	}

	/* Prevent the SBM from attempting to log any output when called via the Secure API,
	 * as the HAL serial port was quiesced when the app was booted, and may have been
	 * reconfigured by the application.
	 *
	 * This is not strictly necessary as logging was disabled just before the app was
	 * booted (see main()), but it is also done here as a safety net in case it was
	 * somehow accidentally re-enabled since then. */
	SBM_LOG_DISABLE();

	secure_api_internal_return_t ret;

#if SBM_PROVISIONED_DATA_ENCRYPTED != 0
	if (!datastore_verify_and_decrypt_pdb()) {
		return SECURE_API_INT_EDP_DECRYPT_ERROR;
	}
#endif

#if defined(SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE) && (SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE != 0)
#ifndef NDEBUG
	if (in_len > sizeof(secure_api_input_params))
	{
#if SBM_PROVISIONED_DATA_ENCRYPTED != 0
		datastore_clear_plaintext_pdb();
#endif
		return SECURE_API_INT_IN_BUF_SIZE_ERROR;
	}
#endif
	/*
	 * Make and use a copy of the caller's non-secure input buffer.
	 * This foils an attack vector where an application interrupt handler
	 * could modify a pointer stored in the input buffer after we've
	 * validated it but before it's dereferenced.
	 */
	if (in_len && in_buf != NULL)
	{
		memcpy(&secure_api_input_params, in_buf, in_len);
	}

	ret = (*api_table[fidx].addr)(&secure_api_input_params, out_buf);
#else
	ret = (*api_table[fidx].addr)(in_buf, out_buf);
#endif /* defined(SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE) && (SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE != 0) */

#if SBM_PROVISIONED_DATA_ENCRYPTED != 0
	datastore_clear_plaintext_pdb();
#endif

	return ret;
}

#if (SBM_APPLICATION_INTERFACE_METHOD_STZ_INDIRECTION != 0) && !defined(SBM_PC_BUILD)
/** Secure API trampoline. */

/* This defines a pointer that simply sits in memory for the application to read. */
__root secure_api_internal_return_t (*const secure_api)(unsigned int fidx, const void *in_buf, uint32_t in_len, void *out_buf, uint32_t out_len) @ "SECAPI_ACCESS_POINTER" =
	sbm_secure_api;
#endif /* (SBM_APPLICATION_INTERFACE_METHOD_STZ_INDIRECTION != 0) && !defined(SBM_PC_BUILD) */
