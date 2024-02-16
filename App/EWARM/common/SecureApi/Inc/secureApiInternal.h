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
 * \brief Internal structures used by secure API.
 */

#ifndef SECURE_API_INTERNAL_H
#define SECURE_API_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "imageInfo.h"
#include "secureApiData.h"

/** Status yielded by API routing function.
 * The values provided here must not be changed in order to preserve backwards compatibility. */
#define SECURE_API_RETURN_VALUES_X \
	X(SECURE_API_INT_OK,                     "No error") \
	X(SECURE_API_INT_MISSING_FUNCTION,       "Secure API function invalid") \
	X(SECURE_API_INT_UNIMPLEMENTED_FUNCTION, "Secure API function unimplemented") \
	X(SECURE_API_INT_IN_BUF_MISSING,         "Input buffer not supplied") \
	X(SECURE_API_INT_OUT_BUF_MISSING,        "Output buffer not supplied") \
	X(SECURE_API_INT_BUF_OVERLAP,            "Input and output buffers overlap") \
	X(SECURE_API_INT_IN_BUF_SIZE_ERROR,      "Input buffer incorrect size") \
	X(SECURE_API_INT_OUT_BUF_SIZE_ERROR,     "Output buffer incorrect size") \
	X(SECURE_API_INT_EDP_DECRYPT_ERROR,      "Decryption of Encrypted Provisioned Data failed")

#define X(name, text) name,
typedef enum
{
	SECURE_API_RETURN_VALUES_X
} secure_api_internal_return_t;
#undef X

/* Certificate API ... */

typedef struct
{
	uint16_t m_usage;
	uint8_t m_instance;
} slot_number_of_device_certificate_args;

typedef struct
{
	uint8_t m_slot;
	uint8_t *m_buf;
	uint16_t m_len;
	uint16_t *m_cert_len;
} get_x509_certificate_from_slot_in_args;

/* Key API ... */

typedef struct
{
	uint16_t m_key_type;
	uint16_t m_key_usage;
} number_of_keys_args;

typedef struct
{
	uint16_t m_key_type;
	uint16_t m_key_usage;
	uint8_t m_instance;
} slot_number_of_key_args;

typedef struct
{
	pd_slot_t m_slot;
	uint16_t *m_key_type;
} slot_number_of_key_for_certificate_args;

typedef struct
{
	pd_slot_t m_slot;
	uint16_t *m_key_type;
	uint16_t *m_key_usage;
	uint8_t *m_public_key;
} details_of_key_args;

typedef struct
{
	pd_slot_t m_slot;
	const uint8_t *m_hash;
	uint16_t m_hlen;
	uint8_t *m_sig;
	uint16_t *m_sig_len;
} sign_using_key_args;

typedef struct
{
	pd_slot_t m_slot;
	const uint8_t *m_hash;
	uint16_t m_hlen;
	const uint8_t *m_sig;
	uint16_t m_slen;
} verify_using_key_args;

typedef struct
{
	pd_slot_t m_slot;
	const uint8_t *m_public_key;
	uint8_t *m_shared_secret;
} generate_shared_secret_in_args;

/* APIs for getting information on the basic SBM capabilities */
typedef struct
{
    char *sbm_ver;
    uint32_t *sbm_ver_length;
    char *sbm_build_time;
    uint32_t *sbm_build_time_length;
    char *provisioned_ver;
    uint32_t *provisioned_ver_length;
    char *provisioned_time;
    uint32_t *provisioned_time_length;
    char *provisioning_machine;
    uint32_t *provisioning_machine_length;
} get_sbm_info_in_args;

typedef struct
{
    uint32_t *update_slot_id;
    uint32_t *start_address;
    uint32_t *slot_size;
} get_update_slot_info_in_args;

typedef struct
{
    uint32_t *status;
    uint8_t *uuid;
    uint16_t *uuid_length;
} get_update_info_in_args;

typedef struct
{
    uint8_t *num_apps;
    app_info_record *app_info_records;
    uint16_t *app_info_records_length;
} get_app_info_in_args;

typedef struct
{
    uint32_t *write_size;
} update_slot_begin_write_in_args;

typedef struct
{
    const void *buffer;
    size_t bytes;
} update_slot_write_in_args;

typedef struct
{
    uint32_t *boot_time;
    uint32_t *sbm_size;
    uint32_t *pd_size;
    uint32_t *watchdog_period;
    uint32_t *watchdog_max_period;
    uint32_t *watchdog_max_activity_start;
    uint32_t *watchdog_max_activity_end;
    uint32_t *sbm_stack_size;
    uint32_t *sbm_stack_used;
} get_sbm_performance_in_args;

typedef struct
{
    uint32_t slot_id;
} set_active_update_slot_in_args;

#if (SBM_APPLICATION_INTERFACE_METHOD_ARM_TRUSTZONE != 0) || defined(SBM_PC_BUILD)
extern secure_api_internal_return_t sbm_secure_api(const unsigned int fidx,
                                        const void *const in_buf,
                                        const uint32_t in_len,
                                        void *const out_buf,
                                        const uint32_t out_len);
#endif

#endif /* SECURE_API_INTERNAL_H */
