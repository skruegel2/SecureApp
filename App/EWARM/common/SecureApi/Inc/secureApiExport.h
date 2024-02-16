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

#ifndef SECURITY_API_EXPORT_H
#define SECURITY_API_EXPORT_H

/** \file
 * \brief Secure API function declarations.
 */

#include <stdint.h>

#include "secureApiData.h"
#include "imageInfo.h"
#include "secureApiReturnCodes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Certificate API ... */

/** Obtain the number of provisioned device certificates.
 *
 * Count the certificate slots matching \a usage class.
 *
 * \param usage Certificate usage class.
 *
 * \return Number of device certificates matching the specified usage class, -ve error code otherwise.
 */
int8_t STZ_getNumberOfDeviceCertificates(uint16_t usage);

/** Find the slot holding a given certificate of specified usage.
 *
 * Find the <em>instance</em>th slot matching \a usage class.
 *
 * \param usage Certificate usage class to search for.
 * \param instance The instance to find.
 *
 * \return Index of required slot if found, -ve error code otherwise.
 */
pd_slot_t STZ_getSlotNumberOfDeviceCertificate(uint16_t usage, uint8_t instance);

/** Copy the certificate from a given slot.
 *
 * If the buffer is too small to receive the data, no data
 * is copied but the required size is written to the object
 * pointed to by the \a cert_len argument.
 *
 * \param slot Slot index to read.
 * \param[out] buf Address of buffer to write.
 * \param buf_len Length of buffer pointed to by \a buf.
 * \param[out] cert_len Address of a uint16_t to be populated
 * with the length of the certificate copied to \a buf.
 *
 * \return Zero on success, -ve error code otherwise.
 */
int8_t STZ_getX509CertificateFromSlot(uint8_t slot, uint8_t *buf,
									  uint16_t buf_len, uint16_t *cert_len);

/** Find the parent of a given certificate.
 *
 * \param slot Slot index to interrogate.
 *
 * \return Index of <em>slot</em>'s parent if it exists, -ve error code otherwise.
 */
pd_slot_t STZ_getParentOfCertificate(pd_slot_t slot);


/* Key API ... */

/** Obtain the number of provisioned keys.
 *
 * \param key_type Type of key.
 * \param key_usage Usage class of key to search for.
 *
 * \return Number of keys of the specified type and usage, -ve error code otherwise.
 */
int8_t STZ_getNumberOfKeys(uint16_t key_type, uint16_t key_usage);

/** Find the slot holding a given key of specified type.
 *
 * Find the <em>instance</em>th key matching \a key_type and \a key_usage.
 *
 * \param key_type Type of key to search for.
 * \param key_usage Usage class of key to search for.
 * \param instance The instance to find.
 *
 * \return Index of required slot if found, -ve error code otherwise.
 */
pd_slot_t STZ_getSlotNumberOfKey(uint16_t key_type, uint16_t key_usage, uint8_t instance);

/** Find the slot holding the private key corresponding to the public key of a given certificate.
 *
 * \param cert_slot Index of slot holding certificate.
 * \param[out] key_type Address of uint16_t to be populated with the key type if found.
 *
 * \return Index of required slot if found, -ve error code otherwise.
 */
pd_slot_t STZ_getSlotNumberOfKeyForCertificate(pd_slot_t cert_slot, uint16_t *key_type);

/** Obtain the details of the key in a given slot.
 *
 * \param slot Index of slot holding key to interrogate.
 * \param[out] key_type Address of uint16_t to be populated with key type.
 * \param[out] key_usage Address of uint16_t to be populated with key usage class.
 * \param[out] public_key Address of buffer to be populated with public key.
 *
 * \note \a public_key must point to a buffer of at least uECC_BYTES * 2 bytes.
 *
 * \return Zero on success, -ve error code otherwise.
 */
int8_t STZ_getDetailsOfKey(pd_slot_t slot, uint16_t *key_type,
						   uint16_t *key_usage, uint8_t *public_key);

/* XX_internal_XX: maybe rethink semantics of sb_len and sig_len: pass pointer to populated object "as usual"? */
/** Sign a hash usaing the (private) key in a given slot.
 *
 * \param slot Index of slot holding key to use.
 * \param[in] hash Address of buffer holding hash to be signed.
 * \param hlen Length of buffer pointed to by \a hash.
 * \param[out] sig Address of buffer to be populated with signature.
 * \param sb_len Length of buffer pointed to by \a sig.
 * \param[out] sig_len Address of a uint16_t to be populated with length
 * of the signature written to \a sig.
 *
 * \return Zero if successful, -ve error code otherwise.
 */
int8_t STZ_signUsingKey(pd_slot_t slot, const uint8_t *hash, uint16_t hlen,
						uint8_t *sig, uint16_t sb_len, uint16_t *sig_len);

/** Verify a hash using the (private) key in a given slot.
 *
 * \param slot Index of slot holding key to use.
 * \param[in] hash Address of buffer holding hash to be verified.
 * \param hlen Length of buffer pointed to by \a hash.
 * \param[in] sig Address of buffer holding signature to use.
 * \param slen Length of buffer pointed to by \a sig.
 *
 * \return Zero if successful, -ve error code otherwise.
 */
int8_t STZ_verifyUsingKey(pd_slot_t slot, const uint8_t *hash, uint16_t hlen,
						  const uint8_t *sig, uint16_t slen);

/** Generate a shared secret from a private and public key.
 *
 * \param slot Index of slot holding private key.
 * \param[in] public_key Public key to be used.
 * \param[out] shared_secret Address of buffer to be populated with shared secret.
 *
 * \return zero if the shared secret is generated, non-zero otherwise.
 */
int8_t STZ_generateSharedSecret(pd_slot_t slot, const uint8_t *public_key,
								uint8_t *shared_secret);

/**
 * Get the SBM information.
 *
 * \param[out] sbm_ver A pointer to a buffer to receive the SBM version (\c SECURE_API_SBM_VER_STR_SIZE).
 * \param[in, out] sbm_ver_len The address of a \c uint32_t containing the length of the buffer pointed to by \a sbm_ver.
 * \param[out] sbm_build_time A pointer to a buffer to receive the SBM build time (\c SECURE_API_SBM_TIME_STR_SIZE).
 * \param[in, out] sbm_build_time_len The address of a \c uint32_t containing the length of the buffer pointed to by \a sbm_build_time.
 * \param[out] provisioned_ver A pointer to a buffer to receive the provisioned data version (\c SECURE_API_PROV_VER_STR_SIZE).
 * \param[in, out] provisioned_ver_len The address of a \c uint32_t containing the length of the buffer pointed to by \a provisioned_ver.
 * \param[out] provisioned_time A pointer to a buffer to receive the provsioned data time (\c SECURE_API_PROV_TIME_STR_SIZE).
 * \param[in, out] provisioned_time_len The address of a \c uint32_t containing the length of the buffer pointed to by \a provisioned_time.
 * \param[out] provisioning_machine A pointer to a buffer to receive the provisioning machine (\c SECURE_API_PROV_MACH_STR_SIZE).
 * \param[in, out] provisioning_machine_len The address of a \c uint32_t containing the length of the buffer pointed to by \a provisioning_machine.
 *
 * On success, the value held in the objects pointed to by each of the length arguments
 * will be populated with the number of bytes written to the corresponding buffer.
 *
 * If any data is unavailable, the buffer will be populated with
 * an empty string <em>but the corresponding length will be set to zero</em>.
 * If the data \e is available but empty, the corresponding length will be set to one.
 * In either case the calling application may print the string without consulting the length.
 *
 * If the \c SECURE_API_ERR_BUFFER_SIZE_INVALID error is returned, each buffer that is large
 * enough to receive the data (and its corresponding length) will be populated as above
 * and each buffer that is too small will not be populated but its length will be
 * populated with the minimum size required to make a successful call.
 *
 * \return Zero if all the SBM information has been successfully copied, -ve error code otherwise.
 */
int8_t STZ_getSBMInformation(char *sbm_ver, uint32_t *sbm_ver_len,
							 char *sbm_build_time, uint32_t *sbm_build_time_len,
							 char *provisioned_ver, uint32_t *provisioned_ver_len,
							 char *provisioned_time, uint32_t *provisioned_time_len,
							 char *provisioning_machine, uint32_t *provisioning_machine_len);

/** Install a Secure API error handler function.
 *
 * \brief The handler will be invoked if the Secure API call gate detects
 *        a problem with the parameters passed into or out of the SBM.
 *
 * \param handler Pointer to handler function.
 */
void STZ_installSecureApiErrorHandler(void (*handler)(const char *error_str,
													  const char *api_fn_str));

/** Get the update slot information.
 *
 * \param update_slot_id The ID of the selected update slot.
 * \param start_address The offset (in bytes) from the device's base address where the update is installed.
 * \param slot_size The size (in bytes) of the update slot.
 *
 * \return zero if the update slot information has been successfully returned.
 */
int8_t STZ_getUpdateSlotInfo(uint32_t *update_slot_id, uint32_t *start_address, uint32_t *slot_size);

/** Get the update information.
 *
 * \param status The status of the update present.
 * \param uuid A buffer for the uuid to be stored.
 * \param uuid_length The length of uuid, the required length will be written back to uuid_length
 *                    by the SBM.
 *
 * \return zero if the update information has been successfully returned.
 */
int8_t STZ_getUpdateInfo(uint32_t *status, uint8_t *uuid, uint16_t *uuid_length);

/** Check the validity of the update slot
 *
 * \return SECURE_API_RETURN_SUCCESS if the slot is valid, otherwise return SECURE_API_ERR_COMMAND_FAILED.
 */
int8_t STZ_checkUpdateSlot(void);

/** Install the update by resetting the device.
 *
 * This will only return if the update validity check fails, otherwise the device
 * will be reset.
 *
 * \return SECURE_API_ERR_COMMAND_FAILED on failure.
 */
int8_t STZ_installUpdate(void);

/** Get the application information.
 *
 * \param num_apps The SBM will write the number of supported applications to this address, the
 *                 application will then know how many records there is in app_info_records.
 * \param app_info_records An array of application records, the SBM will write a record of
 *                 type "app_info_record" for each supported application into this array.
 * \param app_info_records_length The length of app_info_records, the required length will be
 *                                written back to app_info_records_length by the SBM.
 *
 * \return zero if the application information has been successfully returned.
 */
int8_t STZ_getApplicationInfo(uint8_t *num_apps, app_info_record *app_info_records,
							  uint16_t *app_info_records_length);

/** Commence a write operation on the update slot.
 *
 * \brief This will erase the update slot's current contents in preparation for writing a new update.
 *        The current update slot offset will be set to zero. The update slot which is active
 *        at the moment of calling this function will be used consistently throughout the whole
 *        installation process, even if the active slot is changed before the final call to
 *        #STZ_updateSlotEndWrite.
 *
 * \param write_size The SBM will write the underlying Flash device's minimum write size to this address.
 *
 * \return zero on success, else SECURE_API_ERR_COMMAND_FAILED on failure.
 */
int8_t STZ_updateSlotBeginWrite(uint32_t *write_size);

/** Complete a write operation on the update slot.
 *
 * This finalises the contents of the update slot in preparation for installation.
 *
 * \return zero on success, else SECURE_API_ERR_COMMAND_FAILED on failure.
 */
int8_t STZ_updateSlotEndWrite(void);

/** Write a chunk of data to the update slot.
 *
 * \brief The supplied buffer will be written to the current offset within the update slot. The
 *        offset will then be incremented by the supplied number of \a bytes.
 *
 * \param buffer Pointer to buffer containing the data to be written to the update slot. The
 *               buffer must be aligned to a 32-bit boundary.
 * \param bytes Number of bytes in the buffer. This must be a non-zero multiple of the write
 *              size value returned by the call to STZ_updateSlotBeginWrite().
 *
 * \return zero on success, else SECURE_API_ERR_COMMAND_FAILED on failure.
 */
int8_t STZ_updateSlotWrite(const void *buffer, size_t size);

/** Obtain SBM performance figures.
 *
 * \param boot_time Address of uint32_t to recieve total SBM boot time.
 * \param sbm_size Address of uint32_t to recieve SBM size.
 * \param pd_size Address of uint32_t to recieve provisioned data size.
 * \param watchdog_period Unused.
 * \param watchdog_max_period Unused.
 * \param watchdog_max_activity_start Unused.
 * \param watchdog_max_activity_end Unused.
 * \param sbm_stack_size Unused.
 * \param sbm_stack_used Unused.
 *
 * \return zero on success, else SECURE_API_ERR_COMMAND_FAILED on failure.
 */
int8_t STZ_getSBMPerformance(uint32_t *boot_time, uint32_t *sbm_size,
							 uint32_t *pd_size, uint32_t *watchdog_period,
							 uint32_t *watchdog_max_period,
							 uint32_t *watchdog_max_activity_start,
							 uint32_t *watchdog_max_activity_end,
							 uint32_t *sbm_stack_size,
							 uint32_t *sbm_stack_used);

/** Select an active update slot.
 *
 * \brief This allows to select a specific update slot in case several are defined.
 *
 * \param slot_id ID of a slot to select.
 *
 * \return zero on success, else SECURE_API_ERR_COMMAND_FAILED on failure.
 */
int8_t STZ_setActiveUpdateSlot(uint32_t slot_id);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_API_EXPORT_H */
