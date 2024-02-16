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

#ifndef DATASTORE_H
#define DATASTORE_H

/** \file
 * \brief Provides access to provisioned data.
 */

#include <stdint.h>

#include "ecies_crypto.h"
#include "secureApiData.h"
#include "secureApiReturnCodes.h"

/* Provisioning information slot sub-types ... */
#define PROVISIONING_SUMMARY 0U /**< Security world/context. */
#define PROVISIONING_DETAILS 1U /**< Provisioning date, time etc. */

#ifndef SBM_PDB_MAX_SIZE
#define SBM_PDB_MAX_SIZE 4096
#endif /* SBM_PDB_MAX_SIZE */

/* Structures in the provisioning data slots ... */

typedef struct
{
	uint8_t context_uuid[16]; /**< Binary security context UUID. */
	uint16_t iteration; /**< Binary security context freeze number. */
	uint16_t padding;
	uint8_t optional_elements[];
} provisioning_summary;

typedef struct
{
	uint8_t context_uuid_iteration[40]; /**< Textual security contex UUID/freeze number. */
	uint8_t date_time[20]; /**< Textual provisioning time YYYY/MM/DD HH:MM:SS. */
	uint8_t machine_uuid[36]; /**< Textual UUID or MAC address of provisioning machine. */
	uint8_t optional_elements[];
} provisioning_details;

#define SBM_PPD_SEED_BYTE_COUNT 16U
#define SBM_PPD_HASH_256_BYTE_COUNT 32U

/** Provisioned Summary Record. */
typedef struct
{
	uint16_t presence; /**< Set to value of #PSR_PRESENT. */
	uint16_t reserved_0;
	uint8_t  pd_pc_seed[SBM_PPD_SEED_BYTE_COUNT];
	uint8_t  pd_pc_hash[SBM_PPD_HASH_256_BYTE_COUNT];
	uint32_t capability;
	uint32_t length;
	uint16_t data_slots; /**< Number of provisioned data slots. */
	uint16_t reserved_1;
	uint32_t pdsh_offset; /**< Offset (from \link psr PSR\endlink) to \link pdsh_only Provisioned Data Slot Headers\endlink. */
	uint16_t pdsf_offset; /**< Offset (from \link psr PSR\endlink) to \link pdsf Provisioned Data Security Footer\endlink. */
	uint16_t krd_offset; /**< Offset (from \link psr PSR\endlink) to \link krd Key Reference Data\endlink. */
	uint8_t reserved[8];
} psr;

/** Provisioned Data Security Footer. */
typedef struct
{
	uint32_t encryption_key_algo; /* Not used */
	uint32_t authentication_key_algo; /* Not used */
	uint16_t encrypted_start_offset;
	uint16_t encrypted_end_offset;
	uint16_t mac_length;
	uint16_t iv_length;
	/* Variable length fields below */

	/* uint8_t mac[]; */
	/* uint8_t iv[]; */
	/* uint8_t krd[]; */
} pdsf;

#if (SBM_ENABLE_LOG_DATASTORE != 0) && (SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO)
#define DATASTORE_DEBUG
#ifdef DATASTORE_DEBUG
void datastore_dump(void);
#endif /* DATASTORE_DEBUG */
#endif /* (SBM_ENABLE_LOG_DATASTORE != 0) && (SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO) != 0 */

/** Yield the address of the provisioning data summary.
 *
 * \return The address of the provisioning data summay if available, NULL otherwise.
 *
 * \note Called during boot process and from a secure API context.<br>
 * When called from a secure API context, logging must be disabled (see sbm_log_disable()).
 */
const provisioning_summary *datastore_provisioning_data_summary(void);

/** Determine if any provisioned data is present.
 *
 * For the SBM to function it must have been "provisioned" and
 * the summary of the provisioning process must be present.
 *
 * - The PDOR must be non-zero (it must hold the offset to the PSR).
 * - The PSR "presence" field must be correctly set.
 * - The PSR "data_slots" field must be non-zero and contain
 * a value which will fit into a (signed) int8_t.
 * - The provisoning data summary must be present and readable.
 *
 * \return \b true if there is provisioned data, \b false if there isn't.
 *
 * \note Because this function can generate log output,
 * it can only called during the boot process.
 */
bool datastore_data_present(void);

/** Measure SBM code and provisioned data sizes.
 *
 * \param sbm_size Address of uint32_t to receive size of SBM.
 * \param pd_size Address of uint32_t to receive size of provisioned data.
*/
void datastore_calculate_sizes(uint32_t *sbm_size, uint32_t *pd_size);

#if SBM_REPORT_SBM_SIZES != 0
/** Measure and report SBM code and provisioned data sizes.
 *
 * Calls datastore_calculate_sizes() to do the measurement and prints a report.
*/
void datastore_report_sizes(void);
#endif

/** Count provisioned slots holding data of specified type and usage class.
 *
 * \param s_type Slot type to search for.
 * \param usage Certificate/key usage class to search for.
 * \param search_mask Mask of bits in \a s_type to match during search.
 *
 * \return Number of slots matching criteria, -ve error code otherwise.
 */
int8_t datastore_count(const uint16_t s_type, const uint16_t usage, const uint16_t search_mask);

/** Find a given slot holding data of specified type and usage class.
 *
 * Find the <em>instance</em>th slot matching criteria.
 *
 * \param s_type Slot type to search for.
 * \param usage Certificate/key usage class to search for.
 * \param instance The instance to find.
 * \param search_mask Mask of bits in \a s_type to match during search.
 *
 * \return Index of required slot if found, -ve error code otherwise.
 */
pd_slot_t datastore_find(const uint16_t s_type, const uint16_t usage, const uint8_t instance, const uint16_t search_mask);

/** Yield the address of the data in a given slot.
 *
 * \param slot Slot index to read.
 * \param data Address of pointer to be populated with address of data.
 * \param len Address of uint16_t to be populated with length of data.
 *
 * \return Zero on success, -ve API error code otherwise.
 */
int8_t datastore_slot_data(const pd_slot_t slot, const void **const data, uint16_t *const len);

/** Copy data from a given slot.
 *
 * If the buffer is too small to receive the data, no data
 * is copied but the required size is written to the object
 * pointed to by the \a data_len argument.
 *
 * \param slot Slot index to read.
 * \param[out] buf Address of buffer to write.
 * \param buf_len Length of buffer pointed to by \a buf.
 * \param[out] data_len Address of a uint16_t to populate with the length of the data written to \a buf.
 *
 * \return Zero on success, -ve error code otherwise.
 */
int8_t datastore_copy_data(const pd_slot_t slot, uint8_t *const buf,
                           const uint16_t buf_len, uint16_t *const data_len);

/** Find the parent of a given slot.
 *
 * \param slot Slot index to interrogate.
 *
 * \return Index of <em>slot</em>'s parent if found, -ve error code otherwise.
 */
pd_slot_t datastore_parent(const pd_slot_t slot);

/** Find the slot containing the key assocaited with a given certificate.
 *
 * If the caller supplies the number of a slot that doesn't carry a certificate,
 * this results in a "slot type mismatch" error.
 *
 * If the caller supplies the number of a slot that does carry a
 * certificate, but that certificate doesn't have an associated
 * identity key, this results in a "no matching slot found" error.
 * The key slot number may be bogus or refer to
 * a slot that doesn't contain an identity key.
 *
 * \param cert_slot Slot index of certificate to interrogate.
 * \param[out] key_type Address of a uint16_t to populate with the key type if found.
 *
 * \return Index of <em>cert_slot</em>'s key_slot if found, -ve error code otherwise.
 */
pd_slot_t datastore_find_cert_key(const pd_slot_t cert_slot, uint16_t *const key_type);

/** Extract the key details from a given slot.
 *
 * \param slot Index of slot to interrogate.
 * \param[out] key_type Address of a uint16_t to populate with the key type if found.
 * \param[out] key_usage Address of a uint16_t to populate with the key usage class if found.
 * \param[out] public_key Address of a buffer to populate with the public key if found.
 *
 * \note \a public_key must point to a buffer of at least uECC_BYTES * 2 bytes.
 *
 * \return Zero on success, -ve error code otherwise.
 */
int8_t datastore_key_details(const pd_slot_t slot, uint16_t *const key_type,
                             uint16_t *const key_usage, uint8_t *const public_key);

typedef uint8_t private_key_t[32]; /**< Carries a private key. */

/** Extract the address of a private key from a given slot.
 *
 * \param slot Index of slot to interrogate.
 * \param[out] private_key Address of a pointer to populate with the address of the private key if found.
 *
 * \return Zero on success, -ve error code otherwise.
 */
int8_t datastore_private_key(const pd_slot_t slot, const private_key_t **const private_key);

/** Extract the address of a public key from a given slot.
 *
 * \param slot Index of slot to interrogate.
 * \param[out] public_key Address of a pointer to populate with the address of the public key if found.
 *
 * \return Zero on success, -ve error code otherwise.
 */
int8_t datastore_public_key(const pd_slot_t slot, const EccPublicKey **const public_key);

/** Sign a hash using the key from a given slot.
 * \param slot Slot index of private key to use.
 * \param[in] hash Address of hash to sign.
 * \param hlen Length of buffer pointed to by \a hash.
 * \param[out] sig Address of buffer to populate with signature.
 * \param[out] sig_len Address of uint16_t to populate with length of data written to \a sig.
 *
 * \return Zero on success, -ve error code on failure.
 */
int8_t datastore_sign(const pd_slot_t slot, const uint8_t *const hash, const uint16_t hlen,
                      uint8_t *const sig, uint16_t *const sig_len);

/** Verify the signature over a hash using the key from a given slot.
 *
 * \param slot Slot index of public key to use.
 * \param[in] hash Address of hash to verify.
 * \param hlen Length of buffer pointed to by \a hash.
 * \param[in] sig Address of signature to verify.
 * \param sig_len Length of buffer pointed to by \a sig.
 *
 * \return Zero on success, -ve error code on failure.
 */
int8_t datastore_verify(const pd_slot_t slot, const uint8_t *const hash, const uint16_t hlen,
                        const uint8_t *const sig, const uint16_t sig_len);

/** Generate a shared secret from a provisioned private key and a supplied public key.
 *
 * \param slot Slot index of private key to use.
 * \param[in] public_key Address of public key to use.
 * \param[out] secret Address of buffer to populate with generated secret.
 *
 * \return Zero on success, -ve error code on failure.
 */
int8_t datastore_shared_secret(const pd_slot_t slot, const uint8_t *const public_key, uint8_t *const secret);

#if SBM_PROVISIONED_DATA_ENCRYPTED != 0
/** Decrypt the PDB into a RAM buffer internal to datastore
 *
 * WARNING! datastore_clear_plaintext_pdb must be called after the PDB has been used
 *          to ensure the plaintext data is cleared.
 *
 * \return true on success, else false
 */
bool datastore_verify_and_decrypt_pdb(void);

/** Clear the plain text PDB buffer internal to datastore */
void datastore_clear_plaintext_pdb(void);
#endif /* SBM_PROVISIONED_DATA_ENCRYPTED != 0 */

#if SBM_PPD_ENABLE != 0
/** Examine the PSR, calculate the hash and verify it.
 *
 * \return true on success, false on failure.
 */
bool datastore_hash_check(void);
#endif /* SBM_PPD_ENABLE */

#endif /* DATASTORE_H */
