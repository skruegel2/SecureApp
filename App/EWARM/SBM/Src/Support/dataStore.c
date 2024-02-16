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
 * \brief Provisioned data access functions.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "benchmark.h"
#include "dataStore.h"
#include "sbm_api.h"
#include "sbm_memory.h"
#include "sbm_log_datastore.h"
#include "sbm_log_sizes.h"

#include "sha256_wrapper.h"
#include "assert.h"

#include "memoryMap.h"
#if SBM_REPORT_SBM_SIZES != 0
#include "oem.h"
#endif /* SBM_REPORT_SBM_SIZES != 0 */
#if SBM_PPD_ENABLE !=0
#include "sbm_hal_soc.h"
#endif /* SBM_PPD_ENABLE */
#include "ecc.h"

/* Values for tlv.t in slot data */
#define TLV_X509_CERTIFICATE 0x1U
#define TLV_IMMEDIATE_PUBLIC_KEY 0x10U
#define TLV_IMMEDIATE_PRIVATE_KEY 0x11U
#include "sbm_hal_crypto.h"

#ifndef SBM_PC_BUILD

/** Provisioned Data Offset Register.
 *
 * This is a key variable: we want it to be constant because, at run time,
 * it is. As a consequence, accesses to it can be optimised as much as
 * needed. What we cannot allow an optimiser to do is to assume it knows
 * the value in the variable as this will be changed during provisioning.
 * This seems a bit like volatility but it isn't - it doesn't change
 * at run time (it really is constant and only really needs to be read
 * once). There is nothing we can write in C source to inform the compiler,
 * optimiser or linker that the value may change between linking and
 * execution so we have to use proprietary language extensions.
 *
 * For the IAR toolchain, \c __ro_placement does what we need.
 */
__ro_placement
static const uint32_t pd_offset_reg @ "PDOR";
#else
extern void *pd_offset_reg;
#endif /* SBM_PC_BUILD */

/* Masks and shifts for capabilities within the capability word */
#define CAPABILITY_PDB_ENCRYPTED_MASK  (0x1)
#define CAPABILITY_PDB_ENCRYPTED_SHIFT (0)

#define PSR_SIZE 80U
static_assert(sizeof(psr) == PSR_SIZE, "psr invalid size");
#if SBM_PPD_ENABLE !=0
#define SEED_HASHABLE_LENGTH (SBM_PPD_SEED_BYTE_COUNT + SBM_PPD_SECURITY_CONTEXT_RANDOM_BYTE_COUNT + UNIQUE_ID_SIZE)
#endif /* SBM_PPD_ENABLE */

#include "dataStore_types.h"

#if SBM_PROVISIONED_DATA_ENCRYPTED == 0
/** Address of the \link psr Provisioning Summary Record\endlink. */
#ifndef SBM_PC_BUILD
static const uintptr_t pd_offset_reg_address = (uintptr_t)&pd_offset_reg;

#define PSR_ADDRESS (pd_offset_reg_address + pd_offset_reg)
#else
#define PSR_ADDRESS (pd_offset_reg)
#endif /* SBM_PC_BUILD */

#else /* SBM_PROVISIONED_DATA_ENCRYPTED != 0 */

#ifdef SBM_PC_BUILD
extern uint8_t plaintext_provisioned_data_ram[SBM_PDB_MAX_SIZE];
extern const uintptr_t pd_offset_reg_address;

extern const psr * ENCRYPTED_PDB_PTR;
#define PSR_ADDRESS (plaintext_provisioned_data_ram)
#else
static uint8_t plaintext_provisioned_data_ram[SBM_PDB_MAX_SIZE] SBM_PERSISTENT_RAM;

static const uintptr_t pd_offset_reg_address = (uintptr_t)&pd_offset_reg;

#define ENCRYPTED_PDB_PTR ((const psr *)(pd_offset_reg_address + pd_offset_reg))
#define PSR_ADDRESS (plaintext_provisioned_data_ram)
#endif /* SBM_PC_BUILD */


#endif /* SBM_PROVISIONED_DATA_ENCRYPTED != 0 */

/** Pointer to a constant psr structure that facilitates access to the \link psr Provisioning Summary Record\endlink content. */
#define PSR ((const psr *)PSR_ADDRESS)

/** Pointer to a constant pdsh_data structure that facilitates access to the \link pdsh_data Provisioned Data Slot Headers\endlink content. */
#define PDSH_DATA ((const pdsh_data *) (PSR_ADDRESS + PSR->pdsh_offset))
#define PDSH_USAGE ((const pdsh_usage *) (PSR_ADDRESS + PSR->pdsh_offset))
#define PDSH_CERT ((const pdsh_cert *) (PSR_ADDRESS + PSR->pdsh_offset))
#define PDSH_UPDATE_KEY ((const pdsh_update_key *) (PSR_ADDRESS + PSR->pdsh_offset))

/** Pointer to a constant uint8_t that facilitates access to a given slot's data content. */
/** Address of a given slot's data. */
#define SLOT_DATA(n) ((const uint8_t *)(PSR_ADDRESS + PDSH_DATA[n].slot_offset))

#define FLASH_ERASE_VALUE 0xFFFFU /* PSR_PRESENT is defined referenced against the flash erase value */
#define PSR_PRESENT (FLASH_ERASE_VALUE ^ 0x8888)/**< Expected value of psr.presence. */
#define SBM_PPD_SECURITY_CONTEXT_RANDOM_BYTE_COUNT 4U

/** Check if a data slot index is invalid.
 *
 * \param S Slot index to test.
 * \param M Maximum value to test against (psr.data_slots).
 *
 * The Minimum value is always zero.
 *
 * \return \b true if the index appears invalid, \b false if it looks good.
 */
#define PD_SLOT_INVALID(S, M) ((S) < 0 || (S) >= (M))

#if defined(DATASTORE_DEBUG) || defined(SBM_PC_BUILD)
static void dump_provisioning_data_summary(const void *const data, const size_t data_size)
{
#if (SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO) && (SBM_ENABLE_LOG_DATASTORE != 0)
    SBM_LOG_DATASTORE_INFO("provisioning data summary:");
    const provisioning_summary *const d = data;
    for (size_t i = 0; i < sizeof d->context_uuid; ++i)
        SBM_PRINTF_DATASTORE_INFO(" %02" PRIx8, d->context_uuid[i]);
    SBM_PRINTF_DATASTORE_INFO(" 0x%" PRIx16 "\n", d->iteration);
#endif /* (SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO) && (SBM_ENABLE_LOG_DATASTORE != 0) */
}

static void dump_provisioned_details(const void* const data, const size_t data_size)
{
#if (SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO) && (SBM_ENABLE_LOG_DATASTORE != 0)
    const provisioning_details *const d = data;
    SBM_LOG_DATASTORE_INFO("UUID/freeze: %.*s\n", (int)sizeof d->context_uuid_iteration, d->context_uuid_iteration);
    SBM_LOG_DATASTORE_INFO("date/time: %.*s\n", (int)sizeof d->date_time, d->date_time);
    SBM_LOG_DATASTORE_INFO("machine: %.*s\n", (int)sizeof d->machine_uuid, d->machine_uuid);
#endif /* (SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO) && (SBM_ENABLE_LOG_DATASTORE != 0) */
}

void datastore_dump(void)
{
    if (!pd_offset_reg)
    {
        SBM_LOG_DATASTORE_INFO("pd_offset_reg at 0x%p: no provisioned data\n", &pd_offset_reg);
        return;
    }

    SBM_LOG_DATASTORE_INFO("pd_offset_reg at 0x%p: 0x%" PRIxPTR "\n", &pd_offset_reg, (uintptr_t)pd_offset_reg);
    SBM_LOG_DATASTORE_INFO("psr 0x%p { 0x%" PRIx16 ", 0x%" PRIx16 ", 0x%" PRIx32 " }\n", PSR,
               PSR->presence, PSR->data_slots, PSR->pdsh_offset);

    if (PSR_PRESENT != PSR->presence || PSR->data_slots == 0)
        return;

    if (PSR->data_slots > INT8_MAX)
    {
        SBM_LOG_DATASTORE_INFO("psr data slot count invalid: 0x%" PRIx16 "\n",
                   PSR->data_slots);
        return;
    }

    for (int slot = 0; slot < PSR->data_slots; ++slot)
    {
        SBM_LOG_DATASTORE_INFO("PDSH %d 0x%p { 0x%" PRIx16 ", 0x%" PRIx8 ", 0x%" PRIx32
                   ", 0x%" PRIx16 ", 0x%" PRIx16,
                   slot, PDSH_DATA + slot,
                   PDSH_DATA[slot].sh_type,
                   PDSH_DATA[slot].device,
                   PDSH_DATA[slot].slot_offset,
                   PDSH_DATA[slot].slot_size,
                   PDSH_USAGE[slot].usage);

        if (SLOT_PURPOSE_IDENTITY_CERT == SLOT_PURPOSE(PDSH_DATA[slot].sh_type))
            SBM_PRINTF_DATASTORE_INFO(", 0x%" PRIx16 ", 0x%" PRIx8,
                       PDSH_CERT[slot].parent_id, PDSH_CERT[slot].key_slot);

        SBM_PRINTF_DATASTORE_INFO(" }\n");

        /* At the moment, all slot types have a data slot.
           In future, some may not */
        switch (SLOT_PURPOSE(PDSH_DATA[slot].sh_type))
        {
            case SLOT_PURPOSE_IDENTITY_CERT:
                switch (SLOT_SUBTYPE(PDSH_DATA[slot].sh_type) & CERT_LEVEL_MASK)
                {
                case CERT_LEVEL_DEVICE:
                    SBM_LOG_DATASTORE_INFO("Slot contains a device certificate.\n");
                    break;
                case CERT_LEVEL_INTERMEDIATE:
                    SBM_LOG_DATASTORE_INFO("Slot contains an intermediate certificate.\n");
                    break;
                case CERT_LEVEL_ROOT:
                    SBM_LOG_DATASTORE_INFO("Slot contains a root certificate.\n");
                    break;
                default:
                    SBM_LOG_DATASTORE_INFO("Unknown identity certificate type.\n");
                    break;
                }
                break;
            case SLOT_PURPOSE_IDENTITY_KEY:
                SBM_LOG_DATASTORE_INFO("IDENTITY_KEY\n");
                break;
            case SLOT_PURPOSE_TRUST_ANCHOR_KEY:
                SBM_LOG_DATASTORE_INFO("TRUST_ANCHOR_KEY\n");
                break;
            case SLOT_PURPOSE_UPDATE_KEY:
                switch(PDSH_UPDATE_KEY[slot].purpose)
                {
                    case KEY_PURPOSE_DEVICE_UPDATE:
                        SBM_LOG_DATASTORE_INFO("Device (or group) SWUP update key.\n");
                        break;
                    case KEY_PURPOSE_OEM_VALIDATION:
                        SBM_LOG_DATASTORE_INFO("OEM SWUP validation key.\n");
                        break;
                    case KEY_PURPOSE_OEM_TRANSPORTATION:
                        SBM_LOG_DATASTORE_INFO("OEM SWUP transportion key.\n");
                        break;
                    case KEY_PURPOSE_PU_VALIDATION:
                        SBM_LOG_DATASTORE_INFO("Power up validation key.\n");
                        break;
                    default:
                        SBM_LOG_DATASTORE_INFO("Unknown identity update key type.\n");
                        break;
                }
                tlv_dump(SLOT_DATA(slot), PDSH_DATA[slot].slot_size);
                break;
            case SLOT_PURPOSE_PROVISION_INFO:
                SBM_LOG_DATASTORE_INFO("PROVISION_INFO\n");
                switch(SLOT_SUBTYPE(PDSH_DATA[slot].sh_type))
                {
                    case PROVISIONING_SUMMARY:
                        SBM_LOG_DATASTORE_INFO("Subtype: SUMMARY\n");
                        dump_provisioning_data_summary(SLOT_DATA(slot), PDSH_DATA[slot].slot_size);
                        break;
                    case PROVISIONING_DETAILS:
                        SBM_LOG_DATASTORE_INFO("Subtype: DETAILS\n");
                        dump_provisioned_details(SLOT_DATA(slot), PDSH_DATA[slot].slot_size);
                        break;
                    default:
                        break;
                }
                break;
            default:
                break;
        }
    }
}
#endif /* DATASTORE_DEBUG || SBM_PC_BUILD */

const provisioning_summary *datastore_provisioning_data_summary(void)
{
    /* Find the slot containing it */

    const pd_slot_t pss = datastore_find(SLOT_PURPOSE_PROVISION_INFO | PROVISIONING_SUMMARY,
                                         0U, 0U, SLOT_PURPOSE_MASK | SLOT_SUBTYPE_MASK);
    if (pss < 0)
    {
        SBM_LOG_DATASTORE_ERROR("cannot find provisioning data summary slot: %" PRId8 "\n", pss);
        return NULL;
    }

    /* Obtain the pointer to it */

    const provisioning_summary *provisioning_data_summary;
    uint16_t pss_len;
    const int8_t r = datastore_slot_data(pss, (const void **) &provisioning_data_summary, &pss_len);
    if (r)
    {
        /* This failure can only happen if the slot number is corrupted after we obtained it. */
        SBM_LOG_DATASTORE_ERROR("cannot find provisioning data summary: %" PRId8 "\n", r);
        return NULL;
    }

    /* Make sure it's large enough to be plausible */

    if (pss_len < sizeof *provisioning_data_summary)
    {
        SBM_LOG_DATASTORE_ERROR("provisioning data summary too short: 0x%" PRIx16 "\n", pss_len);
        return NULL;
    }

    return provisioning_data_summary;
}

bool datastore_data_present(void)
{
    return pd_offset_reg && PSR_PRESENT == PSR->presence && PSR->data_slots &&
        PSR->data_slots <= INT8_MAX && datastore_provisioning_data_summary();
}

void datastore_calculate_sizes(uint32_t *const sbm_size, uint32_t *const pd_size)
{
    /* Look for the last byte of provisioned data (i.e. the byte
       with the largest offset from the PSR) this allows for the
       data associated with slot headers to appear in any order */

    *pd_size = UINT32_C(0);
    for (int slot = 0; slot < PSR->data_slots; ++slot)
    {
        /* Look for the end of the data for this slot */
        const uint32_t e = PDSH_DATA[slot].slot_offset + PDSH_DATA[slot].slot_size;
        if (e > *pd_size)
            *pd_size = e;
    }

    *sbm_size = (uint32_t) (uintptr_t) ((const uint8_t *) PSR - SOC_FLASH_START_ADDRESS);
}

#if SBM_REPORT_SBM_SIZES != 0
void datastore_report_sizes(void)
{
    uint32_t sbm_size, highest_offset;
    datastore_calculate_sizes(&sbm_size, &highest_offset);

    SBM_LOG_SIZES_INFO("SBM size:   0x%04" PRIx32 " (%" PRIu32 ")\n", sbm_size, sbm_size);
    SBM_LOG_SIZES_INFO("Data size:  0x%04" PRIx32 " (%" PRIu32 ")\n", highest_offset, highest_offset);
    SBM_LOG_SIZES_INFO("Total size: 0x%04" PRIx32 " (%" PRIu32 ")\n", sbm_size + highest_offset, sbm_size + highest_offset);

    oem_report_sbm_sizes(sbm_size, highest_offset);
}
#endif /* SBM_REPORT_SBM_SIZES != 0 */

int8_t datastore_count(const uint16_t s_type, const uint16_t usage, const uint16_t search_mask)
{
    int8_t r = 0;
    const pdsh_usage *sh = PDSH_USAGE;
    const int max_slots = PSR->data_slots;
    for (int i = 0; i < max_slots; ++i, ++sh)
        if ((sh->sh_type & search_mask) == (s_type & search_mask) &&
            (0U == usage || sh->usage == usage))
            ++r;

    return r;
}

pd_slot_t datastore_find(const uint16_t s_type, const uint16_t usage, const uint8_t instance, const uint16_t search_mask)
{
    uint8_t n = 0U;
    const pdsh_usage *sh = PDSH_USAGE;
    const int max_slots = PSR->data_slots;
    for (int i = 0; i < max_slots; ++i, ++sh)
        if ((sh->sh_type & search_mask) == (s_type & search_mask) &&
            (0U == usage || sh->usage == usage))
        {
            if (instance == n)
                return i;
            ++n;
        }

    return SECURE_API_ERR_NO_MATCHING_SLOT_FOUND;
}

int8_t datastore_slot_data(const pd_slot_t slot, const void **const data, uint16_t *const len)
{
    if (PD_SLOT_INVALID(slot, PSR->data_slots))
        return SECURE_API_ERR_SLOT_OUT_OF_RANGE;

    *data = SLOT_DATA(slot);
    *len = PDSH_DATA[slot].slot_size;

    return SECURE_API_RETURN_SUCCESS;
}

static int8_t datastore_slot_type(const pd_slot_t slot, uint16_t *ptype)
{
    if (PD_SLOT_INVALID(slot, PSR->data_slots))
        return SECURE_API_ERR_SLOT_OUT_OF_RANGE;

    *ptype = PDSH_DATA[slot].sh_type;

    return SECURE_API_RETURN_SUCCESS;
}

int8_t datastore_copy_data(const pd_slot_t slot, uint8_t *const buf,
                           const uint16_t buf_len, uint16_t *const data_len)
{
    uint16_t type;
    int8_t rv;

    rv = datastore_slot_type(slot, &type);
    if (rv != SECURE_API_RETURN_SUCCESS)
        return rv;

        /* This may only be used to copy certificates.
           Keys cannot be copied. An attempt to copy
           a key is either a bug or an attempt to breach security. */

    if (SLOT_PURPOSE(type) != SLOT_PURPOSE_IDENTITY_CERT)
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    const uint8_t *cert;
    uint16_t c_len;
    if (tlv_find_node(SLOT_DATA(slot), PDSH_DATA[slot].slot_size,
                      TLV_X509_CERTIFICATE, &cert, &c_len))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    *data_len = c_len;

    if (buf_len < c_len)
        return SECURE_API_ERR_BUFFER_SIZE_INVALID;

    memcpy(buf, cert, c_len);

    return SECURE_API_RETURN_SUCCESS;
}

pd_slot_t datastore_parent(const pd_slot_t slot)
{
    uint16_t type;
    int8_t rv;

    rv = datastore_slot_type(slot, &type);
    if (rv != SECURE_API_RETURN_SUCCESS)
        return (pd_slot_t)rv;

    if (SLOT_PURPOSE(type) != SLOT_PURPOSE_IDENTITY_CERT)
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    return PDSH_CERT[slot].parent_id;
}

pd_slot_t datastore_find_cert_key(const pd_slot_t cert_slot, uint16_t *const key_type)
{
    uint16_t type;
    int8_t rv;

    /* Make sure the slot number supplied is in range... */

    rv = datastore_slot_type(cert_slot, &type);
    if (rv != SECURE_API_RETURN_SUCCESS)
        return (pd_slot_t)rv;

    /* ...and the slot contains a certificate.
       If it doesn't, the error is the responsibility of the
       caller: it needs to provide a different slot number */

    if (SLOT_PURPOSE(type) != SLOT_PURPOSE_IDENTITY_CERT)
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    /* Any further errors are caused by the SBM being unable to find what
       the caller is looking for in the certificate's key slot.
       If these errors occur, there's little that the caller can do:
       the provisioned ata needs to be trawled to find the cause */

    const pd_slot_t key_slot = PDSH_CERT[cert_slot].key_slot;

    /* Is the certificate's key slot number bogus? */

    rv = datastore_slot_type(key_slot, &type);
    if (rv != SECURE_API_RETURN_SUCCESS)
        return (pd_slot_t)rv;

    /* Does the certificate's key slot contain a key? */

    if (SLOT_PURPOSE(type) != SLOT_PURPOSE_IDENTITY_KEY)
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    /* Looking good: the certificate has an associated identity key.
       Yield its type and return its index */

    *key_type = SLOT_SUBTYPE(type);

    return key_slot;
}

int8_t datastore_key_details(const pd_slot_t slot, uint16_t *const key_type,
                             uint16_t *const key_usage, uint8_t *const public_key)
{
    uint16_t type;
    int8_t rv;

    rv = datastore_slot_type(slot, &type);
    if (rv != SECURE_API_RETURN_SUCCESS)
        return rv;

    if (SLOT_PURPOSE(type) != SLOT_PURPOSE_IDENTITY_KEY)
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    *key_type = SLOT_SUBTYPE(type);
    *key_usage = PDSH_USAGE[slot].usage;

    const uint8_t *pub_key;
    uint16_t k_len;
    if (tlv_find_node(SLOT_DATA(slot), PDSH_DATA[slot].slot_size,
                      TLV_IMMEDIATE_PUBLIC_KEY, &pub_key, &k_len))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    memcpy(public_key, pub_key, k_len);

    return SECURE_API_RETURN_SUCCESS;
}

/** Extract the address of a key from a given slot.
 *
 * \param slot Index of slot to interrogate.
 * \param category Key category mask for which to search in slot headers.
 * \param tag TLV node tag for which to search within slot data.
 * \param[out] key Address of a pointer to populate with the address of the key if found.
 *
 * \return Zero on success, -ve error code otherwise.
 */
static int8_t datastore_key(const pd_slot_t slot, const uint16_t category, const uint16_t tag, const uint8_t **const key)
{
    uint16_t type;
    const int8_t rv = datastore_slot_type(slot, &type);
    if (rv != SECURE_API_RETURN_SUCCESS)
        return rv;

    switch (SLOT_PURPOSE(type)) {
    case SLOT_PURPOSE_IDENTITY_KEY:
    case SLOT_PURPOSE_TRUST_ANCHOR_KEY:
    case SLOT_PURPOSE_UPDATE_KEY:
        break;
    default:
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;
    }

    if (!(KEY_CATEGORY(type) & category))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    if (tlv_find_node(SLOT_DATA(slot), PDSH_DATA[slot].slot_size, tag, key, NULL))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    return SECURE_API_RETURN_SUCCESS;
}

int8_t datastore_private_key(const pd_slot_t slot, const private_key_t **const private_key)
{
    /* This may be called from datastore_sign() and datastore_shared_secret(),
       if we keep it */

    return datastore_key(slot, KEY_CATEGORY_PRIVATE, TLV_IMMEDIATE_PRIVATE_KEY, (const uint8_t **) private_key);
}

int8_t datastore_public_key(const pd_slot_t slot, const EccPublicKey **const public_key)
{
    return datastore_key(slot, KEY_CATEGORY_PUBLIC, TLV_IMMEDIATE_PUBLIC_KEY, (const uint8_t **) public_key);
}

int8_t datastore_sign(const pd_slot_t slot, const uint8_t *const hash, const uint16_t hlen,
                      uint8_t *const sig, uint16_t *const sig_len)
{
    uint16_t type;
    int8_t rv;

    rv = datastore_slot_type(slot, &type);
    if (rv != SECURE_API_RETURN_SUCCESS)
        return rv;

    if (SLOT_PURPOSE(type) != SLOT_PURPOSE_IDENTITY_KEY)
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    if (!(KEY_CATEGORY(type) & KEY_CATEGORY_PRIVATE))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    if (hlen < ECC_PRIVATE_KEY_SIZE)
        return SECURE_API_ERR_BUFFER_SIZE_INVALID;

    if (*sig_len < ECC_PUBLIC_KEY_SIZE)
    {
        *sig_len = ECC_PUBLIC_KEY_SIZE;
        return SECURE_API_ERR_BUFFER_SIZE_INVALID;
    }

    const uint8_t *private_key;
    if (tlv_find_node(SLOT_DATA(slot), PDSH_DATA[slot].slot_size,
                      TLV_IMMEDIATE_PRIVATE_KEY, &private_key, NULL))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    if (uECC_sign(private_key, hash, hlen, sig, uECC_CURVE()))
    {
        *sig_len = ECC_PUBLIC_KEY_SIZE;
        return SECURE_API_RETURN_SUCCESS;
    }

    return SECURE_API_ERR_COMMAND_FAILED;
}

int8_t datastore_verify(const pd_slot_t slot, const uint8_t *const hash, const uint16_t hlen,
                        const uint8_t *const sig, const uint16_t sig_len)
{
    uint16_t type;
    const int8_t rv = datastore_slot_type(slot, &type);
    if (rv != SECURE_API_RETURN_SUCCESS)
        return rv;

    switch (SLOT_PURPOSE(type)) {
    case SLOT_PURPOSE_IDENTITY_KEY:
    case SLOT_PURPOSE_TRUST_ANCHOR_KEY:
    case SLOT_PURPOSE_UPDATE_KEY:
        break;
    default:
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;
    }

    if (!(KEY_CATEGORY(type) & KEY_CATEGORY_PUBLIC))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    if (hlen < ECC_PRIVATE_KEY_SIZE || sig_len < ECC_PUBLIC_KEY_SIZE)
        return SECURE_API_ERR_BUFFER_SIZE_INVALID;

    const uint8_t *public_key;
    if (tlv_find_node(SLOT_DATA(slot), PDSH_DATA[slot].slot_size,
                      TLV_IMMEDIATE_PUBLIC_KEY, &public_key, NULL))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    sbm_benchmark_procedure_start(BENCHMARK_VERIFY_SIGNATURE);
    const int uvr = uECC_verify(public_key, hash, hlen, sig, uECC_CURVE());
    sbm_benchmark_procedure_stop(BENCHMARK_VERIFY_SIGNATURE);
    return uvr ? SECURE_API_RETURN_SUCCESS : SECURE_API_ERR_COMMAND_FAILED;
}

int8_t datastore_shared_secret(const pd_slot_t slot, const uint8_t *const public_key, uint8_t *const secret)
{
    uint16_t type;
    int8_t rv;

    rv = datastore_slot_type(slot, &type);
    if (rv != SECURE_API_RETURN_SUCCESS)
        return rv;

    if (SLOT_PURPOSE(type) != SLOT_PURPOSE_IDENTITY_KEY)
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    if (!(KEY_CATEGORY(type) & KEY_CATEGORY_PRIVATE))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    const uint8_t *private_key;
    if (tlv_find_node(SLOT_DATA(slot), PDSH_DATA[slot].slot_size,
                      TLV_IMMEDIATE_PRIVATE_KEY, &private_key, NULL))
        return SECURE_API_ERR_SLOT_TYPE_MISMATCH;

    return uECC_shared_secret(public_key, private_key, secret, uECC_CURVE()) ? SECURE_API_RETURN_SUCCESS :
                                                                 SECURE_API_ERR_COMMAND_FAILED;
}

#if SBM_PPD_ENABLE !=0
#if defined(DATASTORE_DEBUG) || defined(SBM_PC_BUILD) || !defined(NDEBUG)
/** Print the hash out in a useful format to read.
 * To make it easier to human parse we include an _ every 8 characters.
 *
 * \param The hash - or any long hex value - we want to print.
 * \param byte_count - the number of bytes in the value.
 */
static void print_hash_n(const uint8_t *const pHash, const int byte_count)
{
    /* Print out the hash in a nice format */
    for (int i=0; i<byte_count;++i) {
        SBM_PRINTF_DATASTORE_INFO("%02x", pHash[i]);
        if (((i&7)==7) && (i!=(byte_count-1)))
        {
            /* Print helpful delinators occasionally - this is a long string */
            SBM_PRINTF_DATASTORE_INFO("_");
        }
    }
}
#endif /* defined(DATASTORE_DEBUG) || defined(SBM_PC_BUILD) || !defined(NDEBUG) */

/** Copy data to a target address and return
 * the "next" target address suitable for appending.
 *
 * \param dst Address to write to.
 * \param src Address of data to read.
 * \param length Number of bytes to copy.
 *
 * \return Updated dst pointer.
 */
static uint8_t *copy_and_update(uint8_t *const dst, const void *const src, size_t const length)
{
    memcpy(dst, src, length);
    return dst + length;
}

/** Generate a hash over the appropriate
 *  section of the datastore (PSR).
 *
 * \param Pointer to where we want to store the hash.
 *
 * \return true on success, false on failure.
 */
static bool datastore_hash_generate(uint8_t *const pHash)
{
    uint8_t copy_buffer[SEED_HASHABLE_LENGTH];
    uint8_t *copy_buffer_p = copy_and_update(copy_buffer, &PSR->pd_pc_seed, SBM_PPD_SEED_BYTE_COUNT);

    /* This is a constant at compile time
     * Assumed passed in as an unnamed internal static array of char
     */
    copy_buffer_p = copy_and_update(copy_buffer_p, SBM_PPD_4BYTE_SECURITY_CONTEXT_SEED, SBM_PPD_SECURITY_CONTEXT_RANDOM_BYTE_COUNT);

    /* Read device unique ID */
    uint8_t device_id[UNIQUE_ID_SIZE];
    sbm_benchmark_procedure_start(BENCHMARK_GET_TRUST_ANCHOR);
    hal_get_device_trust_anchor(device_id);
    sbm_benchmark_procedure_stop(BENCHMARK_GET_TRUST_ANCHOR);
    copy_buffer_p = copy_and_update(copy_buffer_p, device_id, UNIQUE_ID_SIZE);

    const void *const hashable_start_address = &PSR->capability;
    const uint32_t hashable_length = PSR->length - offsetof(psr, capability);

#ifndef NDEBUG
    SBM_LOG_DATASTORE_INFO("PSR Starts at 0x%p\n", PSR);
    SBM_LOG_DATASTORE_INFO("Start Hashing at 0x%p\n", hashable_start_address);
    SBM_LOG_DATASTORE_INFO("Hash 0x%x bytes as length is 0x%x, offset is 0x%x\n", hashable_length, PSR->length, offsetof(psr, capability));
    SBM_LOG_DATASTORE_INFO("Store Hash to 0x%p\n", pHash);
    SBM_LOG_DATASTORE_INFO("copy_buffer at 0x%p\n", copy_buffer);

    SBM_LOG_DATASTORE_INFO("Provisioned Seed: ");
    print_hash_n(PSR->pd_pc_seed, SBM_PPD_SEED_BYTE_COUNT);
    SBM_PRINTF_DATASTORE_INFO("\n");
    SBM_LOG_DATASTORE_INFO("Security context seed is: ");
    print_hash_n(SBM_PPD_4BYTE_SECURITY_CONTEXT_SEED, 4);
    SBM_PRINTF_DATASTORE_INFO("\n");
    SBM_LOG_DATASTORE_INFO("Device Unique ID: ");
    print_hash_n(device_id, UNIQUE_ID_SIZE);
    SBM_PRINTF_DATASTORE_INFO("\n");
#endif

    const sha256_hash_chunk_t chunk_list[] = {
        {.data =            copy_buffer, .length = SEED_HASHABLE_LENGTH},
        {.data = hashable_start_address, .length =      hashable_length}
    };

    return sha256_calc_hash_chunked(
                        chunk_list,
                        sizeof(chunk_list)/sizeof(chunk_list[0]),
                        pHash
                        );
}

bool datastore_hash_check(void)
{
    uint8_t hash[SBM_PPD_HASH_256_BYTE_COUNT];
    if (!datastore_hash_generate(hash))
    {
        return false;
    }

#if defined(DATASTORE_DEBUG) || defined(SBM_PC_BUILD)
    SBM_LOG_DATASTORE_INFO("Provisioned Hash:\n");
    print_hash_n(PSR->pd_pc_hash, SBM_PPD_HASH_256_BYTE_COUNT);
    SBM_PRINTF_DATASTORE_INFO("\n");

    SBM_LOG_DATASTORE_INFO("Generated Hash:\n");
    print_hash_n(hash, SBM_PPD_HASH_256_BYTE_COUNT);
    SBM_PRINTF_DATASTORE_INFO("\n");
#endif /* DATASTORE_DEBUG || SBM_PC_BUILD */

    return 0 == memcmp(hash, &PSR->pd_pc_hash, SBM_PPD_HASH_256_BYTE_COUNT);
}
#endif /* SBM_PPD_ENABLE */

#if SBM_PROVISIONED_DATA_ENCRYPTED != 0

bool datastore_verify_and_decrypt_pdb(void)
{
#ifndef NDEBUG
    /*
     * Check the RAM PDB is all zeros, this sanity check is to make sure we don't already have a decrypted
     * PDB in RAM
     */
    for (size_t i = sizeof(plaintext_provisioned_data_ram); i != 0; i--)
    {
        if (plaintext_provisioned_data_ram[i-1] != 0)
        {
            return false;
        }
    }
#endif /* NDEBUG */

    /* Now check the PDB contains encrypted data */
    if (0 == (ENCRYPTED_PDB_PTR->capability & CAPABILITY_PDB_ENCRYPTED_MASK))
    {
        return false;
    }
    pdsf *pdb_security_footer = (pdsf *)((uintptr_t)ENCRYPTED_PDB_PTR + ENCRYPTED_PDB_PTR->pdsf_offset);
    if (pdb_security_footer->encrypted_end_offset > sizeof(plaintext_provisioned_data_ram))
    {
        return false;
    }
    /* Switch on crypto unit for decryption / authentication */
    hal_crypto_init();
    uint8_t *mac = (uint8_t *)((uintptr_t)pdb_security_footer + sizeof(pdsf));
    uint8_t *iv = (uint8_t *)((uintptr_t)mac + pdb_security_footer->mac_length);
    uint8_t *krd = (uint8_t *)((uintptr_t)iv + pdb_security_footer->iv_length);

    /* Setup the crypto HW before retrieving keys */
    if (0 != hal_crypto_hw_setup(krd))
    {
        hal_crypto_quiesce();
        return false;
    }

    /* The authenticated area is from the start of the PSR to the start of the MAC */
    if (0 != hal_crypto_authenticate_data((uint8_t *)ENCRYPTED_PDB_PTR,
                                          krd,
                                          (size_t)(mac - (uint8_t *)ENCRYPTED_PDB_PTR),
                                          iv, pdb_security_footer->iv_length, mac))
    {
        hal_crypto_quiesce();
        return false;
    }

    uint32_t encrypted_data_length = (pdb_security_footer->encrypted_end_offset -
                                     pdb_security_footer->encrypted_start_offset) + 1;

    /* First we need to copy the data that is not encrypted at the beginning of the PDB into the RAM buffer */
    memcpy(plaintext_provisioned_data_ram, ENCRYPTED_PDB_PTR,
           pdb_security_footer->encrypted_start_offset);
    uint8_t *encrypted_start = (uint8_t *)((uintptr_t)ENCRYPTED_PDB_PTR + pdb_security_footer->encrypted_start_offset);
    /* Now decrypt the encrypted data within the PDB into the RAM buffer */
    if (0 != hal_crypto_decrypt_data(encrypted_start,
                                     plaintext_provisioned_data_ram + pdb_security_footer->encrypted_start_offset,
                                     krd, encrypted_data_length, iv))
    {
        hal_crypto_quiesce();
        datastore_clear_plaintext_pdb();
        return false;
    }

    hal_crypto_quiesce();
    /* Finally we copy the pdsf in the RAM buffer */
    memcpy(plaintext_provisioned_data_ram + sizeof(psr) + encrypted_data_length, pdb_security_footer, sizeof(pdsf));

    return true;
}

void datastore_clear_plaintext_pdb(void)
{
    memset(plaintext_provisioned_data_ram, 0, sizeof(plaintext_provisioned_data_ram));
}

#endif /* SBM_PROVISIONED_DATA_ENCRYPTED != 0 */
