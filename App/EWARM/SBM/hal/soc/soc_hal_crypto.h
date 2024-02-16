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

#ifndef SOC_HAL_CRYPTO_H
#define SOC_HAL_CRYPTO_H

#if defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0)

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "crypto.h"

/**
 * =================================
 * HAL crypto HW function prototypes
 * =================================
 *
 * \note Functions defined in device specific soc_hal_crypto.c
 *
 */

/**
 * \brief Setup the SOC HW crypto unit before using it
 *
 * \param crypto_init_data Pointer to the data block containing init data for the crypto unit
 *
 * \return True on success, False on failure
 */
extern bool soc_hal_crypto_setup(void *crypto_init_data);

/**
 * \brief Regenerate the stored keys on the HW crypto unit
 *
 * \param p_key_ref Pointer to keys reference / index location
 * \param key_type_t Key type to indicate what key to regenerate
 *
 * \return True on success, False on failure
 */
extern bool soc_hal_crypto_regenerate_key(void *p_keys_ref, key_type_t key_type);

#if defined(SBM_HAL_UNIT_TESTS)
/**
 * \brief Encrypt buffer of data using AES CBC algorithm
 *
 * \param p_data Pointer to the data to encrypt
 * \param cipher_text_buffer Buffer to hold the encrypted data
 * \param data_len Size of the data in the buffer
 * \param iv Initialisation Vector seed
 *
 * \return True on success, False on failure
 */
extern bool soc_hal_crypto_aes_cbc_encrypt(const uint8_t *p_data, uint8_t *cipher_text_buffer,
                                           size_t data_len, const uint8_t *iv);
#endif /* SBM_HAL_UNIT_TESTS */

/**
 * \brief Decrypt buffer of data using AES CBC algorithm
 *
 * \param p_data Pointer to the data to encrypt
 * \param plain_text_buffer Buffer to hold the decrypted data
 * \param data_len Size of the data in the buffer
 * \param iv Initialisation Vector seed
 *
 * \return True on success, False on failure
 */
extern bool soc_hal_crypto_aes_cbc_decrypt(const uint8_t *p_data, uint8_t *plain_text_buffer,
                                           size_t data_len, const uint8_t *iv);

#if (SBM_PROVISIONED_DATA_AUTHENTICATION_ALGORITHM_HMAC_SHA256 != 0)

#if defined(SBM_HAL_UNIT_TESTS)
/**
 * \brief Generate a MAC for a buffer of data using HMAC algorithm
 *
 * \param p_data Pointer to the data to hash
 * \param data_len Size of the data in the buffer
 * \param p_mac Buffer to hold the MAC
 *
 * \return True on success, False on failure
 */
extern bool soc_hal_crypto_hmac_generate(const uint8_t *p_data, size_t data_len, uint8_t *p_mac);
#endif /* defined(SBM_HAL_UNIT_TESTS) */

/**
 * \brief Authenticate a buffer of data using HMAC-SHA256
 *
 * \param p_data1 Pointer to the first part of data to authenticate (NULL if unused)
 * \param data1_len Size of the first part of data in the buffer
 * \param p_data2 Pointer to the second part of data to authenticate (NULL if unused)
 * \param data2_len Size of the second part of data in the buffer
 * \param p_mac Pointer to the MAC
 *
 * \note To improve efficiency, the data are passed in two parts (p_data1 and p_data2),
 *       but internally they are treated as if they were a contiguous block of data.
 * \note At least one part must be defined (both p_data1, p_data2 must not be NULL at the same time)
 *
 * \return True on success, False on failure
 */
extern bool soc_hal_crypto_hmac_authenticate(const uint8_t *p_data1, size_t data1_len,
                                             const uint8_t *p_data2, size_t data2_len,
                                             const uint8_t *p_mac);

#elif (SBM_PROVISIONED_DATA_AUTHENTICATION_ALGORITHM_CMAC_128 != 0)

#if defined(SBM_HAL_UNIT_TESTS)
/**
 * \brief Generate a MAC for a buffer of data using CMAC algorithm
 *
 * \param p_data Pointer to the data to hash
 * \param data_len Size of the data in the buffer
 * \param p_mac Buffer to hold the MAC
 *
 * \return True on success, False on failure
 */
extern bool soc_hal_crypto_cmac_generate(const uint8_t *p_data, size_t data_len, uint8_t *p_mac);
#endif /* defined(SBM_HAL_UNIT_TESTS) */

/**
 * \brief Authenticate a buffer of data using CMAC-128
 *
 * \param p_data1 Pointer to the first part of data to authenticate (NULL if unused)
 * \param data1_len Size of the first part of data in the buffer
 * \param p_data2 Pointer to the second part of data to authenticate (NULL if unused)
 * \param data2_len Size of the second part of data in the buffer
 * \param p_mac Pointer to the MAC
 *
 * \note To improve efficiency, the data are passed in two parts (p_data1 and p_data2),
 *       but internally they are treated as if they were a contiguous block of data.
 * \note At least one part must be defined (both p_data1, p_data2 must not be NULL at the same time)
 *
 * \return True on success, False on failure
 */
extern bool soc_hal_crypto_cmac_authenticate(const uint8_t *p_data1, size_t data1_len,
                                             const uint8_t *p_data2, size_t data2_len,
                                             const uint8_t *p_mac);

#else
#error "Undefined or unrecognized SBM_PROVISIONED_DATA_AUTHENTICATION_ALGORITHM_... macro"
#endif /* (SBM_PROVISIONED_DATA_AUTHENTICATION_ALGORITHM_HMAC_SHA256 != 0) || 
          (SBM_PROVISIONED_DATA_AUTHENTICATION_ALGORITHM_CMAC_128 != 0) */

/**
 * \brief Hash a buffer of data using SHA-256 algorithm
 *
 * \param p_data Pointer to the data to hash
 * \param data_len Size of the data in the buffer
 * \param p_hash Pointer to the generated hash
 *
 * \return True on success, False on failure
 */
extern bool soc_hal_crypto_sha256_hash(const uint8_t *p_data, size_t data_len, uint8_t *p_hash);

#endif /* defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0) */

#endif /* SOC_HAL_CRYPTO_H */
