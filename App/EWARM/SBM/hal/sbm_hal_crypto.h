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

#ifndef SBM_HAL_CRYPTO_H
#define SBM_HAL_CRYPTO_H

#include <stdio.h>
#include <stdint.h>

/** Initialise the hardware crypto engine */
void hal_crypto_init(void);

/** Quiesce the hardware crypto engine, and delete sensitive data */
void hal_crypto_quiesce(void);

#if defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0)
/** Setup the crypto HW
 *
 * \param krd Pointer to the key reference / index block needed to setup the crypto HW
 *
 * \return 0 on success, -1 otherwise
 */
int hal_crypto_hw_setup(uint8_t *krd);

/** Decrypt data buffer
 *
 * \param p_data Pointer to the data to decrypt
 * \param plain_text_buffer Buffer to hold the decrypted data
 * \param krd Pointer to the key reference / index block needed to regenerate stored keys
 * \param data_len Size of the data in the buffer
 * \param iv Initialisation Vector seed
 *
 * \return 0 on success, -1 otherwise
 */
int hal_crypto_decrypt_data(uint8_t *p_data, uint8_t *plain_text_buffer, uint8_t *krd,
                            size_t data_len, const uint8_t *iv);

/** Authenticate data buffer
 *
 * \param p_data Pointer to the data to be authenticated
 * \param krd Pointer to the key reference / index block needed to regenerate stored keys
 * \param data_len Size of the data in the buffer
 * \param iv initialisation vector
 * \param iv_len Size of initialisation vector
 * \param mac The MAC to validate the data against
 *
 * \return 0 on success, -1 otherwise
 */
int hal_crypto_authenticate_data(uint8_t *p_data, uint8_t *krd, size_t data_len,
                                 const uint8_t *iv, size_t iv_len, const uint8_t *mac);

#endif /* defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0) */

#endif /* SBM_HAL_CRYPTO_H */
