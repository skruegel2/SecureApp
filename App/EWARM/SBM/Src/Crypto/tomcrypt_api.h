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
#ifndef TOMCRYPT_API_H
#define TOMCRYPT_API_H

#include <stdint.h>
#include <stdbool.h>

/** Initialise AES-GCM back-end.
 *
 * Since we use LibTomCrypt, this boils down to ensuring the AES cipher
 * is registered with the library.
 *
 * \return true on success, else false.
 */
extern bool aes_gcm_init(void);

/** Decrypt a block of cipher text using AES-GCM.
 *
 * \param pInput Pointer to the buffer containing the cipher text.
 * \param length Length, in bytes, of the cipher text.
 * \param pAad Pointer to additional authentication data block, or NULL
 *        if not required.
 * \param lengthAad Length of the additional authentication data block, or
 *        zero if not required.
 * \param pAesKey AES key to use to decrypt
 * \param pAesIv AES initialisation vector
 * \param pDataOut Destination buffer for the resulting clear text.
 * \param pTag GCM tag result of the decryption operation.
 *
 * \return true on success, false for crypto error.
 */
extern bool aes_gcm_decrypt(const uint8_t *pInput, const uint32_t length,
			    const uint8_t *pAad, const uint32_t lengthAad,
			    const AesKey *pAesKey, const AesGcmIv *pAesIv,
			    uint8_t *pDataOut, AesTag *pTag);

/** Encrypt a block of plain text using AES-GCM.
 *
 * \param pInput Pointer to the buffer containing the plain text.
 * \param length Length, in bytes, of the plain text.
 * \param pAad Pointer to additional authentication data block, or NULL
 *        if not required.
 * \param lengthAad Length of the additional authentication data block, or
 *        zero if not required.
 * \param pAesKey AES key to use to encrypt
 * \param pAesIv AES initialisation vector
 * \param pDataOut Destination buffer for the resulting cipher text.
 * \param pTag GCM tag result of the encryption operation.
 *
 * \return true on success, false for crypto error.
 */
extern bool aes_gcm_encrypt(const uint8_t *pInput, const uint32_t length,
			    const uint8_t *pAad, const uint32_t lengthAad,
			    const AesKey *pAesKey, const AesGcmIv  *pAesIv,
			    uint8_t *pDataOut, AesTag *pTag);

/** Prepare for a "chunked" AES-GCM encryption or decryption operation
 *
 * \param pAesKey AES key
 * \param pAesIv AES initialisation vector
 * \param pAad Pointer to additional authentication data block, or NULL
 *        if not required.
 * \param lengthAad Length of the additional authentication data block, or
 *        zero if not required.
 *
 * \return true on success, false for crypto error.
 */
extern void * aes_gcm_chunked_init(const AesKey *pAesKey,
				  const AesGcmIv *pAesIv,
				  const uint8_t *pAad,
				  const uint32_t lengthAad);

/** Decrypt a "chunk" of cipher text using AES-GCM
 *
 * Decrypt the next "chunk" of cipher text. May be invoked any number of
 * times following an initial call to aes_gcm_chunked_init().
 *
 * \param pContext Opaque pointer returned by aes_gcm_chunked_init().
 * \param pInput Pointer to the buffer containing the cipher text.
 * \param length Length, in bytes, of the cipher text.
 * \param pDataOut Destination buffer for the resulting clear text.
 *
 * \return true on success, false for crypto error.
 */
extern bool aes_gcm_chunked_decrypt(void *pContext,
				    const uint8_t *pInput,
				    const uint32_t length,
				    uint8_t *pDataOut);

/** Encrypt a "chunk" of plain text using AES-GCM
 *
 * Encrypt the next "chunk" of plain text. May be invoked any number of
 * times following an initial call to aes_gcm_chunked_init().
 *
 * \param pContext Opaque pointer returned by aes_gcm_chunked_init().
 * \param pInput Pointer to the buffer containing the plain text.
 * \param length Length, in bytes, of the plain text.
 * \param pDataOut Destination buffer for the resulting cipher text.
 *
 * \return true on success, false for crypto error.
 */
extern bool aes_gcm_chunked_encrypt(void *pContext,
				    const uint8_t *pInput,
				    const uint32_t length,
				    uint8_t *pDataOut);

/** Terminate a "chunked" GCM-AES encryption or decryption operation.
 *
 * \param pContext Opaque pointer returned by ecies_chunked_init().
 * \param tag GCM tag computed during the crypto operation is written here.
 *
 * \return true on success, else false on crypto error
 */
extern bool  aes_gcm_chunked_done(void *pContext, AesTag *pTag);

#endif /* #define TOMCRYPT_API_H */
