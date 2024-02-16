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

#ifndef ECIES_CRYPTO_H
#define ECIES_CRYPTO_H

#include "aesgcm_types.h"
#include "ecc.h"

/*
 * Perform ECIES secret key derivation and AES-GCM Decryption.
 */

/* Size of different keys expressed in bytes */
#define ECC_PUBLIC_KEY_SIZE		64u	/* NIST-256 */
#define ECC_PRIVATE_KEY_SIZE		32u	/* NIST-256 */
#define ECC_SHARED_SECRET_KEY_SIZE	ECC_PRIVATE_KEY_SIZE

/* Useful types */
typedef uint8_t EccPublicKey[ECC_PUBLIC_KEY_SIZE];
typedef uint8_t EccPrivateKey[ECC_PRIVATE_KEY_SIZE];
typedef uint8_t EccSharedSecretKey[ECC_SHARED_SECRET_KEY_SIZE];

/** Initialise ECIES crypto support
 *
 * \return true on success, else false.
 */
extern bool ecies_init(void);

/** Decrypt a block of cipher text
 *
 * Generate ECIES shared secret from provided private key (SBM internal)
 * and public key (provided in SWUP). AES-GCM decrypt using derived key
 * and IV.
 *
 * \param pCipherText Pointer to the buffer containing the cipher text.
 * \param lenCipherText Length, in bytes, of the cipher text.
 * \param privKey Pointer to the private key.
 * \param pubKey Pointer to the public key.
 * \param pAad Pointer to additional authentication data block, or NULL
 *        if not required.
 * \param lenAad Length of the additional authentication data block, or
 *        zero if not required.
 * \param tag GCM tag to compare with the tag computed during the decryption
 *        of the supplied cipher text.
 * \param pPlainTextOut Destination buffer for the resulting clear text.
 *
 * \return true on success, false for crypto error, or tag mismatch.
 */
extern bool ecies_decrypt(const uint8_t *pCipherText, uint32_t lenCipherText,
			  const EccPrivateKey *privKey,
			  const EccPublicKey *pubKey,
			  const uint8_t *pAad, const uint32_t lenAad,
			  const AesTag *tag, uint8_t *pPlainTextOut);

/** Encrypt a block of plain text
 *
 * Generate ECIES shared secret from provided private key (SBM internal)
 * and public key (provided in SWUP). AES-GCM encrypt using derived key
 * and IV.
 *
 * \param pPlainText Pointer to the buffer containing the plain text.
 * \param lenPlainText Length, in bytes, of the plain text.
 * \param privKey Pointer to the private key.
 * \param pubKey Pointer to the public key.
 * \param pAad Pointer to additional authentication data block, or NULL
 *        if not required.
 * \param lenAad Length of the additional authentication data block, or
 *        zero if not required.
 * \param tag Buffer to which computed GCM tag will be written.
 * \param pCipherTextOut Destination buffer for the resulting cipher text.
 *
 * \return true on success, false for crypto error.
 */
extern bool ecies_encrypt(const uint8_t *pPlainText, uint32_t lenPlainText,
			  const EccPrivateKey *privKey,
			  const EccPublicKey *pubKey,
			  const uint8_t *pAad, const uint32_t lenAad,
			  AesTag *tag, uint8_t *pCipherTextOut);

/** Prepare for a "chunked" ECIES encryption or decryption operation.
 *
 * Generate ECIES shared secret from provided private key (SBM internal)
 * and public key (provided in SWUP).
 *
 * \param privKey Pointer to the private key.
 * \param pubKey Pointer to the public key.
 * \param pAad Pointer to additional authentication data block, or NULL
 *        if not required.
 * \param lenAad Length of the additional authentication data block, or
 *        zero if not required.
 * \param decrypt True if initialising for decryption, else false.
 *
 * \return An opaque pointer to internal state, or NULL on error.
 */
extern void *ecies_chunked_init(const EccPrivateKey *privKey,
				const EccPublicKey *pubKey,
				const uint8_t *pAad,
				const uint32_t lenAad,
				bool decrypt);

/** Decrypt a "chunk" of cipher text
 *
 * Decrypt the next "chunk" of cipher text. May be invoked any number of
 * times following an initial call to ecies_chunked_init().
 *
 * \param pContext Opaque pointer returned by ecies_chunked_init().
 * \param pCipherText Pointer to the buffer containing the cipher text.
 * \param lenCipherText Length, in bytes, of the cipher text.
 * \param pPlainTextOut Destination buffer for the resulting clear text.
 *
 * \return true on success, false for crypto error.
 */
extern bool ecies_chunked_decrypt(void *pContext,
				  const uint8_t *pCipherText,
				  const uint32_t lenCipherText,
				  uint8_t *pPlainTextOut);

/** Encrypt a "chunk" of plain text
 *
 * Encrypt the next "chunk" of plain text. May be invoked any number of
 * times following an initial call to ecies_chunked_init().
 *
 * \param pContext Opaque pointer returned by ecies_chunked_init().
 * \param pPlainText Pointer to the buffer containing the plain text.
 * \param lenPlainText Length, in bytes, of the plain text.
 * \param pCipherTextOut Destination buffer for the resulting cipher text.
 *
 * \return true on success, false for crypto error.
 */
extern bool ecies_chunked_encrypt(void *pContext,
				  const uint8_t *pPlainText,
				  const uint32_t lenPlainText,
				  uint8_t *pCipherTextOut);

/** Terminate a "chunked" ECIES encryption or decryption operation.
 *
 * \param pContext Opaque pointer returned by ecies_chunked_init().
 * \param tag GCM tag against which computed GCM tag will be compared if
 *            operating in decryption mode, or buffer to which GCM tag
 *            will be written if operating in encryption mode.
 *            Can be NULL if no tag is required.
 *
 * \return true on success, else false on crypto error or tag mismatch.
 */
extern bool ecies_chunked_done(void *pContext, AesTag *tag);

#endif /* #define ECIES_CRYPTO_H */
