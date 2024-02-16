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

/*
* Wrapper around AES GCM Crypto functions from Tomcrypt
*/
#include <assert.h>
#include <stdbool.h>

#include "benchmark.h"
#include "sbm_hal.h"
#include "sbm_memory.h"
#include "aesgcm_types.h"
#include "tomcrypt.h"
#include "tomcrypt_api.h"

/* A workaround for Tomcrypt issues - see below. */
#ifndef AES_GCM_DECRYPT_USE_GCM_MEMORY
#define AES_GCM_DECRYPT_USE_GCM_MEMORY 0
#endif

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
__weak bool aes_gcm_decrypt(const uint8_t *pInput, const uint32_t length,
    const uint8_t *pAad, const uint32_t lengthAad,
    const AesKey *pAesKey, const AesGcmIv *pAesIv,
    uint8_t *pDataOut, AesTag *pTag)
{
	AesTag  tmpTag;

	if (NULL == pTag)
		pTag = &tmpTag;

#if AES_GCM_DECRYPT_USE_GCM_MEMORY
	if (pAad == NULL && lengthAad)
		return false;

	/* Invoke the Tom Crypto helper */
	return (CRYPT_OK == gcm_memory(find_cipher("aes"),
	    (const unsigned char*)pAesKey, sizeof(AesKey),
	    (const unsigned char*)pAesIv, sizeof(AesGcmIv),
	    (const unsigned char*)pAad, lengthAad,
	    (unsigned char*)pDataOut, length,
	    (unsigned char *)pInput,
	    (unsigned char *)pTag, (long unsigned int *)&tmpTagLength,
	    GCM_DECRYPT));
#else
	/* The latest gcm_memory() doesn't seem to be working for decrypt (it's
	 * fine for encryot), so used chunked mode, which does appear to work.
	 */
	bool ret = true;
	void *gcm = aes_gcm_chunked_init(pAesKey, pAesIv, pAad, lengthAad);
	if (NULL == gcm) {
		ret = false;
	} else {
		if (!aes_gcm_chunked_decrypt(gcm, pInput, length, pDataOut)) {
			ret = false;
		}
		/* Call regardless, to deallocate and clear our context */
		if (!aes_gcm_chunked_done(gcm, pTag)) {
			ret = false;
		}
	}

	return ret;
#endif
}

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
__weak bool aes_gcm_encrypt(const uint8_t *pInput, const uint32_t length,
    const uint8_t *pAad, const uint32_t lengthAad,
    const AesKey *pAesKey, const AesGcmIv *pAesIv,
    uint8_t *pDataOut, AesTag *pTag)
{
	uint32_t tmpTagLength = sizeof(AesTag);
	AesTag  tmpTag;

	if (NULL == pTag)
		pTag = &tmpTag;

	if (pAad == NULL && lengthAad)
		return false;

	/* Invoke the Tom Crypto helper */
	return (CRYPT_OK == gcm_memory(find_cipher("aes"),
	    (const unsigned char*)pAesKey, sizeof(AesKey),
	    (const unsigned char*)pAesIv, sizeof(AesGcmIv),
	    (const unsigned char*)pAad, lengthAad,
	    (unsigned char*)pInput, length,
	    (unsigned char *)pDataOut,
	    (unsigned char *)pTag, (long unsigned int *)&tmpTagLength,
	    GCM_ENCRYPT));
}

/** Prepare for a "chunked" AES-GCM encryption or decryption operation
 *
 * \param pAesKey AES key
 * \param pAesIv AES initialisation vector
 * \param pAad Pointer to additional authentication data block, or NULL
 *        if not required.
 * \param lengthAad Length of the additional authentication data block, or
 *        zero if not required.
 *
 * \return On success, a non-NULL pointer to an opaque structure containing
 *         AES-GCM state. This must be passed to the other aes_gcm_chunked_*()
 *         functions. A NULL return value indicates failure.
 */
__weak void * aes_gcm_chunked_init(const AesKey *pAesKey, const AesGcmIv *pAesIv,
    const uint8_t *pAad, const uint32_t lengthAad)
{
	gcm_state *gcm;
	int cipher;

	if (pAad == NULL && lengthAad)
		return NULL;

	if (cipher_is_valid(cipher = find_cipher("aes")) != CRYPT_OK)
		return NULL;

	gcm = stz_ltc_malloc(sizeof(*gcm));
	if (gcm == NULL)
		return NULL;

	if (gcm_init(gcm, cipher, (const unsigned char*)pAesKey, sizeof(AesKey)) != CRYPT_OK ||
		gcm_add_iv(gcm, (const unsigned char*)pAesIv, sizeof(AesGcmIv)) != CRYPT_OK ||
		gcm_add_aad(gcm, (const unsigned char*)pAad, lengthAad) != CRYPT_OK) {
		stz_ltc_free(gcm);
		return NULL;
	}

	return gcm;
}

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
__weak bool aes_gcm_chunked_decrypt(void *pContext, const uint8_t *pInput,
    const uint32_t length, uint8_t *pDataOut)
{
	/* A simple wrapper around the Tom Crypt helper */
	sbm_benchmark_procedure_start(BENCHMARK_AES_GCM_DECRYPT);
	const int gpr = gcm_process((gcm_state *)pContext,
	    (unsigned char *)pDataOut, (unsigned long)length,
	    (unsigned char *)(uintptr_t)pInput, GCM_DECRYPT);
	sbm_benchmark_procedure_stop(BENCHMARK_AES_GCM_DECRYPT);
	return gpr == CRYPT_OK;
}

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
__weak bool aes_gcm_chunked_encrypt(void *pContext, const uint8_t *pInput,
    const uint32_t length, uint8_t *pDataOut)
{
	return gcm_process((gcm_state *)pContext,
	    (unsigned char *)(uintptr_t)pInput, (unsigned long)length,
	    (unsigned char *)pDataOut, GCM_ENCRYPT) == CRYPT_OK;
}

/** Terminate a "chunked" GCM-AES encryption or decryption operation.
 *
 * \param pContext Opaque pointer returned by ecies_chunked_init().
 * \param tag GCM tag computed during the crypto operation is written here.
 *
 * \return true on success, else false on crypto error
 */
__weak bool aes_gcm_chunked_done(void *pContext, AesTag *pTag)
{
	unsigned long tmpTagLength = sizeof(AesTag);
	AesTag  tmpTag;
	bool rv;

	if (NULL == pTag)
		pTag = &tmpTag;

	rv = gcm_done((gcm_state *)pContext, (unsigned char *)pTag,
	    &tmpTagLength) == CRYPT_OK;

	/* Don't leave potentially sensitive state lying around in RAM. */
	gcm_reset((gcm_state *)pContext);

	stz_ltc_free(pContext);

	return rv;
}

/** Initialise AES-GCM back-end.
 *
 * Since we use LibTomCrypt, this boils down to ensuring the AES cipher
 * is registered with the library.
 *
 * \return true on success, else false.
 */
__weak bool aes_gcm_init(void)
{
  	extern const struct ltc_cipher_descriptor aes_desc;

	/* Register AES cipher with libtomcrypt */
	return (0 <= register_cipher(&aes_desc));
}

/*
 * libtomcrypt's GCM implementation uses malloc to allocate instances of
 * its 'gcm_state' structure. Since we know SBM will only ever use a
 * single instance of the structure at any one time, we can avoid pulling
 * in circa 5KB of library code by rolling our own.
 *
 * See the XMALLOC/XFREE definitions in tomcrypt_custom.h
 */
static gcm_state stz_ltc_gcm_state SBM_PERSISTENT_RAM;		/* gcm_state instance */
static bool stz_ltc_gcm_state_allocated SBM_PERSISTENT_RAM;	/* 'true' if allocated */

void *stz_ltc_malloc(size_t n)
{
	assert(stz_ltc_gcm_state_allocated == false);
	assert(n == sizeof(gcm_state));

	if (stz_ltc_gcm_state_allocated != false)
		return NULL;

	stz_ltc_gcm_state_allocated = true;
	return &stz_ltc_gcm_state;
}

void stz_ltc_free(void *p)
{
	assert(stz_ltc_gcm_state_allocated != false);
	assert(p == &stz_ltc_gcm_state);

	stz_ltc_gcm_state_allocated = false;
}
