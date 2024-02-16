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
 * ECIES derive secret key and AES-GCM decrypt ciphertext
 */

#include <string.h>

#include "benchmark.h"
#include "ecies_crypto.h"
#include "tomcrypt_api.h"
#include "sbm_log.h"
#include "sbm_memory.h"

/*
 * ECIES state is maintained here.
 */
struct ecies_chunk_state {
	/* 'true' if the state is currently in use */
	bool busy;

	/* The 'chunked' API records the crypto direction here */
	bool is_decrypt;

	/* Opaque state from AES-GCM wrapper */
	void *aes_gcm_state;

	/*
	 * The computed shared secret is stored here during crypto operations.
	 * Care is taken to ensure this is cleared when a crypto operation has
	 * completed.
	 */
	EccSharedSecretKey key;
};

static struct ecies_chunk_state *ecies_alloc_state(void)
{
	/* The API currently requires just a single instance of the state */
	static struct ecies_chunk_state one_state SBM_PERSISTENT_RAM;

	if (one_state.busy)
		return NULL;

	one_state.busy = true;
	return (&one_state);
}

static void ecies_free_state(struct ecies_chunk_state *state)
{
	if (state->busy) {
		memset(state->key, 0, sizeof(state->key));
		state->busy = false;
	}
}

/** Constant time memory comparison, for cryptographic use.
 *
 * \param buff1 Pointer to first buffer
 * \param buff2 Pointer to second buffer
 * \param length Number of bytes to compare
 *
 * \return true if buffers are identical, else false.
 */
static bool cmpMemoryConstantTime(const void *buff1, const void *buff2,
    size_t length)
{
	const uint8_t *p1 = buff1, *p2 = buff2;
	bool result = true;

	while (length--) {
		if (*p1++ != *p2++)
			result = false;
	}

	return result;
}

/** Initialise ECIES crypto support
 *
 * \return true on success, else false.
 */
__weak bool ecies_init(void)
{
	return aes_gcm_init();
}

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
__weak bool ecies_decrypt(const uint8_t *pCipherText, uint32_t lenCipherText,
    const EccPrivateKey *privKey, const EccPublicKey *pubKey,
    const uint8_t *pAad, const uint32_t lenAad,
    const AesTag *tag, uint8_t *pPlainTextOut)
{
	AesTag tagCheck;
	bool rv;
	struct ecies_chunk_state *state = ecies_alloc_state();

	if (state == NULL) {
		SBM_LOG_ERROR(__func__, "failed to allocate state\n");
		return false;
	}

	/*
	 * AES Key and IV are made up from the shared secret
	 * Shared secret is 256 bits.AES GCM KEY = first 128 bits.
	 * AES GCM IV = next 128 bits.
	 */
	AesKey *pAesKey = (AesKey *)state->key;
	AesGcmIv *pAesIv = (AesGcmIv *)(state->key + sizeof(AesKey));

	/*
	 * Derive shared secret from ephemeral supplied public + supplied
	 * private key
	 */
	sbm_benchmark_procedure_start(BENCHMARK_GET_SHARED_SECRET);
	
	const int ussr = uECC_shared_secret(*pubKey, (const uint8_t *)privKey,
	    (uint8_t *)&state->key, uECC_CURVE());
	sbm_benchmark_procedure_stop(BENCHMARK_GET_SHARED_SECRET);
	if (0 == ussr) {
		ecies_free_state(state);
		SBM_LOG_ERROR(__func__, "failed to generate secret key\n");
		return false;
	}

	/* Decrypt the supplied ciper text using the generated key */
	if (aes_gcm_decrypt(pCipherText, lenCipherText, pAad, lenAad,
            pAesKey, pAesIv, pPlainTextOut, &tagCheck) == false) {
		ecies_free_state(state);
		SBM_LOG_ERROR(__func__, "failed AES-GCM decryption\n");
		return false;
	}

	/* Validate the GCM tag */
	rv = cmpMemoryConstantTime(tagCheck, tag, sizeof(AesTag));
	if (rv == false)
		SBM_LOG_ERROR(__func__, "tag mismatch\n");

	ecies_free_state(state);

	return rv;
}

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
__weak bool ecies_encrypt(const uint8_t *pPlainText, uint32_t lenPlainText,
    const EccPrivateKey *privKey, const EccPublicKey *pubKey,
    const uint8_t *pAad, const uint32_t lenAad,
    AesTag *tag, uint8_t *pCipherTextOut)
{
	bool rv;
	struct ecies_chunk_state *state = ecies_alloc_state();

	if (state == NULL) {
		SBM_LOG_ERROR(__func__, "failed to allocate state\n");
		return false;
	}

	/*
	 * AES Key and IV are made up from the shared secret
	 * Shared secret is 256 bits.AES GCM KEY = first 128 bits.
	 * AES GCM IV = next 128 bits.
	 */
	AesKey *pAesKey = (AesKey *)state->key;
	AesGcmIv *pAesIv = (AesGcmIv *)(state->key + sizeof(AesKey));

	/*
	 * Derive shared secret from ephemeral supplied public + supplied
	 * private key
	 */
	if (0 == uECC_shared_secret(*pubKey, (const uint8_t *)privKey,
	    (uint8_t *)&state->key, uECC_CURVE())) {
		ecies_free_state(state);
		SBM_LOG_ERROR(__func__, "failed to generate secret key\n");
		return false;
	}

	/* Encrypt the supplied ciper text using the generated key */
	rv = aes_gcm_encrypt(pPlainText, lenPlainText, pAad, lenAad,
	    pAesKey, pAesIv, pCipherTextOut, tag);
	if (rv == false)
		SBM_LOG_ERROR(__func__, "failed AES-GCM encryption\n");

	ecies_free_state(state);

	return rv;
}

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
void *ecies_chunked_init(const EccPrivateKey *privKey,
    const EccPublicKey *pubKey, const uint8_t *pAad, const uint32_t lenAad,
    bool decrypt)
{
	struct ecies_chunk_state *state = ecies_alloc_state();

	if (state == NULL) {
		SBM_LOG_ERROR(__func__, "failed to allocate state\n");
		return false;
	}

	/*
	 * AES Key and IV are made up from the shared secret
	 * Shared secret is 256 bits.AES GCM KEY = first 128 bits.
	 * AES GCM IV = next 128 bits.
	 */
	AesKey *pAesKey = (AesKey *)state->key;
	AesGcmIv *pAesIv = (AesGcmIv *)&(state->key[sizeof(AesKey)]);

	/*
	 * Derive shared secret from ephemeral supplied public + supplied
	 * private key
	 */
	if (0 == uECC_shared_secret(*pubKey, (const uint8_t *)privKey,
	    (uint8_t *)&state->key, uECC_CURVE())) {
		ecies_free_state(state);
		SBM_LOG_ERROR(__func__, "failed to generate secret "
		    "key\n");
		return false;
	}

	/* Initialise AES-GCM */
	state->is_decrypt = decrypt;
	state->aes_gcm_state = aes_gcm_chunked_init(pAesKey, pAesIv,
	    pAad, lenAad);

	if (state->aes_gcm_state == NULL) {
		ecies_free_state(state);
		state = NULL;
	}

	return state;
}

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
bool ecies_chunked_decrypt(void *pContext, const uint8_t *pCipherText,
    const uint32_t lenCipherText, uint8_t *pPlainTextOut)
{
	struct ecies_chunk_state *state = pContext;
	bool rv;

	if (state->is_decrypt == false) {
		SBM_LOG_ERROR(__func__, "State indicates encrypt!\n");
		return false;
	}

	/* Perform the AES-GCM decryption */
	rv = aes_gcm_chunked_decrypt(state->aes_gcm_state, pCipherText,
	    lenCipherText, pPlainTextOut);

	/* In case of error, efface any possible plaintext */
	if (rv == false) {
		memset(pPlainTextOut, 0, lenCipherText);
		SBM_LOG_ERROR(__func__, "failed AES-GCM "
		    "decryption\n");
	}

	return rv;
}

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
bool ecies_chunked_encrypt(void *pContext, const uint8_t *pPlainText,
    const uint32_t lenPlainText, uint8_t *pCipherTextOut)
{
	struct ecies_chunk_state *state = pContext;
	bool rv;

	if (state->is_decrypt) {
		SBM_LOG_ERROR(__func__, "State indicates decrypt!\n");
		return false;
	}

	/* Perform the AES-GCM encryption */
	rv = aes_gcm_chunked_encrypt(state->aes_gcm_state, pPlainText,
	    lenPlainText, pCipherTextOut);

	if (rv == false) {
		SBM_LOG_ERROR(__func__, "failed AES-GCM "
		    "encryption\n");
	}

	return rv;
}

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
bool ecies_chunked_done(void *pContext, AesTag *tag)
{
	struct ecies_chunk_state *state = pContext;
	AesTag tagCheck;
	bool rv;

	rv = aes_gcm_chunked_done(state->aes_gcm_state,
	    (tag != NULL) ? (state->is_decrypt ? &tagCheck : tag) : NULL);
	if (rv == false)
		SBM_LOG_ERROR(__func__, "failed AES-GCM done\n");
	else
        if (tag != NULL && state->is_decrypt) {
		rv = cmpMemoryConstantTime(tagCheck, tag, sizeof(AesTag));
		if (rv == false)
			SBM_LOG_ERROR(__func__, "tag mismatch\n");
	}

	ecies_free_state(state);

	return rv;
}
