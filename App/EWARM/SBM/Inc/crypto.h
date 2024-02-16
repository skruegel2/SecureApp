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

#if !defined CRYPTO_API
#define CRYPTO_API

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES128_KEY_SIZE         16
#define AES128_IV_SIZE          AES128_KEY_SIZE
#define HMAC_KEY_SIZE           32
#define SHA256_SIZE             32
#define ECC_PUBLIC_KEY_SIZE     64
#define ECC_PRIVATE_KEY_SIZE    32
#define ECC_SIGNATURE_SIZE      64

typedef uint8_t AesKey[AES128_KEY_SIZE];
typedef uint8_t AesIv[AES128_IV_SIZE];
typedef uint8_t HmacKey[HMAC_KEY_SIZE];
typedef uint8_t HmacResult[HMAC_KEY_SIZE];
typedef uint8_t Sha256[SHA256_SIZE];
typedef uint8_t EccPublicKey[ECC_PUBLIC_KEY_SIZE];
typedef uint8_t EccPrivateKey[ECC_PRIVATE_KEY_SIZE];
typedef uint8_t EccSignature[ECC_SIGNATURE_SIZE];

#define CRYPTO_DERIVATION_STRING_MT_SIG     "mtSig"
#define CRYPTO_DERIVATION_STRING_DEV_SIGN   "devSign"
#define CRYPTO_DERIVATION_STRING_DEV_ENC    "devEnc"

/** Key types used in the SBM and Provisioning Application */
typedef enum {
    ENC_KEY = 0,
    AUTH_KEY = 1,
    NB_KEYS = 2
} key_type_t;

/** Algorithm type identifier fields
 *
 * |------B31..B24--------|-----B23..B16-----|-------B15..B0-------|
 * |----------------------|------------------|---------------------|
 * | Algorithm Usage Type | Organization ID  | Individual ID Value |
 */
#define GET_ALGO_USAGE(x)       ( (x >> 24u) & 0xFFu )
#define GET_ORG_ID(x)           ( (x >> 16u) & 0xFFu )
#define GET_ID_VAL(x)           ( x & 0xFFFFu )

#define SET_ALGO_USAGE(val, x)  ( ((val & 0xFFu) << 24u) | x )
#define SET_ORG_ID(val, x)      ( ((val & 0xFFu) << 16u) | x )
#define SET_ID_VAL(val, x)      ( (val & 0xFFFFu) | x )

typedef uint32_t key_algo_type_t;

/** Algorithm usage type IDs bitfield
 *
 * Bit 0:   Set for Encryption IDs
 * Bit 1:   Set for Authentication IDs
 * Bit 2:   Set for Device Key Algorithm IDs
 * Bit 3:   Set for General Algorithm IDs
 */
#define IS_GENERAL_ALGO_ID(x)       (bool)( ((x & 0b1000) >> 3u) == 0x1u )
#define IS_DEVICE_KEY_ALGO_ID(x)    (bool)( ((x & 0b100) >> 2u) == 0x1u )
#define IS_AUTHENTICATION_ID(x)     (bool)( ((x & 0b10) >> 1u) == 0x1u )
#define IS_ENCRYPTION_ID(x)         (bool)( (x & 0b1) == 0x1u )

#define SET_GENERAL_ALGO_ID(x)       ( x | (0x1u << 3u) )
#define SET_DEVICE_KEY_ALGO_ID(x)    ( x | (0x1u << 2u) )
#define SET_AUTHENTICATION_ID(x)     ( x | (0x1u << 1u) )
#define SET_ENCRYPTION_ID(x)         ( x | 0x1u )

#define DEVICE_KEY_ENCRYP_ALGO      0x5u
#define DEVICE_KEY_AUTH_ALGO        0x6u
#define GENERAL_KEY_ENCRYP_ALGO     0x9u
#define GENERAL_KEY_AUTH_ALGO       0xAu

/** Org ID for STz */
#define STZ     0x00u

/** key_algo_type_t pre-defined for STZ */
#define AES_CBC_128_ID          (key_algo_type_t)0x09000001
#define HMAC_SHA256_ID          (key_algo_type_t)0x0A000001
#define CMAC_128_ID             (key_algo_type_t)0x0A000002
#define TSIP_AES_CBC_128_ID     (key_algo_type_t)0x05000001
#define TSIP_HMAC_SHA256_ID     (key_algo_type_t)0x06000002
#define TSIP_CMAC_128_ID        (key_algo_type_t)0x06000003
#define PUF_HW_AES_CBC_128_ID   (key_algo_type_t)0x06000004
#define PUF_SWHW_HMAC_SHA256_ID (key_algo_type_t)0x06000005


typedef struct {
    key_algo_type_t encrypt_key_algo;
    key_algo_type_t auth_key_algo;
    uint32_t device_specific_krd_block_len;
    uint8_t device_specific_krd_block[];
} keys_ref_data_block_t;

/*--------------------------------------------------------------------------------
 * Initialisation
 *--------------------------------------------------------------------------------*/
extern bool cryptoInitialise(void);

/*--------------------------------------------------------------------------------
 * General random byte string.
 *--------------------------------------------------------------------------------*/

/* (Used within the SKI to make the random seed). */
extern bool cryptoMakeRandomByteString(uint8_t *pBuffer, uint32_t length);

/*--------------------------------------------------------------------------------
 * Key generation
 *--------------------------------------------------------------------------------*/

/* Generate a random AES key.
 * Passed in a pointer to a sufficiently sized buffer.
 * Return TRUE if pKey is populated.
 */
extern bool cryptoMakeAesKey(
        AesKey *pKey                /* Generated key is written into this buffer */
        );

/* Generate a random SHA256 key.
 * Passed in a pointer to a sufficiently sized buffer.
 * Return TRUE if pKey is populated.
 */
extern bool cryptoMakeHmacKey(
        HmacKey *pKey             /* Generated key is written into this buffer */
        );

/* Generate random pair of ECC keys.
 * Passed in pointer to sufficiently sized buffers.
 * Return TRUE if keys are populated.
 */
extern bool cryptoMakeEccKeys(
        EccPublicKey *pPublic,      /* Generated key is written into this buffer */
        EccPrivateKey *pPrivate     /* Generated key is written into this buffer */
        );


/* Derive an ECC key from (a) the device seed, plus (b) a text string tag.
 * The public/private key pair is returned in the supplied buffers.
 */
extern bool cryptoDeriveEccKey(
        const uint8_t       *pSeed,       /* Pointer to the seed for this device. */
        const char          *pTag,        /* Text string to initialise the key derivation function. */
        EccPublicKey        *pPublicKey,  /* Generated key is written into this buffer */
        EccPrivateKey       *pPrivateKey  /* Generated key is written into this buffer */
        );


/*--------------------------------------------------------------------------------
 * ECC signatures
 *--------------------------------------------------------------------------------*/

/* calculate sha256 hash over the msg buffer.
 * calculate ECC sig over the hash
 * result written into the supplied signature buffer.
 * [often the code of a module is in one buffer and the ModuleUpdateKey in another so have to do a sign over two buffers.]
 */
extern bool cryptoEccHashAndSign(
    const uint8_t       *pBuf1,         /* Buffer to be signed. */
    const uint32_t       length1,       /* Length of the buffer. */
    const uint8_t       *pBuf2,         /* 2nd part of buffer.  [NULL if not present] */
    const uint32_t       length2,       /* Length of 2nd part. */
    const EccPrivateKey *pPrivateKey,   /* ECC private key to be used for the signature */
    EccSignature        *pSig           /* Output - ECC signature of the message. */
    );


/* calculate sha256 hash over the msg buffer.
 * Verify ECC sig over the hash
 * Returns true if sig is good. false otherwise.
 */
extern bool cryptoEccHashAndVerify(
    const uint8_t       * const pBuf1,      /* Buffer to be signed. */
    const uint32_t       length1,       	/* Length of the buffer. */
    const uint8_t       * const pBuf2,      /* 2nd part of buffer.  [NULL if not present] */
    const uint32_t       length2,      		/* Length of 2nd part. */
    const EccPublicKey * const pPublicKey,  /* ECC public key used to check the signature. */
    const EccSignature * const pSig         /* Signature to be checked. */
    );

/* Calculate SHA256 hash over a single buffer.
 * Verify ECC sig over the hash
 * Returns true if sig is good. false otherwise.
 */
extern bool cryptoEccHashAndVerifySingleBuffer(
    const uint8_t      * const pBuf,        /* Buffer to be signed. */
    const uint32_t       length,            /* Length of the buffer. */
    const EccPublicKey * const pPublicKey,  /* ECC public key used to check the signature. */
    const EccSignature * const pSig         /* Signature to be checked. */
    );

/* calculate sha256 hash over the msg buffer.
 * Verify ECC sig over the hash
 * Returns true if sig is good. false otherwise.
 */
extern bool cryptoEccVerifyAHash(
    const Sha256       * const pHash,       /* Hash to be verified. */
    const EccPublicKey * const pPublicKey,  /* ECC public key used to check the signature. */
    const EccSignature * const pSig         /* Signature to be checked. */
    );

/*--------------------------------------------------------------------------------
 * ECIES encrypt/decrypt
 *--------------------------------------------------------------------------------*/

/* ECIES decrypt a buffer.
 * generate shared secret
 * derive keys from the shared secret
 * check hmac across buffer.
 * AES decrypt buffer.
 * Returns true if decrypt succeeds.
 */
extern bool cryptoECIESDecrypt(
        const uint8_t       *pMsg,          /* Message to be decrypted. */
        const uint32_t       length,        /* Length of the message. */
        const EccPrivateKey *pPrivateKey,   /* ECC private key to be used to derive shared secret */
        uint8_t             *pOutput,       /* Buffer into message is decrypted. */
        uint32_t            *pOutLength     /* Input - size of buffer. output = size of decrypted message. */
        );

/* ECIES encrypt a buffer.
 * Generates a random key pair.
 * derives a shared secret from the random keys.
 * AES encrypts the message.
 * calculates and saves an HMAC across the message.
 */
extern bool cryptoECIESEncrypt(
        const uint8_t       *pMsg,          /* Message to be encrypted */
        const uint32_t       length,        /* Length of the message. */
        const EccPublicKey  *pPublicKey,    /* ECC public key to be used to derive shared secret. */
        uint8_t             *pOutput,       /* Buffer into which the message is encrypted. */
        uint32_t            *pOutLength     /* Input - size of buffer. output = size of encypted message. */
        );


/*--------------------------------------------------------------------------------
 * data encrypt/decrypt
 *--------------------------------------------------------------------------------*/

/* AES-CBC encrypt the buffer and then calculate an HMAC over the result. */
extern bool cryptoDataEncrypt(
        const uint8_t   * const pInput,     /* Data to be encrypted */
        const uint32_t   length,            /* Length of data to be encrypted */
        const AesKey    * const pAesKey,    /* AES key use to encrypt. */
        const HmacKey   * const pHmacKey,   /* HMAC key to use to calculate hash. */
        uint8_t         *pEncrypted,        /* Pointer to buffer into which to encrypt data. */
        uint32_t        *pEncryptedLength   /* Input - size of buffer. output = size of encypted message. */
        );

/* Application images could be larger than the onchip ram.
 * 1) HMAC can be performed over the whole image in flash.
 * 2) AES decrypt has to be performed in blocks.
 * AES crypto retains context internally from one invocation to the next.
 */

/* Calculate hash over received data. */
extern bool cryptoDataCheckHmac(
        const uint8_t   *const pInput,      /* Data to be checked. */
        const uint32_t   length,            /* Length of data to be checked. */
        const HmacKey   *const pHmacKey     /* HMAC key to use to calculate hash. */
        );

/* Decrypt the first block of the data */
extern bool cryptoDataDecryptInitial(
        const uint8_t   * const pInput,     /* Data to be decrypted */
        const uint32_t   length,            /* Length of data to be decrypted (If NOT last segment length must be multiple of AES block size = 16) */
        const AesKey    * const pAesKey,    /* AES key use for decrypt. */
        uint8_t         *pPlain,            /* Pointer to buffer into which to encrypt data. */
        uint32_t        *pPlainLength,      /* Input - size of buffer. output = size of decrypted block. */
        const bool       lastSegment        /* True if this is the last segment of the data buffer (and hence de-padding is required). */
        );

/* Decrypt non-first block of the data. */
extern bool cryptoDataDecryptBlock(
        const uint8_t   * const pInput,     /* Data to be decrypted */
        const uint32_t   length,            /* Length of data to be decrypted (If NOT last segment length must be multiple of AES block size = 16) */
        uint8_t         *pPlain,            /* Pointer to buffer into which to encrypt data. */
        uint32_t        *pPlainLength,      /* Input - size of buffer. output = size of decrypted block. */
        const bool       lastSegment        /* True if this is the last segment of the data buffer (and hence de-padding is required). */
        );

/*--------------------------------------------------------------------------------
 * Simple segmented hashes
 *--------------------------------------------------------------------------------*/

/* Each Add/Modify command within an Update contains a hash over the payload.
 * Separately there is a hash over the whole update.
 * Both hashes are separately signed.
 *
 * During the parsing of an update the receiver has to update 1 or both hashes for each block of the update.
 * Therefore 2 hash contexts are required.
 */

typedef enum
{
    SEGMENTED_HASH_1 = 0,
    SEGMENTED_HASH_2,
    NUM_OF_SEGMENTED_HASHES,

    SEGMENTED_HASH_WHOLE_UPDATE = SEGMENTED_HASH_1,
    SEGMENTED_HASH_ADD_MODIFY = SEGMENTED_HASH_2
} SegmentedHashContexts;


/* Calculates a simple sha256 hash over a block of data. */
extern bool cryptoCalculateSha256Start(
    SegmentedHashContexts context,
    const uint8_t   * const pInput,         /* Data to be hashed. */
    const uint32_t   length                 /* Byte length of the data. */
    );

extern bool cryptoCalculateSha256MiddleEnd(
    SegmentedHashContexts context,
    const uint8_t   * const pInput,         /* Data to be hashed. (can be PNULL if no more data to be added). */
    const uint32_t   length,                /* Byte length of the data. */
    bool            final,                  /* True if final segment. */
    Sha256          *pHash                  /* Pointer to a block of memory into which the result can be returned. */
    );





#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_API */
