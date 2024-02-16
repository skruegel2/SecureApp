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

#include "sbm_hal_crypto.h"
#include "sbm_hal.h"

#if defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0)
#include "soc_hal_crypto.h"

#endif /* defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0) */

void hal_crypto_init(void)
{
#if defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0)

    soc_hal_crypto_init();
#endif /* defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0) */
	/* Nothing to do by default */
}

void hal_crypto_quiesce(void)
{
#if defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0)

    soc_hal_crypto_quiesce();
#endif /* defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0) */

    /* Nothing to do by default */
}

#if defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0)

int hal_crypto_hw_setup(uint8_t *krd)
{
    keys_ref_data_block_t *key_ref = (keys_ref_data_block_t *)krd;

    if(!soc_hal_crypto_setup(key_ref->device_specific_krd_block))
    {
        return -1;
    }

    return 0;
}

int hal_crypto_decrypt_data(uint8_t *p_data, uint8_t *plain_text_buffer, uint8_t *krd,
                            size_t data_len, const uint8_t *iv)
{
    keys_ref_data_block_t *key_ref = (keys_ref_data_block_t *)krd;

    /* Regenerate decryption key from crypto HW unit */
    if (!soc_hal_crypto_regenerate_key(key_ref->device_specific_krd_block, ENC_KEY))
    {
        return -1;
    }

    if (!soc_hal_crypto_aes_cbc_decrypt(p_data, plain_text_buffer, data_len, iv))
    {
        return -1;
    }

    return 0;
}

int hal_crypto_authenticate_data(uint8_t *p_data, uint8_t *krd, size_t data_len,
                                 const uint8_t *iv, size_t iv_len, const uint8_t *mac)
{
    keys_ref_data_block_t * key_ref = (keys_ref_data_block_t *)krd;

    /* Regenerate authentication key from crypto HW unit */
    if (!soc_hal_crypto_regenerate_key(key_ref->device_specific_krd_block, AUTH_KEY))
    {
        return -1;
    }

    /* Authenticate data block along with a prefixed IV */

#if (SBM_PROVISIONED_DATA_AUTHENTICATION_ALGORITHM_HMAC_SHA256 != 0)
    if (!soc_hal_crypto_hmac_authenticate(iv, iv_len, p_data, data_len, mac))
    {
        return -1;
    }

#elif (SBM_PROVISIONED_DATA_AUTHENTICATION_ALGORITHM_CMAC_128 != 0)
    if (!soc_hal_crypto_cmac_authenticate(iv, iv_len, p_data, data_len, mac))
    {
        return -1;
    }

#else
#error "Undefined or unrecognized SBM_PROVISIONED_DATA_AUTHENTICATION_ALGORITHM_... macro"
#endif

    return 0;
}

#endif /* defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0) */
