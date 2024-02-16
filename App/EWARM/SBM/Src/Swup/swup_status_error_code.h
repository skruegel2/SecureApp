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
#ifndef SWUP_STATUS_ERROR_CODE_H
#define SWUP_STATUS_ERROR_CODE_H

/* SWUP status values ... */

#define SWUP_STATUS_INITIAL 0U /**< SWUP/update unprocessed. */
#define SWUP_STATUS_ERROR 1U /**< SWUP invalid.*/
#define SWUP_STATUS_INSTALLED_THIS_BOOT 2U /**< Module update installed at most recent boot. */
#define SWUP_STATUS_INSTALLED_PREVIOUS 3U /**< Module update installed during a previous boot. */

/* This error is caused by a consipiracy between an
   otherwise perfectly good SWUP and an existing application
   with a later version ... */

#define SWUP_STATUS_ERROR_ROLLBACK 4U /* Module update refused because of version rollback. */

/* SWUP install status (returned by sbm_swup_install_module()) */

#define SWUP_INSTALL_STATUS_SUCCESS          0U /**< SWUP installed */
#define SWUP_INSTALL_STATUS_SUCCESS_VERIFIED 1U /**< SWUP installed and verified by sbm_executable_slot_module_valid_with_iavvcs() */
#define SWUP_INSTALL_STATUS_FAILURE          2U /**< SWUP not installed, and Exec slot intact */
#define SWUP_INSTALL_STATUS_BRICKED          3U /**< SWUP not installed, but Exec slot erased */

#if SBM_EXTENDED_SWUP_ERRORS != 0
/* Additional values yielded by sbm_update_slot_contains_swup() when enabled.
 *
 * The values in this list should not be changed to preserve compatibility between versions. */
enum
{
	SWUP_STATUS_ERROR_BAD_AES_GCM = SWUP_STATUS_ERROR_ROLLBACK + 1U,
	SWUP_STATUS_ERROR_BAD_CD_ALIGNMENT = SWUP_STATUS_ERROR_ROLLBACK + 2U,
	SWUP_STATUS_ERROR_BAD_CIPHER_SUITE = SWUP_STATUS_ERROR_ROLLBACK + 3U,
	SWUP_STATUS_ERROR_BAD_COMMON_RESERVED_CAPS = SWUP_STATUS_ERROR_ROLLBACK + 4U,
	SWUP_STATUS_ERROR_BAD_COUNTERS = SWUP_STATUS_ERROR_ROLLBACK + 5U,
	SWUP_STATUS_ERROR_BAD_ED_ALIGNMENT = SWUP_STATUS_ERROR_ROLLBACK + 6U,
	SWUP_STATUS_ERROR_BAD_ENC_OPTIONS = SWUP_STATUS_ERROR_ROLLBACK + 7U,
	SWUP_STATUS_ERROR_BAD_EPILOGUE_ALIGNMENT = SWUP_STATUS_ERROR_ROLLBACK + 8U,
	SWUP_STATUS_ERROR_BAD_EPILOGUE_LEN = SWUP_STATUS_ERROR_ROLLBACK + 9U,
	SWUP_STATUS_ERROR_BAD_EUB_ALIGNMENT = SWUP_STATUS_ERROR_ROLLBACK + 10U,
	SWUP_STATUS_ERROR_BAD_EUB_CD_CAP = SWUP_STATUS_ERROR_ROLLBACK + 11U,
	SWUP_STATUS_ERROR_BAD_EUB_CD_PU = SWUP_STATUS_ERROR_ROLLBACK + 12U,
	SWUP_STATUS_ERROR_BAD_EUB_CHECKSUM = SWUP_STATUS_ERROR_ROLLBACK + 13U,
	SWUP_STATUS_ERROR_BAD_EUB_CIPHER_LAYOUT = SWUP_STATUS_ERROR_ROLLBACK + 14U,
	SWUP_STATUS_ERROR_BAD_EUB_CONTENT = SWUP_STATUS_ERROR_ROLLBACK + 15U,
	SWUP_STATUS_ERROR_BAD_EUB_ENC_MODE = SWUP_STATUS_ERROR_ROLLBACK + 16U,
	SWUP_STATUS_ERROR_BAD_EUB_END = SWUP_STATUS_ERROR_ROLLBACK + 17U,
	SWUP_STATUS_ERROR_BAD_EUB_HASH = SWUP_STATUS_ERROR_ROLLBACK + 18U,
	SWUP_STATUS_ERROR_BAD_EUB_PARAMETERS = SWUP_STATUS_ERROR_ROLLBACK + 19U,
	SWUP_STATUS_ERROR_BAD_EUB_PAYLOAD = SWUP_STATUS_ERROR_ROLLBACK + 20U,
	SWUP_STATUS_ERROR_BAD_EUB_PAYLOAD_LEN = SWUP_STATUS_ERROR_ROLLBACK + 21U,
	SWUP_STATUS_ERROR_BAD_EUB_RESERVED = SWUP_STATUS_ERROR_ROLLBACK + 22U,
	SWUP_STATUS_ERROR_BAD_EUB_START = SWUP_STATUS_ERROR_ROLLBACK + 23U,
	SWUP_STATUS_ERROR_BAD_EUB_VERSION_SIZE = SWUP_STATUS_ERROR_ROLLBACK + 24U,
	SWUP_STATUS_ERROR_BAD_EUBS = SWUP_STATUS_ERROR_ROLLBACK + 25U,
	SWUP_STATUS_ERROR_BAD_FOOTER_CHECKSUM = SWUP_STATUS_ERROR_ROLLBACK + 26U,
	SWUP_STATUS_ERROR_BAD_FOOTER_HASH = SWUP_STATUS_ERROR_ROLLBACK + 27U,
	SWUP_STATUS_ERROR_BAD_FOOTER_LEN = SWUP_STATUS_ERROR_ROLLBACK + 28U,
	SWUP_STATUS_ERROR_BAD_FOOTER_RANDOM = SWUP_STATUS_ERROR_ROLLBACK + 29U,
	SWUP_STATUS_ERROR_BAD_FOOTER_SIGNATURE = SWUP_STATUS_ERROR_ROLLBACK + 30U,
	SWUP_STATUS_ERROR_BAD_HEADER_CHECKSUM = SWUP_STATUS_ERROR_ROLLBACK + 31U,
	SWUP_STATUS_ERROR_BAD_HEADER_HASH = SWUP_STATUS_ERROR_ROLLBACK + 32U,
	SWUP_STATUS_ERROR_BAD_HEADER_RANDOM = SWUP_STATUS_ERROR_ROLLBACK + 33U,
	SWUP_STATUS_ERROR_BAD_HEADER_SIGNATURE = SWUP_STATUS_ERROR_ROLLBACK + 34U,
	SWUP_STATUS_ERROR_BAD_LAYOUT = SWUP_STATUS_ERROR_ROLLBACK + 35U,
	SWUP_STATUS_ERROR_BAD_LENGTH = SWUP_STATUS_ERROR_ROLLBACK + 36U,
	SWUP_STATUS_ERROR_BAD_MAGIC = SWUP_STATUS_ERROR_ROLLBACK + 37U,
	SWUP_STATUS_ERROR_BAD_OE_ALIGNMENT = SWUP_STATUS_ERROR_ROLLBACK + 38U,
	SWUP_STATUS_ERROR_BAD_RANDOM = SWUP_STATUS_ERROR_ROLLBACK + 39U,
	SWUP_STATUS_ERROR_BAD_RESERVED_CAPS = SWUP_STATUS_ERROR_ROLLBACK + 40U,
	SWUP_STATUS_ERROR_BAD_SECURITY_ID = SWUP_STATUS_ERROR_ROLLBACK + 41U,
	SWUP_STATUS_ERROR_BAD_SECURITY_ITERATION = SWUP_STATUS_ERROR_ROLLBACK + 42U,
	SWUP_STATUS_ERROR_BAD_SKU = SWUP_STATUS_ERROR_ROLLBACK + 43U,
	SWUP_STATUS_ERROR_BAD_STATUS = SWUP_STATUS_ERROR_ROLLBACK + 44U,
	SWUP_STATUS_ERROR_BAD_SWUP_CIPHER_LAYOUT = SWUP_STATUS_ERROR_ROLLBACK + 45U,
	SWUP_STATUS_ERROR_BAD_SWUP_ENC_MODE = SWUP_STATUS_ERROR_ROLLBACK + 46U,
	SWUP_STATUS_ERROR_BAD_SWUP_EUB_CAP = SWUP_STATUS_ERROR_ROLLBACK + 47U,
	SWUP_STATUS_ERROR_BAD_SWUP_EUB_PU = SWUP_STATUS_ERROR_ROLLBACK + 48U,
	SWUP_STATUS_ERROR_BAD_TRANSPORTATION_KEY = SWUP_STATUS_ERROR_ROLLBACK + 49U,
	SWUP_STATUS_ERROR_BAD_UPDATE_KEY = SWUP_STATUS_ERROR_ROLLBACK + 50U,
	SWUP_STATUS_ERROR_BAD_VALIDATION_KEY = SWUP_STATUS_ERROR_ROLLBACK + 51U,
	SWUP_STATUS_ERROR_BAD_VERSION = SWUP_STATUS_ERROR_ROLLBACK + 52U,
	SWUP_STATUS_ERROR_FAILED_EUB_HASH = SWUP_STATUS_ERROR_ROLLBACK + 53U,
	SWUP_STATUS_ERROR_FAILED_FOOTER_HASH = SWUP_STATUS_ERROR_ROLLBACK + 54U,
	SWUP_STATUS_ERROR_FAILED_HEADER_HASH = SWUP_STATUS_ERROR_ROLLBACK + 55U,
	SWUP_STATUS_ERROR_FAILED_STATUS = SWUP_STATUS_ERROR_ROLLBACK + 56U,
	SWUP_STATUS_ERROR_FAILED_UPDATE_KEY = SWUP_STATUS_ERROR_ROLLBACK + 57U,
	SWUP_STATUS_ERROR_MALFORMED_EUB_VERSION = SWUP_STATUS_ERROR_ROLLBACK + 58U,
	SWUP_STATUS_ERROR_MISSING_EUB_VERSION = SWUP_STATUS_ERROR_ROLLBACK + 59U,
	SWUP_STATUS_ERROR_MISSING_UPDATE_KEY = SWUP_STATUS_ERROR_ROLLBACK + 60U,
	SWUP_STATUS_ERROR_ENCRYPTION_CONFIG_INCONSISTENT = SWUP_STATUS_ERROR_ROLLBACK + 61U,
	SWUP_STATUS_ERROR_EUB_MISSING_END_MARKER = SWUP_STATUS_ERROR_ROLLBACK + 62U,
	SWUP_STATUS_ERROR_MUH_READ_ERROR = SWUP_STATUS_ERROR_ROLLBACK + 63U
};
/* When the extended errors are enabled, all errors manifest as themselves ... */
#define SWUP_STATUS_ERROR_CODE(X) (X)
#else
/* When the extended errors are disabled, all errors manifest as SWUP_STATUS_ERROR ... */
#define SWUP_STATUS_ERROR_CODE(X) SWUP_STATUS_ERROR
#endif /* SBM_EXTENDED_SWUP_ERRORS != 0 */

#endif /* SWUP_STATUS_ERROR_CODE_H */