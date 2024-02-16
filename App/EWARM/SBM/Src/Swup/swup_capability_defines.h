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
#ifndef SWUP_CAPABILITY_DEFINES_H
#define SWUP_CAPABILITY_DEFINES_H

/* SWUP capability flags and masks */
#define SWUP_CAP_ENC_MODE_MASK               0xFU /**< Bits 0-3: Encryption mode. */
#define SWUP_CAP_ENC_MODE_NONE                 0U /**< No encryption. */
#define SWUP_CAP_ENC_MODE_ECIES_AES_GCM        1U /**< Type 1: ECIES+AES-GCM. */
#define SWUP_CAP_CIPHER_LAYOUT_MASK         0xE0U /**< Bits 5-7: Cipher fields layout. */
#define SWUP_CAP_HEAD_FOOT_CIPHER           0x20U /**< Bit 5: SWUP header and footer cipher fields present. */
#define SWUP_CAP_OVERALL_CIPHER             0x40U /**< Bit 6: SWUP overall cipher fields present. */
#define SWUP_CAP_ALT_CIPHER                 0x80U /**< Bit 7: SWUP alternative cipher suites defined. */
#define SWUP_CAP_CIPHER_SUITE_MASK       0xFFF00U /**< Bits 8-19: Cipher suite - most are (also) reserved. */
#define SWUP_CAP_SHA_256                   0x100U /**< Bit 8: SWUP SHA-256 hashing, no signatures. */
#define SWUP_CAP_SHA_256_ECDSA_P_256       0x200U /**< Bit 9: SWUP SHA-256 hashing, ECDSA P-256 signatures. */
#define SWUP_CAP_OPTIONAL_CIPHER_FIELDS  0x80000U /**< Bit 19: Cipher fields in optional elements. */
#define SWUP_CAP_FLASH_COUNTERS_MASK   0xF000000U /**< Bits 24-27: Number of "fuses" in SWUP. */
#define SWUP_CAP_FLASH_COUNTERS_SHIFT         24U
#define SWUP_CAP_VERSION_SIZE_MASK    0xF0000000U /**< Bits 28-31: Maximum number of fields in EUB version numbers. */
#define SWUP_CAP_VERSION_SIZE_SHIFT           28U
#define SWUP_CAP_RESERVED               0xFFFC10U /**< Bits 4, 10-23: Reserved. */

/* Common capability flags and masks */
#define COMMON_CAP_ENC_MODE_MASK              0xFFU /**< Bits 0-7: Encryption mode. */
#define COMMON_CAP_ENC_MODE_NONE                 0U /**< No encryption. */
#define COMMON_CAP_ENC_MODE_AES_GCM_128          1U /**< Type 1: AES GCM 128. */
#define COMMON_CAP_ADV_ENC_OPTIONS_MASK      0xF00U /**< Bits 8-11: Advanced encryption options - reserved: must be zero. */
#define COMMON_CAP_ADV_ENC_OPTIONS_SHIFT         8U
#define COMMON_CAP_CIPHER_LAYOUT_MASK       0x7000U /**< Bits 12-14: Cipher field layout. */
#define COMMON_CAP_FIXED_CIPHER_FIELDS      0x1000U /**< Bit 12: Fixed cipher fields are present. */
#define COMMON_CAP_OPTIONAL_CIPHER_FIELDS   0x2000U /**< Bit 13: Cipher fields in optional elements. */
#define COMMON_CAP_ALT_CIPHER_FIELDS        0x4000U /**< Bit 14: Alternative cipher suites defined. */
#define COMMON_CAP_PU_MASK                0xF00000U /**< Pre-launch (a.k.a. power up) flags. */
#define COMMON_CAP_SINGLE_PU_SIG          0x100000U /**< Bit 20: Single power-up signature checking. */
#define COMMON_CAP_MULTIPLE_PU_SIG        0x200000U /**< Bit 21: Multiple power-up signature checking. */
#define COMMON_CAP_SINGLE_PU_HASH         0x400000U /**< Bit 22: Power-up hash checking. */
#define COMMON_CAP_MULTIPLE_PU_HASH       0x400000U /**< Bit 23: Power-up hash checking. */
#define COMMON_CAP_RESERVED             0xFF0F8FFEU /**< Bits 1-11, 15-19, 24-31: Reserved. */

/* Backwards compatability with 1.20 and earlier */
#define SWUP_UPDATE_STATUS_RECORDS(cap) \
		(((cap) & SWUP_CAP_FLASH_COUNTERS_MASK) >> SWUP_CAP_FLASH_COUNTERS_SHIFT)

#endif /* SWUP_CAPABILITY_DEFINES_H */
