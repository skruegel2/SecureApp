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

#ifndef SECUREAPIDATA_H
#define SECUREAPIDATA_H

/** \file
 * \brief Describes provisioned data.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLOT_PURPOSE_MASK 0xF000U  /**< Slot purpose is top four bits (12-15). */
#define SLOT_PURPOSE(x) ((x) & SLOT_PURPOSE_MASK) /**< Extract slot purpose. */
#define SLOT_PURPOSE_IDENTITY_CERT 0x1000U /**< Slot contains a certificate. */
#define SLOT_PURPOSE_IDENTITY_KEY 0x2000U /**< Slot contains an identity key. */
#define SLOT_PURPOSE_TRUST_ANCHOR_KEY 0x3000U /**< Slot contains a trust anchor key. */
#define SLOT_PURPOSE_UPDATE_KEY 0x8000U /**< Slot contains an update key. */
#define SLOT_PURPOSE_PROVISION_INFO 0xF000U /**< Slot contains provisioning data. */

#define SLOT_SUBTYPE_MASK 0xFFFU /**< Slot subtype is bottom twelve bits. */
#define SLOT_SUBTYPE(x) ((x) & SLOT_SUBTYPE_MASK) /**< Extract slot subtype. */

#define CERT_LEVEL_MASK 3U /**< Certificate level is bottom two bits (0-1). */
#define CERT_LEVEL_ANY 0U /**< Wildcard for searching. */
#define CERT_LEVEL_DEVICE 1U /**< Slot contains a device certificate. */
#define CERT_LEVEL_INTERMEDIATE 2U /**< Slot contains an intermediate certificate. */
#define CERT_LEVEL_ROOT 3U /**< Slot contains a root certificate. */

/* Key presence bitmasks ... */
#define KEY_CATEGORY_MASK 0xC00U /**< Key category is two bits (10-11). */
#define KEY_CATEGORY(x) ((x) & KEY_CATEGORY_MASK)
#define KEY_CATEGORY_ANY 0U /**< Wildcard for searching. */
#define KEY_CATEGORY_PUBLIC 0x400U /**< Public key present. */
#define KEY_CATEGORY_PRIVATE 0x800U /**< Private key present. */
#define KEY_CATEGORY_PAIR (KEY_CATEGORY_PUBLIC | KEY_CATEGORY_PRIVATE) /**< Key pair present. */

/* Key algorithm bitmasks ... */
#define KEY_ALGORITHM_MASK 0x3E0U /**< Key algorithm is five bits (5-9). */
#define KEY_ALGORITHM(x) ((x) & KEY_ALGORITHM_MASK)
#define KEY_ANY 0U /**< Wildcard for searching. */
#define ECC_KEY_NIST_P192 0x20U /**< Not supported. */
#define ECC_KEY_NIST_P224 0x40U /**< Not supported. */
#define ECC_KEY_NIST_P256 0x60U
#define ECC_KEY_NIST_P384 0x80U /**< Not supported. */
#define ECC_KEY_NIST_P521 0xA0U /**< Not supported. */

/* Key curve bitmasks ... */
#define KEY_CURVE_MASK 0x1FU /**< Key curve is bottom five bits (0-4). */
#define KEY_CURVE(x) ((x) & KEY_CURVE_MASK)
#define ECC_KEY_CURVE_ANY 0U /**< Wildcard for searching. */
#define ECC_KEY_CURVE_PURE_256_V1 1U

/* Key purpose (usage) values for update keys ... */
#define KEY_PURPOSE_DEVICE_UPDATE 0U /**< Device (or group) SWUP update key. */
#define KEY_PURPOSE_OEM_VALIDATION 1U /**< OEM SWUP validation key. */
#define KEY_PURPOSE_OEM_TRANSPORTATION 2U /**< OEM SWUP transportion key. */
#define KEY_PURPOSE_PU_VALIDATION 0xFU /**< Power up validation key. */

/* Recommended SBM information string sizes, the SBM will report the required
 * sizes so the application can find out if these have changed.
 * SECURE_API_SBM_TIME_STR_SIZE comprises of 11 chars for the date, 1 char
 * for a space, 8 chars for the time and 1 char for the nul terminator, 21
 * in total. */
#define SECURE_API_SBM_VER_STR_SIZE 15
#define SECURE_API_SBM_TIME_STR_SIZE 21
#define SECURE_API_PROV_VER_STR_SIZE 38
#define SECURE_API_PROV_TIME_STR_SIZE 20
#define SECURE_API_PROV_MACH_STR_SIZE 36

/** Type used to hold data slot indices.
 *
 * Non-negative values are legitimate slot indices.<br>
 * Negative values are error codes.
 */
typedef int8_t pd_slot_t;

#ifdef __cplusplus
}
#endif

#endif /* SECUREAPIDATA_H */
