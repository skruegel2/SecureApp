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
#ifndef DATASTORE_TYPES_H
#define DATASTORE_TYPES_H
#include <stdint.h>
#include "assert.h"

/** Provisioned Data Slot Header with no data. */
typedef struct
{
	/* currently unused */
	uint16_t sh_type; /**< Slot type. */
	/* the rest is for "in header" data */
	uint8_t reserved_0[14];
} pdsh_only;
static_assert(sizeof(pdsh_only) == 16U, "pdsh_only wrong size");

/** Provisioned Data Slot Header with data. */
typedef struct
{
	uint16_t sh_type; /**< Slot type. */
	uint8_t device; /**< Device carrying provisioned data. */
	uint8_t reserved_0;
	uint32_t slot_offset; /**< Offset (from \link psr PSR\endlink) to provisioned data. */
	uint16_t slot_size; /**< Size of provisioned data. */
	/* Variable fields (should be a union but we can't do this without packing) */
	uint8_t reserved_1[6];
} pdsh_data;
static_assert(sizeof(pdsh_data) == sizeof(pdsh_only), "pdsh_data wrong size");

/** Provisioned Data Slot Header for a certificate or key. */
typedef struct
{
	uint16_t sh_type; /**< Slot type. */
	uint8_t device; /**< Device carrying provisioned data. */
	uint8_t reserved_0;
	uint32_t slot_offset; /**< Offset (from \link psr PSR\endlink) to provisioned data. */
	uint16_t slot_size; /**< Size of provisioned data. */
	/* Variable fields */
	uint16_t usage; /**< Usage class. */
	uint8_t reserved_1[4];
} pdsh_usage;
static_assert(sizeof(pdsh_usage) == sizeof(pdsh_only), "pdsh_usage wrong size");

/** Provisioned Data Slot Header for a certificate. */
typedef struct
{
	uint16_t sh_type; /**< Slot type. */
	uint8_t device; /**< Device carrying provisioned data. */
	uint8_t reserved_0;
	uint32_t slot_offset; /**< Offset (from \link psr PSR\endlink) to provisioned data. */
	uint16_t slot_size; /**< Size of provisioned data. */
	/* Variable fields */
	uint16_t cert_usage; /**< Certificate usage class. */
	/* Key slot should be 16 bits or parent should be 8 bits */
	uint16_t parent_id; /**< Slot number of parent certificate. */
	uint8_t reserved_1;
	uint8_t key_slot; /**< Slot containing key associated with certificate. */
} pdsh_cert;
static_assert(sizeof(pdsh_cert) == sizeof(pdsh_only), "pdsh_cert wrong size");

/** Provisioned Data Slot Header for an update key. */
typedef struct
{
	uint16_t sh_type; /**< Slot type. */
	uint8_t device; /**< Device carrying provisioned data. */
	uint8_t reserved_0;
	uint32_t slot_offset; /**< Offset (from \link psr PSR\endlink) to provisioned data. */
	uint16_t slot_size; /**< Size of provisioned data. */
	/* Variable fields
	   The key purpose and set overlay a 16-bit usage */
	uint8_t purpose; /**< Key purpose. */
	uint8_t set; /**< Key set. */
	uint8_t reserved_1[4];
} pdsh_update_key;
static_assert(sizeof(pdsh_update_key) == sizeof(pdsh_only), "pdsh_update_key wrong size");
#endif /* DATASTORE_TYPES_H */
