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
#ifndef SWUP_LAYOUT_DEFINES_H
#define SWUP_LAYOUT_DEFINES_H

#include <stdint.h>
#include <assert.h>

/**
   SWUP header layout
**/
/** Preamble */
#define	SWUP_OFFSET_HEADER_PREAMBLE_MAGIC				0x00u	/* 4-bytes */
#define	SWUP_OFFSET_HEADER_LAYOUT_VERSION				0x04u	/* 4-bytes */
#define	SWUP_OFFSET_HEADER_SWUP_CAPABILITY_FLAGS		0x08u	/* 4-bytes */
#define	SWUP_OFFSET_HEADER_EUB_CAPABILITY_FLAGS			0x0cu	/* 4-bytes */
#define	SWUP_OFFSET_HEADER_LENGTH_OF_SWUP				0x10u	/* 4-bytes */
#define	SWUP_OFFSET_HEADER_NUM_EUBS						0x14u	/* 2-bytes */
/* 2-bytes padding, 4-bytes max_bs (unused) */

/** Layout */
#define	SWUP_OFFSET_HEADER_FOOTER_LENGTH				0x1cu	/* 2-bytes */
/* 2-bytes padding */
#define	SWUP_OFFSET_HEADER_EUB_CLEAR_START				0x20u	/* 2-bytes */
#define	SWUP_OFFSET_HEADER_EUB_ENCRYPTED_START			0x22u	/* 2-bytes */
#define	SWUP_OFFSET_HEADER_EPILOGUE_START				0x24u	/* 2-bytes */
#define	SWUP_OFFSET_HEADER_FIRST_EUB_START				0x26u	/* 2-bytes */
#define	SWUP_OFFSET_HEADER_LAYOUT__SIZEOF				0x08u	/* Not including footer length field */

/** Identity */
#define	SWUP_OFFSET_HEADER_RANDOM						0x28u	/* 4-bytes */
#define	SWUP_OFFSET_HEADER_UPDATE_KEY					0x2cu	/* 64-bytes */
#define	SWUP_OFFSET_HEADER_SECURITY_WORLD_UUID			0x6cu	/* 16-bytes */
#define	SWUP_OFFSET_HEADER_SECURITY_WORLD_ITERATION		0x7cu	/* 2-bytes */
#define	SWUP_OFFSET_HEADER_UPDATE_UUID					0x7eu	/* 16-bytes */
/* 20-bytes timestamp, 16 bytes source device UUID (unused) */

/** 1.20 and earlier: The update status starts here, comprised of
    some zero-filled padding followed by 4 minimum-write-unit-sized
    chunks with all bits set. This is handled at runtime as the padding
    and chunk size varies according to the target SoC. */

/** 1.25 and later: Optional padding to ensure the next object is
    32-bit aligned. */

/** Optional Elements (subject to update status padding, above) */
#define	SWUP_OFFSET_HEADER_OPTIONAL_ELEMENTS			0xb4u	/* n-bytes */
/** Optional padding to ensure the next object is 32-bit aligned */

/**
   SWUP header epilogue layout
**/
/** Hash over SWUP header */
#define	SWUP_OFFSET_HEADER_EPILOGUE_HASH				0x00u	/* 32-bytes */
/** Signature of the above hash, using the OEM validation key */
#define	SWUP_OFFSET_HEADER_EPILOGUE_SIGNATURE			0x20u	/* 64-bytes */
/** Checksum of SWUP header */
#define	SWUP_OFFSET_HEADER_EPILOGUE_CHECKSUM			0x60u	/* 2-bytes */
/* 2-bytes of padding */
#define	SWUP_OFFSET_HEADER_EPILOGUE__SIZEOF				0x64u

/**
   SWUP footer layout
**/
/** Hash over entire SWUP, excluding footer */
#define	SWUP_OFFSET_FOOTER_HASH							0x00u	/* 32-bytes */
/** Signature of the above hash, using the OEM transportation key */
#define	SWUP_OFFSET_FOOTER_SIGNATURE					0x20u	/* 64-bytes */
/** Checksum of the entire SWUP, excluding footer */
#define	SWUP_OFFSET_FOOTER_CHECKSUM						0x60u	/* 2-bytes */
/* 2-bytes of padding */
#define	SWUP_OFFSET_FOOTER_RANDOM						0x64u	/* 4-bytes */
#define	SWUP_OFFSET_FOOTER__SIZEOF						0x68u

/**
   EUB clear details layout
**/
#define	SWUP_OFFSET_EUB_CLEAR_CONTENT					0x00u	/* 2-bytes */
#define	SWUP_OFFSET_EUB_CLEAR_PARAMETERS				0x02u	/* 2-bytes */
#define	SWUP_OFFSET_EUB_CLEAR_CAPABILITY_FLAGS			0x04u	/* 4-bytes */
#define	SWUP_OFFSET_EUB_CLEAR_PAYLOAD_START				0x08u	/* 4-bytes */
#define	SWUP_OFFSET_EUB_CLEAR_PAYLOAD_LENGTH			0x0cu	/* 4-bytes */
#define	SWUP_OFFSET_EUB_CLEAR_HW_SKU					0x10u	/* 4-bytes */
#define	SWUP_OFFSET_EUB_CLEAR_CHECKSUM					0x14u	/* 2-bytes */
/* 2-bytes of padding */
#define	SWUP_OFFSET_EUB_CLEAR_HASH						0x18u	/* 32-bytes */
/** Optional Elements */
#define	SWUP_OFFSET_EUB_CLEAR_OPTIONAL_ELEMENTS			0x38u	/* n-bytes */
#define	SWUP_OFFSET_EUB_CLEAR__SIZEOF					0x38u

/** These structures capture some offsets to key objects within a SWUP.
 *
 * They are populated in the course of performing some simple sanity checks
 * of a candidate SWUP and are used later to deep-dive the objects once the
 * sanity of a SWUP is confirmed. */
typedef struct swup_layout {
	/** Note: These elements must appear in this order such that they
	    align with the fields of the same name in the SWUP header. */
	uint16_t eub_clear_details_start;		/**< Offset to EUB clear details. */
	uint16_t eub_encrypted_details_start;	/**< Offset to EUB encrypted details. */
	uint16_t epilogue_start;				/**< Offset to SWUP epilogue object. */
	uint16_t first_eub_start;				/**< Offset of first EUB. */
} swup_layout_t;
static_assert(sizeof(struct swup_layout) == SWUP_OFFSET_HEADER_LAYOUT__SIZEOF,
			  "swup_layout_t != SWUP_OFFSET_HEADER_LAYOUT__SIZEOF");

#endif /* SWUP_LAYOUT_DEFINES_H */
