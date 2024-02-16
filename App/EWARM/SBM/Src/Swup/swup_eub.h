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
#ifndef SWUP_EUB_H
#define SWUP_EUB_H

#include <stdint.h>
#include <assert.h>
#include "swup_uuid.h"
#include "swup_signature.h"
#include "swup_checksum_and_hash.h"
#include "swup_layout.h"

/* EUB content type */
#define EUB_CONTENT_SW_UPDATE 0U /**< Expected value of eub_clear_details_t.content: EUB contains software update. */

/* EUB parameters */
#define EUB_PARAM_MASTER_MODULE 1U /**< Expected value of eub_clear_details_t.parameters: Identifies update to master module. */

/* This is the offset within the update, not the size of the receiving slot in the target platform. */
#define PIEM_IMAGE_OFFSET 1024U /**< Temporary: should be provided from without. */

/* There are a few random numbers that come in pairs and must match each other.
   There is a case where the number(s) cannot be all zero or all one bits.
   The comparison with zero is easy but the left hand side of the comparison
   with all one bits is tricky unless we know the type of the RHS.
   So, we embody the type in a typedef and policing in a macro. */
typedef uint32_t matching_random_t;
#define INVALID_RANDOM(R) (0U == (R) || UINT32_MAX == (R))

/** Permanently installed executable module.
 *
 * Layout of a module in an EUB.
 * This is copied, wholesale, into the executable slot on installation.
 */
typedef struct
{
	/* Module hash/checksum starts here. */
	union
	{
		/** Module header. */
		struct
		{
			uint32_t module_status; /**< Fixed magic number: expected to be #PIEM_EXPECTED_STATUS. */
			uint32_t footer_offset; /**< Offset to start of module footer. */
			matching_random_t header_random; /**< Must match pie_module_footer_t.footer_random. */
			uint8_t field_presence; /**< Expected to be zero at v1.0. Will disappear soon. */
			uint8_t num_signatures; /**< Number of power on signatures in footer. */
			uint16_t footer_length; /**< Size of footer in bytes. */
			uint8_t sbm_exec_info[];/**< Location of additional info saved by SBM */
		} header;
		uint8_t image_offset[PIEM_IMAGE_OFFSET]; /**< Padding to align start of image. */
	};

	uint8_t image[]; /**< Executable binary as delivered by linker. */

	/* The linker and security manager should conspire to create an
	   image that is a multiple of 32-bits long. If this ever fails,
	   we'll need a means of aligning the module footer correctly. */

	/* Permanently installed executable module footer follows immediately. */
} pie_module_t;
static_assert(((PIEM_IMAGE_OFFSET) & ((PIEM_IMAGE_OFFSET) - 1U)) == 0U, "image offset not a power of two");
static_assert(offsetof(pie_module_t, image) == PIEM_IMAGE_OFFSET, "incorrect image offset");
static_assert((sizeof(pie_module_t) & 3U) == 0U, "pie_module_t invalid size");

/** Permanently installed executable module footer. */
typedef struct
{
	uint32_t version_number; /**< Version number used to police version rollback. */
	/* Module hash/checksum ends here. */
	hash_t block_hash; /**< Hash between start of header and end of version_number. */
	sig_t block_sig; /**< Signature between start of header and end of version_number. */
	uint16_t block_cs; /**< Checksum between start of header and end of version_number. */
	uint16_t pad; /**< To obtain 32-byte alignment for footer_random. */
	matching_random_t footer_random; /**< Must match module_update_t.header_random. */

	/* EOB marker for ALF appears here. */
} pie_module_footer_t;
static_assert((sizeof(pie_module_footer_t) & 3U) == 0U, "pie_module_footer_t invalid size");

/** Additional data saved in the module update header, starting at sbm_exec_info in pie_module_t.header.
 *
 * This is fabricated by SBM when installing a SWUP, and saved in the IAVVCS (Installed Application Validity,
 * Versioning and Capability Slot) along with the PIEM header, above. The UUID of the installed image is,
 * therefore, available for quick comparison with that of a candidate SWUP.
 */
typedef struct {
	uuid_t installed_uuid; /**< UUID of the installed image in the Exec Slot. */

	/* Old MUH stopped here.
	   If this MUH is an IAVVCS, there's also this ... */

	uint16_t iavvcs_capability_indicator;
	uint16_t iavvcs_capability_flags; /**< What elements follow. */
	pie_module_footer_t installed_muf; /**< Copy of module update footer. */
} pie_module_sbm_exec_info_t;

#endif /* SWUP_EUB_H */
