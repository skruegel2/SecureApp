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
#include "swup_oem.h"

#include "datastore.h"

/** Find slot number of key used for OEM SWUP processing.
 *
 * \param purpose Purpose of key for which to search.
 *
 * \return Key slot number if available, -ve otherwise.
 */
pd_slot_t oem_swup_key_slot(const uint8_t purpose)
{
	/* We are passing the 8-bit key "purpose" through a 16-bit argument to
	 * datastore_find(). In that function, it makes a (16-bit) comparison
	 * against the (16-bit) usage in the data slot header, with the knowledge
	 * that what we're looking for is a pdsh_update_key, but the
	 * comparison is being made over a differing type (pdsh_usage).
	 *
	 * It works because we know that the key set in the header will be
	 * zero and the overlay is accurate (by design).
	 *
	 * When we need differing key sets, we'll create another search function.
	 */
	return datastore_find(SLOT_PURPOSE_UPDATE_KEY | KEY_CATEGORY_PUBLIC,
						  purpose, 0U, SLOT_PURPOSE_MASK | KEY_CATEGORY_MASK);
}
