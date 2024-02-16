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
#include "swup_public_key.h"

#include <inttypes.h>
#include <string.h>
#include "datastore.h"
#include "swup_read.h"
#include "sbm_log_update_status.h"

/** Find device update key slot.
 *
 * \param instance Instance number of required key.
 * \param category Key category for which to search.
 *
 * \return Index of required slot if found, -ve error code otherwise.
 * \sa datastore_find().
 *
 * \note Called during boot process and from a secure API context.<br>
 * When called from a secure API context, logging must be disabled (see sbm_log_disable()).
 */
pd_slot_t find_update_key_slot(const uint8_t instance, const uint16_t category)
{
	const pd_slot_t duks = datastore_find(SLOT_PURPOSE_UPDATE_KEY | category,
											KEY_PURPOSE_DEVICE_UPDATE, instance,
											SLOT_PURPOSE_MASK | category);
	if (duks < 0)
		SBM_LOG_UPDATE_ERROR("device update key slot not found: %" PRId8 "\n", duks);

	return duks;
}

/** Find address of public device update key.
 *
 * Find the public part of the device update key and yield its address.
 *
 * \param instance Instance number of required key.
 * \param[out] public_key Address of pointer to public_key.
 *
 * \return \b true on sucess, \b false otherwise.
 * \note When \b true is returned, \a *public_key is populated with the address of the key.
 *
 * \par
 * \note Called during boot process and from a secure API context.<br>
 * When called from a secure API context, logging must be disabled (see sbm_log_disable()).
 */
static bool find_public_update_key(const uint8_t instance, const EccPublicKey **public_key)
{
	/* Find the device update key slot */

	const pd_slot_t duks = find_update_key_slot(instance, KEY_CATEGORY_PUBLIC);
	if (duks < 0)
		return false;

	/* Extract the address of the public key */

	const int8_t dupk = datastore_public_key(duks, public_key);
	if (dupk)
	{
		SBM_LOG_UPDATE_ERROR("device update public key not found in slot 0x%" PRIx8
				 ": 0x%" PRIx8 "\n", duks, dupk);
		return false;
	}

	return true;
}

/** Check that the SWUP update key matches one of the provisioned update keys.
 *
 * Loop over provisioned public update keys and compare.
 *
 * \param[in] update_key Address of update key to check.
 * \param[out] instance Address of a \c uint8_t to populate with instance number of matching key.
 * \note \a instance may be NULL. If it is not NULL, \a *instance is modified in all cases.
 *
 * \return \b false if no matching key found, \b true otherwise.
 * \note If \b true is returned, \a *instance holds the instance number of the update key.
 *
 * \par
 * \note Called during boot process and from a secure API context.<br>
 * When called from a secure API context, logging must be disabled (see sbm_log_disable()).
 */
bool update_key_valid(const EccPublicKey update_key, uint8_t *instance)
{
	uint8_t i;
	if (!instance) instance = &i;

	for (*instance = 0U; *instance < UINT8_MAX; ++*instance)
	{
		const EccPublicKey *public_key;
		if (!find_public_update_key(*instance, &public_key))
		{
			/* This is the "normal" failing return: no provisioned key matches that in the SWUP. */
			return false;
		}

		if (!memcmp(public_key, update_key, sizeof *public_key))
		{
			/* Found what we want, so bail out. */
			return true;
		}

		/* Check the next instance. */
	}

	/* Should never reach here: belt and braces approach to loop termination.
	   If we arrive here, there are very many update keys, none of which matches.
	   There isn't enough room in the provisioned data store for that many. */

	return false;
}
