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

/** \file
 * \brief SWUP related typedefs, macros and function declarations.
 */

#ifndef SWUP_H
#define SWUP_H

#include <stdbool.h>
#include <stdint.h>
#include "imageInfo.h"
#include "memoryMap.h"
#include "memory_devices_and_slots.h"
#include "sbm_hal.h"
#include "sbm_hal_mem.h"
#include "swup_status_error_code.h"
#include "swup_uuid.h"
#include "swup_eub.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Struct used by the update slot selection/priority queue mechanism.
 */
typedef struct
{
    const memory_slot *slot;
    hal_mem_address_t  max_offset;
    uint8_t            key_instance_value;
    uint32_t           version_number;
    unsigned int       swup_status;
} sbm_swup_selector_data;

/** Initialise the SWUP-handling code during startup
 */
extern void sbm_swup_init(void);

#if NUM_UPDATE_SLOTS > 1
/** Builds a priority queue for update slots.
 *
 * \param swup_priority_queue Container for priority queue (array of size #NUM_UPDATE_SLOTS).
 *
 * \note This function is used only when there's more than 1 update slot defined.
 * \note The priority queue is built in descending order (the lower the index, the higher the priority).
 */
void sbm_build_swup_priority_queue(sbm_swup_selector_data swup_priority_queue[NUM_UPDATE_SLOTS]);
#endif /* NUM_UPDATE_SLOTS > 1 */

/** Does the update slot contain a SWUP?
 *
 * Does a maximal validation.
 *
 * \param[in] update_slot The update slot to check for a SWUP.
 * \param[out] max_offset If the SWUP is valid, then this is set to the offset of
 *                        the last byte of the SWUP based on its length. I.e. this is
 *                        equal to the SWUP length minus one.
 * \param[out] key_instance Address of a \c uint8_t to populate with update key instance number.
 * \note \a key_instance may be NULL. If it is not NULL, \a *key_instance is modified in all cases.
 *
 * \retval SWUP_STATUS_INITIAL The SWUP is installable.
 * \retval SWUP_STATUS_INSTALLED_THIS_BOOT The SWUP was installed at most recent boot.
 * \retval SWUP_STATUS_INSTALLED_PREVIOUS The SWUP was installed during a previous boot.
 *
 * \note If SWUP_STATUS_INITIAL is returned, \a *key_instance holds the instance number of the update key.
 *
 * Any other value returned means that the SWUP is erroneous.
 *
 * The values returned can be either from the SWUP update
 * status or, when enabled, the extended error set (see above).
 *
 * \note Called during boot process and from a secure API context.<br>
 * When called from a secure API context, logging must be disabled (see sbm_log_disable()).
 */
unsigned int sbm_update_slot_contains_swup(const memory_slot *update_slot, hal_mem_address_t *max_offset, uint8_t *key_instance);

/** Establish the status of the module within the executable slot.
 *
 * \note This verifies the module using the PIEM/PIEMF located in the MUH slot.
 *
 * \return \b true if the module is good, \b false otherwise.
 *
 * \note Called during boot process and from a secure API context.<br>
 * When called from a secure API context, logging must be disabled (see sbm_log_disable()).
 */
bool sbm_executable_slot_module_valid(void);

/** Return the version number of a permanently installed executable module.
 *
 * \return The version number of the module.
 *
 * \note Called during boot process and from a secure API context.
 */
uint32_t sbm_swup_piem_version(void);

/** Return the version number of the module in the update slot.
 *
 * This depends on the update slot containg a SWUP, the SWUP
 * containing exactly one EUB and the EUB containing a module.
 *
 * \note This reads the metadata from the SWUP and does not look within the EUB.
 *
 * \param[in] update_slot The update slot containing the SWUP to read.
 *
 * \return The version number from the EUB.
 *
 * \note Called during boot process.
 */
uint32_t sbm_swup_eub_version(const memory_slot *update_slot);

/** Compare the versions of the update in the SWUP and the current executable.
 *
 * Assumes that ...
 * * The update slot contains a SWUP.
 * * The SWUP is carrying a single EUB containing a module update.
 * * The executable slot contains a module update.
 *
 * \param[in] update_slot The update slot containing the SWUP to check.
 *
 * \return \b true if version rollback is being attempted, \b false otherwise.
 *
 * \note Called during boot process and from a secure API context.
 */
bool sbm_swup_update_version_rollback(const memory_slot *update_slot);

/** Install a module from an EUB in the SWUP.
 *
 * Assumes that the SWUP is carrying a single, encrypted EUB containing a module.
 *
 * Marks the SWUP as "installed" in passing.
 *
 * \param update_slot The update slot containing the SWUP to install.
 * \param max_offset The offset, relative to the start of the update slot, of the
 *                   last byte of the SWUP. If the SWUP length is unknown, then
 *                   this should be set to the last byte of the update slot.
 * \param key_instance Instance number of update key.
 *
 * \retval SWUP_INSTALL_STATUS_SUCCESS The installation was successful,
 * \retval SWUP_INSTALL_STATUS_SUCCESS_VERIFIED The installation was successful, and has been
 *                                              verified by sbm_executable_slot_module_valid(),
 * \retval SWUP_INSTALL_STATUS_FAILURE The SWUP was not installed but the Exec slot is intact,
 * \retval SWUP_INSTALL_STATUS_BRICKED The SWUP was partially installed, thus the Exec slot has been erased.
 *
 * \note Called during boot process.
 */
unsigned int sbm_swup_install_module(const memory_slot *update_slot, hal_mem_address_t max_offset, uint8_t key_instance);

/** Preserve the update status.
 *
 * Copies the status from the \a status argument into preserved RAM.
 *
 * \param status The update status to be preserved.
 */
void sbm_swup_set_last_status(const unsigned int status);

/** Retrieve the update status.
 *
 * Read the status from preserved RAM.
 *
 * \return The preserved update status.
 */
unsigned int sbm_swup_get_last_status(void);

/** Retrieve the update UUID.
 *
 * Read the UUID from preserved RAM.
 *
 * \param [out] uuid Address of a \c uuid_t into which the update UUID is copied.
 */
void sbm_swup_get_last_installed_uuid(uuid_t uuid);

/** Check if the SWUP in the update slot is valid to be installed.
 *
 * \return \b true if the SWUP is valid, otherwise return \b false.
 *
 * \param[in] update_slot The update slot to check.
 *
 * \note Called from a secure API context.
 */
bool sbm_swup_can_install_update(const memory_slot *update_slot);

/** Get the module info defined by the app_info_record struct.
 *
 * Checks the module stated is valid then copies the relevant information.
 *
 * \param[out] info The location to which the information, of type app_info_record, will be
 *             written.
 *
 * \return \b true if the information was successfully copied, \b false otherwise.
 *
 * \note Called from a secure API context.
 */
bool sbm_swup_get_executable_module_info(app_info_record *info);

#ifdef SBM_PC_BUILD
void sbm_swup_quiesce(void);
#endif

#ifdef __cplusplus
}
#endif
#endif /* SWUP_H */
