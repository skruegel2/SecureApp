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
 * \brief SWUP priority queue implementation for handling multiple SWUPs
 */

#include "memory_devices_and_slots.h"
#include "sbm_hal_mem.h"

#if NUM_UPDATE_SLOTS > 1

#include <assert.h>
#include <stdint.h>
#include "sbm_log_update_status.h"
#include "swup.h"

void sbm_build_swup_priority_queue(sbm_swup_selector_data swup_priority_queue[NUM_UPDATE_SLOTS])
{
    assert(swup_priority_queue);

    uint32_t priority_queue_num_entries_ready = 0;

    /* Iterate through the list of update slots */
    SBM_LOG_UPDATE_DEBUG("searching update slots for an image to select\n");
    for (size_t i = 0; i < NUM_UPDATE_SLOTS; i++)
    {
        const memory_slot *const update_slot = &update_slots[i];

        /* Acknowledge a new entry in priority queue and initially target it for injection */
        uint32_t priority_queue_placement = priority_queue_num_entries_ready;
        priority_queue_num_entries_ready++;

        /* Find out if anything is in the update slot */
        uint8_t key_instance_value = 0;
        hal_mem_address_t max_offset;
        unsigned int swup_status = sbm_update_slot_contains_swup(update_slot, &max_offset, &key_instance_value);
        uint32_t version_number = 0;

        /* Handle valid image */
        if (swup_status == SWUP_STATUS_INITIAL || swup_status == SWUP_STATUS_INSTALLED_PREVIOUS)
        {
            /* Get the version of the image */
            version_number = sbm_swup_eub_version(update_slot);
            SBM_LOG_UPDATE_INFO("update slot \"%s\" contains valid image (version: 0x%" PRIx32 ")\n",
                                update_slot->name,
                                version_number);

            /* Rearrange the priority queue and find the target position for the new entry */
            while (priority_queue_placement)
            {
                /* Check the priority condition */
                if (version_number < swup_priority_queue[priority_queue_placement - 1].version_number)
                {
                    break;
                }
                else if (version_number == swup_priority_queue[priority_queue_placement - 1].version_number)
                {
                    const memory_device *device1 = get_device_from_slot(update_slot);
                    const memory_device *device2 = get_device_from_slot(swup_priority_queue[priority_queue_placement - 1].slot);
                    if (device1->memory_drv < device2->memory_drv)
                    {
                        break;
                    }
                }

                /* Move the slot up the priority queue */
                swup_priority_queue[priority_queue_placement] = swup_priority_queue[priority_queue_placement - 1];
                priority_queue_placement--;
            }
        }

        /* Inject the new entry into priority queue */
        swup_priority_queue[priority_queue_placement].slot = update_slot;
        swup_priority_queue[priority_queue_placement].max_offset = max_offset;
        swup_priority_queue[priority_queue_placement].key_instance_value = key_instance_value;
        swup_priority_queue[priority_queue_placement].version_number = version_number;
        swup_priority_queue[priority_queue_placement].swup_status = swup_status;
    }
}
#endif /* NUM_UPDATE_SLOTS > 1 */
