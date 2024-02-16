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

#include <assert.h>
#include "memory_devices_and_slots.h"

MDAS_STATIC_CONST memory_subregion memory_subregions[] = MEMORY_SUBREGIONS_INIT;
MDAS_STATIC_CONST memory_device    memory_devices[]    = MEMORY_DEVICES_INIT;

MDAS_CONST memory_slot      sbm_slot                       = SBM_MEMORY_SLOT_INIT;
MDAS_CONST memory_slot      app_status_slot                = APP_STATUS_MEMORY_SLOT_INIT;
MDAS_CONST memory_slot      exec_slot                      = EXEC_MEMORY_SLOT_INIT;

#if NUM_UPDATE_SLOTS > 0
MDAS_CONST memory_slot      update_slots[NUM_UPDATE_SLOTS] = { UPDATE_MEMORY_SLOTS_INIT };
#endif /* NUM_UPDATE_SLOTS > 0 */

#define NUM_MEMORY_DEVICES (sizeof memory_devices / sizeof *memory_devices)

const memory_device *get_device_from_slot(const memory_slot *slot)
{
    assert(slot->memory_device_idx < NUM_MEMORY_DEVICES);

    return &memory_devices[slot->memory_device_idx];
}

const memory_slot *get_update_slot_from_id(memory_slot_id_t id)
{
    assert(id != MEMORY_SLOT_ID_INVALID);

#if NUM_UPDATE_SLOTS > 0
    for (size_t idx = 0; idx < NUM_UPDATE_SLOTS; idx++)
    {
        if (update_slots[idx].id == id)
        {
            return &update_slots[idx];
        }
    }
#endif /* NUM_UPDATE_SLOTS > 0 */

    return NULL;
}

const memory_subregion *get_subregion_from_address(const memory_device *device, const uintptr_t address)
{
    assert(device);

    for (const memory_subregion *subregion_it = &memory_subregions[device->first_subregion_idx];
         subregion_it <= &memory_subregions[device->last_subregion_idx];
         subregion_it++)
    {
        if (address >= subregion_it->start_address && address <= subregion_it->end_address)
        {
            return subregion_it;
        }
    }
    return NULL;
}

bool is_address_range_within_memory_device_bounds(const memory_device *device, const uintptr_t address, const size_t size)
{
    /* The address range can span over multiple contiguous subregions */
    const memory_subregion *const first_subregion = get_subregion_from_address(device, address);
    const memory_subregion *const last_subregion  = get_subregion_from_address(device, address + size - 1);

    if ((first_subregion == NULL) || (last_subregion == NULL))
    {
        return NULL;
    }

    /* Check that the subregions are contiguous */
    const memory_subregion *prev_subregion = first_subregion;
    const memory_subregion *this_subregion = first_subregion + 1;
    while (this_subregion <= last_subregion)
    {
        if (this_subregion->start_address != (prev_subregion->end_address + 1))
        {
            return false;
        }

        prev_subregion = this_subregion;
        ++this_subregion;
    }

    return true;
}
