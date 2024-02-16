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

#include <stdint.h>
#include <stdbool.h>
#include "bufferCheck.h"
#include "memoryMap.h"
#include "memory_devices_and_slots.h"
#include "sbm_memory.h"
#include "sbm_hal_mem.h"


#if defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)
/* With TrustZone buffers are verified with hal_check_permission */
#include "sbm_hal.h"

#else

/** Check if addr range is wholly contained within one of the given regions
 *
 * \param[in]  b_first      The first buffer address/offset
 * \param[in]  b_last       The buffer end address/offset
 * \param[in]  regions      The regions
 * \param[in]  num_regions  The number regions
 * \param[in]  can_write    True if region is expected to be writable
 *
 * \return     True if in a region, False otherwise.
 */
static bool is_within_regions(uintptr_t b_first, uintptr_t b_last, size_t num_regions,
                                const hal_mem_desc_t *regions)
{
    while (0 != num_regions--)
    {
        /**
         * There are four cases (b_first < b_last already checked):
         *            first_addr             last_addr
         * * #1 --b_first--|-------b_last--------|------------
         * * #2 --b_first--|---------------------|---b_last---
         * * #3 -----------|-------b_first-------|---b_last---
         * * #4 -----------|-b_first------b_last-|------------
         */
        if ( ((b_last >= regions->first_addr) && (b_last <= regions->last_addr)) /* #1 and #4 */
            || ((b_first >= regions->first_addr) && (b_first <= regions->last_addr)) /* #3 and #4 */
            || ((b_first <= regions->first_addr) && (b_last >= regions->last_addr)) ) /* #2 */
        {
            return true;
        }
        ++regions;
    }
    return false;
}

/** Check if addr range is accessible (RO) from the application
 *
 * \param[in]  b_first      The first buffer address/offset
 * \param[in]  b_last       The buffer end address/offset
 *
 * \return     True if accesible as expected, False otherwise.
 */
static bool is_valid_app_region(uintptr_t b_first, uintptr_t b_last)
{
    /* Memory region for the SBM code */
    const hal_mem_desc_t sbm_mem_regions[] =
    {
        {
            sbm_slot.start_address,
            sbm_slot.start_address + (sbm_slot.size - 1)
        },
        {
            app_status_slot.start_address,
            app_status_slot.start_address + (app_status_slot.size - 1)
        },
        {
            SBM_SECURE_API_ADDRESS,
            SBM_SECURE_API_END_ADDRESS
        },
    };

    size_t num_sbm_regions = sizeof(sbm_mem_regions)/sizeof(sbm_mem_regions[0]);

    /* If within the "SBM regions", no access allowed */
    if (is_within_regions(b_first, b_last, num_sbm_regions, sbm_mem_regions))
    {
        return false;
    }

    /* The app can read everywhere in the ROM, apart from SBM areas */
    return true;
}

/** Check if RAM addr range is accessible (RO or RW) from the application
 *
 * \param[in]  b_first      The first buffer address/offset
 * \param[in]  b_last       The buffer end address/offset
 * \param[in]  can_write    True if RAM addr range is expected to be writable from the App
 *
 * \return     True if accesible as expected, False otherwise.
 */
static bool is_valid_ram_region(uintptr_t b_first, uintptr_t b_last, bool can_write)
{
    /** RAM reserved for the SBM
     *
     * \note: SBM_PERSISTENT_RAM_START/END comes from sbm_memory.h, where these addresses are defined
     * with attributes __section_begin and __section_end. As "IAR C/C++ Development Guide" states:
     * " __section_end Returns the address of the first byte after the named section or block."
     * Hence, "-1" to determine the upper limit of the persistent RAM section.
     */
    const hal_mem_desc_t sbm_ram_regions[] =
    {
        {
            SBM_PERSISTENT_RAM_START,
            (SBM_PERSISTENT_RAM_END - 1u) /* See comment above */
        },
    };

    size_t num_sbm_ram_regions = sizeof(sbm_ram_regions) / sizeof(sbm_ram_regions[0]);

    /* Unused for now */
    (void)can_write;

    /* If within the "SBM RAM" (i.e. persistent RAM), no access allowed */
    if(is_within_regions(b_first, b_last, num_sbm_ram_regions, sbm_ram_regions))
    {
        return false;
    }

    /* By default, anything that is not persistent RAM is RW for the App */
    return true;
}
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */

bool buffer_check_app_permissions_ram(const void *const buffer, const uint32_t bytes, const bool can_write)
{
    uintptr_t b_first = (uintptr_t) buffer;
    uintptr_t b_last = b_first + bytes - 1;

    /* Early bail for invalid parameters */
    if (0 == bytes || b_first > b_last)
    {
        /* RAM extension to be supported */
        return false;
    }

#if defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)

  /* If firewall is enabled we need device-dependent checks */
    return (hal_check_permission(buffer, bytes, can_write));
#else

    return (is_valid_ram_region(b_first, b_last, can_write));
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */
}

bool buffer_check_app_permissions_rom(const void *const buffer, const uint32_t bytes)
{
    uintptr_t b_first = (uintptr_t) buffer;
    uintptr_t b_last  = b_first + bytes - 1;

    /* Early bail for invalid parameters */
    if (0 == bytes || b_first > b_last)
    {
        return false;
    }

#if defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)

    return hal_check_permission(buffer, bytes, false);
#else

    return (is_valid_app_region(b_first, b_last));
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */
}
