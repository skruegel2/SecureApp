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

#include <setjmp.h>
#include "lockdown.h"
#include "memoryMap.h"
#include "memory_devices_and_slots.h"
#include "sbm_hal.h"
#include "soc_lockdown.h"
#include "stm32h7xx_hal.h"

#if defined(SBM_LOCKDOWN_LEVEL) && (SBM_LOCKDOWN_LEVEL != 0) || \
    defined(SBM_HAL_UNIT_TESTS)
/*
 * Define LOCKDOWN_SAFETY_NET to prevent the code from raising RDP, otherwise
 * you stand a very real chance of bricking your device.
 */
/*#define LOCKDOWN_SAFETY_NET*/

/*
 * Linker "magic". See the STM32H7 linker script for more details.
 */
#pragma section="ROPCODE"
#pragma section="ROPSECTION"
#define SBM_PCROP_START     ((uintptr_t)__section_begin("ROPCODE"))
#define SBM_PCROP_END       (((uintptr_t)__section_end("ROPCODE")) - 1)
#define SBM_PCROP_SIZE      __section_size("ROPSECTION")
#define SBM_PCROP_EXISTS    (SBM_PCROP_SIZE != 0)

/*
 * Convert RDP magic numbers into a useful level
 */
#define CURRENT_RDP_LEVEL(rdp)                                           \
    (                                                                    \
        (rdp) == OB_RDP_LEVEL_0 ? SBM_LOCKDOWN_LEVEL_UNLOCKED : (        \
            (rdp) == OB_RDP_LEVEL_2 ? SBM_LOCKDOWN_LEVEL_LOCKED_PERM :   \
                SBM_LOCKDOWN_LEVEL_LOCKED_TEMP                           \
        )                                                                \
    )

/* returns a flash address sector */
#define FLASH_ADDR2SEC(addr) (((addr)-SOC_FLASH_START_ADDRESS)/FLASH_SECTOR_SIZE)

/**
 * Return a WRPSector configuration to protect the sectors between start and end address (inclusive).
 * The field supports an OR mask of values of OB_WRP_SECTOR_X, being X the sector number.
 * Each OB_WRP_SECTOR_X = 1 << X
 * @param start_address Start address for write protection
 * @param end_address End address for write protection
 * @return Value to put in \ref FLASH_OBProgramInitTypeDef.WRPSector to write protect the given address range.
 */
static uint32_t wrp_sectors_for(uint32_t start_address, uint32_t end_address)
{
    uint32_t wrp_sectors = 0;

    for(int sector = FLASH_ADDR2SEC(start_address); sector <= FLASH_ADDR2SEC(end_address); ++sector)
    {
#if (FLASH_SECTOR_TOTAL == 8U)
        wrp_sectors |= (1 << sector);
#elif (FLASH_SECTOR_TOTAL == 128)
        /* One bit is used to select group of 4 sectors for H7B3 */
        wrp_sectors |= (1 << (sector / 4));
#else
#error "Unsupported flash sector count"
#endif
    }

    return wrp_sectors;
}


int soc_lockdown_level(void)
{
    FLASH_OBProgramInitTypeDef options;

    /* Fetch the current options from Bank 1 */
    options.Banks = FLASH_BANK_1;
    HAL_FLASHEx_OBGetConfig(&options);

    return CURRENT_RDP_LEVEL(options.RDPLevel);
}

int soc_lockdown_raise_level(int new_level)
{
    FLASH_OBProgramInitTypeDef options;
    int current_level, rv;

    /* Fetch the current options from Bank 1 */
    options.Banks = FLASH_BANK_1;
    HAL_FLASHEx_OBGetConfig(&options);

    /* Get current level and validate requested level. */
    current_level = CURRENT_RDP_LEVEL(options.RDPLevel);
    if (new_level < SBM_LOCKDOWN_LEVEL_UNLOCKED ||
        new_level > SBM_LOCKDOWN_LEVEL_LOCKED_PERM)
    {
        return -1;
    }

    /* We can only raise lockdown level. */
    if (new_level <= current_level)
        return current_level;

#ifndef LOCKDOWN_SAFETY_NET
    /* Set the new RDP level */
    options.OptionType = OPTIONBYTE_RDP;
    options.RDPLevel = (new_level == 2) ? OB_RDP_LEVEL_2 : OB_RDP_LEVEL_1;
#else
    /* The safety net will raise to RDP level 1 only */
    options.OptionType = OPTIONBYTE_RDP;
    options.RDPLevel = OB_RDP_LEVEL_1;
    (void) new_level;
#endif

    uint32_t sectors_to_lock = wrp_sectors_for(sbm_slot.start_address,
                                               sbm_slot.start_address + sbm_slot.size - 1);

    if ((sectors_to_lock & options.WRPSector) != sectors_to_lock)
    {
        /* Write-protect the SBM sector */
        options.WRPSector |= sectors_to_lock;
        options.OptionType |= OPTIONBYTE_WRP;
        options.WRPState = OB_WRPSTATE_ENABLE;
    }

    if (SBM_PCROP_EXISTS &&
        (options.PCROPStartAddr != SBM_PCROP_START ||
        options.PCROPEndAddr != SBM_PCROP_END))
    {
        /* Define the SBM Execute Only area */
        options.PCROPConfig = OB_PCROP_RDP_ERASE;
        options.PCROPStartAddr = SBM_PCROP_START;
        options.PCROPEndAddr = SBM_PCROP_END;
        options.OptionType |= OPTIONBYTE_PCROP;
    }

#ifdef LOCKDOWN_SAFETY_NET
    /*
     * Just return if nothing has changed
     */
    if (options.OptionType == 0)
        return current_level;
#endif

    /* Unlock access to Option byte "*_PRG" registers */
    (void) HAL_FLASH_OB_Unlock();

    /* Make the necessary changes to the option bytes */
    /* On success, commit the changes and make them active */
    rv = HAL_FLASHEx_OBProgram(&options);
    if (rv == HAL_OK)
    {
        HAL_FLASH_OB_Launch();
    }

    /* Lock option byte "*_PRG" registers */
    (void) HAL_FLASH_OB_Lock();

    return rv == HAL_OK ? soc_lockdown_level() : -1;
}

int soc_lockdown_firmware(void)
{
    /* This device doesn't provide any temporary locking mechanism. */
    return soc_lockdown_level();
}
#endif /* defined(SBM_LOCKDOWN_LEVEL) && (SBM_LOCKDOWN_LEVEL != 0) */
