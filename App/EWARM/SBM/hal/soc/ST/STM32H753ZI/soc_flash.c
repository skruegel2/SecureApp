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
#include <stdint.h>
#include <string.h>
#include "sbm_hal.h"
#include "stm32h7xx_hal.h"
#include "memoryMap.h"

#define FLASH_ERASE_VALUE 0xFFu

#define FLASH_SECTORS_PER_BANK  (FLASH_BANK_SIZE / FLASH_SECTOR_SIZE)

#ifdef DUAL_BANK
#define FLASH_NBANKS            2u
#else
#define FLASH_NBANKS            1u
#endif

#define FLASH_PROGRAM_SIZE  (FLASH_NB_32BITWORD_IN_FLASHWORD * 4)

static void STZ_HAL_FLASH_Unlock(uint32_t bank);
static void STZ_HAL_FLASH_Lock(uint32_t bank);
static uint32_t get_sector_bank(uint32_t sector);
static uint32_t get_address_bank(hal_mem_address_t address);

void soc_flash_init(void)
{
    /* Purge any left-over errors */
    uint32_t flash_flags_to_clear = FLASH_FLAG_EOP | FLASH_FLAG_WRPERR | FLASH_FLAG_PGSERR;

#if defined (FLASH_SR_OPERR)
    flash_flags_to_clear |= FLASH_FLAG_OPERR;
#endif

    HAL_FLASH_Unlock();
    __HAL_FLASH_CLEAR_FLAG(flash_flags_to_clear);
    HAL_FLASH_Lock();
}

size_t soc_flash_page_size(void)
{
    return FLASH_PROGRAM_SIZE;
}

hal_mem_result_t soc_flash_read(hal_mem_address_t address, void *dst, size_t size)
{
    /* Precondition checks */
    assert(dst != NULL);

    /* Sanity check address range */
    assert(address >= SOC_FLASH_START_ADDRESS);
    assert(address <  (SOC_FLASH_START_ADDRESS + (FLASH_BANK_SIZE * FLASH_NBANKS)));
    assert(size    <= (SOC_FLASH_START_ADDRESS + (FLASH_BANK_SIZE * FLASH_NBANKS)) - address);

    memcpy(dst, (const void*)address, size);
    return HAL_MEM_SUCCESS;
}

hal_mem_result_t soc_flash_write(hal_mem_address_t address, const void *src, size_t size)
{
    /* Precondition checks */
    assert(src != NULL);
    assert(((uintptr_t)src & 0x3) == 0);
    assert((address % FLASH_PROGRAM_SIZE) == 0);
    assert((size % FLASH_PROGRAM_SIZE) == 0);

    const uint32_t *src_words = (const uint32_t*)src;

    for (size_t i = 0; 
         i < size;
         i         += FLASH_PROGRAM_SIZE,
         address   += FLASH_PROGRAM_SIZE,
         src_words += FLASH_NB_32BITWORD_IN_FLASHWORD)
    {
        const uint32_t bank = get_address_bank(address);

        /*
        * The Program function is located in RAM, and we must ensure Flash is not
        * accessed while the program operation is in progress, thus interrupts
        * must be disabled during programming.
        */
        const uint32_t x = cpu_critical_enter();

        STZ_HAL_FLASH_Unlock(bank);
        const HAL_StatusTypeDef status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_FLASHWORD,
                                                           address,
                                                           (uintptr_t)src_words);
        STZ_HAL_FLASH_Lock(bank);

        cpu_critical_exit(x);

        /*
        * Ensure the target page is not cached so that the new contents are
        * immediately visible to te CPU. This is probably overkill since the
        * Flash region is write-through by default, but it does no harm to
        * err on the side of caution.
        *
        * We don't need to flush the instruction cache because we have yet to
        * execute anything from the Exec slot.
        */
        SCB_InvalidateDCache_by_Addr((uint32_t *)(uintptr_t)address, FLASH_PROGRAM_SIZE);

        if (status != HAL_OK)
        {
            return HAL_MEM_PROGRAM_ERROR;
        }
    }

    return HAL_MEM_SUCCESS;
}

hal_mem_result_t soc_flash_erase(hal_mem_address_t address, size_t size)
{
    FLASH_EraseInitTypeDef pEraseInit;
    uint32_t SectorError;
    HAL_StatusTypeDef status;

    /* Calculate the range of sector numbers being erased. */
    const uint32_t first_sector = (address                - SOC_FLASH_START_ADDRESS) / FLASH_SECTOR_SIZE;
    const uint32_t last_sector  = (((address + size) - 1) - SOC_FLASH_START_ADDRESS) / FLASH_SECTOR_SIZE;

    size_t sectors_remaining = (last_sector - first_sector) + 1;
    size_t sector            = first_sector;
    uint32_t bank_num = get_sector_bank(sector);

    /* Break the erases into batches across each bank */
    while (sectors_remaining > 0)
    {
        /* Calculate the number of sectors being erased in this bank */
        const uint32_t sector_in_bank = sector % FLASH_SECTORS_PER_BANK;
        uint32_t num_erase_sectors    = (FLASH_SECTORS_PER_BANK - sector_in_bank);
        if (num_erase_sectors > sectors_remaining)
        {
            num_erase_sectors = sectors_remaining;
        }

        /* Prepare the Erase structure passed to ST's HAL function */
        pEraseInit.TypeErase = FLASH_TYPEERASE_SECTORS;
        pEraseInit.Banks     = bank_num;
        pEraseInit.Sector    = sector_in_bank;
        pEraseInit.NbSectors = num_erase_sectors;
    #if defined (FLASH_CR_PSIZE)
        pEraseInit.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    #endif

        /*
        * Ensure there are no stale entries in the Dcache for the sector.
        * It's cheaper to invalidate the entire Dcache than cycle through
        * a 128KB sector.
        */
        SCB_CleanInvalidateDCache();

        /*
        * The Erase function is located in RAM, and we must ensure Flash is not
        * accessed while the erase operation is in progress, thus interrupts
        * must be disabled.
        */
        const uint32_t x = cpu_critical_enter();

        /* Unlock Flash and perform the erase */
        STZ_HAL_FLASH_Unlock(bank_num);
        status = HAL_FLASHEx_Erase(&pEraseInit, &SectorError);
        STZ_HAL_FLASH_Lock(bank_num);

        /* Restore interrupts */
        cpu_critical_exit(x);

        if (status != HAL_OK)
        {
            return HAL_MEM_ERASE_ERROR;
        }

        /* Advance to next bank */
        sectors_remaining -= num_erase_sectors;
        sector            += num_erase_sectors;
        ++bank_num;
    }

    return HAL_MEM_SUCCESS;
}

hal_mem_result_t soc_flash_verify_erased(hal_mem_address_t address, size_t size)
{
    /* Check that all bytes in the specified range are at their erased value */
    const uint8_t *source = (const uint8_t*)address;
    for (size_t i = 0U; i < size; i++)
    {
        if (source[i] != FLASH_ERASE_VALUE)
        {
            return HAL_MEM_NOT_ERASED;
        }
    }

    return HAL_MEM_SUCCESS;
}

/*
 * Roll our own local variants of ST's HAL_FLASH_Lock/Unlock(). Their version
 * operates on both banks, whereas we need to be rather more selective since
 * bank 1 could/should be locked down. (This is really only an issue for the
 * unit test framework; SBM will not write to Flash after lockdown is
 * established).
 */
static void STZ_HAL_FLASH_Unlock(uint32_t bank)
{
    if (FLASH_BANK_1 == bank)
    {
        if (READ_BIT(FLASH->CR1, FLASH_CR_LOCK) != RESET)
        {
            /* Authorize the FLASH A Registers access */
            WRITE_REG(FLASH->KEYR1, FLASH_KEY1);
            WRITE_REG(FLASH->KEYR1, FLASH_KEY2);
        }
    }
#ifdef FLASH_BANK_2
    else if (FLASH_BANK_2 == bank)
    {
        if (READ_BIT(FLASH->CR2, FLASH_CR_LOCK) != RESET)
        {
            /* Authorize the FLASH B Registers access */
            WRITE_REG(FLASH->KEYR2, FLASH_KEY1);
            WRITE_REG(FLASH->KEYR2, FLASH_KEY2);
        }
    }
#endif
}

static void STZ_HAL_FLASH_Lock(uint32_t bank)
{
    if (FLASH_BANK_1 == bank)
    {
        /* Set the LOCK Bit to lock the FLASH A Registers access */
        SET_BIT(FLASH->CR1, FLASH_CR_LOCK);
    }
#ifdef FLASH_BANK_2
    else if (FLASH_BANK_2 == bank)
    {
        /* Set the LOCK Bit to lock the FLASH B Registers access */
        SET_BIT(FLASH->CR2, FLASH_CR_LOCK);
    }
#endif
}

static uint32_t get_sector_bank(uint32_t sector)
{
#ifdef FLASH_BANK_2
    return (sector / FLASH_SECTORS_PER_BANK) ? FLASH_BANK_2 : FLASH_BANK_1;
#else
    return FLASH_BANK_1;
#endif
}

static uint32_t get_address_bank(hal_mem_address_t address)
{
#ifdef FLASH_BANK_2
    return (address >= (SOC_FLASH_START_ADDRESS + FLASH_BANK_SIZE)) ? FLASH_BANK_2 : FLASH_BANK_1;
#else
    return FLASH_BANK_1;
#endif
}
