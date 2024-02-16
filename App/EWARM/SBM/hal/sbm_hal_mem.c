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
* SUBSTITUTE GOODS OR SERVICES LOSS OF USE, DATA, OR PROFITS OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "soc_flash.h"
#include "sbm_hal_mem.h"
#include "sbm_memory.h"
#include "oem.h"

/* This configures the size of the buffer used during verification
 * to read back the data that was written.
 *
 * This buffer is stored on the stack, so modifying this value affects
 * the amount of stack memory used by hal_mem_verify().
 */
#ifndef SBM_VERIFY_BUF_SIZE
#define SBM_VERIFY_BUF_SIZE 128
#endif

/*
 * To deal with writes of partial pages, and misaligned source buffers, we
 * need a page buffer in RAM, the size of which can be configured by OEM
 * code.
 *
 * This buffer is stored on the stack, so modifying this value affects
 * the amount of stack memory used by hal_mem_program().
 */
#ifndef OEM_FLASH_MAX_PAGE_SIZE
#define OEM_FLASH_MAX_PAGE_SIZE 256 /* Size, in bytes */
#endif

#define DEFAULT_ERASE_VALUE 0xFFu

#define IS_ADDRESS_4BYTE_ALIGNED(ADDR) (((ADDR) & 0x3) == 0)

static const memory_device* lookup_device_and_address(const memory_slot *slot,
                                                      hal_mem_address_t offset_in_slot,
                                                      size_t size,
                                                      hal_mem_address_t *address);
static uint8_t get_erase_value(const memory_device *const device,
                               hal_mem_address_t address);
static size_t get_page_size(const memory_device *device);
static hal_mem_result_t page_program(const memory_device *device,
                                     hal_mem_address_t address,
                                     const void *src,
                                     size_t size);
static void disable_caches(const memory_device *device);
static void enable_and_flush_caches(const memory_device *device);

#if SOC_RAM_DRV_ENABLED != 0
static hal_mem_result_t verify_erased_ram(const memory_device *device,
                                          hal_mem_address_t address,
                                          size_t size);
#endif /* SOC_RAM_DRV_ENABLED != 0 */

void hal_mem_init(void)
{
    soc_flash_init();
    oem_flash_init();
}

bool hal_mem_device_present(const memory_device *device)
{
#ifndef NDEBUG
    if (NULL == device)
    {
        return false;
    }
#endif /* NDEBUG */

    /* Non-removable devices are always assumed to be present */
    if (!device->removable)
    {
        return true;
    }

    switch (device->memory_drv)
    {
#if EXT_FLASH_DRV_ENABLED != 0
        case EXT_FLASH_DRV:
            return oem_flash_ext_present(device->id);
#endif /* EXT_FLASH_DRV_ENABLED != 0 */

#if EXT_MEM_MAPPED_DRV_ENABLED != 0
        case EXT_MEM_MAPPED_DRV:
            return oem_ext_mm_present();
#endif /* EXT_MEM_MAPPED_DRV_ENABLED != 0 */

#if SOC_RAM_DRV_ENABLED != 0
        case SOC_RAM_DRV: /* fall through */
#endif /* SOC_RAM_DRV_ENABLED != 0 */
        case SOC_FLASH_DRV:
            /* These devices are always assumed to be connected */
            return true;

        default:
            return false;
    }
}

hal_mem_result_t hal_mem_read(const memory_slot *slot,
                              hal_mem_address_t offset_in_slot,
                              void *dst,
                              size_t size)
{
#ifndef NDEBUG
    if ((NULL == slot) || (NULL == dst))
    {
        return HAL_MEM_PARAM_ERROR;
    }
#endif /* NDEBUG */

    hal_mem_address_t address;
    const memory_device *device = lookup_device_and_address(slot, offset_in_slot, size, &address);
    if (NULL == device)
    {
        return HAL_MEM_PARAM_ERROR;
    }

    switch (device->memory_drv)
    {
#if SOC_RAM_DRV_ENABLED != 0
        case SOC_RAM_DRV:
            (void)memcpy(dst, (void*)(uintptr_t)address, size);
            return HAL_MEM_SUCCESS;
#endif /* SOC_RAM_DRV_ENABLED != 0 */

#if EXT_MAPPED_MEM_DRV_ENABLED != 0
        case EXT_MEM_MAPPED_DRV:
            return oem_ext_mm_read(address, dst, size);
#endif /* EXT_MAPPED_MEM_DRV_ENABLED != 0 */

        case SOC_FLASH_DRV:
            return soc_flash_read(address, dst, size);

#if EXT_FLASH_DRV_ENABLED != 0
        case EXT_FLASH_DRV:
            return oem_flash_ext_read(device->id, address, dst, size);
#endif /* EXT_FLASH_DRV_ENABLED != 0 */

        default:
            return HAL_MEM_INTERNAL_ERROR;
    }
}

hal_mem_result_t hal_mem_program(const memory_slot *slot,
                                 const hal_mem_address_t offset_in_slot,
                                 const void *const src,
                                 const size_t size)
{
#if __IAR_SYSTEMS_ICC__<9
    #pragma data_alignment=4
    uint8_t page_buffer[OEM_FLASH_MAX_PAGE_SIZE];
#else
    uint8_t page_buffer[OEM_FLASH_MAX_PAGE_SIZE] __attribute__ ((aligned(4)));
#endif

#ifndef NDEBUG
    if ((NULL == slot) || (NULL == src))
    {
        return HAL_MEM_PARAM_ERROR;
    }
#endif /* NDEBUG */

    hal_mem_address_t address;
    const memory_device *device = lookup_device_and_address(slot, offset_in_slot, size, &address);
    if (NULL == device)
    {
        return HAL_MEM_PARAM_ERROR;
    }

    const size_t page_size = get_page_size(device);

    /* Sanity check that the page buffer is big enough to hold the device's page size */
    if (page_size > sizeof(page_buffer))
    {
        return HAL_MEM_INTERNAL_ERROR;
    }

    /*
     * At the present time, we do not need to support
     * addresses which are not a multiple of the page
     * size. The SWUP code will always write in
     * contiguous 1KB chunks, hence there is as yet
     * no need to add complexity here.
     */
    if ((address % page_size) != 0)
    {
        return HAL_MEM_PARAM_ERROR;
    }

    disable_caches(device);

    const uint8_t *src_bytes = (const uint8_t*)src;
    hal_mem_result_t result = HAL_MEM_SUCCESS;

    size_t remaining = size;
    size_t offset    = 0;

    /* Write full pages */
    while ((remaining >= page_size) && (result == HAL_MEM_SUCCESS))
    {
        const void *src_buffer;
        size_t write_size;

         /* Note: Some low-level drivers require the page buffer to be 4-byte aligned.
          * If the source buffer is already aligned, then we can pass it directly
          * and write as many contiguous full pages as possible.
          * Otherwise, it needs to go via the page_buffer which is aligned appropriately.
          */
        if (IS_ADDRESS_4BYTE_ALIGNED((uintptr_t)src_bytes))
        {
            src_buffer = &src_bytes[offset];
            write_size = remaining - (remaining % page_size); /* align size to a multiple of the page size */
        }
        else
        {
            memcpy(page_buffer, &src_bytes[offset], page_size);
            src_buffer = page_buffer;
            write_size = page_size;
        }

        result = page_program(device, address + offset, src_buffer, write_size);

        remaining -= write_size;
        offset    += write_size;
    }

    /* Write any leftovers in a final partial page. */
    if ((remaining > 0) && (result == HAL_MEM_SUCCESS))
    {
        memcpy(page_buffer, &src_bytes[offset], remaining);

        memset(&page_buffer[remaining],
               get_erase_value(device, address + offset),
               page_size - remaining);

        result = page_program(device, address + offset, page_buffer, page_size);
    }

    enable_and_flush_caches(device);
    return result;
}

hal_mem_result_t hal_mem_verify(const memory_slot *slot,
                                hal_mem_address_t offset_in_slot,
                                const void *src,
                                size_t size)
{
#ifndef NDEBUG
    if ((NULL == slot) || (NULL == src))
    {
        return HAL_MEM_PARAM_ERROR;
    }
#endif /* NDEBUG */

    uint8_t verify_buf[SBM_VERIFY_BUF_SIZE];
    hal_mem_result_t mem_result;

    size_t remaining = size;
    size_t offset = 0u;
    const uint8_t *const src_bytes = (const uint8_t*)src;

    while (remaining > 0)
    {
        /* Clamp the read size to SBM_VERIFY_BUF_SIZE */
        const size_t read_size = (remaining < SBM_VERIFY_BUF_SIZE) ? remaining : SBM_VERIFY_BUF_SIZE;

        mem_result = hal_mem_read(slot, offset_in_slot + offset, verify_buf, read_size);

        if (mem_result != HAL_MEM_SUCCESS)
        {
            return mem_result;
        }

        if (0 != memcmp(verify_buf, &src_bytes[offset], read_size))
        {
            return HAL_MEM_VERIFY_ERROR;
        }

        remaining -= read_size;
        offset    += read_size;
    }

    return HAL_MEM_SUCCESS;
}

hal_mem_result_t hal_mem_erase(const memory_slot *slot,
                               hal_mem_address_t offset_in_slot,
                               size_t size)
{
#ifndef NDEBUG
    if (NULL == slot)
    {
        return HAL_MEM_PARAM_ERROR;
    }
#endif /* NDEBUG */

    if (slot->prevent_erase)
    {
        return HAL_MEM_PARAM_ERROR;
    }

    hal_mem_address_t address;
    const memory_device *device = lookup_device_and_address(slot, offset_in_slot, size, &address);
    if (NULL == device)
    {
        return HAL_MEM_PARAM_ERROR;
    }

    hal_mem_result_t result;

    switch (device->memory_drv)
    {
#if SOC_RAM_DRV_ENABLED != 0
        case SOC_RAM_DRV:
            (void)memset((void*)(uintptr_t)address,
                         (int)get_erase_value(device, address),
                         size);
            return HAL_MEM_SUCCESS;
#endif /* SOC_RAM_DRV_ENABLED != 0 */

        case SOC_FLASH_DRV:
            soc_flash_disable_caches();
            result = soc_flash_erase(address, size);
            soc_flash_enable_and_flush_caches();
            return result;

#if EXT_FLASH_DRV_ENABLED != 0
        case EXT_FLASH_DRV:
            oem_flash_ext_disable_caches(device->id);
            result = oem_flash_ext_erase(device->id, address, size);
            oem_flash_ext_enable_and_flush_caches(device->id);
            return result;
#endif /* EXT_FLASH_DRV_ENABLED != 0 */

#if EXT_MAPPED_MEM_DRV_ENABLED != 0
        case EXT_MEM_MAPPED_DRV:
            oem_ext_mm_disable_caches();
            result = oem_ext_mm_erase(address, size);
            oem_ext_mm_enable_and_flush_caches();
            return result;
#endif /* EXT_MAPPED_MEM_DRV_ENABLED != 0 */

        default:
            return HAL_MEM_INTERNAL_ERROR;
    }
}

hal_mem_result_t hal_mem_verify_erased(const memory_slot *slot,
                                       hal_mem_address_t offset_in_slot,
                                       size_t size)
{
#ifndef NDEBUG
    if (NULL == slot)
    {
        return HAL_MEM_PARAM_ERROR;
    }
#endif /* NDEBUG */

    hal_mem_address_t address;
    const memory_device *device = lookup_device_and_address(slot, offset_in_slot, size, &address);
    if (NULL == device)
    {
        return HAL_MEM_PARAM_ERROR;
    }

    switch (device->memory_drv)
    {
#if SOC_RAM_DRV_ENABLED != 0
        case SOC_RAM_DRV:
            return verify_erased_ram(device, address, size);
#endif /* SOC_RAM_DRV_ENABLED != 0 */

        case SOC_FLASH_DRV:
            return soc_flash_verify_erased(address, size);

#if EXT_FLASH_DRV_ENABLED != 0
        case EXT_FLASH_DRV:
            return oem_flash_ext_verify_erased(device->id, address, size);
#endif /* EXT_FLASH_DRV_ENABLED != 0 */

#if EXT_MAPPED_MEM_DRV_ENABLED != 0
        case EXT_MEM_MAPPED_DRV:
            return oem_ext_mm_verify_erased(address, size);
#endif /* EXT_MAPPED_MEM_DRV_ENABLED != 0 */

        default:
            return HAL_MEM_INTERNAL_ERROR;
    }
}

/** Looks up the memory device and physical address from a sub-region of a slot.
 *
 * This also validates the parameters and returns \c NULL if any parameters
 * exceeds the bounds of the slot or mapped memory device.
 *
 * \pre slot != NULL
 * \pre address != NULL
 *
 * \param[in] slot The source memory slot.
 * \param[in] offset_in_slot The offset relative to the start of the slot's address.
 * \param[in] size The number of bytes in the range, starting at \p offset.
 * \param[out] address The corresponding physical address of the slot & offset within
 *                     the target memory device's address space. This is only valid
 *                     if a non-NULL value is returned.
 * \return A pointer to the memory device in which the slot is located.
 *         \c NULL is returned if the underlying memory device could not be retrieved,
 *         or if the specified range exceeds the bounds of the memory slot or underlying
 *         memory device's address space.
 */
static const memory_device* lookup_device_and_address(const memory_slot *slot,
                                                      hal_mem_address_t offset_in_slot,
                                                      size_t size,
                                                      hal_mem_address_t *address)
{
    /* Validate that the requested offset range is within the slot boundary */
    if ((offset_in_slot >= slot->size) ||
        (size > (slot->size - offset_in_slot)))
    {
        return NULL;
    }

    const memory_device *const device = get_device_from_slot(slot);
    if (NULL == device)
    {
        return NULL;
    }

    /* Validate that the resulting physical address is within the memory device's address space */
    *address = slot->start_address + offset_in_slot;
    if (!is_address_range_within_memory_device_bounds(device, *address, size))
    {
        return NULL;
    }

    return device;
}

static uint8_t get_erase_value(const memory_device *const device,
                               hal_mem_address_t address)
{
    const memory_subregion *const subregion = get_subregion_from_address(device, address);

    if (NULL == subregion)
    {
        return DEFAULT_ERASE_VALUE;
    }

    return subregion->erase_value;
}

/** Verify whether a RAM region is set to its erase value.
 *
 * \param[in] device  The memory device to query.
 * \param[in] address The address of the first memory-mapped byte to check.
 * \param[in] size    The number of consecutive bytes to check, starting from \p address.
 *
 * \retval HAL_MEM_SUCCESS if all bytes in the specified range are at their erase value.
 * \retval HAL_MEM_NOT_ERASED if one or more bytes are not at their erase value.
 */
#if SOC_RAM_DRV_ENABLED != 0
static hal_mem_result_t verify_erased_ram(const memory_device *device,
                                          hal_mem_address_t address,
                                          size_t size)
{
    const uint8_t *src_bytes = (const uint8_t*)address;
    const uint8_t erase_value = get_erase_value(device, address);

    for (size_t i = 0; i < size; i++)
    {
        if (src_bytes[i] != erase_value)
        {
            return HAL_MEM_NOT_ERASED;
        }
    }

    return HAL_MEM_SUCCESS;
}
#endif /* SOC_RAM_DRV_ENABLED != 0 */

/** Get the page size of the device.
 *
 * This queries the underlying driver to get the page size for programming.
 *
 * \post retval > 0
 */
static size_t get_page_size(const memory_device *device)
{
    switch (device->memory_drv)
    {
        case SOC_FLASH_DRV:
            return soc_flash_page_size();

#if EXT_FLASH_DRV_ENABLED != 0
        case EXT_FLASH_DRV:
            return oem_flash_ext_page_size(device->id);
#endif /* EXT_FLASH_DRV_ENABLED != 0 */

#if EXT_MAPPED_MEM_DRV_ENABLED != 0
        case EXT_MEM_MAPPED_DRV:
            return oem_ext_mm_page_size();
#endif /* EXT_MAPPED_MEM_DRV_ENABLED != 0 */

        case SOC_RAM_DRV: /* fall through */
        default:
            return 1;
    }
}

/** Program one or more consecutive pages to a memory device.
 *
 * \pre device != NULL
 * \pre address % get_page_size(device) == 0
 * \pre size % get_page_size(device) == 0
 *
 * \param[in] device  The target memory device to write to.
 * \param[in] address The address of the first byte to write. This must be a multiple
 *                    of \c device->min_write_size
 * \param[in] src     Buffer containing the data to write to memory.
 * \param[in] size    The number of bytes to write. This must be a multiple of
 *                    \c device->min_write_size.
 *
 * \return The result of the page program.
 */
static hal_mem_result_t page_program(const memory_device *device,
                                     hal_mem_address_t address,
                                     const void *src,
                                     size_t size)
{
    assert(NULL != device);
    assert((address % get_page_size(device)) == 0);
    assert((size % get_page_size(device)) == 0);

    switch (device->memory_drv)
    {
#if SOC_RAM_DRV_ENABLED != 0
        case SOC_RAM_DRV:
            (void)memcpy((void*)(uintptr_t)address, src, size);
            return HAL_MEM_SUCCESS;
#endif /* SOC_RAM_DRV_ENABLED != 0 */

        case SOC_FLASH_DRV:
            return soc_flash_write(address, src, size);

#if EXT_FLASH_DRV_ENABLED != 0
        case EXT_FLASH_DRV:
            return oem_flash_ext_write(device->id, address, src, size);
#endif /* EXT_FLASH_DRV_ENABLED != 0 */

#if EXT_MAPPED_MEM_DRV_ENABLED != 0
        case EXT_MEM_MAPPED_DRV:
            return oem_ext_mm_write(address, src, size);
#endif /* EXT_MAPPED_MEM_DRV_ENABLED != 0 */

        default:
            return HAL_MEM_INTERNAL_ERROR;
    }
}

/** Disable the caches for the specified memory device
 *
 * \pre device != NULL
 *
 * \param[in] device The target memory device to disable caches for.
 */
static void disable_caches(const memory_device *device)
{
    assert(NULL != device);

    switch (device->memory_drv)
    {
        case SOC_FLASH_DRV:
            soc_flash_disable_caches();

#if EXT_FLASH_DRV_ENABLED != 0
        case EXT_FLASH_DRV:
            oem_flash_ext_disable_caches(device->id);
#endif /* EXT_FLASH_DRV_ENABLED != 0 */

#if EXT_MAPPED_MEM_DRV_ENABLED != 0
        case EXT_MEM_MAPPED_DRV:
            oem_ext_mm_disable_caches();
            break;
#endif /* EXT_MAPPED_MEM_DRV_ENABLED != 0 */

        case SOC_RAM_DRV:   /* fall through */
        default:
            /* Nothing to do */
            break;
    }
}

/** Enable & flush the caches for the specified memory device
 *
 * \pre device != NULL
 *
 * \param[in] device The target memory device to enable & flush caches for.
 */
static void enable_and_flush_caches(const memory_device *device)
{
    assert(NULL != device);

    switch (device->memory_drv)
    {
        case SOC_FLASH_DRV:
            soc_flash_enable_and_flush_caches();

#if EXT_FLASH_DRV_ENABLED != 0
        case EXT_FLASH_DRV:
            oem_flash_ext_enable_and_flush_caches(device->id);
#endif /* EXT_FLASH_DRV_ENABLED != 0 */

#if EXT_MAPPED_MEM_DRV_ENABLED != 0
        case EXT_MEM_MAPPED_DRV:
            oem_ext_mm_enable_and_flush_caches();
            break;
#endif /* EXT_MAPPED_MEM_DRV_ENABLED != 0 */

        case SOC_RAM_DRV:   /* fall through */
        default:
            /* Nothing to do */
            break;
    }
}
