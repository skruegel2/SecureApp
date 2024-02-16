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

#ifndef SOC_FLASH_H
#define SOC_FLASH_H

#include "sbm_hal_mem.h"

/** \file
 * \brief API to the on-chip flash memory driver.
 *
 * For the purposes of this API, a *page* is defined as the smallest unit
 * that can be programmed (written) to flash memory, and a *sector* is the
 * smallest unit that can be erased. A sector consists of one or more pages.
 * For example, a flash may have 64 kB erasable sectors and 256 byte writable pages.
 * 
 * It is assumed that the flash may have non-uniform sector sizes, but
 * that all pages have the same size.
 */

/** Initialise support for on-chip Flash memory */
void soc_flash_init(void);

/** Get the page size of the flash memory.
 * 
 * While flash devices may have sectors of different sizes, it is assumed
 * that they have a uniform page size for programming.
 * 
 * \post retval > 0
 * 
 * \return The device's page size, in bytes.
 */
size_t soc_flash_page_size(void);

/** Read \p size bytes of data from the SOC flash memory.
 *
 * \pre dst != NULL
 *
 * \param[in] address The address of the first byte in the flash to be read.
 * \param[in] dst     The read data is copied into this buffer.
 * \param[in] size    The number of bytes to read.
 *
 * \return \c HAL_MEM_SUCCESS if the data was read successfully.
 *         \c HAL_MEM_READ_ERROR if the flash memory could not be read.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t soc_flash_read(hal_mem_address_t address, void *dst, size_t size);

/** Write one or more consecutive pages to the SOC flash memory.
 *
 * The address and size must both be aligned to the flash page boundary.
 *
 * \note This function does not guarantee that the data was written correctly
 * after programming. Verification should be done separately by the caller, if needed.
 *
 * \pre src != NULL
 * \pre (uintptr_t)src % 4 == 0
 * \pre address % soc_flash_page_size() == 0
 * \pre size % soc_flash_page_size() == 0
 *
 * \param[in] address The address of the first byte in the memory region to be written.
 *                    This must be aligned to a page boundary.
 * \param[in] src     Pointer to the source buffer containing the data to be written.
 *                    This buffer MUST be aligned to a 32-bit boundary.
 * \param[in] size    The number of bytes to program. This must be a multiple of the page size.
 *
 * \return \c HAL_MEM_SUCCESS if the program operation completed successfully.
 *         \c HAL_MEM_PROGRAM_ERROR if the program operation failed.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t soc_flash_write(hal_mem_address_t address, const void *src, size_t size);

/** Erase length \p size bytes of memory starting at the specified \p address
 * within the SOC flash memory address space.
 *
 * \note The start address will be rounded down to the nearest sector.
 *
 * \note The size will be rounded up to the next flash sector boundary.
 *
 * \param[in] address The address of the first byte in the memory region to be erased.
 * \param[in] size    The size of the region to erase, in bytes.
 *
 * \return \c HAL_MEM_SUCCESS if the erase operation completed successfully.
 *         \c HAL_MEM_ERASE_ERROR if one or more sectors could not be erased successfully.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t soc_flash_erase(hal_mem_address_t address, size_t size);

/** Verify that an area of SOC flash memory is erased.
 *
 * Note: on most devices, the verification process simply
 * checks if all the cells in a given range are set to the erase value
 * (usually 0xFF or 0x00). However, on some devices, the erase process
 * locks the read access to the erased ranged, so this method
 * of verification wouldn't work. For those devices, this function
 * instead checks if the area is writable in its entirety, as this indicates
 * that the area has been properly erased.
 *
 * To be explicit: an HAL_MEM_SUCCESS return from this function establishes
 * that the area in question is writable in its entirety. It DOES NOT
 * assert that any or all of it is readable!
 *
 * \param[in] address The address of the first byte in the memory region to be verified.
 * \param[in] size    The size of the region to verify, in bytes.
 *
 * \return \c HAL_MEM_SUCCESS if the specified region is fully writable in its entirety.
 *         \c HAL_MEM_NOT_ERASED if at least part of the specified region is not fully writable.
 *         \c HAL_MEM_READ_ERROR if part of the specified region could not be checked.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t soc_flash_verify_erased(hal_mem_address_t address, size_t size);

/** Disable all caches (called prior to write/erase operations)
 *
 * This is called before the start of a sequence of erase or write operations.
 *
 * \note This function is optional and needs to be implemented only by the
 * flash drivers that use caching mechanism.
 * The default (weak) implementation of this function is a no-op.
 */
void soc_flash_disable_caches(void);

/** Enable & flush all caches (called after write/erase operations)
 *
 * This is called after the completion of a sequence of erase or write operations,
 * regardless of the success or failure of that operation sequence.
 *
 * \note This function is optional and needs to be implemented only by the
 * flash drivers that use caching mechanism.
 * The default (weak) implementation of this function is a no-op.
 */
void soc_flash_enable_and_flush_caches(void);

#endif /* SOC_FLASH_H */
