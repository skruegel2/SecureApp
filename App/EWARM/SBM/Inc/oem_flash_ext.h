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
#ifndef OEM_FLASH_EXT_H
#define OEM_FLASH_EXT_H

#include "memory_devices_and_slots.h"

#if EXT_FLASH_DRV_ENABLED != 0

#include "sbm_hal_mem.h"

/** \file
 * \brief Defines OEM-specific low-level external flash routines.
 *
 * These are invoked for values of 'memory_drv' which are EXT_MEM_MAPPED_DRV.
 * This provides the option to support off-chip memory-mapped devices.
 * If these HAL functions are not provided, no-op defaults will be used.
 *
 * \warning Unless you take special measures to reserve a chunk of SRAM
 * for SBMs use, these functions must not read/write SRAM-resident global
 * variables once the application has been started. This includes calling
 * any HAL/SBM API which uses global variables.
 */

/** Initialise all known external flash devices ready for use.
 *
 * If it returns false, external flash is permanently
 * unavailable and should be disabled for this reset/boot/power cycle.
 *
 * This function may communicate with the flash device(s) to confirm correct
 * type and functioning.
 *
 * \returns true on success; false if external flash is inoperative
 */
bool oem_flash_ext_init(void);

/** Quiesce all external flash devices */
void oem_flash_ext_quiesce(void);

/** Probe the external flash to determine if it is connected.
 * 
 * This is used for external flash devices that are removable, for example
 * a flash chip on a removable header board. If the specific hardware architecture
 * used does not support removable flashes (e.g. all flash devices are soldered
 * onto the PCB), then the implementation of this function should always return
 * \c true.
 * 
 * \note This function does not impose any particular method to probe
 * the flash. Possible implementations can include reading a presence detect GPIO,
 * or reading a register (e.g. JEDEC ID) to check for a valid response.
 * 
 * \param[in] device_id The ID of the device to query. This is used to distinguish
 *      between specific external flash devices if multiple devices are supported.
 * 
 * \retval true if the external flash is connected and can be used.
 * \retval false if the external flash is not connected.
 */
bool oem_flash_ext_present(uint32_t device_id);

/** Get the page size of the external flash memory.
 * 
 * While flash devices may have sectors of different sizes, it is assumed
 * that they have a uniform page size for programming.
 * 
 * \post retval > 0
 * 
 * \return The device's page size, in bytes.
 */
size_t oem_flash_ext_page_size(uint32_t device_id);

/** Read \p size bytes of data from external flash memory.
 *
 * \pre dst != NULL
 *
 * \param[in] device_id Identifies the specific external flash device to read.
 *                      This is used to distinguish between multiple external flash devices,
 *                      if multiple devices are supported by the implementation.
 * \param[in] address   The address of the first byte in the flash to be read.
 *                      This is a zero-based offset from the beginning of the external
 *                      flash memory address space.
 * \param[in] dst       The read data is copied into this buffer.
 * \param[in] size      The number of bytes to read.
 *
 * \return \c HAL_MEM_SUCCESS if the data was read successfully.
 *         \c HAL_MEM_READ_ERROR if the flash memory could not be read.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t oem_flash_ext_read(uint32_t device_id, hal_mem_address_t address, void *dst, size_t size);

/** Write one or more consecutive pages to external flash memory.
 *
 * The address and size must both be aligned to the flash page boundary.
 *
 * \note This function does not guarantee that the data was written correctly
 * after programming. Verification should be done separately by the caller, if needed.
 *
 * \pre src != NULL
 * \pre (uintptr_t)src % 4 == 0
 * \pre address % oem_flash_ext_page_size(device_id) == 0
 * \pre size % oem_flash_ext_page_size(device_id) == 0
 *
 * \param[in] device_id Identifies the specific external flash device to write.
 *                      This is used to distinguish between multiple external flash devices,
 *                      if multiple devices are supported by the implementation.
 * \param[in] address   The address of the first byte in the memory region to be written.
 *                      This must be aligned to a page boundary.
 *                      This is a zero-based offset from the beginning of the external
 *                      flash memory address space.
 * \param[in] src       Pointer to the source buffer containing the data to be written.
 *                      This buffer MUST be aligned to a 32-bit boundary.
 * \param[in] size      The number of bytes to program. This must be a multiple of the page size.
 *
 * \return \c HAL_MEM_SUCCESS if the program operation completed successfully.
 *         \c HAL_MEM_PROGRAM_ERROR if the program operation failed.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t oem_flash_ext_write(uint32_t device_id, hal_mem_address_t address, const void *src, size_t size);

/** Erase length \p size bytes of memory starting at the specified \p address
 * within the external flash memory address space.
 *
 * \note The start address will be rounded down to the nearest sector.
 *
 * \note The size will be rounded up to the next flash sector boundary.
 *
 * \param[in] device_id Identifies the specific external flash device to erase.
 *                      This is used to distinguish between multiple external flash devices,
 *                      if multiple devices are supported by the implementation.
 * \param[in] address   The address of the first byte in the memory region to be erased.
 *                      This is a zero-based offset from the beginning of the external
 *                      flash memory address space.
 * \param[in] size      The size of the region to erase, in bytes.
 *
 * \return \c HAL_MEM_SUCCESS if the erase operation completed successfully.
 *         \c HAL_MEM_ERASE_ERROR if one or more sectors could not be erased successfully.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t oem_flash_ext_erase(uint32_t device_id, hal_mem_address_t address, size_t size);

/** Verify that an area of external flash memory is erased.
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
 * \param[in] device_id Identifies the specific external flash device to verify.
 *                      This is used to distinguish between multiple external flash devices,
 *                      if multiple devices are supported by the implementation.
 * \param[in] address   The address of the first byte in the memory region to be verified.
 *                      This is a zero-based offset from the beginning of the external
 *                      flash memory address space.
 * \param[in] size      The size of the region to verify, in bytes.
 *
 * \return \c HAL_MEM_SUCCESS if the specified region is fully writable in its entirety.
 *         \c HAL_MEM_NOT_ERASED if at least part of the specified region is not fully writable.
 *         \c HAL_MEM_READ_ERROR if part of the specified region could not be checked.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t oem_flash_ext_verify_erased(uint32_t device_id, hal_mem_address_t address, size_t size);

/** Disable any caches for the external flash (called prior to write/erase operations)
 *
 * This is called before the start of a sequence of erase or write operations.
 *
 * \note This function is optional and needs to be implemented only by the
 * external flash drivers that use caching mechanism.
 * The default (weak) implementation of this function is a no-op.
 * 
 * \param[in] device_id Identifies the specific external flash device to disable caches for.
 *                      This is used to distinguish between multiple external flash devices,
 *                      if multiple devices are supported by the implementation.
 */
void oem_flash_ext_disable_caches(uint32_t device_id);

/** Enable & flush all caches for the external flash (called after write/erase operations)
 *
 * This is called after the completion of a sequence of erase or write operations,
 * regardless of the success or failure of that operation sequence.
 *
 * \note This function is optional and needs to be implemented only by the
 * external flash drivers that use caching mechanism.
 * The default (weak) implementation of this function is a no-op.
 * 
 * \param[in] device_id Identifies the specific external flash device to enable caches for.
 *                      This is used to distinguish between multiple external flash devices,
 *                      if multiple devices are supported by the implementation.
 */
void oem_flash_ext_enable_and_flush_caches(uint32_t device_id);

#endif /* EXT_FLASH_DRV_ENABLED != 0 */

#endif /* OEM_FLASH_EXT_H */
