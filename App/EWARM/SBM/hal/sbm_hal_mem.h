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

#ifndef SBM_HAL_MEM_H
#define SBM_HAL_MEM_H

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "memory_devices_and_slots.h"

/** Descriptor for a memory region */
typedef struct
{
    uintptr_t   first_addr;	/* Mem addr, or offset if off-CPU */
    uintptr_t   last_addr;	/* Last addr/offset in region */
} hal_mem_desc_t;

typedef enum
{
    HAL_MEM_SUCCESS,        /**< The operation completed successfully */
    HAL_MEM_NOT_ERASED,     /**< Indicates that at least part of the memory is not erased
                                 when verifying whether the memory is erased (hal_mem_verify_erased()) */
    HAL_MEM_VERIFY_ERROR,   /**< A verify operation failed */
    HAL_MEM_READ_ERROR,     /**< A read operation failed */
    HAL_MEM_PROGRAM_ERROR,  /**< A program (write) operation failed */
    HAL_MEM_ERASE_ERROR,    /**< An erase operation failed */
    HAL_MEM_PARAM_ERROR,    /**< One or more parameters are invalid */
    HAL_MEM_INTERNAL_ERROR, /**< Bug detected */
} hal_mem_result_t;

/** Flash addresses are passed around using the following type.
 *
 * For on-chip Flash, this is is an absolute address in the CPU's
 * normal address space.
 * For external Flash, this is the offset from the beginning of
 * the address space.
 */
typedef uintptr_t hal_mem_address_t;
#define	PRIxMEM_ADDR PRIxPTR

/** Initialise all memory devices.
 */
void hal_mem_init(void);

/** Query if a memory device is present.
 *
 * This applies to removable memory devices only. Non-removable devices always return \c true.
 *
 * \pre device != NULL
 *
 * \param[in] device The memory device to query.
 * \return \c true if the specified memory device is currently present, or \c false otherwise.
 */
bool hal_mem_device_present(const memory_device *device);

/** Read \p size bytes of data from a memory slot.
 *
 * \pre slot != NULL
 * \pre dst != NULL
 * \pre offset_in_slot < slot->size
 * \pre size <= (slot->size - offset_in_slot) + 1
 *
 * \param[in] slot           The memory slot to read from.
 * \param[in] offset_in_slot The offset of the first byte to read relative to the
 *                           start of the slot.
 * \param[in] dst            The read data is copied into this buffer.
 * \param[in] size           The number of bytes to read, starting at \p offset_in_slot.
 *
 * \return \c HAL_MEM_SUCCESS if the data was read successfully.
 *         \c HAL_MEM_READ_ERROR if the memory device could not be read.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t hal_mem_read(const memory_slot *slot,
                              hal_mem_address_t offset_in_slot,
                              void *dst,
                              size_t size);

/** Write \p size bytes of data to the memory device.
 *
 * \note This function does not guarantee that the data was written correctly
 * after programming. Verification should be done separately by the caller, if needed,
 * by using the \c hal_mem_verify function.
 *
 * \see hal_mem_verify
 *
 * \pre slot != NULL
 * \pre src != NULL
 * \pre offset_in_slot < slot->size
 * \pre size <= (slot->size - offset_in_slot) + 1
 *
 * \param[in] slot           The memory slot to write to.
 * \param[in] offset_in_slot The offset of the first byte to write relative to the
 *                           start of the slot.
 * \param[in] src            The read data is copied into this buffer.
 * \param[in] size           The number of bytes to program, starting at \p offset_in_slot.
 *
 * \return \c HAL_MEM_SUCCESS if the program operation completed successfully.
 *         \c HAL_MEM_PROGRAM_ERROR if the program operation failed.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t hal_mem_program(const memory_slot *slot,
                                 hal_mem_address_t offset_in_slot,
                                 const void *src,
                                 size_t size);

/** Verify \p size bytes of data in the memory device against
 * the contents of the supplied buffer.
 *
 * \pre slot != NULL
 * \pre src != NULL
 * \pre offset_in_slot < slot->size
 * \pre size <= (slot->size - offset_in_slot) + 1
 *
 * \param[in] slot           The memory slot to verify.
 * \param[in] offset_in_slot The offset of the first byte to verify relative to the
 *                           start of the slot.
 * \param[in] src            The data is compared against the contents of this buffer.
 * \param[in] size           The number of bytes to read & verify, starting at \p offset_in_slot.
 *
 * \return \c HAL_MEM_SUCCESS if the data was successfully verified.
 *         \c HAL_MEM_READ_ERROR if the region could not be successfully read for verification.
 *         \c HAL_MEM_VERIFY_ERROR if the memory was successfully read, but the memory contents
 *                                 do not match the contents of the \p src buffer.
 */
hal_mem_result_t hal_mem_verify(const memory_slot *slot,
                                hal_mem_address_t offset_in_slot,
                                const void *src,
                                size_t size);

/** Erase length \p size bytes of memory starting at the specified \p address
 * within the device's address space.
 *
 * \note The start address will be rounded down to the nearest erase sector.
 *
 * \note The size will be rounded up to a multiple of the device's erase block size.
 *
 * \pre slot != NULL
 * \pre offset_in_slot < slot->size
 * \pre size <= (slot->size - offset_in_slot) + 1
 *
 * \param[in] slot           The memory slot to erase.
 * \param[in] offset_in_slot The offset of the first byte to erase relative to the
 *                           start of the slot.
 * \param[in] size           The size of the region to erase, in bytes.
 *
 * \return \c HAL_MEM_SUCCESS if the erase operation completed successfully.
 *         \c HAL_MEM_ERASE_ERROR if one or more sectors could not be erased successfully.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t hal_mem_erase(const memory_slot *slot,
                               hal_mem_address_t offset_in_slot,
                               size_t size);

/** Check whether an area of memory is erased.
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
 * \pre slot != NULL
 * \pre offset_in_slot < slot->size
 * \pre size <= (slot->size - offset_in_slot) + 1
 *
 * \param[in] slot           The memory slot to query.
 * \param[in] offset_in_slot The offset of the first byte to verify relative to the
 *                           start of the slot.
 * \param[in] size           The size of the region to verify, in bytes.
 *
 * \return \c HAL_MEM_SUCCESS if the specified region is fully writable in its entirety.
 *         \c HAL_MEM_NOT_ERASED if at least part of the specified region is not fully writable.
 *         \c HAL_MEM_READ_ERROR if part of the specified region could not be checked.
 *         \c HAL_MEM_PARAM_ERROR if one or more parameters are invalid.
 */
hal_mem_result_t hal_mem_verify_erased(const memory_slot *slot,
                                       hal_mem_address_t offset_in_slot,
                                       size_t size);

#endif /* SBM_HAL_MEM_H */
