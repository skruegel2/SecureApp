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

#ifndef BUFFERCHECK_H
#define BUFFERCHECK_H

/** \file
 * \brief Provides memory location (RAM/ROM) tests.
 */

#include <stdbool.h>
#include <stdint.h>

/** Determine if the buffer is within allowed* RAM region.
 * 
 * \note *"allowed" is a region that is not the SBM areas and where the Application has RW access
 * \note No data is read or written through the \a buffer argument.
 *
 * \param buffer Address of region to check.
 * \param bytes Length of region.
 * \param can_write `true` if the buffer is writable, else `false`.
 *
 * \return \b true if the region is in RAM, \b false otherwise.
 */
bool buffer_check_app_permissions_ram(const void *const buffer, const uint32_t bytes,
                       const bool can_write);

/** Determine if the buffer is within allowed* ROM region.
 * 
 * \note *"allowed" is a region that is not the SBM areas and where the Application has read access
 * \note No data is read or written through the \a buffer argument.
 *
 * \param buffer Address of region to check.
 * \param bytes Length of region.
 *
 * \return \b true if the buffer is in valid ROM region, \b false otherwise.
 */
bool buffer_check_app_permissions_rom(const void *const buffer, const uint32_t bytes);

/** Determine if a buffer is within allowed* region, ROM or RAM.
 *
 * \note *"allowed" is a region that is not the SBM areas and where the Application has read access
 * \note No data is read or written through the \a buffer argument.
 *
 * \param buffer Address of region to check.
 * \param bytes Length of region.
 *
 * \return \b true if the region is in valid region, \b false otherwise.
 */
#define	buffer_check_app_permissions(buffer,bytes)	\
    (buffer_check_app_permissions_ram((buffer),(bytes), false) || \
     buffer_check_app_permissions_rom((buffer),(bytes)))

#endif /* BUFFERCHECK_H */
