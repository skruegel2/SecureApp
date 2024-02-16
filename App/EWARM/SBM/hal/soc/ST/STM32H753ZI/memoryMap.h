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

#ifndef MEMORYMAP_H
#define MEMORYMAP_H

extern void STZ_ADDR_ROM_START;
extern void STZ_ADDR_ROM_END;
extern void STZ_ADDR_RAM_START;
extern void STZ_ADDR_RAM_END;

extern void STZ_ADDR_SECAPI_ACCESS_WINDOW_START;
extern void STZ_ADDR_SECAPI_ACCESS_WINDOW_END;
extern void STZ_ADDR_APPLICATION_RAM_START;
extern void STZ_ADDR_APPLICATION_RAM_END;


/** The following are required for bufferCheck.c
 @{
 */
#include "memory_map_flash.h"

/* These undefs can be removed when predefinition of
   the macros in SBM project files is withdrawn ... */

#undef SOC_FLASH_START_ADDRESS
#undef SOC_FLASH_END_ADDRESS
#undef SOC_RAM_START_ADDRESS
#undef SOC_RAM_END_ADDRESS
#undef SBM_SECURE_API_ADDRESS
#undef SBM_SECURE_API_END_ADDRESS

#define SOC_FLASH_START_ADDRESS ((uintptr_t) &STZ_ADDR_ROM_START)
#define SOC_FLASH_END_ADDRESS   ((uintptr_t) &STZ_ADDR_ROM_END)

#define SOC_RAM_START_ADDRESS ((uintptr_t) &STZ_ADDR_RAM_START)
#define SOC_RAM_END_ADDRESS   ((uintptr_t) &STZ_ADDR_RAM_END)

#define SBM_SECURE_API_ADDRESS     ((uintptr_t) &STZ_ADDR_SECAPI_ACCESS_WINDOW_START)
#define SBM_SECURE_API_END_ADDRESS ((uintptr_t) &STZ_ADDR_SECAPI_ACCESS_WINDOW_END)

#define SOC_APP_RAM_START_ADDRESS ((uintptr_t) &STZ_ADDR_APPLICATION_RAM_START)
#define SOC_APP_RAM_END_ADDRESS   ((uintptr_t) &STZ_ADDR_APPLICATION_RAM_END)

#endif /* MEMORYMAP_H */
