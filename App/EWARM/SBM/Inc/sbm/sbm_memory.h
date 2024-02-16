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

#ifndef SBM_MEMORY_H
#define SBM_MEMORY_H

/*
 * Macroes controlling placement of variables in RAM.
 *
 * A region of target SRAM is set aside for the exclusive use of SBM. From
 * the linker script's point of view, this will be contained in a section
 * called "PERSISTENT_RAM". By default, all non-automatic SBM variables will
 * be placed in "PERSISTENT_RAM", however it is a requirement going forward
 * that all SBM variables are placed in the "PERSISTENT_RAM" section
 * explicitly by decorating variable declarations with the "SBM_PERSISTENT_RAM"
 * attribute. The linker map file will be audited periodically for all
 * instances of variables placed in the persistent section by default.
 *
 * Variables which are not required after the application is invoked can be
 * placed outside the persistent region by decorating the declaration with
 * SBM_EPHEMERAL_RAM. The contents of such variables will not be preserved
 * once the application has been started (they will in fact be zeroed just
 * before the application is invoked), and they must not be touched by SBM
 * when servicing a Secure API call.
 *
 * Variables located within the persistent region will be available to SBM
 * after the application has started. This is especially useful to maintain
 * state across Secure API calls.
 *
 * On platforms where the SBM_FIREWALL option is supported, the persistent
 * RAM will be completely inaccessible to application firmware.
 */
#ifndef SBM_PC_BUILD
#define	SBM_PERSISTENT_RAM	__attribute__ ((section("PERSISTENT_RAM")))
#define	SBM_EPHEMERAL_RAM	__attribute__ ((section("EPHEMERAL_RAM")))

/*
 * Declare the persistent and ephemeral memory blocks so that they can be
 * referenced within __section_{start,size,end} intrinsics.
 */
#pragma	section = "SBM_PERSISTENT_RAM"
#pragma	section = "SBM_EPHEMERAL_RAM"

#define	SBM_PERSISTENT_RAM_START	((uintptr_t)__section_begin("SBM_PERSISTENT_RAM"))
#define	SBM_PERSISTENT_RAM_END		((uintptr_t)__section_end("SBM_PERSISTENT_RAM"))
#define	SBM_PERSISTENT_RAM_SIZE		((uint32_t)__section_size("SBM_PERSISTENT_RAM"))
#define	SBM_EPHEMERAL_RAM_START		((uintptr_t)__section_begin("SBM_EPHEMERAL_RAM"))
#define	SBM_EPHEMERAL_RAM_END		((uintptr_t)__section_end("SBM_EPHEMERAL_RAM"))
#define	SBM_EPHEMERAL_RAM_SIZE		((uint32_t)__section_size("SBM_EPHEMERAL_RAM"))

#else /* SBM_PC_BUILD */
#define	SBM_PERSISTENT_RAM		/* Empty */
#define	SBM_EPHEMERAL_RAM		/* Empty */
#endif /* SBM_PC_BUILD */

#endif /* SBM_MEMORY_H */
