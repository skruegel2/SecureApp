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

#ifndef LOCKDOWN_H
#define LOCKDOWN_H

/* For use in C++ */
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Enumerate the lockdown levels. Note: These need to be visible to
 * the C pre-processor, so #define is used rather than an enum.
 */
#define	SBM_LOCKDOWN_LEVEL_UNLOCKED	0
#define	SBM_LOCKDOWN_LEVEL_LOCKED_TEMP	1
#define	SBM_LOCKDOWN_LEVEL_LOCKED_PERM	2

#if (SBM_LD_IMMEDIATE_DEBUG_PERM != 0) || \
    (SBM_LD_DELAYED_DEBUG_PERM != 0)
#define	SBM_LOCKDOWN_LEVEL	SBM_LOCKDOWN_LEVEL_LOCKED_PERM
#warning "FULL HARDWARE LOCKDOWN ENABLED - USE WITH CAUTION"
#elif (SBM_LD_IMMEDIATE_DEBUG_TEMP != 0) || \
      (SBM_LD_DELAYED_DEBUG_TEMP != 0)
#define	SBM_LOCKDOWN_LEVEL	SBM_LOCKDOWN_LEVEL_LOCKED_TEMP
#endif

#if SBM_LOCKDOWN_LEVEL != 0
void sbm_lockdown_firmware(void);
void sbm_disable_debug(void);

#include "soc_lockdown.h"

#if  (SBM_LD_IMMEDIATE_DEBUG_PERM != 0) || \
     (SBM_LD_IMMEDIATE_DEBUG_TEMP != 0)
#define SBM_LOCKDOWN_IMMEDIATE 1
#else
#define SBM_LOCKDOWN_DELAYED 1
#endif

#endif /* SBM_LOCKDOWN_LEVEL */

/* For use in C++ */
#ifdef __cplusplus
}
#endif
#endif /* LOCKDOWN_H */
