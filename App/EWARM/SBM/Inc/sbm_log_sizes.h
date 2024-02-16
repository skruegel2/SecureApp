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

#ifndef SBM_LOG_SIZES_H
#define SBM_LOG_SIZES_H

#include "sbm_log.h"

#if SBM_ENABLE_LOG_SIZES != 0
    #define SBM_LOG_SIZES(level, ...)            SBM_LOG_##level("sizes", __VA_ARGS__)
    #define SBM_PRINTF_SIZES(level, ...)         SBM_PRINTF_##level(__VA_ARGS__)
    #define SBM_HEXDUMP_SIZES(level, data, size) SBM_HEXDUMP_##level((data), (size))
#else
    #define SBM_LOG_SIZES(level, ...)            do {} while(0)
    #define SBM_PRINTF_SIZES(level, ...)         do {} while(0)
    #define SBM_HEXDUMP_SIZES(level, data, size) do {} while(0)
#endif /* SBM_ENABLE_LOG_SIZES != 0 */

#define SBM_LOG_SIZES_ERROR(...)   SBM_LOG_SIZES(ERROR, __VA_ARGS__)
#define SBM_LOG_SIZES_WARNING(...) SBM_LOG_SIZES(WARNING, __VA_ARGS__)
#define SBM_LOG_SIZES_INFO(...)    SBM_LOG_SIZES(INFO, __VA_ARGS__)
#define SBM_LOG_SIZES_DEBUG(...)   SBM_LOG_SIZES(DEBUG, __VA_ARGS__)

#define SBM_PRINTF_SIZES_ERROR(...)   SBM_PRINTF_SIZES(ERROR, __VA_ARGS__)
#define SBM_PRINTF_SIZES_WARNING(...) SBM_PRINTF_SIZES(WARNING, __VA_ARGS__)
#define SBM_PRINTF_SIZES_INFO(...)    SBM_PRINTF_SIZES(INFO, __VA_ARGS__)
#define SBM_PRINTF_SIZES_DEBUG(...)   SBM_PRINTF_SIZES(DEBUG, __VA_ARGS__)

#define SBM_HEXDUMP_SIZES_ERROR(data, size)   SBM_HEXDUMP_SIZES(ERROR, (data), (size))
#define SBM_HEXDUMP_SIZES_WARNING(data, size) SBM_HEXDUMP_SIZES(WARNING, (data), (size))
#define SBM_HEXDUMP_SIZES_INFO(data, size)    SBM_HEXDUMP_SIZES(INFO, (data), (size))
#define SBM_HEXDUMP_SIZES_DEBUG(data, size)   SBM_HEXDUMP_SIZES(DEBUG, (data), (size))

#endif /* SBM_LOG_SIZES_H */
