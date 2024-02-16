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

#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <ctype.h>
#include "sbm_log.h"
#include "sbm_memory.h"

#if SBM_LOG_VERBOSITY > SBM_LOG_LEVEL_NONE

/* Use a random value as a key to enable logging.
 * This makes it unlikely that logging will be enabled if `s_logging_enabled`
 * is corrupted. */
#define SBM_LOG_ENABLE_VALUE (0xD87E194)

static uint32_t s_logging_enabled SBM_PERSISTENT_RAM = SBM_LOG_ENABLE_VALUE;

void sbm_log_disable(void)
{
    s_logging_enabled = 0U;
}

void sbm_log(sbm_log_level_t log_level, const char *module, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    sbm_vlog(log_level, module, format, args);
    va_end(args);
}

void sbm_vlog(sbm_log_level_t log_level, const char *module, const char *format, va_list args)
{
    if (s_logging_enabled == SBM_LOG_ENABLE_VALUE)
    {
        static const char *const level_strs[SBM_LOG_LEVEL_MAX + 1] =
        {
            "",          /* SBM_LOG_LEVEL_NONE */
            "Error: ",   /* SBM_LOG_LEVEL_ERROR */
            "Warning: ", /* SBM_LOG_LEVEL_WARNING */
            "Info: ",    /* SBM_LOG_LEVEL_INFO */
            "Debug: "    /* SBM_LOG_LEVEL_DEBUG */
        };

        const char *level_str;
        if (log_level <= SBM_LOG_LEVEL_MAX) /* bounds check */
        {
            level_str = level_strs[log_level];
        }
        else
        {
            level_str = "";
        }

        if (module != NULL)
        {
            printf("$[%s] %s", module, level_str);
        }
        else
        {
            printf("$[] %s", level_str);
        }

        vprintf(format, args);
    }
}

void sbm_printf(const char *format, ...)
{
    if (s_logging_enabled == SBM_LOG_ENABLE_VALUE)
    {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}

void sbm_hexdump(const void *data, size_t size)
{
    if ((s_logging_enabled == SBM_LOG_ENABLE_VALUE) && (data != NULL))
    {
        const uint8_t *const buf = (const uint8_t*)data;
        for (size_t i = 0U; i < size; i += 16U)
        {
            /* Cast size_t to uint32_t for printf, since the 'z' size
             * modifier is not available on every compiler (e.g. some MinGW builds) */
            printf("%06" PRIu32 "  ", (uint32_t)i);
            for (size_t j = 0U; j < 16U; ++j)
            {
                if (i + j < size)
                {
                    printf("%02" PRIx8 " ", buf[i + j]);
                }
                else
                {
                    printf("   ");
                }
            }

            printf(" ");
            for (size_t j = 0U; j < 16U; ++j)
            {
                if (i + j < size)
                {
                    printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
                }
            }
            printf("\n");
        }
    }
}

#endif /* SBM_LOG_VERBOSITY > SBM_LOG_LEVEL_NONE */
