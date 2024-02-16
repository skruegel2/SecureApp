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

#ifndef SBM_LOG_H
#define SBM_LOG_H

/** \file
 *
 * \brief SBM logging utilities.
 *
 * This file provides facilities to print formatted logging messages via the
 * OEM serial port. The logging functions are based on \c printf, so can accept
 * any formatters supported by \c printf.
 *
 * \par Logging levels
 * The logging functions use conditional compilation to enable/disable logging
 * and to change the level (verbosity) of the logging messages.
 * Five logging levels are supported:
 *   - 0 or not defined: No messages are logged, and logging support is disabled.
 *   - 1: Only error messages are enabled.
 *   - 2: Error and warning messages are enabled.
 *   - 3: Error, warning, and info messages are enabled.
 *   - 4: Error, warning, info, and debug messages are enabled.
 *
 * The logging level is configured by setting \c SBM_LOG_VERBOSITY to one
 * of the above numbers.
 *
 * \par Logging macros
 * The \c SBM_LOG_<level> macros are used to log messages, where \c <level> is
 * \c ERROR, \c WARNING, \c INFO, or \c DEBUG.
 * These macros take the following arguments:
 *  -# An optional null-terminated string of the name of the module that is
 *     printing the error message (e.g. "main", "OEM", "SWUP", etc...).
 *     This can also be \c NULL in which case no module name is included in the
 *     log message.
 *  -# The log message as a null-terminated formatted string (compatible with \c printf).
 *  -# Optional additional arguments that are passed to \c printf.
 *
 * Examples:
 * \code
 * SBM_LOG_ERROR("main", "something went wrong\n");
 * SBM_LOG_WARNING("SWUP", "SWUP verification failed\n");
 * SBM_LOG_INFO("main", "booting application\n");
 * SBM_LOG_DEBUG("SWUP", "copying block 0x%lx -> 0x%lx\n", src_addr, dest_addr);
 * \endcode
 *
 * The above code will print the following log messages
 * (assuming \c SBM_LOG_VERBOSITY is set to \c SBM_LOG_LEVEL_DEBUG ):
 * \code
 * $[main] Error: something went wrong
 * $[SWUP] Warning: SWUP verification failed
 * $[main] Info: booting application
 * $[SWUP] Debug: copying block 0x0100 -> 0x8000100
 * \endcode
 *
 * \par
 * Logging messages can be broken up across multiple calls by using a combination
 * of \c SBM_LOG_<level> and \c SBM_PRINTF_<level>. For example:
 * \code
 * SBM_LOG_INFO("main", "values:");
 * for (uint32_t i = 0U; i < 10U; i++)
 * {
 *     SBM_PRINTF_INFO(" %" PRIu32, i);
 * }
 * SBM_PRINTF_INFO("\n");
 * \endcode
 *
 * outputs:
 * \code
 * $[main] values: 0 1 2 3 4 5 6 7 8 9
 * \endcode
 */

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

/* Log levels */
#define SBM_LOG_LEVEL_NONE    0 /* No messages are logged */
#define SBM_LOG_LEVEL_ERROR   1 /* Only error messages are logged */
#define SBM_LOG_LEVEL_WARNING 2 /* Error and warning messages are logged */
#define SBM_LOG_LEVEL_INFO    3 /* Error, warning, and info messages are logged */
#define SBM_LOG_LEVEL_DEBUG   4 /* All messages (error, warning, info, and debug) are logged */

#define SBM_LOG_LEVEL_MAX     SBM_LOG_LEVEL_DEBUG

typedef uint8_t sbm_log_level_t; /* valid range: [0..4] */

#if SBM_LOG_VERBOSITY > SBM_LOG_LEVEL_NONE
    #define SBM_LOG_DISABLE() sbm_log_disable()
#else
    #define SBM_LOG_DISABLE() do {} while (0)
#endif

/* Error logging macros definitions */

#if SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_ERROR
    #define SBM_LOG_ERROR(module, ...)              sbm_log(SBM_LOG_LEVEL_ERROR, (module), __VA_ARGS__)
    #define SBM_PRINTF_ERROR(...)                   sbm_printf(__VA_ARGS__)
    #define SBM_HEXDUMP_ERROR(data, size)           sbm_hexdump((data), (size))
#else /* SBM_LOG_VERBOSITY < SBM_LOG_LEVEL_ERROR */
    #define SBM_LOG_ERROR(...)                      do {} while(0)
    #define SBM_PRINTF_ERROR(...)                   do {} while(0)
    #define SBM_HEXDUMP_ERROR(data, size)           do {} while(0)
#endif /* SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_ERROR */

/* Warning logging macros definitions */

#if SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_WARNING
    #define SBM_LOG_WARNING(module, ...)              sbm_log(SBM_LOG_LEVEL_WARNING, (module), __VA_ARGS__)
    #define SBM_PRINTF_WARNING(...)                   sbm_printf(__VA_ARGS__)
    #define SBM_HEXDUMP_WARNING(data, size)           sbm_hexdump((data), (size))
#else /* SBM_LOG_VERBOSITY < SBM_LOG_LEVEL_WARNING */
    #define SBM_LOG_WARNING(module, ...)              do {} while(0)
    #define SBM_PRINTF_WARNING(...)                   do {} while(0)
    #define SBM_HEXDUMP_WARNING(data, size)           do {} while(0)
#endif /* SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_WARNING */

/* Info logging macros definitions */

#if SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO
    #define SBM_LOG_INFO(module, ...)              sbm_log(SBM_LOG_LEVEL_INFO, (module), __VA_ARGS__)
    #define SBM_PRINTF_INFO(...)                   sbm_printf(__VA_ARGS__)
    #define SBM_HEXDUMP_INFO(data, size)           sbm_hexdump((data), (size))
#else /* SBM_LOG_VERBOSITY < SBM_LOG_LEVEL_INFO */
    #define SBM_LOG_INFO(module, ...)              do {} while(0)
    #define SBM_PRINTF_INFO(...)                   do {} while(0)
    #define SBM_HEXDUMP_INFO(data, size)           do {} while(0)
#endif /* SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO */

/* Debug logging macros definitions */

#if SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_DEBUG
    #define SBM_LOG_DEBUG(module, ...)              sbm_log(SBM_LOG_LEVEL_DEBUG, (module), __VA_ARGS__)
    #define SBM_PRINTF_DEBUG(...)                   sbm_printf(__VA_ARGS__)
    #define SBM_HEXDUMP_DEBUG(data, size)           sbm_hexdump(SBM_LOG_LEVEL_DEBUG, (data), (size))
#else /* SBM_LOG_VERBOSITY < SBM_LOG_LEVEL_DEBUG */
    #define SBM_LOG_DEBUG(module, ...)              do {} while(0)
    #define SBM_PRINTF_DEBUG(...)                   do {} while(0)
    #define SBM_HEXDUMP_DEBUG(data, size)           do {} while(0)
#endif /* SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_DEBUG */

#if SBM_LOG_VERBOSITY > SBM_LOG_LEVEL_NONE

/**
 * \brief Disable logging globally.
 *
 * \note Logging is enabled by default after a reset. This function disables
 * logging and should be called before booting the application.
 */
void sbm_log_disable(void);

/**
 * \brief Print a formatted log message.
 *
 * Messages are printed to the standard output (via printf) in the format:
 *
 * $[<module>] [<level>: ] <format>
 *
 * For example:
 *
 * \code
 * sbm_log(SBM_LOG_LEVEL_INFO, "main", "Hello, World!\n");
 * \endcode
 *
 * will output "$[main] Info: Hello, World!".
 *
 * \note This function has no effect if logging is disabled.
 *
 * \param[in] log_level The logging level of the message.
 *      This must be one of the \c SBM_LOG_LEVEL_* macros. If an invalid value
 *      is supplied, then the <level> part of the log message is omitted.
 *
 * \param[in] module An option null-terminated string for the name of the module
 *      that is logging the message. If this is \c NULL then the <module> part
 *      of the log message is omitted.
 *
 * \param[in] format The null-terminated format string to pass to \c printf.
 */
void sbm_log(sbm_log_level_t log_level, const char *module, const char *format, ...);

/**
 * \brief Print a formatted log message.
 *
 * This is identical to \p sbm_log() except the format arguments are passed
 * via a \c va_list.
 *
 * \see sbm_log()
 */
void sbm_vlog(sbm_log_level_t log_level, const char *module, const char *format, va_list args);

/**
 * \brief Conditionally call printf if logging is enabled.
 *
 * If logging is disabled, this function has no effect.
 */
void sbm_printf(const char *format, ...);

/**
 * \brief Print binary data.
 *
 * \param[in] data Pointer to the data buffer to print. This can be \c NULL,
 *      in which case nothing is printed.
 *
 * \param[in] size Number of bytes to print from the \p data buffer.
 */
void sbm_hexdump(const void *data, size_t size);

#endif /* SBM_LOG_VERBOSITY > SBM_LOG_LEVEL_NONE */

#endif /* SBM_LOG_H */
