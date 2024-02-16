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

#ifndef BENCHMARK_H
#define BENCHMARK_H

/** \file
 * \brief Handle benchmarking of SBM performance.
 */

#if SBM_RECORD_BOOT_TIME != 0

/** Record start of boot timing. */
void sbm_benchmark_boot_start(void);

/** Record end of boot time.
 *
 * \note It is vital that sbm_benchmark_boot_stop()
 * is called before the application is launched.
 * Failure to do so will result in mayhem when a call comes through the
 * secure API which calls sbm_benchmark_*_start() or sbm_benchmark_*_stop().
*/
void sbm_benchmark_boot_stop(void);

#include <stdint.h>

/* This macro is defined here but could be moved to Security Manager control.
   As a consequence, it must be defined explicitly as zero or non-zero.
   Not being defined is equivalent to being defined as zero. */

#define SBM_BENCHMARKING 0

#if SBM_BENCHMARKING != 0

#include "sbm_log.h"

#define FOREACH_FEATURE(e) \
        e(BENCHMARK_FEATURE_NONE) \
        e(BENCHMARK_PPD_CHECK) \
        e(BENCHMARK_PD_DUMP) \
        e(BENCHMARK_PD_MEASURE) \
        e(BENCHMARK_PRE_SWUP_APP_INTEGRITY) \
        e(BENCHMARK_APP_INTEGRITY) \
        e(BENCHMARK_SWUP_CHECK) \
        e(BENCHMARK_SWUP_INSTALL)

#define FOREACH_PROCEDURE(e) \
        e(BENCHMARK_GET_TRUST_ANCHOR) \
        e(BENCHMARK_AES_GCM_DECRYPT) \
        e(BENCHMARK_CALCULATE_SHA256) \
        e(BENCHMARK_VERIFY_SIGNATURE) \
        e(BENCHMARK_GET_SHARED_SECRET)

#define GENERATE_ENUM(e) e,

typedef enum {
    FOREACH_FEATURE(GENERATE_ENUM)
    BENCHMARK_FEATURES_MAX
}
benchmark_feature_t;

#define BENCHMARK_NUM_FEATURES (BENCHMARK_FEATURES_MAX - BENCHMARK_FEATURE_NONE - 1)

typedef enum {
    FOREACH_PROCEDURE(GENERATE_ENUM)
    BENCHMARK_NUM_PROCEDURES
}
benchmark_procedure_t;

/** Record start of feature activity timing.
 *
 * \param feature Feature against which to record time.
 */
void sbm_benchmark_feature_start(benchmark_feature_t feature);

/** Record start of procedure activity timing.
 *
 * \param procedure Procedure against which to record time.
 */
void sbm_benchmark_procedure_start(benchmark_procedure_t procedure);

/** Record end of feature timing.
 *
 * \param feature Feature against which time is being recorded.
 */
void sbm_benchmark_feature_stop(benchmark_feature_t feature);

/** Record end of procedure timing.
 *
 * \param procedure Procedure against which time is being recorded.
 */
void sbm_benchmark_procedure_stop(benchmark_procedure_t procedure);

#if SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO
/** Print timing report. */
void sbm_benchmark_report(void);
#else
#define sbm_benchmark_report() do { } while (0)
#endif /* SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO */

#else /* SBM_BENCHMARKING != 0 */

/* If we're not benchmarking, all these calls just "evaporate" ... */

#define sbm_benchmark_feature_start(feature) do { } while (0)
#define sbm_benchmark_procedure_start(procedure) do { } while (0)
#define sbm_benchmark_feature_stop(feature) do { } while (0)
#define sbm_benchmark_procedure_stop(procedure) do { } while (0)
#define sbm_benchmark_report() do { } while (0)

/* Note: sbm_benchmark_boot_time() does not need the same
   treatment because all calls to it are conditionally compiled
   and none are made when SBM_RECORD_BOOT_TIME is zero. */

#endif /* SBM_BENCHMARKING != 0 */

/** Yield total boot time. */
uint32_t sbm_benchmark_boot_time(void);

#else /* SBM_RECORD_BOOT_TIME != 0 */

/* If we're not recording boot time, all these calls just "evaporate" ... */

#define sbm_benchmark_boot_start() do { } while (0)
#define sbm_benchmark_boot_stop() do { } while (0)
#define sbm_benchmark_feature_start(feature) do { } while (0)
#define sbm_benchmark_procedure_start(procedure) do { } while (0)
#define sbm_benchmark_feature_stop(feature) do { } while (0)
#define sbm_benchmark_procedure_stop(procedure) do { } while (0)
#define sbm_benchmark_report() do { } while (0)

#endif /* SBM_RECORD_BOOT_TIME != 0 */

#endif /* BENCHMARK_H */
