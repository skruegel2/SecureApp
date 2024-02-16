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

/** \file
 * \brief Handle benchmarking of SBM performance.
 */

#if SBM_RECORD_BOOT_TIME != 0

#include <stdint.h>
#include <stdio.h>

#include "benchmark.h"
#include "sbm_memory.h"
#include "sbm_hal.h"
#include "sbm_log.h"

#if SBM_BENCHMARKING != 0
#include <assert.h>
#endif /* SBM_BENCHMARKING != 0 */

/* When using the IAR debugger, this macro can be defined
   to emit events at activity start and stop times.
   This is useful to calibrate the benchmaking code ... */
/* #define EMIT_EVENTS */

#ifdef EMIT_EVENTS
#include <arm_itm.h>

/* These are the channels to which events are sent ... */
#define BENCHMARK_EVENT_BOOT_START_CH 1
#define BENCHMARK_EVENT_BOOT_STOP_CH 2
#define BENCHMARK_EVENT_FEATURE_START_CH 3
#define BENCHMARK_EVENT_FEATURE_STOP_CH 4
/* We only have four channels so re-use 1 and 2 because procedure events
   are not likely to be confused with the total boot time events as
   they will only appear between feature start and stop events ... */
#define BENCHMARK_EVENT_PROCEDURE_START_CH 1
#define BENCHMARK_EVENT_PROCEDURE_STOP_CH 2
#endif /* EMIT_EVENTS */

/** Timer value at boot start. */
static uint32_t total_boot_time_start SBM_EPHEMERAL_RAM;
/** Total time used at boot stop. */
static uint32_t total_boot_time SBM_PERSISTENT_RAM = UINT32_C(0);

void sbm_benchmark_boot_start(void)
{
#ifdef EMIT_EVENTS
    ITM_EVENT8(BENCHMARK_EVENT_BOOT_START_CH, BENCHMARK_FEATURE_NONE);
#endif /* EMIT_EVENTS */

    total_boot_time_start = hal_timer_get();
}

#if SBM_BENCHMARKING != 0
/** Remember what we're doing at the moment.
 *
 * This has to be kept in persistent RAM so calls arriving here through
 * the secure API can be prevented from causing carnage by attempting
 * to address the activity_times array.
 */
static benchmark_feature_t benchmark_feature SBM_PERSISTENT_RAM = BENCHMARK_FEATURE_NONE;
#endif /* SBM_BENCHMARKING != 0 */

void sbm_benchmark_boot_stop(void)
{
#ifdef EMIT_EVENTS
    ITM_EVENT8(BENCHMARK_EVENT_BOOT_STOP_CH, BENCHMARK_FEATURE_NONE);
#endif /* EMIT_EVENTS */

    total_boot_time = hal_timer_get() - total_boot_time_start;

#if SBM_BENCHMARKING != 0
    /* When we reach this point, we must suspend benchmarking ... */
    benchmark_feature = BENCHMARK_FEATURES_MAX;
#endif /* SBM_BENCHMARKING != 0 */
}

#if SBM_BENCHMARKING != 0

/* Define this macro to count each time a feature or procedure is measured ... */
/* #define USE_HIT_COUNT */

/** Table of activity times.
 *
 * The table is organised thus:
 *
 * \code
 * Features  Procedures --->                            +-- BENCHMARK_NUM_PROCEDURES
 *     |        0       1      ...                      V
 *     |    +-------+-------+-------+-------+-------+-------+
 *     |  0 |       |       |       |       |       |       |
 *     |    +-------+-------+-------+-------+-------+-------+
 *     V  1 |       |       |       |       |       |       |
 *          +-------+-------+-------+-------+-------+-------+
 *        : |       |       |       |       |       |       |
 *          +-------+-------+-------+-------+-------+-------+
 *  +-----> |       |       |       |       |       |       |
 *  |       +-------+-------+-------+-------+-------+-------+
 *  |                                                   ^
 *  +-- BENCHMARK_NUM_FEATURES - 1                      |
 *                                             This column is the
 *                                             total per feature.
 * \endcode
 *
 * Each cell holds the time at which timing was started
 * and accumulated execution time so far.
 */
static struct
{
    uint32_t accumulated; /**< Total time accumulated so far. */
    uint32_t started;     /**< Time at start of activity. */
#ifdef USE_HIT_COUNT
    uint32_t hits;
#endif /* USE_HIT_COUNT */
} activity_times[BENCHMARK_NUM_FEATURES][BENCHMARK_NUM_PROCEDURES + 2] SBM_EPHEMERAL_RAM;

void sbm_benchmark_feature_start(benchmark_feature_t feature)
{
    /* If we've stopped measuring the total boot time, return immediately ... */
    if (BENCHMARK_FEATURES_MAX == benchmark_feature)
    {
        return;
    }

#ifdef EMIT_EVENTS
    ITM_EVENT8(BENCHMARK_EVENT_FEATURE_START_CH, feature);
#endif /* EMIT_EVENTS */

    benchmark_feature = feature; /* Remember what we're doing at the moment. */

    activity_times[benchmark_feature - 1][BENCHMARK_NUM_PROCEDURES].started = hal_timer_get();
#ifdef USE_HIT_COUNT
    ++activity_times[benchmark_feature - 1][BENCHMARK_NUM_PROCEDURES].hits;
#endif /* USE_HIT_COUNT */
}

void sbm_benchmark_procedure_start(benchmark_procedure_t procedure)
{
    /* If we haven't started or we've stopped measuring
       the total boot time, return immediately ... */
    if (BENCHMARK_FEATURE_NONE == benchmark_feature ||
        BENCHMARK_FEATURES_MAX == benchmark_feature)
        {
            return;
        }

#ifdef EMIT_EVENTS
    ITM_EVENT8(BENCHMARK_EVENT_PROCEDURE_START_CH, procedure);
#endif /* EMIT_EVENTS */

    activity_times[benchmark_feature - 1][procedure].started = hal_timer_get();
#ifdef USE_HIT_COUNT
    ++activity_times[benchmark_feature - 1][procedure].hits;
#endif /* USE_HIT_COUNT */
}

void sbm_benchmark_feature_stop(benchmark_feature_t feature)
{
    /* If we haven't started or we've stopped measuring
       the total boot time, return immediately ... */
    if (BENCHMARK_FEATURE_NONE == benchmark_feature ||
        BENCHMARK_FEATURES_MAX == benchmark_feature)
        {
            return;
        }

    assert(benchmark_feature == feature);

#ifdef EMIT_EVENTS
    ITM_EVENT8(BENCHMARK_EVENT_FEATURE_STOP_CH, feature);
#endif /* EMIT_EVENTS */

    activity_times[benchmark_feature - 1][BENCHMARK_NUM_PROCEDURES].accumulated +=
        hal_timer_get() - activity_times[benchmark_feature - 1][BENCHMARK_NUM_PROCEDURES].started;

    benchmark_feature = BENCHMARK_FEATURE_NONE;
}

void sbm_benchmark_procedure_stop(benchmark_procedure_t procedure)
{
    /* If we haven't started or we've stopped measuring
       the total boot time, return immediately ... */
    if (BENCHMARK_FEATURE_NONE == benchmark_feature ||
        BENCHMARK_FEATURES_MAX == benchmark_feature)
        {
            return;
        }

#ifdef EMIT_EVENTS
    ITM_EVENT8(BENCHMARK_EVENT_PROCEDURE_STOP_CH, procedure);
#endif /* EMIT_EVENTS */

    activity_times[benchmark_feature - 1][procedure].accumulated +=
        hal_timer_get() - activity_times[benchmark_feature - 1][procedure].started;
}

#if SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO

#define GENERATE_STRING(s) #s,

static const char *feature_string[] = {
    FOREACH_FEATURE(GENERATE_STRING)
};

static const char *procedure_string[] = {
    FOREACH_PROCEDURE(GENERATE_STRING)
};

void sbm_benchmark_report(void)
{
    for (unsigned int feature = 0; feature < BENCHMARK_NUM_FEATURES; ++feature)
    {
        for (unsigned int procedure = 0; procedure < BENCHMARK_NUM_PROCEDURES + 1; ++procedure)
        {
            if (activity_times[feature][procedure].accumulated)
            {
#ifdef USE_HIT_COUNT
                sbm_log(SBM_LOG_LEVEL_INFO, "benchmark", "%s, %s, %" PRIu32 ", %" PRIu32 "\n",
#else /* USE_HIT_COUNT */
                sbm_log(SBM_LOG_LEVEL_INFO, "benchmark", "%s, %s, %" PRIu32 "\n",
#endif /* USE_HIT_COUNT */
                       feature_string[feature + 1],
                       BENCHMARK_NUM_PROCEDURES == procedure
                           ? "" : procedure_string[procedure],
#ifdef USE_HIT_COUNT
                       activity_times[feature][procedure].accumulated,
                       activity_times[feature][procedure].hits);
#else /* USE_HIT_COUNT */
                       activity_times[feature][procedure].accumulated);
#endif /* USE_HIT_COUNT */
            }
        }
    }

    sbm_log(SBM_LOG_LEVEL_INFO, "benchmark", "TOTAL_BOOT, %" PRIu32 "\n", total_boot_time);
    if (BENCHMARK_FEATURES_MAX != benchmark_feature)
    {
        sbm_log(SBM_LOG_LEVEL_INFO, "benchmark", "warning: report incomplete\n");
    }
}

#endif /* SBM_LOG_VERBOSITY >= SBM_LOG_LEVEL_INFO */

#endif /* SBM_BENCHMARKING != 0 */

uint32_t sbm_benchmark_boot_time(void)
{
    return total_boot_time;
}

#endif /* SBM_RECORD_BOOT_TIME != 0 */
