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
 * \brief HAL definitions
 */

#ifndef SBM_HAL_H
#define SBM_HAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*============================================================================*/
/*===================== T Y P E  D E F I N I T I O N S =======================*/
/*============================================================================*/

/** Timer ticks since reset are represented by the following type */
typedef uint32_t     hal_tick_value_t;

/** hal_tick_value_t is also used to represent timeout.
 *
 * The following constant represents an infinite timeout (though it may
 * actually imply a timeout of around 46 days which, from the point of
 * view of SBM, is effectively infinite).
 */
#define	HAL_TICK_INFINITE	(~(hal_tick_value_t)0u)

#if (NDRIVERS==0)
/** Serial ports required by the SBM HAL */
#include "sbm_hal_serial.h"
#endif /* (NDRIVERS==0) */
/* Pull in the SoC-specific HAL implementations */
#include "sbm_hal_soc.h"
#include "hal_rng.h"

/*============================================================================*/
/*===================== P R I M A R Y  H A L  A P I ==========================*/
/*============================================================================*/

/** Set up the target's HAL
 *
 * This will initialise the CPU, SoC and OEM subsystems.
 */
extern void hal_init(void);

/** Return the target to a quiescent state
 *
 * This is called just prior to SBM invoking an installed application
 * so it must ensure that the peripherals are returned to their
 * power-on state where possible. It should also return various CPU
 * settings (clocks, vector table base, etc) to the power-on default
 * (if possible/applicable).
 */
extern void hal_quiesce(void);

#if (NDRIVERS==0)
#if defined(__IAR_SYSTEMS_ICC__)
/** Reset the target. This does not return. */
extern __noreturn void hal_reset(void);
#elif defined(__GNUC__)
extern void hal_reset(void) __attribute__ ((noreturn));
#else
extern void hal_reset(void);
#endif
#endif /* (NDRIVERS==0) */

/** Return a short string describing the target
 *
 * Currently only used by the unit-test framework
 */
extern const char *hal_target_string(void);

/** Run the application code at address \a entry_point
 *
 * \param app_address Address of the application image.
 */
extern void hal_run_application(uintptr_t app_address);

/** Initialise a 1mS timer for use by the HAL */
extern void hal_tick_init(void);

/** Invoked every 1mS by the timer interrupt routine
 *
 * \param frame Pointer to CPU-specific interrupt frame.
 */
extern void hal_tick_isr(void *frame);

/** Optional ISR routine invoked by hal_tick_isr(). */
extern void hal_tick_isr_hook(void *frame);

/** Return the current value of the HAL tick counter
 *
 * Note that this cannot be used once the application has started.
 *
 * \return The number of 1mS ticks since the last reset.
 */
extern hal_tick_value_t hal_tick_get(void);

/** Block the caller for the number of milliseconds specified by \a ms
 *
 * \param ms Number of milliseconds to delay
 *
 * This is implemented as a busy-wait. Interrupts must be enabled
 * when invoked.
 */
extern void hal_tick_delay(hal_tick_value_t ms);

#if defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)
/** Check if application has permission to access the specified memory region.
 *
 * \param[in] base_address Start of the memory region
 * \param[in] bytes Size of the memory region, in bytes.
 * \param[in] can_write True to check if the app can write the region,
 *                      otherwise false for read access.
 *
 * \return True if access is permitted, else false.
 */
extern bool hal_check_permission(const void *base_address, uint32_t bytes,
                                 bool can_write);
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */
#if SBM_PPD_ENABLE !=0
/**
 * \brief Read the Unique ID
 * \param byte_array Pointer to return unique ID to be used as trust anchor,
 *                   this memory must be at least UNIQUE_ID_SIZE*sizeof(uint8_t)
 *                   bytes long
 * \return UNIQUE_ID_SIZE
 */
size_t hal_get_device_trust_anchor(uint8_t *byte_array);
#endif

#if SBM_RECORD_BOOT_TIME != 0
/** Initialise a 1us timer for use by the HAL. */
void hal_timer_init(void);

/** Take the 1us timer out of service. */
void hal_timer_quiesce(void);

/** Return the current value of the SBM HAL timer counter.
 *
 * \return The number of 1us ticks since initialised.
 */
uint32_t hal_timer_get(void);
#endif /* SBM_RECORD_BOOT_TIME != 0 */

/*============================================================================*/
/*=================== A P I  P R O V I D E D  B Y  S O C =====================*/
/* These are not normally invoked directly by consumers of the HAL API; they  */
/* are instead called by the main API routines defined above.                 */
/*============================================================================*/

/** Set up the SoC */
extern void	soc_init(void);

/** Return the SoC to a quiescent state */
extern void	soc_quiesce(void);

/** Reset the SoC. */
extern void	soc_reset(void);

/** Return a short string describing the SoC
 *
 * \return Pointer to a human-readable string describing the SoC.
 */
extern const char *soc_target_string(void);

/** Jump to the application at the specified address. Note that the first
 * instruction may be elsewhere; it's up to the SoC-specific code to determine
 * the correct entry point.
 *
 * \param[in] app_address Address of the application. Normally the start of
 *                        the executable slot.
 */
extern void	soc_app_start(uintptr_t app_address);

#if defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)
/*
 * SoC-specific function to check if application has permission to access
 * the specified memory region.
 * Note: Don't call directly. Use hal_check_permission() instead.
 * Note: A default will be provided if a SoC-specific function is not
 * required. The default will always return true.
 */
extern bool soc_check_permission(const void *base_address, uint32_t bytes,
                                 bool can_write);
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */

#if SBM_PPD_ENABLE !=0
/**
 * \brief Read the Unique ID
 * \param byte_array Pointer to return unique ID to be used as trust anchor,
 *                   this memory must be at least UNIQUE_ID_SIZE*sizeof(uint8_t)
 *                   bytes long
 * \return UNIQUE_ID_SIZE
 */
 size_t soc_get_device_trust_anchor(uint8_t *byte_array);
#endif /* SBM_PPD_ENABLE */

#if SBM_RECORD_BOOT_TIME != 0
/** Initialise a 1us timer for use by the HAL. */
void soc_timer_init(void);

/** Take the 1us timer out of service. */
void soc_timer_quiesce(void);

/** Return the current value of the SBM HAL timer counter.
 *
 * \return The number of 1us ticks since initialised.
 */
uint32_t soc_timer_get(void);
#endif /* SBM_RECORD_BOOT_TIME != 0 */

#if defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0)

/** Initialise the SOC HW crypto unit */
void soc_hal_crypto_init(void);

/**
 * \brief Shutdown / deinit the SOC HW crypto unit
 */
void soc_hal_crypto_quiesce(void);

#endif /* defined(SBM_PROVISIONED_DATA_ENCRYPTED) && (SBM_PROVISIONED_DATA_ENCRYPTED != 0) */
/*============================================================================*/
/*=================== A P I  P R O V I D E D  B Y  C P U =====================*/
/* These are not normally invoked directly by consumers of the HAL API; they  */
/* are instead called by the main or SoC API routines defined above.          */
/*                                                                            */
/* In addition to the functions declared below, sbm_hal_cpu.h must also       */
/* declare cpu_critical_enter() and cpu_critical_exit(). These should ideally */
/* be declared as inline functions. See hal/cpu/arm/sbm_hal_cpu.h for an      */
/* example implementation for ARM.                                            */
/*============================================================================*/

/** Perform CPU-specific initialisation, if required. For instance, on ARM this
 * will enabled caches if they exist, and will enable interrupts.
 */
extern void cpu_init(void);

/** Undo the work carried out by cpu_init(). This will be invoked just before
 * jumping to the application. */
extern void cpu_quiesce(void);

#if (NDRIVERS==0)
/** Cause a system reset. This function must not return */
#if defined(__IAR_SYSTEMS_ICC__)
extern __noreturn void cpu_reset(void);
#elif defined(__GNUC__)
extern void cpu_reset(void) __attribute__ ((noreturn));
#else
extern void cpu_reset(void);
#endif
#endif /* (NDRIVERS==0) */
#if defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)
/*
 * CPU-specific function to check if application has permission to access
 * the specified memory region.
 * Note: Don't call directly. Use hal_check_permission() instead.
 * Note: A default will be provided if a CPU-specific function is not
 * required. The default will always return true.
 */
extern bool cpu_check_permission(const void *base_address, uint32_t bytes,
                                 bool can_write);
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */

#if (NDRIVERS==0)
#include "sbm_hal_mem.h"
#endif  /* (NDRIVERS==0) */
#endif /* SBM_HAL_H */
