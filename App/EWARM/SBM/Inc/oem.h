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

#ifndef OEM_H
#define OEM_H

/* For use in C++ */
#ifdef __cplusplus
extern "C" {
#endif
/** \file
 * \brief Declarations of example OEM functions.
 */

#include <stdbool.h>
#include <stdint.h>

#include "sbm_hal.h"
#include "sbm_hal_mem.h"
#include "oem_flash_ext.h"
#include "oem_ext_mm.h"

/** OEM provided function to initialise the target platform.
 *
 * This will be invoked *after* CPU and basic SoC initialisation has
 * been performed, and is expected to initialise specific features of
 * the target, such as LEDs.
 *
 * The function is optional - a "No-Op" default will be used if not
 * provided.
 */
extern void oem_init(void);

/** OEM provided function to quiesce the target platform.
 *
 * This will be invoked *before* the SoC devices and CPU are quiesced
 * and is expected to undo most/all of the initialisation carried out
 * by oem_init().
 *
 * The function is optional - a "No-Op" default will be used if not
 * provided.
 */
extern void oem_quiesce(void);

/** OEM provided function to reset the target platform.
 *
 * Called before trying hal_soc_reset() in case OEM hardware has a
 * better way to invoke reset, or perhaps needs to manually reset other
 * hardware on the board before the SoC is reset.
 *
 * The function is optional - a "No-Op" default will be used if not
 * provided.
 */
extern void oem_reset(void);

/** OEM provided function to return a short string which describes the target.
 *
 * The function is optional - the SoC-specific default will be used if not
 * provided.
 */
extern const char *oem_target_string(void);


#if SBM_BOOT_STATUS_TRACKING != 0
typedef enum
{
	OEM_BOOT_STAGE_STARTING,
	OEM_BOOT_STAGE_EXAMINING_UPDATE,
	OEM_BOOT_STAGE_EXAMINING_IMAGE,
	OEM_BOOT_STAGE_BAD_TARGET,
	OEM_BOOT_STAGE_BAD_VERSION,
	OEM_BOOT_STAGE_NO_UPDATE,
	OEM_BOOT_STAGE_UPDATE,
	OEM_BOOT_STAGE_INSTALLING_UPDATE,
	OEM_BOOT_STAGE_UPDATE_INSTALLED,
	OEM_BOOT_STAGE_LAUNCHING_IMAGE,
	OEM_BOOT_STAGE_NO_IMAGE,
	OEM_BOOT_STAGE_CHECKING_VERSION,
	OEM_BOOT_STAGE_FAILED,
	OEM_BOOT_STAGE_RAISING_LOCKDOWN_LEVEL,
	OEM_BOOT_STAGE_IMAGE_RETURNED,
	OEM_BOOT_STAGE_NO_PROVISIONED_DATA,
	OEM_BOOT_STAGE_BAD_PROVISIONED_DATA_HASH,
	OEM_BOOT_STAGE_CHECKING_PROVISIONED_DATA,
	OEM_BOOT_STAGE_GOOD_PROVISIONED_DATA
} oem_boot_stage_t;

/** OEM provided function for reporting boot progress.
 *
 * \param s Status being reported.
 */
void oem_boot_status(const oem_boot_stage_t s);

/** OEM provided function for starting the boot signal.
 */
void oem_boot_signal_start(void);

/** OEM provided function for ending the boot signal.
 */
void oem_boot_signal_end(void);
#endif

#if SBM_UPDATE_LOGGING != 0
typedef enum
{
	OEM_UPDATE_NONE,
	OEM_UPDATE_SUCCESS,
	OEM_UPDATE_FAIL_TARGET,
	OEM_UPDATE_FAIL_VERSION
} oem_update_t;

/** OEM provided function for reporting application updates.
 *
 * \param u Status being reported.
 */
void oem_update_log(const oem_update_t u);
#endif

#if SBM_FAIL_LAUNCH_API != 0
/** OEM provided function for reporting application launch failure.
 *
 * This function need not return.
 * This implementation doesn't.
 */
void oem_launch_fail(void);
#endif

#if SBM_RECORD_BOOT_TIME != 0
typedef enum
{
	OEM_NORMAL_BOOT, /**< There was no new application update to be performed and the previous application was launched. */
	OEM_UPDATE_AND_BOOT, /**< A new application was successfully installed, and the new application was launched. */
	OEM_FAILED_UPDATE, /**< A new application update was unsuccessfully processed, and the previous application was launched. */
	OEM_NO_APPLICATION /**< No application could be launched (and the failed to boot application processing was performed). */
} oem_boot_performed_t;

/** OEM provided function for reporting SBM boot time.
 *
 * \param reason Indication of update and boot status.
 */
void oem_record_boot_time(oem_boot_performed_t reason);
#endif

#if SBM_REPORT_SBM_SIZES != 0
/** OEM provided function for reporting SBM and provisioned data sizes.
 *
 * \param sbm_size Size of SBM code in bytes.
 * \param pd_size Size of provisioned data in bytes.
 */
void oem_report_sbm_sizes(const uint32_t sbm_size, const uint32_t pd_size);
#endif

/** Initialise all OEM-specific flash drivers.
 * 
 * This should call oem_flash_ext_init() and oem_ext_mm_init(), if those
 * drivers are used.
 */
extern void oem_flash_init(void);

/** Quiesce all OEM-specific flash drivers.
 * 
 * This should call oem_flash_ext_quiesce() and oem_ext_mm_quiesce(), if those
 * drivers are used.
 */
extern void oem_flash_quiesce(void);

/** OEM LED interface - optional
 *
 * The generic OEM code (in oem.c) assumes there are at least two LEDs
 * available on the target board. One is used to indicate the SBM is
 * running while the other is flashed to indicate a boot error (such as
 * no application found).
 */
typedef enum {
	OEM_LED_STARTUP,	/* Lit during startup */
	OEM_LED_ERROR,		/* Flashes on error */
	OEM_LED__COUNT__
} oem_led_t;

/* LEDs are either on or off */
typedef enum {
	OEM_LED_STATE_ON,
	OEM_LED_STATE_OFF,
} oem_led_state_t;

/** Set LED \a led either on or off as determined by \a state.
 *
 * \param led   The LED to control.
 * \param state Desired LED state.
 *
 * This function is optional. If OEM code does not supply an implementation
 * then a default "No-Op" function will be provided automatically.
 */
void oem_led_set(oem_led_t led, oem_led_state_t state);

/** Invert the current state of LED \a led.
 *
 * \param led   The LED to control.
 *
 * This function is optional. If OEM code does not supply an implementation
 * then a default "No-Op" function will be provided automatically.
 */
void oem_led_toggle(oem_led_t led);

#ifdef __cplusplus
}
#endif
#endif /* OEM_H */

