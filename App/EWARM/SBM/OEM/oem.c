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
 * \brief Example implementation of OEM functions.
 */

#include <stdio.h>
#include <inttypes.h>

#include "oem.h"
#include "oem_board.h"

#if SBM_BOOT_STATUS_TRACKING != 0
#include "memoryMap.h" /* for SBM_EXECUTABLE_ADDR and SBM_UPDATE_ADDR */
#include "memory_devices_and_slots.h"
#include "swup.h"
#endif

#include "lockdown.h"
#include "sbm_log_oem.h"

#if defined(__IAR_SYSTEMS_ICC__)
#define __WEAK_FUNC __weak
#elif defined(__GNUC__)
#define __WEAK_FUNC __attribute__((weak))
#else
#define __WEAK_FUNC
#endif

/*
 * OEM code can choose not to implement these, at least during initial
 * bring-up. In such as case, provide weak stubs.
 */
__WEAK_FUNC void oem_init(void)
{
	oem_flash_init();
}

__WEAK_FUNC void oem_quiesce(void)
{
	oem_flash_quiesce();
}

__WEAK_FUNC void oem_reset(void)
{
	/* No-op */
}

__WEAK_FUNC const char *oem_target_string(void)
{
	return soc_target_string();
}

__WEAK_FUNC void oem_flash_init(void)
{
#if EXT_FLASH_DRV_ENABLED != 0
	oem_flash_ext_init();
#endif
#if EXT_MAPPED_MEM_DRV_ENABLED != 0
	oem_ext_mm_init();
#endif
}

__WEAK_FUNC void oem_flash_quiesce(void)
{
#if EXT_FLASH_DRV_ENABLED != 0
	/*
	 * Note to OEMs...
	 * Quiescing the external Flash driver before starting the application
	 * may seem like a good idea. However, it also de-registers the driver
	 * from SBM's Flash framework. This will render the Secure API
	 * "STZ_checkUpdateSlot()" service inoperable.
	 * If your application does not make use of the service then this will
	 * not be an issue, and the following function call can be enabled.
	 */
	/* oem_flash_ext_quiesce(); */
#endif
#if EXT_MAPPED_MEM_DRV_ENABLED != 0
	/* oem_ext_mm_quiesce(); */
#endif
}

#if EXT_FLASH_DRV_ENABLED != 0

__WEAK_FUNC bool oem_flash_ext_init(void)
{
	return false;
}

__WEAK_FUNC void oem_flash_ext_quiesce(void)
{
	/* No-op */
}

__WEAK_FUNC bool oem_flash_ext_present(uint32_t device_id)
{
	(void)device_id;
	return false;
}

__WEAK_FUNC size_t oem_flash_ext_page_size(uint32_t device_id)
{
	(void)device_id;
	return 1;
}

__WEAK_FUNC hal_mem_result_t oem_flash_ext_read(uint32_t device_id, hal_mem_address_t address, void *dst, size_t size)
{
	(void)device_id;
	(void)address;
	(void)dst;
	(void)size;
	return HAL_MEM_INTERNAL_ERROR;
}

__WEAK_FUNC hal_mem_result_t oem_flash_ext_write(uint32_t device_id, hal_mem_address_t address, const void *src, size_t size)
{
	(void)device_id;
	(void)address;
	(void)src;
	(void)size;
	return HAL_MEM_INTERNAL_ERROR;
}

__WEAK_FUNC hal_mem_result_t oem_flash_ext_erase(uint32_t device_id, hal_mem_address_t address, size_t size)
{
	(void)device_id;
	(void)address;
	(void)size;
	return HAL_MEM_INTERNAL_ERROR;
}

__WEAK_FUNC hal_mem_result_t oem_flash_ext_verify_erased(uint32_t device_id, hal_mem_address_t address, size_t size)
{
	(void)device_id;
	(void)address;
	(void)size;
	return HAL_MEM_INTERNAL_ERROR;
}

__WEAK_FUNC void oem_flash_ext_disable_caches(uint32_t device_id)
{
	(void)device_id;
	/* No-op */
}

__WEAK_FUNC void oem_flash_ext_enable_and_flush_caches(uint32_t device_id)
{
	(void)device_id;
	/* No-op */
}

#endif /* EXT_FLASH_DRV_ENABLED != 0 */

#if EXT_MAPPED_MEM_DRV_ENABLED != 0

__WEAK_FUNC bool oem_ext_mm_init(void)
{
	return false;
}

__WEAK_FUNC void oem_ext_mm_quiesce(void)
{
	/* No-op */
}

__WEAK_FUNC bool oem_ext_mm_present(void)
{
	return false;
}

__WEAK_FUNC size_t oem_ext_mm_page_size(void)
{
	return 1;
}

__WEAK_FUNC hal_mem_result_t oem_ext_mm_read(hal_mem_address_t address, void *dst, size_t size)
{
	(void)address;
	(void)dst;
	(void)size;
	return HAL_MEM_INTERNAL_ERROR;
}

__WEAK_FUNC hal_mem_result_t oem_ext_mm_write(hal_mem_address_t address, const void *src, size_t size)
{
	(void)address;
	(void)src;
	(void)size;
	return HAL_MEM_INTERNAL_ERROR;
}

__WEAK_FUNC hal_mem_result_t oem_ext_mm_erase(hal_mem_address_t address, size_t size)
{
	(void)address;
	(void)size;
	return HAL_MEM_INTERNAL_ERROR;
}

__WEAK_FUNC hal_mem_result_t oem_ext_mm_verify_erased(hal_mem_address_t address, size_t size)
{
	(void)address;
	(void)size;
	return HAL_MEM_INTERNAL_ERROR;
}

__WEAK_FUNC void oem_ext_mm_disable_caches(void)
{
	/* No-op */
}

__WEAK_FUNC void oem_ext_mm_enable_and_flush_caches(void)
{
	/* No-op */
}

#endif /* EXT_MAPPED_MEM_DRV_ENABLED != 0 */

/*
 * LED API is optional, so provide weak stubs if OEM code
 * does not implement it.
 */

__WEAK_FUNC void oem_led_set(oem_led_t led, oem_led_state_t state)
{
	(void) led;
	(void) state;
}

__WEAK_FUNC void oem_led_toggle(oem_led_t led)
{
	(void) led;
}

#if SBM_BOOT_STATUS_TRACKING != 0
/*
 * Boot signal APIs are optional, so provide weak stubs if
 * OEM code does not implement them.
 */
__WEAK_FUNC void oem_boot_signal_start(void)
{
}

__WEAK_FUNC void oem_boot_signal_end(void)
{
}

static void boot_starting(void)
{
	oem_boot_signal_start();

	/* Emit one green pulse ... */
	oem_led_set(OEM_LED_STARTUP, OEM_LED_STATE_ON);
	hal_tick_delay(500);
	oem_led_set(OEM_LED_STARTUP, OEM_LED_STATE_OFF);
}

__WEAK_FUNC void oem_boot_status(const oem_boot_stage_t s)
{
	SBM_LOG_OEM_DEBUG("%s(%d) called: implementation to be supplied\n", __func__, s);
	switch (s)
	{
		case OEM_BOOT_STAGE_STARTING:
			boot_starting();
			break;

		case OEM_BOOT_STAGE_LAUNCHING_IMAGE:
			oem_boot_signal_end();
			break;

		case OEM_BOOT_STAGE_FAILED:
			oem_boot_signal_end();
			break;

#if (SBM_LOCKDOWN_LEVEL !=0)
		case OEM_BOOT_STAGE_RAISING_LOCKDOWN_LEVEL:
#endif
		case OEM_BOOT_STAGE_CHECKING_VERSION:
		case OEM_BOOT_STAGE_EXAMINING_UPDATE:
		case OEM_BOOT_STAGE_EXAMINING_IMAGE:
		case OEM_BOOT_STAGE_BAD_TARGET:
		case OEM_BOOT_STAGE_BAD_VERSION:
		case OEM_BOOT_STAGE_UPDATE:
		case OEM_BOOT_STAGE_NO_UPDATE:
		case OEM_BOOT_STAGE_INSTALLING_UPDATE:
		case OEM_BOOT_STAGE_UPDATE_INSTALLED:
		case OEM_BOOT_STAGE_NO_IMAGE:
		case OEM_BOOT_STAGE_IMAGE_RETURNED:
		case OEM_BOOT_STAGE_NO_PROVISIONED_DATA:
		case OEM_BOOT_STAGE_CHECKING_PROVISIONED_DATA:
		case OEM_BOOT_STAGE_GOOD_PROVISIONED_DATA:
		default:
			break;
	}
}
#endif

#if SBM_UPDATE_LOGGING != 0
void oem_update_log(const oem_update_t u)
{
	SBM_LOG_OEM_DEBUG("%s(%d) called: implementation to be supplied\n", __func__, (int)u);
}
#endif

#if SBM_FAIL_LAUNCH_API != 0
void oem_launch_fail(void)
{
	SBM_LOG_OEM_DEBUG("%s() called: implementation to be supplied\n", __func__);

	oem_led_set(OEM_LED_STARTUP, OEM_LED_STATE_OFF);
	oem_led_set(OEM_LED_STARTUP, OEM_LED_STATE_OFF);

	for (;;)
	{
		hal_tick_delay(500);
		oem_led_toggle(OEM_LED_ERROR);
	}
}
#endif

#if SBM_RECORD_BOOT_TIME != 0
void oem_record_boot_time(const oem_boot_performed_t reason)
{
	SBM_LOG_OEM_DEBUG("%s() called: implementation to be supplied\n", __func__);
}
#endif

#if SBM_REPORT_SBM_SIZES != 0
void oem_report_sbm_sizes(const uint32_t sbm_size, const uint32_t pd_size)
{
	SBM_LOG_OEM_DEBUG("%s() called: implementation to be supplied\n", __func__);
}
#endif
