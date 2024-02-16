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
 * \brief Main SBM source file.
 */

#include <assert.h>
#include <string.h>

#include "benchmark.h"
#include "sbm_hal.h"
#include "sbm_api.h"
#include "memoryMap.h"
#include "imageInfo.h"
#include "oem.h"
#include "dataStore.h"
#include "swup.h"
#include "lockdown.h"
#include "memory_devices_and_slots.h"
#include "sbm_log_boot_status.h"
#include "sbm_log_boot_time.h"

/** Enter endless loop.
 *
 * Called when an application cannot be launched.
 *
 * Calls oem_launch_fail() if there is one.
 *
 * Never returns.
 */
__noreturn
static void launch_fail(void)
{
#if SBM_PROVISIONED_DATA_ENCRYPTED != 0
	datastore_clear_plaintext_pdb();
#endif /* SBM_PROVISIONED_DATA_ENCRYPTED != 0 */

	SBM_LOG_BOOT_STATUS_ERROR("Boot failed\n");

#if SBM_BOOT_STATUS_TRACKING != 0
	oem_boot_status(OEM_BOOT_STAGE_FAILED);
#endif
#if SBM_FAIL_LAUNCH_API != 0
	oem_launch_fail();
#endif
#ifndef SBM_PC_BUILD
	for (;;)
		;
#else
	sbm_pc_exit(1);
#endif
}

static inline void log_boot_starting(void)
{
	SBM_LOG_BOOT_STATUS_INFO("==========================================\n");
	SBM_LOG_BOOT_STATUS_INFO("SBM %s %s\n", __DATE__, __TIME__);
	SBM_LOG_BOOT_STATUS_INFO("Configuration parameters:\n");
#ifdef SBM_BOOT_STATUS_TRACKING
	SBM_LOG_BOOT_STATUS_INFO(" SBM_BOOT_STATUS_TRACKING:       %d\n", SBM_BOOT_STATUS_TRACKING);
#endif
#ifdef SBM_UPDATE_LOGGING
	SBM_LOG_BOOT_STATUS_INFO(" SBM_UPDATE_LOGGING:             %d\n", SBM_UPDATE_LOGGING);
#endif
#ifdef SBM_FAIL_LAUNCH_API
	SBM_LOG_BOOT_STATUS_INFO(" SBM_FAIL_LAUNCH_API:            %d\n", SBM_FAIL_LAUNCH_API);
#endif
#ifdef SBM_VERSION_CHECKING
	SBM_LOG_BOOT_STATUS_INFO(" SBM_VERSION_CHECKING:           %d\n", SBM_VERSION_CHECKING);
#endif
#ifdef SBM_BOOT_INTEGRITY_CHECKING
	SBM_LOG_BOOT_STATUS_INFO(" SBM_BOOT_INTEGRITY_CHECKING:    %d\n", SBM_BOOT_INTEGRITY_CHECKING);
#endif
#ifdef SBM_RECORD_BOOT_TIME
	SBM_LOG_BOOT_STATUS_INFO(" SBM_RECORD_BOOT_TIME:           %d\n", SBM_RECORD_BOOT_TIME);
#endif
#ifdef SBM_REPORT_SBM_SIZES
	SBM_LOG_BOOT_STATUS_INFO(" SBM_REPORT_SBM_SIZES:           %d\n", SBM_REPORT_SBM_SIZES);
#endif
#ifdef SBM_INCLUDE_LOADER
	SBM_LOG_BOOT_STATUS_INFO(" SBM_INCLUDE_LOADER:             %d\n", SBM_INCLUDE_LOADER);
#endif
#ifdef SBM_LOCKDOWN_LEVEL
	SBM_LOG_BOOT_STATUS_INFO(" SBM_LOCKDOWN_LEVEL:             %d\n", SBM_LOCKDOWN_LEVEL);
#endif
#ifdef SBM_PROVISIONED_DATA_ENCRYPTED
	SBM_LOG_BOOT_STATUS_INFO(" SBM_PROVISIONED_DATA_ENCRYPTED: %d\n", SBM_PROVISIONED_DATA_ENCRYPTED);
#endif
#ifdef SBM_LOG_VERBOSITY
	SBM_LOG_BOOT_STATUS_INFO(" SBM_LOG_VERBOSITY:              %d\n", SBM_LOG_VERBOSITY);
#endif
#ifdef SBM_ENABLE_LOG_BOOT_STATUS
	SBM_LOG_BOOT_STATUS_INFO(" SBM_ENABLE_LOG_BOOT_STATUS:     %d\n", SBM_ENABLE_LOG_BOOT_STATUS);
#endif
#ifdef SBM_ENABLE_LOG_BOOT_TIME
	SBM_LOG_BOOT_STATUS_INFO(" SBM_ENABLE_LOG_BOOT_TIME:       %d\n", SBM_ENABLE_LOG_BOOT_TIME);
#endif
#ifdef SBM_ENABLE_LOG_SIZES
	SBM_LOG_BOOT_STATUS_INFO(" SBM_ENABLE_LOG_SIZES:           %d\n", SBM_ENABLE_LOG_SIZES);
#endif
#ifdef SBM_ENABLE_LOG_UPDATE_STATUS
	SBM_LOG_BOOT_STATUS_INFO(" SBM_ENABLE_LOG_UPDATE_STATUS:   %d\n", SBM_ENABLE_LOG_UPDATE_STATUS);
#endif
#ifdef SBM_ENABLE_LOG_DATASTORE
	SBM_LOG_BOOT_STATUS_INFO(" SBM_ENABLE_LOG_DATASTORE:       %d\n", SBM_ENABLE_LOG_DATASTORE);
#endif
#ifdef SBM_ENABLE_LOG_OEM
	SBM_LOG_BOOT_STATUS_INFO(" SBM_ENABLE_LOG_OEM:             %d\n", SBM_ENABLE_LOG_OEM);
#endif
}

#if SBM_RECORD_BOOT_TIME != 0
static inline void log_boot_time(const oem_boot_performed_t reason)
{
	SBM_LOG_BOOT_TIME_INFO("SBM boot time: %" PRIu32 " ms (",
	    (sbm_benchmark_boot_time() + UINT32_C(500)) / UINT32_C(1000));

	switch (reason)
	{
		case OEM_NORMAL_BOOT:
			SBM_PRINTF_BOOT_TIME_INFO("no update installed)\n");
			break;
		case OEM_UPDATE_AND_BOOT:
			SBM_PRINTF_BOOT_TIME_INFO("install succeeded)\n");
			break;
		case OEM_FAILED_UPDATE:
			SBM_PRINTF_BOOT_TIME_INFO("failed update)\n");
			break;
		case OEM_NO_APPLICATION:
			SBM_PRINTF_BOOT_TIME_INFO("no application present)\n");
			break;
		default:
			SBM_PRINTF_BOOT_TIME_INFO("unknown boot reason)\n");
			break;
	}
}
#endif /* SBM_RECORD_BOOT_TIME != 0 */

/** Report that there is no application image to launch.
 *
 * Never returns (transitively: calls launch_fail() which never returns).
 */
__noreturn
static void no_image(void)
{
#if SBM_BOOT_STATUS_TRACKING != 0
	oem_boot_status(OEM_BOOT_STAGE_NO_IMAGE);
#endif

	launch_fail();
}

#if SBM_RECORD_BOOT_TIME != 0
static oem_boot_performed_t install_reason = OEM_NORMAL_BOOT;
#endif

#if NUM_UPDATE_SLOTS > 0
/** Attempt to install SWUP and handle the result.
 *
 * \param slot_and_image_data Address of struct holding data gathered during update slot querying phase.
 *
 * \retval SWUP install status.
 */
static unsigned int update_app(sbm_swup_selector_data *slot_and_image_data)
{
	assert(slot_and_image_data);

	unsigned int install_status = SWUP_INSTALL_STATUS_FAILURE;

	if (SWUP_STATUS_INITIAL == slot_and_image_data->swup_status)
	{
		sbm_benchmark_feature_start(BENCHMARK_PRE_SWUP_APP_INTEGRITY);
		/* There's a new update in situ. */
		bool install_update = true;

		if (sbm_executable_slot_module_valid())
		{
			/* There's a module in the executable slot so we can
			   police the version of the update against it */

			SBM_LOG_BOOT_STATUS_INFO("Checking update version\n");

#if SBM_BOOT_STATUS_TRACKING != 0
			oem_boot_status(OEM_BOOT_STAGE_CHECKING_VERSION);
#endif
			/* If we're attempting a rollback, reject the update */

			if (sbm_swup_update_version_rollback(slot_and_image_data->slot))
			{
				/* Version rollback attempt */
				SBM_LOG_BOOT_STATUS_WARNING("Update failed: version rollback from 0x%" PRIx32 " to 0x%" PRIx32 " not permitted\n",
				                            sbm_swup_piem_version(),
				                            slot_and_image_data->version_number);

#if SBM_BOOT_STATUS_TRACKING != 0
				oem_boot_status(OEM_BOOT_STAGE_BAD_VERSION);
#endif
#if SBM_UPDATE_LOGGING != 0
				oem_update_log(OEM_UPDATE_FAIL_VERSION);
#endif
#if SBM_RECORD_BOOT_TIME != 0
				install_reason = OEM_FAILED_UPDATE;
#endif
				/* Capture "rollback" as the failure reason ... */
				slot_and_image_data->swup_status = SWUP_STATUS_ERROR_ROLLBACK;

				install_update = false;
			}
			else
			{
				SBM_LOG_BOOT_STATUS_INFO("Update from version 0x%" PRIx32 " to 0x%" PRIx32 "\n",
				                         sbm_swup_piem_version(),
				                         slot_and_image_data->version_number);
#if SBM_BOOT_STATUS_TRACKING != 0
				oem_boot_status(OEM_BOOT_STAGE_UPDATE);
#endif
			}
		}
		sbm_benchmark_feature_stop(BENCHMARK_PRE_SWUP_APP_INTEGRITY);

		if (install_update)
		{
			SBM_LOG_BOOT_STATUS_INFO("Installing version 0x%" PRIx32 "\n",
			                         slot_and_image_data->version_number);

#if SBM_BOOT_STATUS_TRACKING != 0
			oem_boot_status(OEM_BOOT_STAGE_INSTALLING_UPDATE);
#endif

			sbm_benchmark_feature_start(BENCHMARK_SWUP_INSTALL);
			install_status = sbm_swup_install_module(slot_and_image_data->slot,
			                                         slot_and_image_data->max_offset,
			                                         slot_and_image_data->key_instance_value);
			sbm_benchmark_feature_stop(BENCHMARK_SWUP_INSTALL);

			if ((install_status == SWUP_INSTALL_STATUS_SUCCESS) ||
			    (install_status == SWUP_INSTALL_STATUS_SUCCESS_VERIFIED))
			{
				/* The SWUP was installed successfully */
				slot_and_image_data->swup_status = SWUP_STATUS_INSTALLED_THIS_BOOT;

				SBM_LOG_BOOT_STATUS_INFO("Update installed\n");

#if SBM_BOOT_STATUS_TRACKING != 0
				oem_boot_status(OEM_BOOT_STAGE_UPDATE_INSTALLED);
#endif
#if SBM_UPDATE_LOGGING != 0
				oem_update_log(OEM_UPDATE_SUCCESS);
#endif
#if SBM_RECORD_BOOT_TIME != 0
				install_reason = OEM_UPDATE_AND_BOOT;
#endif
			}
			else
			{
				/*
				 * The SWUP was not installed, and the Exec slot was not compromised.
				 * We should be able to start the existing application, if it exists.
				 */
				slot_and_image_data->swup_status = SWUP_STATUS_ERROR;
			}
		}
	}
	else if (SWUP_STATUS_INSTALLED_PREVIOUS == slot_and_image_data->swup_status)
	{
		/* Return success */
		install_status = SWUP_INSTALL_STATUS_SUCCESS;
	}

	sbm_swup_set_last_status(slot_and_image_data->swup_status);

	return install_status;
}
#endif /* NUM_UPDATE_SLOTS > 0 */

/**
 * \brief Check the integrity of the installed application.
 *
 * If the integrity check fails, then no_image() is called which does not return.
 */
static void check_app_slot_integrity(void)
{
	sbm_benchmark_feature_start(BENCHMARK_APP_INTEGRITY);
	const bool esmv = sbm_executable_slot_module_valid();
	sbm_benchmark_feature_stop(BENCHMARK_APP_INTEGRITY);
	if (!esmv)
	{
		sbm_benchmark_boot_stop();
#if SBM_RECORD_BOOT_TIME != 0
		log_boot_time(OEM_NO_APPLICATION);
		oem_record_boot_time(OEM_NO_APPLICATION);
#endif
		sbm_benchmark_report();
		no_image();
	}
}

int main(void)
{
	/* Initialise all required board hardware */
	hal_init();

	sbm_benchmark_boot_start();

#if SBM_LOCKDOWN_IMMEDIATE != 0
	/* Raise lockdown level, if required */
	if (soc_lockdown_level() < SBM_LOCKDOWN_LEVEL)
	{
		SBM_LOG_BOOT_STATUS_INFO("Raising lockdown level to %d\n", SBM_LOCKDOWN_LEVEL);

#if SBM_BOOT_STATUS_TRACKING != 0
		oem_boot_status(OEM_BOOT_STAGE_RAISING_LOCKDOWN_LEVEL);
#endif
		sbm_disable_debug();
	}
#endif	/* SBM_LOCKDOWN_IMMEDIATE */

	log_boot_starting();

#if SBM_BOOT_STATUS_TRACKING != 0
	oem_boot_status(OEM_BOOT_STAGE_STARTING);
	oem_boot_status(OEM_BOOT_STAGE_CHECKING_PROVISIONED_DATA);
#endif

#if SBM_PROVISIONED_DATA_ENCRYPTED != 0
	if (!datastore_verify_and_decrypt_pdb())
	{
		launch_fail();
	}
#endif /* SBM_PROVISIONED_DATA_ENCRYPTED != 0 */

#ifdef DATASTORE_DEBUG
	/* Debugging during development */
	sbm_benchmark_feature_start(BENCHMARK_PD_DUMP);
	datastore_dump();
	sbm_benchmark_feature_stop(BENCHMARK_PD_DUMP);
#endif

	if (!datastore_data_present())
	{
		SBM_LOG_BOOT_STATUS_ERROR("No provisioned data\n");

#if SBM_BOOT_STATUS_TRACKING != 0
		oem_boot_status(OEM_BOOT_STAGE_NO_PROVISIONED_DATA);
#endif
		launch_fail();
	}

#if SBM_REPORT_SBM_SIZES != 0
	sbm_benchmark_feature_start(BENCHMARK_PD_MEASURE);
	datastore_report_sizes();
	sbm_benchmark_feature_stop(BENCHMARK_PD_MEASURE);
#endif

#if SBM_PPD_ENABLE != 0
	sbm_benchmark_feature_start(BENCHMARK_PPD_CHECK);
	const bool dshc = datastore_hash_check();
	sbm_benchmark_feature_stop(BENCHMARK_PPD_CHECK);
	if (!dshc)
	{
		SBM_LOG_BOOT_STATUS_ERROR("Bad provisioned data hash\n");

#if SBM_BOOT_STATUS_TRACKING != 0
		oem_boot_status(OEM_BOOT_STAGE_BAD_PROVISIONED_DATA_HASH);
#endif
		launch_fail();
	}
#endif

#if SBM_BOOT_STATUS_TRACKING != 0
	oem_boot_status(OEM_BOOT_STAGE_GOOD_PROVISIONED_DATA);
#endif

#if NUM_UPDATE_SLOTS > 0
	/* Bring up SWUP support */
	unsigned int install_result_final = SWUP_INSTALL_STATUS_FAILURE;
	sbm_swup_init();

#if SBM_BOOT_STATUS_TRACKING != 0
	oem_boot_status(OEM_BOOT_STAGE_EXAMINING_UPDATE);
#endif

#if NUM_UPDATE_SLOTS > 1
	/* Build SWUP priority queue */
	sbm_benchmark_feature_start(BENCHMARK_SWUP_CHECK);
	sbm_swup_selector_data swup_priority_queue[NUM_UPDATE_SLOTS];
	sbm_build_swup_priority_queue(swup_priority_queue);
	sbm_benchmark_feature_stop(BENCHMARK_SWUP_CHECK);

	/* Go through all the slots in priority queue and attempt to install from them */
	for (sbm_swup_selector_data *sbm_swup_selector_data_it = swup_priority_queue;
	     sbm_swup_selector_data_it < swup_priority_queue + NUM_UPDATE_SLOTS;
	     sbm_swup_selector_data_it++)
	{
		SBM_LOG_BOOT_STATUS_INFO("update slot \"%s\" selected for installation\n",
		                         sbm_swup_selector_data_it->slot->name);

		unsigned int install_result = update_app(sbm_swup_selector_data_it);

		/* Update the final installation result */
		if (install_result == SWUP_INSTALL_STATUS_BRICKED ||
		    install_result == SWUP_INSTALL_STATUS_SUCCESS ||
			install_result == SWUP_INSTALL_STATUS_SUCCESS_VERIFIED)
		{
			install_result_final = install_result;
		}

		/* If installation succedded, we're done; else - go to next update slot */
		if (install_result_final == SWUP_INSTALL_STATUS_SUCCESS ||
		    install_result_final == SWUP_INSTALL_STATUS_SUCCESS_VERIFIED)
		{
			break;
		}
	}

#else /* NUM_UPDATE_SLOTS == 1 */
	sbm_swup_selector_data slot_and_image_data;
	sbm_benchmark_feature_start(BENCHMARK_SWUP_CHECK);
	slot_and_image_data.swup_status = sbm_update_slot_contains_swup(&update_slots[0],
	                                                                &slot_and_image_data.max_offset,
																	&slot_and_image_data.key_instance_value);
	sbm_benchmark_feature_stop(BENCHMARK_SWUP_CHECK);
	slot_and_image_data.version_number = sbm_swup_eub_version(&update_slots[0]);
	slot_and_image_data.slot = &update_slots[0];

	install_result_final = update_app(&slot_and_image_data);
#endif /* NUM_UPDATE_SLOTS >= 1 */

	if (install_result_final == SWUP_INSTALL_STATUS_BRICKED)
	{
		/*
		 * SWUP was not installed, but we passed the point of no return;
		 * the Exec slot has been partially or wholly erased.
		 */

		launch_fail();
	}
	else if (install_result_final == SWUP_INSTALL_STATUS_FAILURE)
	{
		/* No update to install - it's missing or erroneous. */
		SBM_LOG_BOOT_STATUS_INFO("No update present\n");

#if SBM_BOOT_STATUS_TRACKING != 0
		oem_boot_status(OEM_BOOT_STAGE_NO_UPDATE);
#endif
#if SBM_UPDATE_LOGGING != 0
		oem_update_log(OEM_UPDATE_NONE);
#endif
	}


#endif /* NUM_UPDATE_SLOTS > 0 */

	SBM_LOG_BOOT_STATUS_INFO("Checking installed executable signature\n");

#if SBM_BOOT_STATUS_TRACKING != 0
	oem_boot_status(OEM_BOOT_STAGE_EXAMINING_IMAGE);
#endif

#if NUM_UPDATE_SLOTS > 0
	/* Skip verification if it was already done during installation */
	if (install_result_final != SWUP_INSTALL_STATUS_SUCCESS_VERIFIED)
	{
		check_app_slot_integrity();
	}
#else /* NUM_UPDATE_SLOTS == 0 */
	check_app_slot_integrity();
#endif /* NUM_UPDATE_SLOTS > 0 */

#if SBM_LOCKDOWN_DELAYED != 0
	/* Raise lockdown level, if required */
	if (soc_lockdown_level() < SBM_LOCKDOWN_LEVEL)
	{
		SBM_LOG_BOOT_STATUS_INFO("Raising lockdown level to %d\n", SBM_LOCKDOWN_LEVEL);

#if SBM_BOOT_STATUS_TRACKING != 0
		oem_boot_status(OEM_BOOT_STAGE_RAISING_LOCKDOWN_LEVEL);
#endif
		sbm_disable_debug();
	}
#endif	/* SBM_LOCKDOWN_DELAYED */

#if SBM_LOCKDOWN_DELAYED != 0 || SBM_LOCKDOWN_IMMEDIATE != 0
	sbm_lockdown_firmware();
#endif

	/* Run it! */

	SBM_LOG_BOOT_STATUS_INFO("Running executable image version 0x%" PRIx32 "\n",
	                         sbm_swup_piem_version());

#if SBM_BOOT_STATUS_TRACKING != 0
	oem_boot_status(OEM_BOOT_STAGE_LAUNCHING_IMAGE);
#endif

#if SBM_PROVISIONED_DATA_ENCRYPTED != 0
	/* The plaintext PDB should already be cleared, but let's make sure before
	 * we run the application. */
	datastore_clear_plaintext_pdb();
#endif /* SBM_PROVISIONED_DATA_ENCRYPTED != 0 */

	sbm_benchmark_boot_stop();

#if SBM_RECORD_BOOT_TIME != 0
	log_boot_time(install_reason);
	oem_record_boot_time(install_reason);
#endif

	sbm_benchmark_report();

	SBM_LOG_DISABLE();

	hal_run_application(exec_slot.start_address);

	/* Should never return but, just in case... */

#if SBM_BOOT_STATUS_TRACKING != 0
	oem_boot_status(OEM_BOOT_STAGE_IMAGE_RETURNED);
#endif

	launch_fail();

#ifdef SBM_PC_BUILD
	return -1;
#endif
}
