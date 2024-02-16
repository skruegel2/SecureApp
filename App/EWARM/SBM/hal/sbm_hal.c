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

#if SBM_INCLUDE_CONSOLE != 0
/* For __write() prototype, and __LLIO_* definitions */
#include <LowLevelIOInterface.h>
#endif

#include "sbm_hal.h"
#include "sbm_hal_mem.h"
#include "sbm_hal_crypto.h"
#include "oem.h"

/** Set up the target's HAL
 *
 * This will initialise the CPU, SoC and OEM subsystems.
 */
void hal_init(void)
{
	/* Basic SoC initialisation (clocks, cache, ...) */
	soc_init();

	/* SBM HAL initialisation */

#if SBM_RECORD_BOOT_TIME != 0
	hal_timer_init(); /* Must come after the last clock change. */
#endif /* SBM_RECORD_BOOT_TIME != 0 */

	hal_tick_init();

	/* Board-specific initialisation */
	oem_init();

	/* Initialise supported memory devices */
	hal_mem_init();
}

/** Return the target to a quiescent state
 *
 * This is called just prior to SBM invoking an installed application
 * so it must ensure that the peripherals are returned to their
 * power-on state where possible. It should also return various CPU
 * settings (clocks, vector table base, etc) to the power-on default
 * (if possible/applicable).
 */
void hal_quiesce(void)
{
	/* Quiesce the board-specific parts of the target */
	oem_flash_quiesce();
	oem_quiesce();

#if SBM_RECORD_BOOT_TIME != 0
	hal_timer_quiesce();
#endif /* SBM_RECORD_BOOT_TIME != 0 */

	/* Quiesce the SoC */
	soc_quiesce();
}

/** Reset the target. This must not return. */
void hal_reset(void)
{
	/* Try the OEM reset */
	oem_reset();

	/* If that returns, use the SoC reset */
	soc_reset();
	/*NOTREACHED*/
}

/** Return a short string describing the target */
const char *hal_target_string(void)
{
	return oem_target_string();
}

/** Run the application code at address \a entry_point
 *
 * \param app_address Address of the application image.
 */
void hal_run_application(uintptr_t app_address)
{
	/* Quiesce the SoC before jumping to the application */
	hal_quiesce();

	soc_app_start(app_address);
}

#if defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)
__weak bool soc_check_permission(const void *base_address,
                                 const uint32_t bytes, bool can_write)
{
    (void) base_address;
    (void) bytes;
    (void) can_write;

    return true;
}

__weak bool cpu_check_permission(const void *base_address,
                                 const uint32_t bytes, bool can_write)
{
    (void) base_address;
    (void) bytes;
    (void) can_write;

    return true;
}

bool hal_check_permission(const void *base_address, const uint32_t bytes,
                          bool can_write)
{
    return soc_check_permission(base_address, bytes, can_write) &&
           cpu_check_permission(base_address, bytes, can_write);
}
#endif /* defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0) */
#if SBM_PPD_ENABLE !=0
size_t hal_get_device_trust_anchor(uint8_t *byte_array)
{
    return soc_get_device_trust_anchor(byte_array);
}
#endif /* SBM_PPD_ENABLE */
#if SBM_INCLUDE_CONSOLE != 0
/** Retargets IAR's C library low-level IO __write() function to the USART.
  *
  * /param  handle Usually one of _LLIO_STDOUT or _LLIO_STDERR.
  * /param  buffer Points to the data to write to the USART.
  * /param  size The number of bytes in the buffer.
  *
  * /retval The number of bytes written, or _LLIO_ERROR.
  *
  * Note: __weak attribute added to permit this version to be over-ridden
  * by platform-specific code.
  */
__weak size_t __write(int handle, const unsigned char *buffer, size_t size)
{
	if ((buffer == 0) || (size == 0)) {
		/*
		 * This means that we should flush internal buffers.  Since we
		 * don't we just return.  (Remember, "handle" == -1 means that
		 * all handles should be flushed.)
		 */
		return 0;
	}

	/*
	 * This implementation only writes to "standard out" and "standard err",
	 * for all other file handles it returns failure.
	 */
	if ((handle != _LLIO_STDOUT) && (handle != _LLIO_STDERR))
		return _LLIO_ERROR;

	size_t count = size;

	/* Send buffer contents to the UART */
	while (count--) {
		const char ch = *buffer++;

#if !defined(SBM_CONSOLE_NO_CRLF) || (SBM_CONSOLE_NO_CRLF == 0)
		/* Emit a carriage-return before each line-feed */
		if (ch == '\n' && !hal_serial_transmit(HAL_SERIAL_PORT_CONSOLE, '\r'))
			break;
#endif

		if (!hal_serial_transmit(HAL_SERIAL_PORT_CONSOLE, ch))
			break;
	}

	return size - (count + 1);
}
#endif /* SBM_INCLUDE_CONSOLE != 0 */
