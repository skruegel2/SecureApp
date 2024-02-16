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

#include "sbm_memory.h"
#include "sbm_hal.h"
#include "sbm_hal_serial.h"
#include "oem.h"

#if SBM_INCLUDE_CONSOLE != 0

/*
 * Pointers to serial devices registered with SBM are recorded here. The array
 * is allocated in persistent RAM but all entries should be NULL before the
 * application is started. This prevents corruption caused by inadvertent use
 * of the hal_serial() API after that time.
 */
hal_serial_device_t hal_serial_devices[HAL_SERIAL__NUM_PORTS__] SBM_PERSISTENT_RAM;

void
hal_serial_register(hal_serial_port_t port, hal_serial_device_t serial)
{
	/* Record the device */
	hal_serial_devices[port] = serial;
}

bool
hal_serial_transmit(hal_serial_port_t port, uint8_t ch)
{
	hal_serial_device_t dev = hal_serial_devices[port];

	/* Make sure there is a device available */
	if (dev != NULL) {
		/* Always use the polled Tx handler if available. */
		if (dev->polled_tx) {
			(dev->polled_tx)(dev, ch);
			return true;
		}
	}

	/* The character could not be transmitted */
	return false;
}

#endif /* SBM_INCLUDE_CONSOLE != 0 */
