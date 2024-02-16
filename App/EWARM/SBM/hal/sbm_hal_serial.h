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

#ifndef SBM_HAL_SERIAL_H
#define SBM_HAL_SERIAL_H

#include <stdint.h>
#include <stdbool.h>

/**
 * SBM HAL Serial Device Support
 *
 * SBM uses serial devices (UARTs, for the most part) for console output
 * (mostly for debugging purposes during product development). These devices
 * support polled-mode Tx only, thus it is safe to invoke
 * hal_serial_transmit(HAL_SERIAL_PORT_CONSOLE) from interrupt and/or
 * exception handlers.
 */

/** Serial ports required by the SBM HAL */
typedef enum {
	HAL_SERIAL_PORT_CONSOLE,

	/* Add more before this line */
	HAL_SERIAL__NUM_PORTS__
} hal_serial_port_t;

/* Forward declaration of the serial device state structure */
struct hal_serial_device;
typedef struct hal_serial_device *hal_serial_device_t;

/** Prototype for the hardware-specific Polled Tx function */
typedef void (*hal_serial_polled_tx_t)(hal_serial_device_t s, uint8_t ch);

/**
 * State structure for SBM serial devices. OEM code is responsible for
 * allocating an instance of this structure per UART as required.
 */
struct hal_serial_device {
	/** Pointer to the device-specific polled-Tx routine */
	hal_serial_polled_tx_t polled_tx;
};

/** Register a serial device with the SBM HAL.
 *
 * \param port Specifies the port being registered. Must be
 *             HAL_SERIAL_PORT_CONSOLE.
 * \param serial Pointer to the serial device state structure.
 */
extern void hal_serial_register(hal_serial_port_t port, hal_serial_device_t serial);

/** Deregister a serial device
 *
 * \param port Specifies the port being deregistered. Must be
 *             HAL_SERIAL_PORT_CONSOLE.
 */
#define HAL_SERIAL_UNREGISTER(port)	do { hal_serial_devices[port] = NULL; } while (0)

/** Fetch the state structure for the supplied serial device.
 *
 * \param port Specifies the serial port. Must be
 *             HAL_SERIAL_PORT_CONSOLE.
 *
 * \return Pointer to the serial state structure, or NULL if no serial
 * device is registered for the specified port.
 */
#define	HAL_SERIAL_GET_DEVICE(port)	hal_serial_devices[port]

/** Transmit a character on the specified SBM serial port
 *
 * \param port Specifies the serial port. Must be
 *             HAL_SERIAL_PORT_CONSOLE.
 * \param ch The character to transmit.
 *
 * \return true if the character was transmitted, else false.
 *
 * \note This routine supports both polled and async Tx. For polled
 * transmission, the routine will block until the character is sent, thus
 * will always return 'true'. For async, the routine will return
 * immediately with the appropriate return value.
 */
extern bool hal_serial_transmit(hal_serial_port_t port, uint8_t ch);

/**
 * Array of SBM HAL serial devices. Do not access directly.
 * Use HAL_SERIAL_GET_DEVICE(), hal_serial_register() and
 * HAL_SERIAL_UNREGISTER() instead.
 */
extern hal_serial_device_t hal_serial_devices[HAL_SERIAL__NUM_PORTS__];

#endif /* SBM_HAL_SERIAL_H */
