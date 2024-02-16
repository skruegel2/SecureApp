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

#ifndef HAL_CONSOLE_H_
#define HAL_CONSOLE_H_

#include <stdint.h>
#include "soc_arm_cmsis.h"

/**
 * Initialise console peripherals.
 * @return HAL status
 */
HAL_StatusTypeDef hal_console_init(void);

/**
 * Write one character to the serial port.
 * @param ch - Character to write.
 * @return HAL status.
 */
HAL_StatusTypeDef hal_console_write(uint8_t ch);

/**
 * Blocking read from console.
 *
 * @param data - Pointer to array to store the received data.
 * @param length - Expected data to read (in bytes).
 * @return HAL status.
 */
HAL_StatusTypeDef hal_console_read(uint8_t *data, size_t length);

/**
 * Blocking read from console - with timeout.
 *
 * @param data - Pointer to array to store the received data.
 * @param length - Expected data to read (in bytes).
 * @param timeout - Timeout of the operation (in ms).
 * @return HAL status.
 */
HAL_StatusTypeDef hal_console_read_timeout(uint8_t *data, size_t length, uint32_t timeout);

/**
 * Quiesce the console peripherals.
 */
void hal_console_quiesce(void);

#endif /* HAL_CONSOLE_H_ */
