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

#ifndef OEM_ST_NUCLEO_H753ZI_H_
#define OEM_ST_NUCLEO_H753ZI_H_

#if !defined(OEM_ST_NUCLEO_H753ZI)
#error "Invalid include."
#endif

#include "stm32h7xx_hal.h"

/* Clock chain. */
#define OEM_CLOCK_RCC_PLLN          275U
#define OEM_CLOCK_RCC_PLLP          2U
#define OEM_CLOCK_AHB_CLOCK_DIVIDER RCC_HCLK_DIV2
#define OEM_FLASH_LATENCY           FLASH_LATENCY_4
#define OEM_PWR_SUPPLY              PWR_LDO_SUPPLY

/* Console. */
#define OEM_CONSOLE_USART                USART3
#define OEM_CONSOLE_USART_CLK_ENABLE     __HAL_RCC_USART3_CLK_ENABLE
#define OEM_CONSOLE_USART_CLK_DISABLE    __HAL_RCC_USART3_CLK_DISABLE
#define OEM_CONSOLE_USART_FORCE_RESET    __HAL_RCC_USART3_FORCE_RESET
#define OEM_CONSOLE_USART_RELEASE_RESET  __HAL_RCC_USART3_RELEASE_RESET

#define OEM_CONSOLE_TX_GPIO_CLK_ENABLE   __HAL_RCC_GPIOD_CLK_ENABLE
#define OEM_CONSOLE_TX_GPIO_PORT         GPIOD
#define OEM_CONSOLE_TX_GPIO_PIN          GPIO_PIN_8
#define OEM_CONSOLE_TX_GPIO_AF           GPIO_AF7_USART3

#define OEM_CONSOLE_RX_GPIO_CLK_ENABLE   __HAL_RCC_GPIOD_CLK_ENABLE
#define OEM_CONSOLE_RX_GPIO_PORT         GPIOD
#define OEM_CONSOLE_RX_GPIO_PIN          GPIO_PIN_9
#define OEM_CONSOLE_RX_GPIO_AF           GPIO_AF7_USART3

#define OEM_CONSOLE_RCC_PERIPHCLK               RCC_PERIPHCLK_USART3
#define OEM_CONSOLE_USART234578_CLOCK_SELECTION RCC_USART234578CLKSOURCE_D2PCLK1

/* LEDs. */
#define OEM_LED_ACTIVE_HIGH             1

#define OEM_LED_STARTUP_GPIO_PORT       GPIOB
#define OEM_LED_STARTUP_GPIO_PIN        GPIO_PIN_0
#define OEM_LED_STARTUP_GPIO_CLK_ENABLE __HAL_RCC_GPIOB_CLK_ENABLE

#define OEM_LED_ERROR_GPIO_PORT       GPIOB
#define OEM_LED_ERROR_GPIO_PIN        GPIO_PIN_14
#define OEM_LED_ERROR_GPIO_CLK_ENABLE __HAL_RCC_GPIOB_CLK_ENABLE

/* Board name. */
#define OEM_TARGET_STRING "STMicro STM32H753ZI Nucleo"

#endif /* OEM_ST_NUCLEO_H753ZI_H_ */
