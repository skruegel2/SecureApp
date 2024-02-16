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

#include "sbm_hal.h"
#include "oem.h"

#if SBM_BOOT_STATUS_TRACKING != 0

/* Delay a few cycles. */
#define DELAY() do { for(int i=0; i < 10; ++i) { asm volatile("nop"); } } while(0)

/*
 * The boot signal pin is connected to PB8 in the Nucleo H743ZI board,
 * and is active low.
 */
#define	BOOT_SIGNAL_GPIO GPIOB
#define	BOOT_SIGNAL_PIN GPIO_PIN_8

void oem_boot_signal_start(void)
{
	GPIO_InitTypeDef gpio_initstruct;
	GPIO_TypeDef *gpio = BOOT_SIGNAL_GPIO;
	uint32_t pin = BOOT_SIGNAL_PIN;

	gpio_initstruct.Pin = pin;
	gpio_initstruct.Mode = GPIO_MODE_OUTPUT_PP;
	gpio_initstruct.Pull = GPIO_PULLUP;
	gpio_initstruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;

	HAL_GPIO_Init(gpio, &gpio_initstruct);
	HAL_GPIO_WritePin(gpio, pin, GPIO_PIN_SET);
	DELAY();

	HAL_GPIO_WritePin(gpio, pin, GPIO_PIN_RESET);
}

void oem_boot_signal_end(void)
{
	GPIO_TypeDef *gpio = BOOT_SIGNAL_GPIO;
	uint32_t pin = BOOT_SIGNAL_PIN;

	HAL_GPIO_WritePin(gpio, pin, GPIO_PIN_SET);

	DELAY();

	/* Deinitialise GPIO (quiesce). */
	HAL_GPIO_DeInit(gpio, pin);
}

#endif /* SBM_BOOT_STATUS_TRACKING != 0 */
