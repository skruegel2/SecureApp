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
#include <stddef.h>
#include <assert.h>

#include "hal_gpio.h"

void hal_gpio_init(const hal_gpio_t *hal_gpio, GPIO_InitTypeDef *gpio_init_args)
{
    assert(NULL != hal_gpio);
    assert(NULL != gpio_init_args);

    HAL_GPIO_Init(hal_gpio->gpio, gpio_init_args);
}

void hal_gpio_quiesce(const hal_gpio_t *hal_gpio)
{
    assert(NULL != hal_gpio);

    HAL_GPIO_DeInit(hal_gpio->gpio, hal_gpio->pin);
}

void hal_gpio_write(const hal_gpio_t *hal_gpio, bool set)
{
    assert(NULL != hal_gpio);

    HAL_GPIO_WritePin(hal_gpio->gpio, hal_gpio->pin, set ? GPIO_PIN_SET : GPIO_PIN_RESET);
}

void hal_gpio_toggle(const hal_gpio_t *hal_gpio)
{
    assert(NULL != hal_gpio);

    HAL_GPIO_TogglePin(hal_gpio->gpio, hal_gpio->pin);
}

bool hal_gpio_read(const hal_gpio_t *hal_gpio)
{
    assert(NULL != hal_gpio);

    return GPIO_PIN_SET == HAL_GPIO_ReadPin(hal_gpio->gpio, hal_gpio->pin);
}
