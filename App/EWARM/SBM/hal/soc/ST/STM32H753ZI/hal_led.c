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

#include "hal_led.h"
#include "soc_arm_cmsis.h"

void hal_led_init(const hal_led_t *hal_led)
{
    assert(NULL != hal_led);

    GPIO_InitTypeDef gpio_init_args =
    {
        .Pin = hal_led->hal_gpio.pin,
        .Mode = GPIO_MODE_OUTPUT_PP,
        .Pull = GPIO_PULLUP,
        .Speed = GPIO_SPEED_FREQ_HIGH,
        .Alternate = 0
    };

    hal_gpio_init(&hal_led->hal_gpio, &gpio_init_args);
    hal_led_set(hal_led, false);
}

void hal_led_quiesce(const hal_led_t *hal_led)
{
    assert(NULL != hal_led);

    hal_led_set(hal_led, false);
    hal_gpio_quiesce(&hal_led->hal_gpio);
}

void hal_led_set(const hal_led_t *hal_led, bool turn_on)
{
    assert(NULL != hal_led);

    hal_gpio_write(&hal_led->hal_gpio, turn_on ? hal_led->active_high : !hal_led->active_high);
}

void hal_led_toggle(const hal_led_t *hal_led)
{
    assert(NULL != hal_led);

    hal_gpio_toggle(&hal_led->hal_gpio);
}
