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
#include "oem_bsp.h"
#include "soc_arm_cmsis.h"

/* The UART handle used for TX and RX communications. */
static UART_HandleTypeDef console_handle =
{
    .Instance = OEM_CONSOLE_USART,
    .Init =
    {
        .BaudRate = 115200U,
        .WordLength = UART_WORDLENGTH_8B,
        .StopBits = UART_STOPBITS_1,
        .Parity = UART_PARITY_NONE,
        .HwFlowCtl = UART_HWCONTROL_NONE,
        .Mode = UART_MODE_RX | UART_MODE_TX,
        .OverSampling = UART_OVERSAMPLING_16
    }
};

static void usart_gpio_init(GPIO_TypeDef *port, uint32_t pin, uint32_t af)
{
    GPIO_InitTypeDef gpio =
    {
        .Mode = GPIO_MODE_AF_PP,
        .Pull = GPIO_NOPULL,
        .Speed = GPIO_SPEED_FREQ_HIGH,
        .Pin = pin,
        .Alternate = af
    };

    HAL_GPIO_Init(port, &gpio);
}

HAL_StatusTypeDef hal_console_init(void)
{
    OEM_CONSOLE_TX_GPIO_CLK_ENABLE();
    OEM_CONSOLE_RX_GPIO_CLK_ENABLE();
    OEM_CONSOLE_USART_CLK_ENABLE();

    usart_gpio_init(OEM_CONSOLE_TX_GPIO_PORT, OEM_CONSOLE_TX_GPIO_PIN, OEM_CONSOLE_TX_GPIO_AF);
    usart_gpio_init(OEM_CONSOLE_RX_GPIO_PORT, OEM_CONSOLE_RX_GPIO_PIN, OEM_CONSOLE_RX_GPIO_AF);

    return HAL_UART_Init(&console_handle);
}

HAL_StatusTypeDef hal_console_write(uint8_t ch)
{
    return HAL_UART_Transmit(&console_handle, &ch, 1, HAL_MAX_DELAY);
}

HAL_StatusTypeDef hal_console_read_timeout(uint8_t *data, size_t length, uint32_t timeout)
{
    /* When timeout is HAL_MAX_DELAY ST Cube waits forever for completion, which
     * is not the same as having a timeout of HAL_MAX_DELAY ms.
     *
     * The way around it is to decrement the timeout, which will make the Cube API wait for
     * (HAL_MAX_DELAY - 1) ms before it cancels the operation and returns HAL_TIMEOUT.
     */
    if (HAL_MAX_DELAY == timeout)
    {
        --timeout;
    }

    return HAL_UART_Receive(&console_handle, (uint8_t *)data, length, timeout);
}

HAL_StatusTypeDef hal_console_read(uint8_t *data, size_t length)
{

    HAL_StatusTypeDef status = HAL_UART_Receive(&console_handle, (uint8_t *)data, length,
                                                HAL_MAX_DELAY);

    /* Flush remaining data to prevent from overrun error */
    HAL_UART_AbortReceive(&console_handle);

    return status;
}

void hal_console_quiesce(void)
{
    OEM_CONSOLE_USART_FORCE_RESET();
    OEM_CONSOLE_USART_RELEASE_RESET();

    HAL_GPIO_DeInit(OEM_CONSOLE_TX_GPIO_PORT, OEM_CONSOLE_TX_GPIO_PIN);
    HAL_GPIO_DeInit(OEM_CONSOLE_RX_GPIO_PORT, OEM_CONSOLE_RX_GPIO_PIN);

    OEM_CONSOLE_USART_CLK_DISABLE();
}
