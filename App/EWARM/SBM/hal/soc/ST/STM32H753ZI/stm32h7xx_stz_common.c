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
#include "soc_stm32xx.h"
#include "stm32h7xx_stz_common.h"

uint32_t stm32h7xx_get_flash_programming_delay(uint32_t flash_latency)
{
    switch(flash_latency)
    {
#if defined (STM32H743xx) || defined (STM32H753xx)
        /* See ST RM0433 - Rev7.
         * Table 17. FLASH recommended number of wait states and programming delay
         */
        case FLASH_ACR_LATENCY_0WS:
            return FLASH_PROGRAMMING_DELAY_0;

        case FLASH_ACR_LATENCY_1WS:
        case FLASH_ACR_LATENCY_2WS:
            return FLASH_PROGRAMMING_DELAY_1;

        case FLASH_ACR_LATENCY_3WS:
        case FLASH_ACR_LATENCY_4WS:
            return FLASH_PROGRAMMING_DELAY_2;

#elif defined (STM32H725xx) || defined (STM32H735xx)
        /* See ST RM0468 - Rev2.
         * Table 16. FLASH recommended number of wait states and programming delay
         */
        case FLASH_ACR_LATENCY_0WS:
            return FLASH_PROGRAMMING_DELAY_0;

        case FLASH_ACR_LATENCY_1WS:
            return FLASH_PROGRAMMING_DELAY_1;

        case FLASH_ACR_LATENCY_2WS:
            return FLASH_PROGRAMMING_DELAY_2;

        case FLASH_ACR_LATENCY_3WS:
            return FLASH_PROGRAMMING_DELAY_3;

#elif defined (STM32H7B3xxQ)
        /* See ST RM0455 - Rev4.
         * Table 15. FLASH recommended number of wait states and programming delay
         */
        case FLASH_ACR_LATENCY_0WS:
        case FLASH_ACR_LATENCY_1WS:
            return FLASH_PROGRAMMING_DELAY_0;

        case FLASH_ACR_LATENCY_2WS:
        case FLASH_ACR_LATENCY_3WS:
            return FLASH_PROGRAMMING_DELAY_1;

        case FLASH_ACR_LATENCY_4WS:
        case FLASH_ACR_LATENCY_5WS:
            return FLASH_PROGRAMMING_DELAY_2;

        case FLASH_ACR_LATENCY_6WS:
        case FLASH_ACR_LATENCY_7WS:
            return FLASH_PROGRAMMING_DELAY_3;
#else
/* In order to support more devices:
 * - In the reference manual check for the flash wait states (latency) relation with flash programming delay (WRHIGHFREQ).
 * - If the relation is the same as one of the above just add the device to the "[el]if defined(device)" list
 * - If it's a new relation add another #elif branch.
 */
#error "Missing flash programming delay configuration for the current device."
#endif
        default:
            /* We don't support this flash_latency, handle as needed.
             * NOTE: bigger latency is allowed but we don't have a reason (yet) to support it. */
            Error_Handler();
    }

    return 0;
}

void soc_stm32xx_init(void)
{
    /* Disable caches to avoid speculative reads from SystemMemory */
    SCB_DisableDCache();
    SCB_DisableICache();

    /* Get the MPU up and running */
    stm32h7xx_mpu_config();
}

void soc_stm32xx_quiesce(void)
{
    /* Disable all GPIO clocks. */
    __HAL_RCC_GPIOA_CLK_DISABLE();
    __HAL_RCC_GPIOB_CLK_DISABLE();
    __HAL_RCC_GPIOC_CLK_DISABLE();
    __HAL_RCC_GPIOD_CLK_DISABLE();
    __HAL_RCC_GPIOE_CLK_DISABLE();
    __HAL_RCC_GPIOF_CLK_DISABLE();
    __HAL_RCC_GPIOG_CLK_DISABLE();
    __HAL_RCC_GPIOH_CLK_DISABLE();
#ifdef GPIOI
    __HAL_RCC_GPIOI_CLK_DISABLE();
#endif
    __HAL_RCC_GPIOJ_CLK_DISABLE();
    __HAL_RCC_GPIOK_CLK_DISABLE();

    HAL_MPU_Disable();

    /* Reset the RCC clock configuration to the default reset state */
    HAL_RCC_DeInit();

    /* Disable the SysTick timer again */
    NVIC_DisableIRQ(SysTick_IRQn);
    SysTick->CTRL = 0u;
    NVIC_ClearPendingIRQ(SysTick_IRQn);
}
