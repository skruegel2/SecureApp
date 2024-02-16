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

/**
 * @brief STM32H7xx system clock config using internal oscillators.
 *
 * This implementations only uses internal oscillators:
 * - HSI -> PLL -> SYSCLK
 * - HSI48 -> RNG
 *
 * We try to share as much configuration between the same devices as we can.
 * Currently this function is configured with:
 * - TARGET_RCC_PLLN
 * - TARGET_RCC_PLLP
 * - TARGET_FLASH_LATENCY
 * - TARGET_CONSOLE_RCC_PERIPHCLK
 * - TARGET_PWR_SUPPLY
 *
 * In this function we configure:
 * - Power supply;
 * - RCC oscillators;
 * - CPU, AHB and APB buses clocks;
 * - Peripheral clock to setup RNG and UART clock origin;
 * - Flash programming delay.
 *
 * NOTES:
 * - Any implementation should target maximum speed.
 * - The sequence taken here is only valid when raising the speed.
 */
void SystemClock_Config(void)
{
    /* Supply configuration update enable */
    HAL_PWREx_ConfigSupply(OEM_PWR_SUPPLY);

    /* Configure the main internal regulator output voltage */
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE0);

    while (!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY))
    {
    }

    /* Initializes the RCC Oscillators according to the specified parameters
     * in the RCC_OscInitTypeDef structure.
     */
    RCC_OscInitTypeDef RCC_OscInitStruct =
    {
        .OscillatorType = RCC_OSCILLATORTYPE_HSI48 | RCC_OSCILLATORTYPE_HSI,
        .HSIState = RCC_HSI_DIV1,
        .HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT,
        .HSI48State = RCC_HSI48_ON,
        .PLL =
        {
            .PLLState = RCC_PLL_ON,
            .PLLSource = RCC_PLLSOURCE_HSI,
            .PLLM = 32,
            .PLLN = OEM_CLOCK_RCC_PLLN,
            .PLLP = OEM_CLOCK_RCC_PLLP,
            .PLLQ = 2,
            .PLLR = 2,
            .PLLRGE = RCC_PLL1VCIRANGE_1,
            .PLLVCOSEL = RCC_PLL1VCOWIDE,
            .PLLFRACN = 0,
        }
    };

    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
    {
        Error_Handler();
    }

    /* Initializes the CPU, AHB and APB buses clocks. */
    RCC_ClkInitTypeDef RCC_ClkInitStruct =
    {
        .ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
                | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2 | RCC_CLOCKTYPE_D3PCLK1
                | RCC_CLOCKTYPE_D1PCLK1,
        .SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK,
        .SYSCLKDivider = RCC_SYSCLK_DIV1,
        .AHBCLKDivider = OEM_CLOCK_AHB_CLOCK_DIVIDER,
        .APB3CLKDivider = RCC_APB3_DIV2,
        .APB1CLKDivider = RCC_APB1_DIV2,
        .APB2CLKDivider = RCC_APB2_DIV2,
        .APB4CLKDivider = RCC_APB4_DIV2
    };

    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, OEM_FLASH_LATENCY) != HAL_OK)
    {
        Error_Handler();
    }

    RCC_PeriphCLKInitTypeDef PeriphClkInitStruct =
    {
        .PeriphClockSelection = OEM_CONSOLE_RCC_PERIPHCLK | RCC_PERIPHCLK_RNG,
        .RngClockSelection = RCC_RNGCLKSOURCE_HSI48,
#if defined(OEM_CONSOLE_USART16_CLOCK_SELECTION)
        .Usart16ClockSelection = OEM_CONSOLE_USART16_CLOCK_SELECTION,
#elif defined(OEM_CONSOLE_USART234578_CLOCK_SELECTION)
        .Usart234578ClockSelection = OEM_CONSOLE_USART234578_CLOCK_SELECTION,
#else
#error "Undefined USART clock source."
#endif
    };

    if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct) != HAL_OK)
    {
        Error_Handler();
    }

    /* ST's HAL does not configure FLASH_ACR.WRHIGHFREQ */
    __HAL_FLASH_SET_PROGRAM_DELAY(stm32h7xx_get_flash_programming_delay(OEM_FLASH_LATENCY));
}
