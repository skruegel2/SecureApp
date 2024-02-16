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

#if SBM_RECORD_BOOT_TIME != 0

#include <stdint.h>

#include "sbm_hal.h"
#include "sbm_memory.h"
#include "stm32h7xx.h"
#include "soc_stm32xx.h"

static TIM_HandleTypeDef HTIMx SBM_EPHEMERAL_RAM = {
    .Instance = TIM2,
    .Init = {
        .CounterMode = TIM_COUNTERMODE_UP,
        .Period = UINT32_MAX,
        .ClockDivision = TIM_CLOCKDIVISION_DIV1,
        .AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_ENABLE
    }
};

void soc_timer_init(void)
{
    /* Initialise TIM2 to clock at a 1us rate continuously */

    HTIMx.Init.Prescaler = HAL_RCC_GetHCLKFreq() / UINT32_C(1000000);
    if (HAL_TIM_Base_Init(&HTIMx) != HAL_OK)
    {
        Error_Handler();
    }

    TIM_ClockConfigTypeDef sClockSourceConfig = {
        .ClockSource = TIM_CLOCKSOURCE_INTERNAL
    };
    if (HAL_TIM_ConfigClockSource(&HTIMx, &sClockSourceConfig) != HAL_OK)
    {
        Error_Handler();
    }

    TIM_MasterConfigTypeDef sMasterConfig = {
        .MasterOutputTrigger = TIM_TRGO_RESET,
        .MasterSlaveMode = TIM_MASTERSLAVEMODE_DISABLE
    };
    if (HAL_TIMEx_MasterConfigSynchronization(&HTIMx, &sMasterConfig) != HAL_OK)
    {
        Error_Handler();
    }

    HAL_TIM_Base_Start(&HTIMx);
}

void soc_timer_quiesce(void)
{
    HAL_TIM_Base_DeInit(&HTIMx);
}

void HAL_TIM_Base_MspInit(TIM_HandleTypeDef *const htim_base)
{
    if (htim_base->Instance == TIM2)
    {
        /* Peripheral clock enable */
        __HAL_RCC_TIM2_CLK_ENABLE();
    }
}

uint32_t soc_timer_get(void)
{
    return TIM2->CNT;
}

#endif /* SBM_RECORD_BOOT_TIME != 0 */
