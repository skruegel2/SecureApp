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

#include "soc_stm32xx_rng.h"
#include "soc_rng.h"

static RNG_HandleTypeDef rng_handle;

HAL_StatusTypeDef soc_stm32xx_rng_init()
{
    /* HAL_RNG_Init() relies on certain fields of the RNG_HandleTypeDef
     * structure being initialised.
     */
    rng_handle = (RNG_HandleTypeDef) {
        .Instance = RNG,
        .State = HAL_RNG_STATE_RESET,
        .Lock = HAL_UNLOCKED
    };

    /* Enable RNG peripheral clock */
    if (!__HAL_RCC_RNG_IS_CLK_ENABLED())
    {
        __HAL_RCC_RNG_CLK_ENABLE();
    }

    return HAL_RNG_Init(&rng_handle);
}

HAL_StatusTypeDef soc_stm32xx_rng_quiesce()
{
    /* Disable RNG peripheral clock */
    if (__HAL_RCC_RNG_IS_CLK_ENABLED())
    {
        __HAL_RCC_RNG_CLK_DISABLE();
    }

    return HAL_RNG_DeInit(&rng_handle);
}

int soc_rng_generate(uint32_t *r)
{
    /* Check if the RNG handle is initialized.
     *  */
    if(HAL_RNG_STATE_RESET == HAL_RNG_GetState(&rng_handle))
    {
        if(HAL_OK != soc_stm32xx_rng_init())
        {
            return 0;
        }
    }

    /* Return zero on error, non-zero otherwise */
    return (HAL_OK == HAL_RNG_GenerateRandomNumber(&rng_handle, r)) ? 1 : 0;
}
