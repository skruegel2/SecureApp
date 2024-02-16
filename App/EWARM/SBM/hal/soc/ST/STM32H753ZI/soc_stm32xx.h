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

#ifndef SOC_STM32XX_H_
#define SOC_STM32XX_H_

/**
 * STM32 SOC specific initialisation function.
 *
 * It's called as part of the STM32 generic initialisation function.
 *
 * @note See soc_init in stm32xx_soc.c to know what still needs to be initialized.
 */
void soc_stm32xx_init(void);

/**
 * STM32 SOC specific quiescing function.
 *
 * It's called as part of the STM32 generic quiescing function.
 *
 * @note This function should quiesce the same components that are initialized in
 * stm32xx_soc_init, but in the opposite order.
 */
void soc_stm32xx_quiesce(void);

/**
 * @brief System Clock Configuration.
 *
 * This function configures the system clock, but it can also be used to:
 * - Configure (and enable) the RNG clock;
 * - Configure (and enable) the UART clock.
 *
 * Check implementation for more details.
 */
void SystemClock_Config(void);

/**
 * STM32 system tick function.
 */
void SysTick_Handler(void);

/**
 * STM32 error handler function.
 */
void Error_Handler(void);

#endif /* SOC_STM32XX_H_ */
