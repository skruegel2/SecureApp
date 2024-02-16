#include "soc_arm_cmsis.h"
#include "sbm_hal.h"
#include "soc_stm32xx.h"

#include "soc_stm32xx.h"
#include "soc_stm32xx_rng.h"
#include "sbm_hal.h"

/*
 * Base soc_init for STM32 devices.
 */
void soc_init(void)
{
    /* Basic CPU initialisation (Cache, IRQs) */
    cpu_init();

    /* STM HAL Initialisation */
    HAL_Init();

    /* Enable SYS and RNG clocks */
    /* Some ST devices don't require SYS clock to be enabled, no macro is defined in this case */
#if defined(__HAL_RCC_SYSCFG_CLK_ENABLE)
    __HAL_RCC_SYSCFG_CLK_ENABLE();
#endif
    __HAL_RCC_RNG_CLK_ENABLE();

    /* SOC specific initialization routine */
    soc_stm32xx_init();

    /* Initialise clock chain */
    SystemClock_Config();

    /* Update core clock */
    SystemCoreClockUpdate();

    /* STM32 RNG HAL init */
    soc_stm32xx_rng_init();
}

/*
 * Base soc_quiesce for STM32 devices.
 * This function must quiesce the same components initialized in soc_init,
 * but in the opposite order.
 */
void soc_quiesce(void)
{
    soc_stm32xx_rng_quiesce();

    soc_stm32xx_quiesce();

    cpu_quiesce();
}

void soc_app_start(uintptr_t app_address)
{
    const uint32_t *const e = (const uint32_t *) app_address;

    /* Validate the stack and entry point */
    if (e[0] == 0xffffffffu || e[1] == 0xffffffffu || (e[1] & 1u) == 0)
    {
        return;
    }

    /* Configure VTOR and stacks as per a regular CPU reset */
    #if defined(SBM_TZ_FIREWALL_ACTIVE) && (SBM_TZ_FIREWALL_ACTIVE != 0)
        SCB_NS->VTOR = (uint32_t) e;
    #else
        SCB->VTOR = (uint32_t) e;
    #endif

    /* Set the stack, clear insecure memory, and invoke the application */
    cpu_clear_memory_and_invoke_app(e[0], e[1]);
}

void soc_reset(void)
{
    /* Use the generic ARM reset */
    cpu_reset();
}

/* Override the weak SysTick_Implementation in arm/cpu_support.c */
void SysTick_Implementation(uint32_t *frame);
void SysTick_Implementation(uint32_t *frame)
{
    /* ST's HAL maintains a tick counter */
    HAL_IncTick();

    /* Invoke the SBM HAL's tick handler */
    hal_tick_isr(frame);
}
