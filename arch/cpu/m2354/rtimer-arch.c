#include "NuMicro.h"
#include "contiki.h"
#include "timer.h"
#include "clk.h"

static volatile rtimer_clock_t g_ticks = 0;
static volatile rtimer_clock_t g_time = 0;

void rtimer_arch_init(void)
{
	CLK_EnableModuleClock(TMR0_MODULE);
	CLK_SetModuleClock(TMR0_MODULE, CLK_CLKSEL1_TMR0SEL_PCLK0, 0);

	TIMER_Open(TIMER0, TIMER_PERIODIC_MODE, RTIMER_ARCH_SECOND);

	TIMER_EnableInt(TIMER0);
	NVIC_EnableIRQ(TMR0_IRQn);

	TIMER_Start(TIMER0);
}

void rtimer_arch_schedule(rtimer_clock_t t)
{
	g_time = t;
}

rtimer_clock_t rtimer_arch_now(void)
{
	return g_ticks;
}

void TMR0_IRQHandler(void)
{
	if (g_time && g_time <= g_ticks) {
		g_time = 0;
		rtimer_run_next();
	}
		
	g_ticks++;
	TIMER_ClearIntFlag(TIMER0);
}

