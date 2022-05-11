#include "contiki.h"
#include "NuMicro.h"

void watchdog_init(void)
{
	/* Enable WDT module clock */
	CLK_EnableModuleClock(WDT_MODULE);
	CLK_SetModuleClock(WDT_MODULE, CLK_CLKSEL1_WDTSEL_LIRC, 0);
}

void watchdog_start(void)
{
	WDT_Open(WDT_TIMEOUT_2POW14, WDT_RESET_DELAY_18CLK, TRUE, TRUE);
}

void watchdog_periodic(void)
{
	WDT_Close();
	WDT_Open(WDT_TIMEOUT_2POW14, WDT_RESET_DELAY_18CLK, TRUE, TRUE);
}

void watchdog_reboot(void)
{
	WDT_Close();
	WDT_Open(WDT_TIMEOUT_2POW14, WDT_RESET_DELAY_18CLK, TRUE, FALSE);
	while (1);
}

