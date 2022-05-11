/*
 * Copyright (C) 2020 Yago Fontoura do Rosario <yago.rosario@hotmail.com.br>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*---------------------------------------------------------------------------*/
/**
 * \addtogroup nrf-platforms
 * @{
 *
 * \file
 *      Platform implementation for nRF
 * \author
 *      Yago Fontoura do Rosario <yago.rosario@hotmail.com.br>
 */
/*---------------------------------------------------------------------------*/
#include "contiki.h"

#if 0
#include "dev/gpio-hal.h"
#include "dev/button-hal.h"
#include "dev/leds.h"
#include "dev/serial-line.h"

#include "random.h"
#include "int-master.h"
#include "sensors.h"
#include "uarte-arch.h"
#include "linkaddr-arch.h"
#include "reset-arch.h"

#include "lpm.h"
#else
#include "dev/serial-line.h"
#include "sensors.h"
#include "NuMicro.h"
#endif

/*---------------------------------------------------------------------------*/
/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "M2354"
#define LOG_LEVEL LOG_LEVEL_MAIN
/*---------------------------------------------------------------------------*/

SENSORS_SENSOR(dummy_sensor, "dummy", NULL, NULL, NULL);
SENSORS(&dummy_sensor);

void
platform_init_stage_one(void)
{
#if 0
  gpio_hal_init();
  leds_init();
#endif
}
/*---------------------------------------------------------------------------*/

void UART0_IRQHandler(void)
{
	uint8_t c = 0xff;
	uint32_t int_sts = UART0->INTSTS;

	if (int_sts & UART_INTSTS_RDAINT_Msk) {
		/* Get all the input characters */
		while (UART_IS_RX_READY(UART0)) {
			/* Get the character from UART Buffer */
			c = (uint8_t)UART_READ(UART0);
			printf("%c", c);
			if (c == '\n')
				printf("\r");
			else if (c == '\r')
				printf("\n");
			fflush(stdout);
			serial_line_input_byte(c);
		}

	}

	/* Handle transmission error */
	if (UART0->FIFOSTS & (UART_FIFOSTS_BIF_Msk | UART_FIFOSTS_FEF_Msk |
				UART_FIFOSTS_PEF_Msk | UART_FIFOSTS_RXOVIF_Msk))
		UART0->FIFOSTS = (UART_FIFOSTS_BIF_Msk | UART_FIFOSTS_FEF_Msk |
				UART_FIFOSTS_PEF_Msk | UART_FIFOSTS_RXOVIF_Msk);
}

static void uart0_init(void)
{
	/* Enable UART0 module clock */
	CLK_EnableModuleClock(UART0_MODULE);

	/* Select UART0 module clock source as HIRC and UART0 module clock divider as 1 */
	CLK_SetModuleClock(UART0_MODULE, CLK_CLKSEL2_UART0SEL_HIRC, CLK_CLKDIV0_UART0(1));

	/* Set multi-function pins for UART0 RXD and TXD */
	SYS->GPA_MFPL = (SYS->GPA_MFPL & (~(UART0_RXD_PA6_Msk | UART0_TXD_PA7_Msk)))
		| UART0_RXD_PA6 | UART0_TXD_PA7;
	/* Configure UART0: 115200, 8-bit word, no parity bit, 1 stop bit. */
	UART_Open(UART0, 115200);

	NVIC_EnableIRQ(UART0_IRQn);
	UART_EnableInt(UART0, UART_INTEN_RDAIEN_Msk);
}

void platform_init_stage_two(void)
{
	uart0_init();
	serial_line_init();
	
#if 0
  button_hal_init();

  /* Seed value is ignored since hardware RNG is used. */
  random_init(0x5678);

#if PLATFORM_HAS_UARTE
  uarte_init();
  serial_line_init();
#if BUILD_WITH_SHELL
  uarte_set_input(serial_line_input_byte);
#endif /* BUILD_WITH_SHELL */
#endif /* PLATFORM_HAS_UARTE */
  populate_link_address();

  reset_debug();
#endif
}
/*---------------------------------------------------------------------------*/
void
platform_init_stage_three(void)
{
  //process_start(&sensors_process, NULL);
}
/*---------------------------------------------------------------------------*/
void
platform_idle()
{
#if 0
  lpm_drop();
#endif
}
/*---------------------------------------------------------------------------*/
/**
 * @}
 */
