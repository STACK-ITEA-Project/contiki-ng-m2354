/*
 * Copyright (c) 2005, Swedish Institute of Computer Science
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */
#include "meter-serial.h"
#include "meterif_data.h"
#include <string.h> /* for memcpy() */
#include <stdio.h>  // native 

#include "lib/ringbuf.h"

#define BUFSIZE 128

#if (BUFSIZE & (BUFSIZE - 1)) != 0
#error SERIAL_LINE_CONF_BUFSIZE must be a power of two (i.e., 1, 2, 4, 8, 16, 32, 64, ...).
#error Change SERIAL_LINE_CONF_BUFSIZE in contiki-conf.h.
#endif

static struct ringbuf rxbuf;
static uint8_t rxbuf_data[BUFSIZE];

PROCESS(meter_if_serial_process, "meter-if driver");

process_event_t meter_if_serial_event_message;

/*---------------------------------------------------------------------------*/
// called from meter_dev_process.native
int
meter_if_serial_input_byte(unsigned char c)
{
  int ret = 1;
  
  printf("%s: 0x%x\n", __func__, c);
    /* Add character */
  if(ringbuf_put(&rxbuf, c) == 0) {
      ret = 0;
    /* Buffer overflow: ignore the rest of the line */
  }
  /* Wake up consumer process */
  //process_poll(&meter_if_serial_process);
  process_post(&meter_if_serial_process, meter_if_serial_event_message, NULL);
  return ret;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(meter_if_serial_process, ev, data)
{
//  static char buf[BUFSIZE];
//  static int ptr;
  PROCESS_BEGIN();

  meter_if_serial_event_message = process_alloc_event();

//  ptr = 0;

  while(1) {
    /* Fill application buffer until newline or empty */
    int c = ringbuf_get(&rxbuf);
    static meterif_data_context_t ctx;
    
    if(c == -1) {
      /* Buffer empty, wait for poll */
      PROCESS_YIELD();
    } else {
        if (meterif_data_beginning(c)) {
            meterif_data_init(&ctx);
        }
        meterif_data_accumulate(&ctx, c);
        if (meterif_data_complete(&ctx)) {
            meterif_data_process(&ctx);
        }

    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
void
meter_if_serial_init(void)
{
  ringbuf_init(&rxbuf, rxbuf_data, sizeof(rxbuf_data));
  process_start(&meter_if_serial_process, NULL);
}
/*---------------------------------------------------------------------------*/
