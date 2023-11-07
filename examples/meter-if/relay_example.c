#include <stdio.h>
#include "dev/relay_control.h"

void meter_relay_example(void)
{
  printf("call relay off\n");
  gpio_relay_off();
  printf("call relay on\n");
  gpio_relay_on();
}
