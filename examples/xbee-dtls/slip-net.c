#include "contiki.h"
#include "net/netstack.h"
#include "net/ipv6/uip.h"
#include "dev/slip.h"

#define SLIP_END     0300
#define SLIP_ESC     0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335

static void
slipnet_init(void)
{
}

static void
slipnet_input(void)
{
}

static uint8_t
slipnet_output(const linkaddr_t *localdest)
{
  const uint8_t *ptr = uip_buf;
  uint16_t i;
  uint8_t c;

  slip_arch_writeb(SLIP_END);

  for(i = 0; i < uip_len; ++i) {
    c = *ptr++;
    if(c == SLIP_END) {
      slip_arch_writeb(SLIP_ESC);
      c = SLIP_ESC_END;
    } else if(c == SLIP_ESC) {
      slip_arch_writeb(SLIP_ESC);
      c = SLIP_ESC_ESC;
    }
    slip_arch_writeb(c);
  }

  slip_arch_writeb(SLIP_END);

  return 1;
}

const struct network_driver slipnet_driver = {
  "slipnet",
  slipnet_init,
  slipnet_input,
  slipnet_output
};

