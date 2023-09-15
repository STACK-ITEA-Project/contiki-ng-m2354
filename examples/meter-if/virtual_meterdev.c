#ifdef CONTIKI_TARGET_NATIVE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include "meter-serial.h"

PROCESS(meter_dev_process, "meter-if driver");

#define DATAFILE "sampledata1.txt"

PROCESS_THREAD(meter_dev_process, ev, data)
{
    size_t fsize;
    static size_t sz;
    static size_t i;
    struct stat statbuf;
    static uint8_t *databuf = NULL;
    unsigned int v;
    FILE *fp;
    static struct etimer timer;

    PROCESS_BEGIN();
    if (stat(DATAFILE, &statbuf) < 0) {
        fprintf(stderr, "%s: %s\n", DATAFILE, strerror(errno));
        exit(1);
    }
    fsize = statbuf.st_size;

    fp = fopen(DATAFILE, "r");
    if (NULL == fp) {
        fprintf(stderr, "%s: %s\n", DATAFILE, strerror(errno));
        exit(1);
    }
    databuf = calloc(1, fsize);
    for (sz=0; sz<fsize; ++sz) {
        if (fscanf(fp, "%02X", &v) < 0) {
            break;
        }
        databuf[sz] = (uint8_t)v;
    }
    fclose(fp);

    printf("%s: %ld bytes read\n", __func__, sz);

    etimer_set(&timer, 1);

    for (i=0; i<sz;) {
      if (meter_if_serial_input_byte(databuf[i]) != 0) {
          i++;
      }
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
      etimer_reset(&timer);
    }
    printf("%s: %ld bytes sent\n", __func__, i);

    PROCESS_END();
}

void meter_dev_init(void)
{
    printf("%s\n", __func__);
  process_start(&meter_dev_process, NULL);
}
#endif /* CONTIKI_TARGET_NATIVE */
