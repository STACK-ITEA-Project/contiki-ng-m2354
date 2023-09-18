#include <stdio.h>
#include "debug-uart.h"

static char debugbuf[256];
static int  debugpos = 0;
static char usedebug = 1;

static void _hexdump_line(char *buf, int len)
{
    int i;
    for (i=0; i< len; ++i) {
        printf("%02x ", buf[i]);
    }
    for (; i<16; ++i) {
        printf("   ");
    }
    printf("\r\n");
}
static void hexdump(char *buf, int len)
{
    int i;
    if (len <= 0 || !usedebug) {
        return;
    }
    printf("%dB\r\n", len);
    for (i=0; i<len; i+= 16) {
        _hexdump_line(buf, len-i > 16 ? 16 : len-i);
    }
    printf("\r\n");
}
void show_uart_debug_info(void)
{
    hexdump(debugbuf, debugpos);
    debugpos = 0;
}
void archive_uart_debug_info(char c)
{
    debugbuf[debugpos] = c;
    debugpos ++;
    if (debugpos == 256) {
        show_uart_debug_info();
    }
}
