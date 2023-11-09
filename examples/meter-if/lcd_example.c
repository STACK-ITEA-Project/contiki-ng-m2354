#include <stdio.h>
#include "lcdlib.h"

void meter_lcd_example(void)
{
    printf("init LCD...\n");
    _lcd_init();
    printf("turn off LCD...\n");
    lcd_turnoff();
    printf("turn on LCD...\n");
    lcd_turnon();
    printf("Done\n");

    lcd_turnoff();
    lcd_set_antenna(1);
    lcd_print("STACK");
    /*
    unsigned char c;
    int i;
    for (i=0; i<6; ++i) {
        for (c='A'; c <= 'Z'; ++c) {
            lcd_show_digit(i, c);
            clock_wait(40);
            lcd_digit_off(i);
        }
        for (c='0'; c <= '9'; ++c) {
            lcd_show_digit(i, c);
            clock_wait(40);
            lcd_digit_off(i);
        }
    }
    */
}
