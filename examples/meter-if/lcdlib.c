#include <string.h>
#include <ctype.h>
#include "contiki.h"
#include "NuMicro.h"
#include "lcdlib.h"

void _lcd_init(void)
{
    S_LCD_CFG_T g_LCDCfg = {
        __LIRC,                     /* LCD clock source frequency */
        LCD_COM_DUTY_1_4,           /* COM duty */
        LCD_BIAS_LV_1_3,            /* Bias level */
        30,                         /* Operation frame rate */
        LCD_WAVEFORM_TYPE_A_NORMAL, /* Waveform type */
        0, //LCD_FRAME_COUNTING_END_INT, /* Interrupt source */
        LCD_LOW_DRIVING_AND_BUF_ON, /* Driving mode */
        LCD_VOLTAGE_SOURCE_CP,
    };

    //SYS_ResetModule(LCD_RST);
    LCD_DisableInt(LCD_FRAME_COUNTING_END_INT |LCD_FRAME_END_INT | LCD_CPTOUT_INT);
    LCD_Open(&g_LCDCfg);
    LCD_SET_CP_VOLTAGE(LCD_CP_VOLTAGE_LV_1);
    LCD_ENABLE_DISPLAY();
}

void lcd_turnoff(void)
{
    LCD_SetAllPixels(0);
}

void lcd_turnon(void)
{
    LCD_SetAllPixels(1);
}

void set_lcd_segment(int com, int seg, int on)
{
    if (on) {
        LCD->DATA[com] |= 1<<seg;
    } else {
        LCD->DATA[com] &= ~(1<<seg);
    }
}

void lcd_print(char *str)
{
    int i;
    char c;
    if (str) {
        for (i=0; i<6; ++i) {
            if (str[i] == 0) {
                break;
            }
            c = toupper(str[i]);
            lcd_show_digit(5-i, c);
        }
    }
}

void lcd_set_antenna(int on)
{
    set_lcd_segment(2, 27, on);
}

typedef struct {
    uint8_t com;
    uint8_t seg;
} lcdpos_t;

lcdpos_t digitpos[6][8] = {
    { {4,24},{4,25},{4,26},{4,27}, {5, 0},{5, 1},{5, 2},{5, 3}, },
    { {4, 8},{4, 9},{4,10},{4,11}, {4,16},{4,17},{4,18},{4,19}, },
    { {3,16},{3,17},{3,18},{3,19}, {3,24},{3,25},{3,26},{3,27},},
    { {3, 0},{3, 1},{3, 2},{3, 3}, {3, 8},{3, 9},{3,10},{3,11},},
    { {2, 8},{2, 9},{2,10},{2,11}, {2,16},{2,17},{2,18},{2,19}, },
    { {1,24},{1,25},{1,26},{1,27}, {2, 0},{2, 1},{2, 2},{2, 3}, },
};

void bit_to_array(uint8_t x, char buf[8])
{
    int i;
    for (i=0; i<8; ++i) {
        buf[7-i] = 0;
        if (x & (1<<i)) {
            buf[7-i] = 1;
        }
    }
}

void get_pattern(unsigned char c, char buf[8])
{
    char patterns[256] = {
        ['0'] = 0x5f, ['1'] = 0x06, ['2'] = 0x6b, ['3'] = 0x2f,
        ['4'] = 0x36, ['5'] = 0x3d, ['6'] = 0x7d, ['7'] = 0x07,
        ['8'] = 0x7f, ['9'] = 0x37,
        ['A'] = 0x77, ['B'] = 0x7c, ['C'] = 0x59, ['D'] = 0x6e,
        ['E'] = 0x79, ['F'] = 0x71, ['G'] = 0x3f, ['H'] = 0x76,
        ['I'] = 0x06, ['J'] = 0x0d, ['K'] = 0x76, ['L'] = 0x58,
                      ['N'] = 0x57, ['O'] = 0x5f, ['P'] = 0x73,
        ['Q'] = 0x37, ['R'] = 0x60, ['S'] = 0x3d, ['T'] = 0x78,
        ['U'] = 0x5e,
        ['Y'] = 0x36, ['Z'] = 0x6b,
        0,
    };
    bit_to_array(patterns[c], buf);
}

void set_lcd_digit_pattern(unsigned int nth, char onoff[8])
{
    int i;
    if (nth > 6) {
        return;
    }
    for (i=1; i<8; ++i) {
        lcdpos_t *pos = &digitpos[nth][i];
        set_lcd_segment(pos->com, pos->seg, onoff[i]);
    }
}

void lcd_show_digit(unsigned int nth, unsigned char c)
{
    char segonoff[8];
    get_pattern(c, segonoff);
    set_lcd_digit_pattern(nth, segonoff);
}

void lcd_digit_off(unsigned int nth)
{
    char segonoff[8] = {0,};
    set_lcd_digit_pattern(nth, segonoff);
}
