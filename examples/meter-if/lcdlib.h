#pragma once

void _lcd_init(void);
void lcd_set_antenna(int on);
void lcd_print(char *str);
void lcd_show_digit(unsigned int nth, unsigned char c);
void lcd_digit_off(unsigned int nth);
void lcd_turnoff(void);
void lcd_turnon(void);
