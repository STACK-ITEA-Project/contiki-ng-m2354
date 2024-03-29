#include "dsunit.h"
#include <stdint.h>

#include "../adc_data.c"

uint8_t data1[] = {
0x43, 0x5C, 0x5C, 0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x58, 0x2B, 0x5F,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x42, 0x70, 0x10, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00,
0x00,
0x41, 0xB9, 0xF2, 0xA9,
0x00, 
};

void test_adc_pushdata_read_uint8(void)
{
    ssize_t r;
    uint8_t buf;
    assert_equal(adc_pushdata_read_uint8(&buf, data1, 0), -1);

    assert_equal(adc_pushdata_read_uint8(&buf, data1, 1), 1);
    assert_equal(buf, data1[0]);
}

void test_adc_pushdata_read_float(void)
{
    ssize_t r;
    float32_t buf;
    assert_equal(adc_pushdata_read_float(&buf, data1, 3), -1);

    assert_equal(adc_pushdata_read_float(&buf, data1, 4), 4);
    assert_equal(buf.c[0], data1[3]);
    assert_equal(buf.c[1], data1[1]);
    assert_equal(buf.c[2], data1[2]);
    assert_equal(buf.c[3], data1[0]);
}

void test_adc_pushdata_read(void)
{
    ssize_t r;
    adc_pushdata_t buf;
    assert_equal(adc_pushdata_read(&buf, data1, 3), -1);
    assert_equal(adc_pushdata_read(&buf, data1, 194), -1);

    assert_equal(adc_pushdata_read(&buf, data1, sizeof(data1)), 195);
    assert_equal(buf.r.voltage.u32, 0x435c5cb2);
    assert_equal(buf.r.current.u32, 0x0);
    assert_equal(buf.r.phase.u32, 0x0);
    assert_equal(buf.r.act.u32, 0x0);
    assert_equal(buf.r.react.u32, 0x0);
    assert_equal(buf.r.vol_thd.u32, 0x40582b5f);
    assert_equal(buf.s.voltage.u32, 0x0);
    assert_equal(buf.s.current.u32, 0x0);
    assert_equal(buf.s.phase.u32, 0x0);
    assert_equal(buf.s.act.u32, 0x0);
    assert_equal(buf.s.react.u32, 0x0);
    assert_equal(buf.s.vol_thd.u32, 0x0);
    assert_equal(buf.t.voltage.u32, 0x0);
    assert_equal(buf.t.current.u32, 0x0);
    assert_equal(buf.t.phase.u32, 0x0);
    assert_equal(buf.t.act.u32, 0x0);
    assert_equal(buf.t.react.u32, 0x0);
    assert_equal(buf.t.vol_thd.u32, 0x0);
    assert_equal(buf.freq.u32, 0x42701000);
    assert_equal(buf.rs_phase.u32, 0x0);
    assert_equal(buf.rt_phase.u32, 0x0);
    assert_equal(buf.rst_accum.DeliAct.u32, 0x0);
    assert_equal(buf.rst_accum.DLagReact.u32, 0x0);
    assert_equal(buf.rst_accum.DLeadReact.u32, 0x0);
    assert_equal(buf.rst_accum.DeliApp.u32, 0x0);
    assert_equal(buf.rst_accum.ReceiAct.u32, 0x0);
    assert_equal(buf.rst_accum.RLeadReact.u32, 0x0);
    assert_equal(buf.rst_accum.RLagReact.u32, 0x0);
    assert_equal(buf.rst_accum.ReceiApp.u32, 0x0);
    assert_equal(buf.r_accum.DeliAct.u32, 0x0);
    assert_equal(buf.r_accum.DLagReact.u32, 0x0);
    assert_equal(buf.r_accum.DLeadReact.u32, 0x0);
    assert_equal(buf.r_accum.ReceiAct.u32, 0x0);
    assert_equal(buf.r_accum.RLeadReact.u32, 0x0);
    assert_equal(buf.r_accum.RLagReact.u32, 0x0);
    assert_equal(buf.s_accum.DeliAct.u32, 0x0);
    assert_equal(buf.s_accum.DLagReact.u32, 0x0);
    assert_equal(buf.s_accum.DLeadReact.u32, 0x0);
    assert_equal(buf.s_accum.ReceiAct.u32, 0x0);
    assert_equal(buf.s_accum.RLeadReact.u32, 0x0);
    assert_equal(buf.s_accum.RLagReact.u32, 0x0);
    assert_equal(buf.t_accum.DeliAct.u32, 0x0);
    assert_equal(buf.t_accum.DLagReact.u32, 0x0);
    assert_equal(buf.t_accum.DLeadReact.u32, 0x0);
    assert_equal(buf.t_accum.ReceiAct.u32, 0x0);
    assert_equal(buf.t_accum.RLeadReact.u32, 0x0);
    assert_equal(buf.t_accum.RLagReact.u32, 0x0);
    assert_equal(buf.sag_count, 0x0);
    assert_equal(buf.swell_count, 0x0);
    assert_equal(buf.temp.u32, 0x41b9f2a9);
    assert_equal(buf.cal_disp_sts, 0x0);

}

void test_float_to_string(void)
{
    float f = 1.1;
    char buf[256];
    char *p;
    p = _float_to_char(f, buf, 4);
    assert_true(p == buf);
    assert_equal_string(buf, "1.1");

    f = 1.234567;
    p = _float_to_char(f, buf, 9);
    assert_true(p == buf);
    assert_equal_string(buf, "1.234567");

    f = 220.123;
    p = _float_to_char(f, buf, 8);
    assert_true(p == buf);
    assert_equal_string(buf, "220.123");

}

void main(void)
{
    _setup();
    run_test(test_adc_pushdata_read_uint8);
    run_test(test_adc_pushdata_read_float);
    run_test(test_adc_pushdata_read);
    run_test(test_float_to_string);
}
