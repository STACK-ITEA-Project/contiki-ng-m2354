#pragma once

#include <stdint.h>

typedef union {
    uint8_t c[4];
    uint32_t u32; // for unittest
    float f;
} float32_t;

typedef struct
{
    float32_t DeliAct;
    float32_t DLagReact;
    float32_t DLeadReact;
    float32_t ReceiAct;
    float32_t RLeadReact;
    float32_t RLagReact;
} accum_energy_t;

typedef struct
{
    float32_t DeliAct;
    float32_t DLagReact;
    float32_t DLeadReact;
    float32_t DeliApp;
    float32_t ReceiAct;
    float32_t RLeadReact;
    float32_t RLagReact;
    float32_t ReceiApp;
} accum_rst_energy_t;

typedef struct {
    float32_t voltage;
    float32_t current;
    float32_t phase;
    float32_t act;
    float32_t react;
    float32_t vol_thd;
} energy_t;

typedef struct
{
    energy_t r;
    energy_t s;
    energy_t t;

    float32_t freq;

    float32_t rs_phase;
    float32_t rt_phase;

    accum_rst_energy_t rst_accum;
    accum_energy_t r_accum;
    accum_energy_t s_accum;
    accum_energy_t t_accum;

    uint8_t sag_count;
    uint8_t swell_count;
    float32_t temp;
    uint8_t cal_disp_sts;
} adc_pushdata_t;

int adc_pushdata_process(uint8_t *data, size_t sz);
