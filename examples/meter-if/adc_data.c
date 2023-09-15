#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include "adc_data.h"

ssize_t adc_pushdata_read_uint8(uint8_t *pdata, uint8_t *bin, size_t sz)
{
    if (sz < sizeof(uint8_t)) {
        return -1;
    }
    *pdata = *bin;
    return sizeof(uint8_t);
}

#define sz_float32_t 4
ssize_t adc_pushdata_read_float(float32_t *pdata, uint8_t *bin, size_t sz)
{
    int i;
    if (sz < sz_float32_t) {
        return -1;
    }
    for (i=0; i < sz_float32_t; ++i) {
        pdata->c[i] = bin[sz_float32_t - 1 - i];
    }
    return sz_float32_t;
}
ssize_t adc_pushdata_read_energy_t(energy_t *pdata, uint8_t *bin, size_t sz)
{
    ssize_t r;
    size_t remaining = sz;
    uint8_t *ptr = bin;

    r = adc_pushdata_read_float(&pdata->voltage, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->current, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->phase, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->act, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->react, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->vol_thd, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    return (ssize_t)(ptr - bin);
}
ssize_t adc_pushdata_read_accum_rst_energy_t(accum_rst_energy_t *pdata, uint8_t *bin, size_t sz)
{
    ssize_t r;
    size_t remaining = sz;
    uint8_t *ptr = bin;

    r = adc_pushdata_read_float(&pdata->DeliAct, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->DLagReact, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->DLeadReact, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->DeliApp, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->ReceiAct, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->RLeadReact, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->RLagReact, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->ReceiApp, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    return (ssize_t)(ptr - bin);
}
ssize_t adc_pushdata_read_accum_energy_t(accum_energy_t *pdata, uint8_t *bin, size_t sz)
{
    ssize_t r;
    size_t remaining = sz;
    uint8_t *ptr = bin;

    r = adc_pushdata_read_float(&pdata->DeliAct, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->DLagReact, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->DLeadReact, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->ReceiAct, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->RLeadReact, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    r = adc_pushdata_read_float(&pdata->RLagReact, ptr, remaining);
    if (r < 0)
        return r;
    ptr += r; remaining -= r;

    return (ssize_t)(ptr - bin);
}

/**
  @return length of data read.
 */
int adc_pushdata_read(adc_pushdata_t *pdata, uint8_t *bin, size_t sz)
{
    uint8_t *ptr;
    ssize_t rsz = 0;
    size_t remaining;
    if (NULL == pdata) {
        return -1;
    }
    ptr = bin;
    remaining = sz;
    rsz = adc_pushdata_read_energy_t(&pdata->r, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;
    rsz = adc_pushdata_read_energy_t(&pdata->s, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;
    rsz = adc_pushdata_read_energy_t(&pdata->t, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;

    rsz = adc_pushdata_read_float(&pdata->freq, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;
    rsz = adc_pushdata_read_float(&pdata->rs_phase, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;
    rsz = adc_pushdata_read_float(&pdata->rt_phase, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;

    rsz = adc_pushdata_read_accum_rst_energy_t(&pdata->rst_accum, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;
    rsz = adc_pushdata_read_accum_energy_t(&pdata->r_accum, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;
    rsz = adc_pushdata_read_accum_energy_t(&pdata->s_accum, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;
    rsz = adc_pushdata_read_accum_energy_t(&pdata->t_accum, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;

    rsz = adc_pushdata_read_uint8(&pdata->sag_count, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;
    rsz = adc_pushdata_read_uint8(&pdata->swell_count, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;

    rsz = adc_pushdata_read_float(&pdata->temp, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz; remaining -= rsz;
    rsz = adc_pushdata_read_uint8(&pdata->cal_disp_sts, ptr, remaining);
    if (rsz < 0)
        return rsz;
    ptr += rsz;
    return (int)(ptr - bin);
}

int adc_pushdata_process(uint8_t *data, size_t sz)
{
    adc_pushdata_t pdata = {0,};
    adc_pushdata_read(&pdata, data, sz);

    printf("0x%"PRIx32" 0x%"PRIx32"\n", pdata.r.voltage.u32, pdata.r.vol_thd.u32);
    return 0;
}
