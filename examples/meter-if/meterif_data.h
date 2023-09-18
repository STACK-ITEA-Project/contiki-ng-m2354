#pragma once
#include <stdint.h>

#define METERIF_SZ_DATABUF 256

typedef struct {
    uint8_t st;
    uint16_t len;
    uint8_t data[METERIF_SZ_DATABUF];
    uint8_t sp;
    void * state;
} meterif_data_context_t;

int meterif_data_beginning(uint8_t c);
int meterif_data_init(meterif_data_context_t *ctx);
int meterif_data_accumulate(meterif_data_context_t *ctx, uint8_t c);
int meterif_data_complete(meterif_data_context_t *ctx);
int meterif_data_process(meterif_data_context_t *ctx);
