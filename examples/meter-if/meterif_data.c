#include <string.h>
#include <stdlib.h>
#include "meterif_data.h"
#include "adc_data.h"

#define METERIF_BEGINNING 0xF7
#define METERIF_END 0xFE

enum {
    FSM_INIT,
    FSM_LEN1,
    FSM_LEN2,
    FSM_DATA,
    FSM_COMPLETE,
    FSM_MAX
};

typedef struct {
    uint8_t fsm;
    uint16_t count;
} meterif_data_state_t;

int meterif_data_finish(meterif_data_context_t *ctx)
{
    if (ctx && ctx->state) {
        free(ctx->state);
        ctx->state = NULL;
    }
    return 0;
}

int meterif_data_init(meterif_data_context_t *ctx)
{
    if (ctx) {
        meterif_data_finish(ctx);
        memset(ctx, 0, sizeof(meterif_data_context_t));
        ctx->state = calloc(1, sizeof(meterif_data_state_t));
    }
    return 0;
}

int meterif_data_beginning(uint8_t c)
{
    return c == METERIF_BEGINNING;
}

int meterif_data_state_init_input(meterif_data_context_t *ctx, uint8_t c)
{
    meterif_data_state_t *pstate = ctx->state;
    if (c == METERIF_BEGINNING) {
        pstate->fsm = FSM_LEN1;
    }
    return 0;
}

int meterif_data_state_len1_input(meterif_data_context_t *ctx, uint8_t c)
{
    meterif_data_state_t *pstate = ctx->state;
    uint16_t len = c;
    ctx->len = (len << 8);
    pstate->fsm = FSM_LEN2;
    return 0;
}

int meterif_data_state_len2_input(meterif_data_context_t *ctx, uint8_t c)
{
    meterif_data_state_t *pstate = ctx->state;
    uint16_t len = c;
    ctx->len += len;
    pstate->fsm = FSM_DATA;
    return 0;
}

int meterif_data_state_data_input(meterif_data_context_t *ctx, uint8_t c)
{
    int r = 0;
    meterif_data_state_t *pstate = ctx->state;
    ctx->data[pstate->count] = c;
    pstate->count++;
    if (pstate->count == ctx->len) {
        if (c == METERIF_END) {
            pstate->fsm = FSM_COMPLETE;
            ctx->sp = c;
        } else {
            pstate->fsm = FSM_MAX;
            r = -1;
        }
    }
    return r;
}

int meterif_data_accumulate(meterif_data_context_t *ctx, uint8_t c)
{
    int r = 0;
    meterif_data_state_t *pstate;
    if (NULL == ctx) {
        return -1;
    }

    pstate = ctx->state;
    if (pstate->fsm == FSM_INIT) {
        r = meterif_data_state_init_input(ctx, c);
    } else if (pstate->fsm == FSM_LEN1) {
        r = meterif_data_state_len1_input(ctx, c);
    } else if (pstate->fsm == FSM_LEN2) {
        r = meterif_data_state_len2_input(ctx, c);
    } else if (pstate->fsm == FSM_DATA) {
        r = meterif_data_state_data_input(ctx, c);
    }
    return r;
}

int meterif_data_complete(meterif_data_context_t *ctx)
{
    return (ctx && ctx->sp == METERIF_END);
}

int meterif_data_process(meterif_data_context_t *ctx)
{
    int r = 0;
    if (NULL == ctx || !meterif_data_complete(ctx)) {
        r = -1;
        return r;
    }
    if (ctx->data[0] == 0xb3) {
        r = adc_pushdata_process(ctx->data+1, ctx->len-4);  // 4 = type + crc + END
    }
    return r;
}

