#include <string.h>
#include "axiocrypto.h"

int axiocrypto_handle_is_blank(ctx_handle_t handle)
{
    ctx_handle_t blank_handle = {0,};
    if (0 == memcmp(handle, blank_handle, sizeof(blank_handle))) {
        return 1;
    }
    return 0;
}

void axiocrypto_handle_init(ctx_handle_t handle, const uint8_t *buf)
{
    if (NULL == handle)
        return;
    if (NULL == buf) {
        memset(handle, 0, sizeof(ctx_handle_t));
    } else {
        memcpy(handle, buf, sizeof(ctx_handle_t));
    }
}

static uint16_t CRC_IMPL(uint16_t sum, const uint8_t *p, const uint32_t len)
{
    uint32_t l = len;
    while (l--) {
        uint8_t byte = *p++;

        for (int i = 0; i < 8; i++) {
            uint16_t osum = sum;

            sum <<= 1;

            if (byte & 0x80)
                sum |= 1;

            if (osum & 0x8000)
                sum ^= 0x1021;  // the polynomial

            byte <<= 1;
        }
    }
    return sum;
}

uint16_t axiocrypto_crc(const uint8_t *p, const uint32_t len)
{
    uint8_t zeroes[] = {0, 0};
    if (NULL == p || 0 == len) {
        return 0;
    }

    return CRC_IMPL(CRC_IMPL(0, p, len), zeroes, 2);
}

static void _xor_32B(uint8_t *a, uint8_t *b, uint32_t l)
{
    uint32_t i;
    if (l > 32) {
        l = 32;
    }
    for (i=0; i<l; ++i) {
        a[i] = a[i] ^ b[i];
    }
}

int axiocrypto_xor_entityid(uint8_t *a, uint8_t *entityid32B, uint32_t sz)
{
    uint32_t l;
    if (NULL == a || NULL == entityid32B) {
        return CRYPTO_ERR_BUFFER_NULL;
    }
    for (l = 0; l<sz; l+=32) {
        _xor_32B(&a[l], entityid32B, sz-l);
    }
    return 0;
}
