#pragma once
#include "axiocrypto.h"

int axiocrypto_handle_is_blank(ctx_handle_t handle);
const char * axiocrypto_strerror(CRYPTO_STATUS e) __attribute((weak));
const char * operation_mode_string(operation_mode_t opmode);
void axiocrypto_handle_init(ctx_handle_t handle, const uint8_t *buf);
uint16_t axiocrypto_crc(const uint8_t *p, const uint32_t len);
int axiocrypto_xor_entityid(uint8_t *a, uint8_t *entityid32B, uint32_t sz);
const char * algorithm_string(ALGORITHM algo);
const char * mode_string(SYM_MODE mode);
