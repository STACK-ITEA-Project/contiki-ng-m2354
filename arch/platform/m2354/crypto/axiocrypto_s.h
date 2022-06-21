/**
 * @file axiocrypto_s.h
 * @addtogroup  MA_1HWENGINE
 */
#include "cpu.h"

#define CRYPTO_ERR_LOCKED               -15
#define CRYPTO_ERR_INVALID_VERSION      -26

/**
 * @brief NSC 버전 확인용 패턴. 2020.02.26, API 형상이 변경되면 패턴을 새로 만들어서 등록함으로써 구분
 */
#define AXIOCRYPTO_MAGIC 0xdcd7504d

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_allocate_slot(uint32_t magic, void *v[3]);
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_free_slot(uint32_t magic, void *v[2]);

/**
 * @brief Signature_Gen_Key ()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Signature_Gen_Key ()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_asym_genkey(uint32_t magic, void *v[3]);

/**
 * @brief Signature_Put_Key()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Signature_Put_Key()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_asym_putkey(uint32_t magic, void *v[9]);

/**
 * @brief Signature_Sign()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Signature_Sign()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_asym_sign(uint32_t magic, void *v[6]);

/**
 * @brief Signature_Verify()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Signature_Verify()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_asym_verify(uint32_t magic, void *v[6]);

/**
 * @brief Signature_Get_Key()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Signature_Get_Key()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_asym_getkey(uint32_t magic, void *v[3]);

/**
 * @brief Key_Exchange_Gen_Key()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Key_Exchange_Gen_Key()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_ecdh_genkey(uint32_t magic, void *v[3]);

/**
 * @brief Key_Exchange_Get_Key()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Key_Exchange_Gen_Key()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
CRYPTO_STATUS nsc_ecdh_getkey(uint32_t magic, void *v[3]);

/**
 * @brief Key_Exchange_Put_Key()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Key_Exchange_Put_Key()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_ecdh_putkey(uint32_t magic, void *v[9]);

/**
 * @brief Key_Exchange_Compute_Key()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Key_Exchange_Compute_Key()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_ecdh_computekey(uint32_t magic, void *v[5]);

/**
 * @brief Symmetric_Put_Key()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Put_Key()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_putkey(uint32_t magic, void *v[5]);

/**
 * @brief Symmetric_Enc_Init()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Enc_Init()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_enc_init(uint32_t magic, void *v[5]);

/**
 * @brief Symmetric_Enc_Update()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Enc_Update()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_enc_update(uint32_t magic, void *v[5]);

/**
 * @brief Symmetric_Enc_Final()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Enc_Final()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_enc_final(uint32_t magic, void *v[3]);

/**
 * @brief Symmetric_Dec_Init()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Dec_Init()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_dec_init(uint32_t magic, void *v[5]);

/**
 * @brief Symmetric_Dec_Update()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Dec_Update()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_dec_update(uint32_t magic, void *v[5]);

/**
 * @brief Symmetric_Dec_Final()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Dec_Final()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_dec_final(uint32_t magic, void *v[3]);

/**
 * @brief Symmetric_Enc_ECB()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Enc_ECB()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_enc_ECB(uint32_t magic, void *v[6]);

/**
 * @brief Symmetric_Dec_ECB()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Dec_ECB()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_dec_ECB(uint32_t magic, void *v[6]);

/**
 * @brief Symmetric_Enc_GCM()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Enc_GCM()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_enc_GCM(uint32_t magic, void *v[12]);

/**
 * @brief Symmetric_Dec_GCM()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Symmetric_Dec_GCM()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_sym_dec_GCM(uint32_t magic, void *v[12]);

/**
 * @brief SHA_Init()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v SHA_Init()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_hash_init(uint32_t magic, void *v[2]);

/**
 * @brief SHA_Update()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v SHA_Update()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_hash_update(uint32_t magic, void *v[3]);

/**
 * @brief SHA_Final()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v SHA_Final()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_hash_final(uint32_t magic, void *v[3]);

/**
 * @brief SHA()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v SHA()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_hash(uint32_t magic, void *v[5]);

/**
 * @brief HMAC_Put_Key()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v HMAC_Put_Key()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_hmac_putkey(uint32_t magic, void *v[5]);

/**
 * @brief HMAC_Init()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v HMAC_Init()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_hmac_init(uint32_t magic, void *v[1]);

/**
 * @brief HMAC_Update()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v HMAC_Update()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_hmac_update(uint32_t magic, void *v[3]);

/**
 * @brief HMAC_Final()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v HMAC_Final()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_hmac_final(uint32_t magic, void *v[3]);

/**
 * @brief HMAC()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v HMAC()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_hmac(uint32_t magic, void *v[7]);

/**
 * @brief Random()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Random()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_random(uint32_t magic, void *v[2]);

/**
 * @brief Info ()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param v Info ()에서 사용할 파라미터들을 일괄적으로 변형하여 배열의 형태로 전달함.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_info(uint32_t magic, void *v[3]);

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_set_mode(uint32_t magic, void *v[1]);

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_clear_all(uint32_t magic);

/**
 * @brief axiocrypto_init()를 NSC에 등록하기 위한 함수.
 * @param magic AXIOCRYPTO_MAGIC을 전달함. 버전 구분용.
 * @param verbose 진행상황 표시 여부
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_axiocrypto_init(uint32_t magic, void *v[3]);

/**
 * @brief axiocrypto_finish ()를 NSC에 등록하기 위한 함수.
 */
__NONSECURE_ENTRY
CRYPTO_STATUS nsc_axiocrypto_finish(void);

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_set_entity_info(uint32_t magic, void *v[1]);

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_pbkdf(uint32_t magic, void *v[7]);

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_get_slotinfo(uint32_t magic, void *v[3]);

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_get_version(uint32_t magic, void *v[2]);

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_trng_random(uint32_t magic, void *v[3]);

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_self_test(uint32_t magic);

__NONSECURE_ENTRY
CRYPTO_STATUS nsc_get_critical_error(uint32_t magic);
#if defined(AXIOCRYPTO_FAULT_INDUCTION)
__NONSECURE_ENTRY CRYPTO_STATUS nsc_set_error(uint32_t magic, void *v[2]);
__NONSECURE_ENTRY CRYPTO_STATUS nsc_show_keystorage(uint32_t magic);
__NONSECURE_ENTRY CRYPTO_STATUS nsc_drbg_set_context(uint32_t magic, void *v[3]);
__NONSECURE_ENTRY CRYPTO_STATUS nsc_drbg_init(uint32_t magic, void *v[6]);
__NONSECURE_ENTRY CRYPTO_STATUS nsc_drbg_update(uint32_t magic, void *v[4]);
__NONSECURE_ENTRY CRYPTO_STATUS nsc_drbg_final(uint32_t magic, void *v[9]);
__NONSECURE_ENTRY CRYPTO_STATUS nsc_drbg(uint32_t magic, void *v[15]);
#endif
