#include "axiocrypto.h"
#include "axiocrypto_s.h"

CRYPTO_STATUS axiocrypto_init(uint8_t *password, uint32_t sz)
{
    uint32_t verbose=0;
    void *v[] = {(void *)verbose, (void *)password, (void *)sz};
    return nsc_axiocrypto_init(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_finish(void)
{
    return nsc_axiocrypto_finish();
}

CRYPTO_STATUS axiocrypto_allocate_slot(ctx_handle_t handle, ALGORITHM algo, ctx_attr_t attr)
{
    uint32_t p = attr;
    void *v[] = {(void *)handle, (void *)algo, (void *)p};
    return nsc_allocate_slot(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_free_slot(ctx_handle_t handle, ALGORITHM algo)
{
    void *v[] = {(void *)handle, (void *)algo};
    return nsc_free_slot(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_asym_genkey(const ctx_handle_t handle, const ALGORITHM algo, const ctx_attr_t attr)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)attr};

    if (algo == ASYM_ECDSA_P256) {
        return nsc_asym_genkey(AXIOCRYPTO_MAGIC, v);
    } else if (algo == ASYM_ECDH_P256) {
        return nsc_ecdh_genkey(AXIOCRYPTO_MAGIC, v);
    } else {
        return CRYPTO_ERR_NOT_SUPPORT_ALGORITHM;
    }
}

CRYPTO_STATUS axiocrypto_ecdsa_genkey(const ctx_handle_t handle, const ALGORITHM algo, const ctx_attr_t attr)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)attr};

    return nsc_asym_genkey(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_ecdh_genkey(const ctx_handle_t handle, const ALGORITHM algo, const ctx_attr_t attr)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)attr};

    return nsc_ecdh_genkey(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_asym_putkey(const ctx_handle_t handle, const ALGORITHM algo,
                    const uint8_t *d, const uint32_t dsz, uint16_t dcrc,
                    const uint8_t *Q, const uint32_t Qsz, uint16_t Qcrc, const ctx_attr_t attr)
{
    uint32_t _dcrc = dcrc;
    uint32_t _Qcrc = Qcrc;
    void * v[] = {(void *)handle, (void *)algo, (void *)d, (void *)dsz, (void *)_dcrc,
		  (void *)Q, (void *)Qsz, (void *)_Qcrc, (void *)attr};

    if (algo == ASYM_ECDSA_P256) {
        return nsc_asym_putkey(AXIOCRYPTO_MAGIC, v);
    } else if (algo == ASYM_ECDH_P256) {
        return nsc_ecdh_putkey(AXIOCRYPTO_MAGIC, v);
    } else {
        return CRYPTO_ERR_NOT_SUPPORT_ALGORITHM;
    }
}

CRYPTO_STATUS axiocrypto_ecdsa_putkey(const ctx_handle_t handle, const ALGORITHM algo,
                    const uint8_t *d, const uint32_t dsz, uint16_t dcrc,
                    const uint8_t *Q, const uint32_t Qsz, uint16_t Qcrc, const ctx_attr_t attr)
{
    uint32_t _dcrc = dcrc;
    uint32_t _Qcrc = Qcrc;
    void * v[] = {(void *)handle, (void *)algo, (void *)d, (void *)dsz, (void *)_dcrc,
		  (void *)Q, (void *)Qsz, (void *)_Qcrc, (void *)attr};

    return nsc_asym_putkey(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_ecdh_putkey(const ctx_handle_t handle, const ALGORITHM algo,
                    const uint8_t *d, const uint32_t dsz, uint16_t dcrc,
                    const uint8_t *Q, const uint32_t Qsz, uint16_t Qcrc, const ctx_attr_t attr)
{
    uint32_t _dcrc = dcrc;
    uint32_t _Qcrc = Qcrc;
    void * v[] = {(void *)handle, (void *)algo, (void *)d, (void *)dsz, (void *)_dcrc,
		  (void *)Q, (void *)Qsz, (void *)_Qcrc, (void *)attr};

    return nsc_ecdh_putkey(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_asym_sign(const ctx_handle_t handle,
                            const uint8_t* inMessage, const uint32_t inMsz, const uint32_t hashedinM,
			    uint8_t *sig, uint32_t *sigsz)
{
    void *v[] = {(void *)handle, (void *)inMessage, (void *)inMsz, (void *)hashedinM,
		 (void *)sig, (void *)sigsz};
    return nsc_asym_sign(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_asym_verify(
                const ctx_handle_t handle, const uint8_t* inMessage, const uint32_t inMsz,
                const uint32_t hashedinM, const uint8_t *sig, const uint32_t sigsz)
{
    void *v[] = {(void *)handle, (void *)inMessage, (void *)inMsz, (void *)hashedinM,
		(void *)sig, (void *)sigsz};
    return nsc_asym_verify(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_asym_getkey(const ctx_handle_t handle,  ALGORITHM algo, uint8_t *Q, const uint32_t Qsz)
{
    void *v[] = {(void *)handle, (void *)Q, (void *)Qsz};

    if (algo == ASYM_ECDSA_P256) {
        return nsc_asym_getkey(AXIOCRYPTO_MAGIC, v);
    } else if (algo == ASYM_ECDH_P256) {
        return nsc_ecdh_getkey(AXIOCRYPTO_MAGIC, v);
    } else {
        return CRYPTO_ERR_NOT_SUPPORT_ALGORITHM;
    }
}

CRYPTO_STATUS axiocrypto_ecdh_computekey(const ctx_handle_t handle, const uint8_t *KT, const uint32_t KTsz,
		  uint8_t *out, const uint32_t outsz)
{
    void *v[] = {(void *)handle, (void *)KT, (void *)KTsz, (void *)out, (void *)outsz};
    return nsc_ecdh_computekey(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_putkey(const ctx_handle_t handle, const uint8_t* key, const uint32_t keysz, const uint16_t crc, const ctx_attr_t attr)
{
    uint32_t _crc = crc;
    void *v[] = {(void *)handle, (void *)key, (void *)keysz, (void *)_crc, (void *)attr};
    return nsc_sym_putkey(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_enc_init(const ctx_handle_t handle, const ALGORITHM algo, const SYM_MODE mode,
                                 const uint8_t* iv, const uint32_t ivsz)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)mode,
                 (void *)iv, (void *)ivsz};
    return nsc_sym_enc_init(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_enc_update(const ctx_handle_t handle,
                                 const uint8_t*  pt, const uint32_t  ptsz,
                                 uint8_t* ct, uint32_t* ctsz)
{
    void *v[] = {(void *)handle, (void *)pt, (void *)ptsz, (void *)ct, (void *)ctsz};
    return nsc_sym_enc_update(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_enc_final(const ctx_handle_t handle,
                                 uint8_t* ct, uint32_t* ctsz)
{
    void *v[] = {(void *)handle, (void *)ct, (void *)ctsz};
    return nsc_sym_enc_final(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_dec_init(const ctx_handle_t handle, const ALGORITHM algo, const SYM_MODE mode,
                                 const uint8_t* iv, const uint32_t ivsz)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)mode,
                 (void *)iv, (void *)ivsz};
    return nsc_sym_dec_init(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_dec_update(const ctx_handle_t handle,
                                 const uint8_t*  ct, const uint32_t  ctsz,
                                 uint8_t* pt, uint32_t* ptsz)
{
    void *v[] = {(void *)handle, (void *)ct, (void *)ctsz, (void *)pt, (void *)ptsz};
    return nsc_sym_dec_update(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_dec_final(const ctx_handle_t handle,
                                 uint8_t*  pt, uint32_t *ptsz)
{
    void *v[] = {(void *)handle, (void *)pt, (void *)ptsz};
    return nsc_sym_dec_final(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_enc_ECB(ctx_handle_t handle, ALGORITHM algo,
		  uint8_t*  pt, uint32_t  ptsz, uint8_t* ct, uint32_t* ctsz)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)pt, (void *)ptsz, (void *)ct, (void *)ctsz};
    return nsc_sym_enc_ECB(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_dec_ECB(const ctx_handle_t handle, const ALGORITHM algo,
                                     const uint8_t*  ct, const uint32_t  ctsz,
                                     uint8_t* pt, uint32_t* ptsz)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)ct, (void *)ctsz, (void *)pt, (void *)ptsz};
    return nsc_sym_dec_ECB(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_enc_GCM(ctx_handle_t handle, ALGORITHM algo,
                                const uint8_t* pt,  const uint32_t  ptsz,
                                const uint8_t* aad, const uint32_t  aadsz,
                                      uint8_t* tag, const uint32_t  tagsz,
                                const uint8_t* iv,  const uint32_t  ivsz,
                                      uint8_t* ct,        uint32_t* ctsz)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)pt, (void *)ptsz,
                 (void *)aad, (void *)aadsz, (void *)tag, (void *)tagsz,
                 (void *)iv,  (void *)ivsz,
                 (void *)ct, (void *)ctsz};
    return nsc_sym_enc_GCM(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_sym_dec_GCM(const ctx_handle_t handle, const ALGORITHM algo,
                                     const uint8_t* ct,  const uint32_t  ctsz,
                                     const uint8_t* aad, const uint32_t  aadsz,
                                     const uint8_t* tag, const uint32_t  tagsz,
                                     const uint8_t* iv,  const uint32_t  ivsz,
                                           uint8_t* pt,        uint32_t* ptsz)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)ct, (void *)ctsz,
                 (void *)aad, (void *)aadsz, (void *)tag, (void *)tagsz,
                 (void *)iv,  (void *)ivsz,
                 (void *)pt, (void *)ptsz};
    return nsc_sym_dec_GCM(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_hash_init(ctx_handle_t handle, const ALGORITHM algo)
{
    void *v[] = {(void *)handle, (void *)algo};
    return nsc_hash_init(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_hash_update(const ctx_handle_t handle, const uint8_t *in, const uint32_t sz)
{
    void *v[] = {(void *)handle, (void *)in, (void *)sz};
    return nsc_hash_update(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_hash_final(const ctx_handle_t handle, uint8_t* out, const uint32_t sz)
{
    void *v[] = {(void *)handle, (void *)out, (void *)sz};
    return nsc_hash_final(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_hash(const ALGORITHM algo, const uint8_t *in, const uint32_t insz, uint8_t *out, const uint32_t outsz)
{
    void *v[] = {(void *)algo, (void *)in, (void *)insz, (void *)out, (void *)outsz};
    return nsc_hash(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_hmac_putkey(ctx_handle_t handle, const ALGORITHM algo, const uint8_t *key, const uint32_t keysz, uint16_t crc)
{
    uint32_t _crc = crc;
    void *v[] = {(void *)handle, (void *)algo, (void *)key, (void *)keysz, (void *)_crc};
    return nsc_hmac_putkey(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_hmac_init(const ctx_handle_t handle)
{
    void *v[] = {(void *)handle};
    return nsc_hmac_init(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_hmac_update(const ctx_handle_t handle, const uint8_t * in, const uint32_t  insz)
{
    void *v[] = {(void *)handle, (void *)in, (void *)insz};
    return nsc_hmac_update(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_hmac_final(const ctx_handle_t handle, uint8_t *out, const uint32_t outsz)
{
    void *v[] = {(void *)handle, (void *)out, (void *)outsz};
    return nsc_hmac_final(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_hmac(const ALGORITHM algo, const uint8_t *key, const uint32_t keysz,
     const uint8_t *in, const uint32_t insz, uint8_t *out, const uint32_t outsz)
{
    void *v[] = {(void *)algo, (void *)key, (void *)keysz, (void *)in, (void *)insz, (void *)out, (void *)outsz};
    return nsc_hmac(AXIOCRYPTO_MAGIC, v);
}


CRYPTO_STATUS axiocrypto_random(uint8_t *out,  const uint32_t outsz)
{
    void *v[] = {(void *)outsz, (void *)out};
    return nsc_random(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_info( char versionstr[32], uint32_t versionstrlen, operation_mode_t *opmode )
{
    void *v[] = {(void *)versionstr, (void *)versionstrlen, (void *)opmode};
    return nsc_info(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_set_mode(operation_mode_t opmode)
{
    uint32_t m = (uint32_t)opmode;
    void *v[] = {(void *)m};
    return nsc_set_mode(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_clear_all(void)
{
    return nsc_clear_all(AXIOCRYPTO_MAGIC);
}

CRYPTO_STATUS axiocrypto_set_entity_info(uint8_t *entityinfo)
{
    void *v[] =  {(void *)entityinfo};
    return nsc_set_entity_info(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_pbkdf(uint8_t *pw, uint32_t pwsz, uint8_t *salt, uint32_t saltsz, uint32_t iter, uint8_t *key, uint32_t keysz)
{
    void *v[] = {pw, (void *)pwsz, salt, (void *)saltsz, (void *)iter, key, (void *)keysz};
    return nsc_pbkdf(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_get_slotinfo(const ctx_handle_t handle, const ALGORITHM algo, uint16_t *info)
{
    void *v[] = {(void *)handle, (void *)algo, (void *)info};
    return nsc_get_slotinfo(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_get_version(char *verstr, uint32_t verstrlen)
{
    void *v[] = {(void *)verstr, (void *)verstrlen};
    return nsc_get_version(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_trng_random(unsigned char *output, uint32_t len, uint32_t *olen)
{
    void *v[] = {(void *)output, (void *)len, (void *)olen};
    return nsc_trng_random(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_self_test(void)
{
    return nsc_self_test(AXIOCRYPTO_MAGIC);
}

CRYPTO_STATUS axiocrypto_get_critical_error(void)
{
    return nsc_get_critical_error(AXIOCRYPTO_MAGIC);
}
#if defined(AXIOCRYPTO_FAULT_INDUCTION)
CRYPTO_STATUS axiocrypto_set_error(int e, int save)
{
    void *v[2] = {(void *)e, (void *)save};
    return nsc_set_error(AXIOCRYPTO_MAGIC, v);
}
CRYPTO_STATUS axiocrypto_show_keystorage(void)
{
    return nsc_show_keystorage(AXIOCRYPTO_MAGIC);
}
CRYPTO_STATUS axiocrypto_drbg(uint32_t reqsz, uint8_t* nonce, uint32_t noncesz, uint8_t* perStr, uint32_t perStrsz, uint8_t* eInput, uint32_t eInputsz, uint8_t* addReseed, uint32_t addReseedsz, uint8_t* eInputReseed, uint32_t eInputReseedsz,  uint8_t* addInput, uint32_t addInputsz, uint8_t* out, uint32_t outsz)
{
    void *v[15] = { (void *) reqsz,
                    nonce, (void *) noncesz,
                    perStr, (void *) perStrsz,
                    eInput, (void *) eInputsz,
                    addReseed, (void *) addReseedsz,
                    eInputReseed, (void *) eInputReseedsz,
                    addInput, (void *) addInputsz,
                    out, (void *) outsz};
    return nsc_drbg(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_drbg_set_context(ALGORITHM mode, uint32_t prMode, uint32_t updatePeriod[2])
{
    uint32_t v0 = (uint32_t)mode;
    void *v[3] = {(void *)v0, (void *)prMode, updatePeriod};
    return nsc_drbg_set_context(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_drbg_init(uint8_t* entropyInput, uint32_t entropyInputBitSize,
		  uint8_t* nonce, uint32_t nonceBitSize, uint8_t* str, uint32_t strBitSize)
{
    void *v[6] = {entropyInput, (void *)entropyInputBitSize,
		  nonce, (void *)nonceBitSize,
		  str, (void *)strBitSize};
    return nsc_drbg_init(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_drbg_update(uint8_t* entropyInput, uint32_t entropyInputBitSize,
		  uint8_t* addInput, uint32_t addInputBitSize)
{
    void *v[4] = {entropyInput, (void *)entropyInputBitSize,
		  addInput, (void *)addInputBitSize};
    return nsc_drbg_update(AXIOCRYPTO_MAGIC, v);
}

CRYPTO_STATUS axiocrypto_drbg_final(uint32_t reqBitSize,
                                    uint8_t* addReseed, uint32_t addReseedBitSize,
                                    uint8_t* eInputReseed, uint32_t eInputReseedBitSize,
                                    uint8_t* addInput, uint32_t addInputBitSize,
                                    uint8_t* out, uint32_t outBitSize)
{
    void *v[9] = {(void *)reqBitSize,
                  addReseed, (void *) addReseedBitSize,
                  eInputReseed, (void *) eInputReseedBitSize,
                  addInput, (void *) addInputBitSize,
                  out, (void *) outBitSize};
    return nsc_drbg_final(AXIOCRYPTO_MAGIC, v);
}
#else
CRYPTO_STATUS axiocrypto_set_error(int e, int save)
{
    (void)e;
    (void)save;
    printf("NOT implemented\n");
    return 0;
}
CRYPTO_STATUS axiocrypto_show_keystorage(void)
{
    printf("NOT implemented\n");
    return 0;
}
#endif
