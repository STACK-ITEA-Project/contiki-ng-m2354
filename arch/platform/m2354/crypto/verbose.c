#include "axiocrypto.h"
#include "axiocrypto_util.h"
const char * operation_mode_string(operation_mode_t opmode)
{
    switch(opmode) {
        case OP_MODE_APPROVED_FIPS1402:
            return "FIPS 140-2";
        case OP_MODE_APPROVED_KCMVP:
            return "KCMVP";
        case OP_MODE_NON_APPROVED:
        default:
            return "Non-Approved";
    }
}

const char * axiocrypto_strerror(CRYPTO_STATUS e)
{
    const char * s = "OK";
    if (e < 0) {
        s = "ERROR";
    }
    switch(e) {
        case CRYPTO_ERROR:                              s = "error"; break;
        case CRYPTO_ERR_NOT_INITIALIZED:
        case CRYPTO_ERR_HASH_CTX_NOT_INIT:
        case CRYPTO_ERR_HMAC_CTX_NOT_INIT:		s = "not initialized"; break;
        case CRYPTO_GCM_REJECT:
        case CRYPTO_SIG_REJECT:				s = "rejected"; break;
        case CRYPTO_ERR_INVALID_PARAM:			s = "invalid parameter"; break;
        case CRYPTO_ERR_BUFFER_NULL:
        case CRYPTO_ERR_KEY_EXCHANGE_BUFFER_NULL: 	s = "buffer null"; break;
        case CRYPTO_ERR_INVALID_LENGTH:                 s = "invalid length"; break;
        case CRYPTO_ERR_OPERATION_FAIL:			s = "operation failed"; break;
        case CRYPTO_ERR_ALREADY_INIT:			s = "already init"; break;
        case CRYPTO_ERR_SLOT_FULL:			s = "slot full"; break;
        case CRYPTO_ERR_KEY_RDONLY:			s = "key is read-only"; break;
        case CRYPTO_ERR_SYM_NOKEY:
        case CRYPTO_ERR_SIG_NOKEY:
        case CRYPTO_ERR_KEX_NOKEY:			s = "no key"; break;
        case CRYPTO_ERR_SAVE_KEY:			s = "Key save failure"; break;
        case CRYPTO_ERR_NOT_ALLOWED_IN_APPROVED_MODE:   s = "op. not allowd in approved mode"; break;
        case CRYPTO_ERR_KEY_STORAGE_ALGORITHM_NO_SUPPORT: s = "KEY_STORAGE_ALGORITHM_NO_SUPPORT"; break;
        case CRYPTO_ERR_NOT_SUPPORT_ALGORITHM           : s = "NOT_SUPPORT_ALGORITHM"; break;
        case CRYPTO_ERR_SIGNATURE_INVALID:		s = "Signature Sturct Invalid"; break;
        case CRYPTO_ERR_SIG_KEY_EMPTY:			s = "Private or Public Key not set"; break;
        case CRYPTO_ERR_SIG_MESSAGE_INVALID:		s = "message invalid"; break;
        case CRYPTO_ERR_ECC_PUBLICKEY_VALIDATION_PKEY_IS_NOT_VALID:s = "ECC public key validation failed"; break;
        case CRYPTO_ERR_KEY_EXCHANGE_NOT_SUPPORT_ALGORITHM:s = "Not supported DH algorithm"; break;
        case CRYPTO_ERR_KEY_EXCHANGE_BUFFER_SIZE_INVALID:s = "buffer size invalid"; break;
        case CRYPTO_ERR_SYM_NOT_SUPPORT_MODE:		s = "not supported operation mode"; break;
        case CRYPTO_ERR_SIG_NOT_SUPPORT_ALGORITHM:
        case CRYPTO_ERR_SYM_NOT_SUPPORT_ALGORITHM:
        case CRYPTO_ERR_HASH_NOT_SUPPORT_ALGORITHM:     s = "not supported algorithm"; break;
        case CRYPTO_ERR_SIG_PUBLICKEY_INVALID:
        case CRYPTO_ERR_SIG_PRIVATEKEY_INVALID:
        case CRYPTO_ERR_KEY_EXCHANGE_PRIVATEKEY_INVALID:
        case CRYPTO_ERR_KEY_EXCHANGE_PUBLICKEY_INVALID:
        case CRYPTO_ERR_SYM_KEY_INVALID:		s = "invalid key"; break;
        case CRYPTO_ERR_SYM_NOT_SUPPORT_SECURITY_LEVEL:	s = "invalid security level"; break;
        case CRYPTO_ERR_SYM_KEYGEN:			s = "key generation failed"; break;
        case CRYPTO_ERR_SYM_IV_INVALID:			s = "invalid iv"; break;
        case CRYPTO_ERR_SYM_IV_SIZE_INVALID:		s = "iv size invalid"; break;
        case CRYPTO_ERR_SYM_PT_SIZE_INVALID:		s = "plaintext size invalid"; break;
        case CRYPTO_ERR_SYM_CT_SIZE_INVALID:		s = "ciphertext size invalid"; break;
        case CRYPTO_ERR_SYM_TAG_SIZE_INVALID:		s = "invalid tag size"; break;
        case CRYPTO_ERR_SYM_PT_NULL:		        s = "plaintext buffer null"; break;
        case CRYPTO_ERR_SYM_CT_NULL:		        s = "ciphertext buffer null"; break;
        case CRYPTO_ERR_SYM_AAD_INVALID:                s = "invalid aad"; break;
        case CRYPTO_ERR_SYM_TAG_INVALID:                s = "invalid tag"; break;
        case CRYPTO_ERR_HASH_IN_PARAMETER_INVALID:	s = "input parameter invalid"; break;
        case CRYPTO_ERR_HASH_OUT_PARAMETER_INVALID:	s = "output parameter invalid"; break;
        case CRYPTO_ERR_SIG_CTX_HANDLE_INVALID:
        case CRYPTO_ERR_KEY_EXCHANGE_CTX_HANDLE_INVALID:
        case CRYPTO_ERR_SYM_CTX_HANDLE_INVALID:
        case CRYPTO_ERR_HMAC_CTX_HANDLE_INVALID:
        case CRYPTO_ERR_HASH_CTX_HANDLE_INVALID:
        case CRYPTO_ERR_HANDLE_INVALID_VALUE:		s = "invalid handle"; break;
        default:
                                                        break;
    }
    return s;
}

const char * algorithm_string(ALGORITHM algo)
{
	switch (algo) {
		case ASYM_ECDSA_P256:
			return "ECDSA-P256";
		case ASYM_ECDSA_SM2:
			return "ECDSA-SM2-P256";
		case HASH_SHA_256:
			return "SHA-256";
		case DRBG_HASH_SHA256:
			return "DRBG-SHA256";
		case ASYM_ECDH_P256:
			return "ECDH-P256";
		case HMAC_SHA_256:
			return "HMAC-SHA256";
		case HASH_SM3:
			return "SM3-256";
		case SYM_ARIA:
			return "ARIA";
		case SYM_LEA:
			return "LEA";
		case SYM_AES:
			return "AES";
		case SYM_SM4:
			return "SM4";
		default:
			return "Unknown Algorithm";
	}
}

const char * mode_string(SYM_MODE mode)
{
	switch (mode) {
		case SYM_MODE_CBC:
			return "CBC";
		case SYM_MODE_CTR:
			return "CTR";
		case SYM_MODE_GCM:
			return "GCM";
		case SYM_MODE_ECB:
			return "ECB";
		default:
			return "Unknown Mode";
	}
}
