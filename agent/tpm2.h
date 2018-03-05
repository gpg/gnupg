#ifndef _TPM2_H
#define _TPM2_H

#include <tss2/tss.h>

#define TSS2_LIB "libtss.so.0"
#define TPM2_PARENT 0x81000001

int tpm2_start(TSS_CONTEXT **tssc);
void tpm2_end(TSS_CONTEXT *tssc);
void tpm2_flush_handle(TSS_CONTEXT *tssc, TPM_HANDLE h);
int tpm2_load_key(TSS_CONTEXT *tssc, const unsigned char *shadow_info,
                  TPM_HANDLE *key, TPMI_ALG_PUBLIC *type);
int tpm2_sign(ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
	      TPMI_ALG_PUBLIC type,
              const unsigned char *digest, size_t digestlen,
              unsigned char **r_sig, size_t *r_siglen);
int tpm2_import_key(ctrl_t ctrl, TSS_CONTEXT *tssc, char *pub, int *pub_len,
                    char *priv, int *priv_len, gcry_sexp_t s_skey);
int tpm2_rsa_decrypt(ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
		     const char *ciphertext, int ciphertext_len,
		     char **decrypt, size_t *decrypt_len);
int tpm2_ecc_decrypt(ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
		     const char *ciphertext, int ciphertext_len,
		     char **decrypt, size_t *decrypt_len);

#endif
