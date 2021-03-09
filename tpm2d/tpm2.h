#ifndef _TPM2_H
#define _TPM2_H

#include "../common/util.h"
#include "ibm-tss.h"

int tpm2_start (TSS_CONTEXT **tssc);
void tpm2_end (TSS_CONTEXT *tssc);
void tpm2_flush_handle (TSS_CONTEXT *tssc, TPM_HANDLE h);
int tpm2_load_key (TSS_CONTEXT *tssc, const unsigned char *shadow_info,
		   TPM_HANDLE *key, TPMI_ALG_PUBLIC *type);
int tpm2_sign (ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
	       gpg_error_t (*pin_cb)(ctrl_t ctrl, const char *info,
				     char **retstr),
	       TPMI_ALG_PUBLIC type,
	       const unsigned char *digest, size_t digestlen,
	       unsigned char **r_sig, size_t *r_siglen);
int tpm2_import_key (ctrl_t ctrl, TSS_CONTEXT *tssc,
		     gpg_error_t (*pin_cb)(ctrl_t ctrl, const char *info,
					   char **retstr),
		     unsigned char **shadow_info, size_t *shadow_len,
		     gcry_sexp_t s_skey, unsigned long parent);
int tpm2_rsa_decrypt (ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
		      gpg_error_t (*pin_cb)(ctrl_t ctrl, const char *info,
					    char **retstr),
		      const char *ciphertext, int ciphertext_len,
		      char **decrypt, size_t *decrypt_len);
int tpm2_ecc_decrypt (ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
		      gpg_error_t (*pin_cb)(ctrl_t ctrl, const char *info,
					    char **retstr),
		      const char *ciphertext, int ciphertext_len,
		      char **decrypt, size_t *decrypt_len);

#endif
