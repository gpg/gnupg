/* tpm2.h - Definitions for supporting TPM routines for the IBM TSS
 * Copyright (C) 2021 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _GNUPG_TPM2_H
#define _GNUPG_TPM2_H

#include "../common/util.h"
#ifdef HAVE_INTEL_TSS
#include "intel-tss.h"
#else
#include "ibm-tss.h"
#endif

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
