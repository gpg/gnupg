/* ibm-tss.h -  Supporting TPM routines for the IBM TSS
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

#ifndef _TPM2_IBM_TSS_H
#define _TPM2_IBM_TSS_H

#define TSSINCLUDE(x) < TSS_INCLUDE/x >
#include TSSINCLUDE(tss.h)
#include TSSINCLUDE(tssutils.h)
#include TSSINCLUDE(tssresponsecode.h)
#include TSSINCLUDE(tssmarshal.h)
#include TSSINCLUDE(Unmarshal_fp.h)
#include TSSINCLUDE(tsscryptoh.h)

#define EXT_TPM_RH_OWNER	TPM_RH_OWNER

#define VAL(X)			X.val
#define VAL_2B(X, MEMBER)	X.t.MEMBER

static const char *tpm2_dir;

/* The TPM builds a small database of active files representing key
 * parameters used for authentication and session encryption.  Make sure
 * they're contained in a separate directory to avoid stepping on any
 * other application uses of the TPM */
static inline const char *
tpm2_set_unique_tssdir (void)
{
  char *prefix = getenv ("XDG_RUNTIME_DIR"), *template,
    *dir;
  int len = 0;

  if (!prefix)
    prefix = "/tmp";

  len = snprintf (NULL, 0, "%s/tss2.XXXXXX", prefix);
  if (len <= 0)
    return NULL;
  template = xtrymalloc (len + 1);
  if (!template)
    return NULL;

  len++;
  len = snprintf (template, len, "%s/tss2.XXXXXX", prefix);

  dir = mkdtemp (template);

  return dir;
}

static inline void
tpm2_error (TPM_RC rc, const char *prefix)
{
  const char *msg, *submsg, *num;

  TSS_ResponseCode_toString (&msg, &submsg, &num, rc);
  log_error ("%s gave TPM2 Error: %s%s%s", prefix, msg, submsg, num);
}

static inline int
TSS_start (TSS_CONTEXT **tssc)
{
  TPM_RC rc;

  tpm2_dir = tpm2_set_unique_tssdir ();
  if (!tpm2_dir)
    /* make this non fatal */
    log_error ("Failed to set unique TPM directory\n");

  rc = TSS_Create (tssc);
  if (rc)
    {
      tpm2_error (rc, "TSS_Create");
      return GPG_ERR_CARD;
    }
  rc = TSS_SetProperty (*tssc, TPM_DATA_DIR, tpm2_dir);
  if (rc)
    /* make this non fatal */
    tpm2_error (rc, "TSS_SetProperty");

  return 0;
}

static inline TPM_RC
tpm2_CreatePrimary (TSS_CONTEXT *tssContext, TPM_HANDLE primaryHandle,
		    TPM2B_SENSITIVE_CREATE *inSensitive,
		    TPM2B_PUBLIC *inPublic, TPM_HANDLE *objectHandle)
{
  CreatePrimary_In in;
  CreatePrimary_Out out;
  TPM_RC rc;

  in.primaryHandle = primaryHandle;
  in.inSensitive = *inSensitive;
  in.inPublic = *inPublic;
  /* no outside info */
  in.outsideInfo.t.size = 0;
  /* no PCR state */
  in.creationPCR.count = 0;

  rc = TSS_Execute (tssContext,
		    (RESPONSE_PARAMETERS *)&out,
		    (COMMAND_PARAMETERS *)&in,
		    NULL,
		    TPM_CC_CreatePrimary,
		    TPM_RS_PW, NULL, 0,
		    TPM_RH_NULL, NULL, 0);

  *objectHandle = out.objectHandle;

  return rc;
}

static inline TPM_RC
tpm2_FlushContext (TSS_CONTEXT *tssContext, TPM_HANDLE flushHandle)
{
  FlushContext_In in;
  TPM_RC rc;

  in.flushHandle = flushHandle;

  rc = TSS_Execute (tssContext,
		    NULL,
		    (COMMAND_PARAMETERS *)&in,
		    NULL,
		    TPM_CC_FlushContext,
		    TPM_RH_NULL, NULL, 0);

  return rc;
}

static inline TPM_RC
tpm2_ReadPublic (TSS_CONTEXT *tssContext, TPM_HANDLE objectHandle,
		 TPMT_PUBLIC *pub, TPM_HANDLE auth)
{
  ReadPublic_In rin;
  ReadPublic_Out rout;
  TPM_RC rc;
  UINT32 flags = 0;

  if (auth != TPM_RH_NULL)
    flags = TPMA_SESSION_ENCRYPT;

  rin.objectHandle = objectHandle;

  rc = TSS_Execute (tssContext,
		    (RESPONSE_PARAMETERS *)&rout,
		    (COMMAND_PARAMETERS *)&rin,
		    NULL,
		    TPM_CC_ReadPublic,
		    auth, NULL, flags,
		    TPM_RH_NULL, NULL, 0);

  if (rc)
    {
      tpm2_error (rc, "TPM2_ReadPublic");
      return rc;
    }

  if (pub)
    *pub = rout.outPublic.publicArea;

  return rc;
}

static inline TPM_RC
tpm2_StartAuthSession (TSS_CONTEXT *tssContext, TPM_HANDLE tpmKey,
		       TPM_HANDLE bind, TPM_SE sessionType,
		       TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash,
		       TPM_HANDLE *sessionHandle,
		       const char *bindPassword)
{
  StartAuthSession_In in;
  StartAuthSession_Out out;
  StartAuthSession_Extra extra;
  TPM_RC rc;

  memset (&in, 0, sizeof(in));
  memset (&extra, 0 , sizeof(extra));

  extra.bindPassword = bindPassword;

  in.tpmKey = tpmKey;
  in.bind = bind;
  in.sessionType = sessionType;
  in.symmetric = *symmetric;
  in.authHash = authHash;

  if (tpmKey != TPM_RH_NULL)
    {
      /*
       * For the TSS to use a key as salt, it must have
       * access to the public part.  It does this by keeping
       * key files, but request the public part just to make
       * sure
       */
      tpm2_ReadPublic (tssContext, tpmKey,  NULL, TPM_RH_NULL);
      /*
       * don't care what rout returns, the purpose of the
       * operation was to get the public key parameters into
       * the tss so it can construct the salt
       */
    }

  rc = TSS_Execute (tssContext,
		    (RESPONSE_PARAMETERS *)&out,
		    (COMMAND_PARAMETERS *)&in,
		    (EXTRA_PARAMETERS *)&extra,
		    TPM_CC_StartAuthSession,
		    TPM_RH_NULL, NULL, 0);

  *sessionHandle = out.sessionHandle;

  return rc;
}

static inline TPM_RC
tpm2_Sign (TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle, DIGEST_2B *digest,
	   TPMT_SIG_SCHEME *inScheme, TPMT_SIGNATURE *signature,
	   TPM_HANDLE auth, const char *authVal)
{
  Sign_In in;
  Sign_Out out;
  TPM_RC rc;

  in.keyHandle = keyHandle;
  in.digest.t = *digest;
  in.inScheme = *inScheme;
  in.validation.tag = TPM_ST_HASHCHECK;
  in.validation.hierarchy = TPM_RH_NULL;
  in.validation.digest.t.size = 0;

  rc = TSS_Execute (tssContext,
		    (RESPONSE_PARAMETERS *)&out,
		    (COMMAND_PARAMETERS *)&in,
		    NULL,
		    TPM_CC_Sign,
		    auth, authVal, 0,
		    TPM_RH_NULL, NULL, 0);

  *signature = out.signature;

  return rc;
}

static inline TPM_RC
tpm2_ECDH_ZGen (TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle,
		TPM2B_ECC_POINT *inPoint, TPM2B_ECC_POINT *outPoint,
		TPM_HANDLE auth, const char *authVal)
{
  ECDH_ZGen_In in;
  ECDH_ZGen_Out out;
  TPM_RC rc;

  in.keyHandle = keyHandle;
  in.inPoint = *inPoint;

  rc = TSS_Execute (tssContext,
		    (RESPONSE_PARAMETERS *)&out,
		    (COMMAND_PARAMETERS *)&in,
		    NULL,
		    TPM_CC_ECDH_ZGen,
		    auth, authVal, TPMA_SESSION_ENCRYPT,
		    TPM_RH_NULL, NULL, 0);

  *outPoint = out.outPoint;

  return rc;
}

static inline TPM_RC
tpm2_RSA_Decrypt (TSS_CONTEXT *tssContext, TPM_HANDLE keyHandle,
		  PUBLIC_KEY_RSA_2B *cipherText, TPMT_RSA_DECRYPT *inScheme,
		  PUBLIC_KEY_RSA_2B *message,
		  TPM_HANDLE auth, const char *authVal, int flags)
{
  RSA_Decrypt_In in;
  RSA_Decrypt_Out out;
  TPM_RC rc;

  in.keyHandle = keyHandle;
  in.inScheme = *inScheme;
  in.cipherText.t = *cipherText;
  in.label.t.size = 0;

  rc = TSS_Execute (tssContext,
		    (RESPONSE_PARAMETERS *)&out,
		    (COMMAND_PARAMETERS *)&in,
		    NULL,
		    TPM_CC_RSA_Decrypt,
		    auth, authVal, flags,
		    TPM_RH_NULL, NULL, 0);

  *message = out.message.t;

  return rc;
}

static inline TPM_RC
tpm2_Load (TSS_CONTEXT *tssContext, TPM_HANDLE parentHandle,
	   PRIVATE_2B *inPrivate, TPM2B_PUBLIC *inPublic,
	   TPM_HANDLE *objectHandle,
	   TPM_HANDLE auth, const char *authVal)
{
  Load_In in;
  Load_Out out;
  TPM_RC rc;

  in.parentHandle = parentHandle;
  in.inPrivate.t = *inPrivate;
  in.inPublic = *inPublic;

  rc = TSS_Execute (tssContext,
		    (RESPONSE_PARAMETERS *)&out,
		    (COMMAND_PARAMETERS *)&in,
		    NULL,
		    TPM_CC_Load,
		    auth, authVal, 0,
		    TPM_RH_NULL, NULL, 0);

  if (rc == TPM_RC_SUCCESS)
    *objectHandle = out.objectHandle;

  return rc;
}

static inline TPM_RC
tpm2_Import (TSS_CONTEXT *tssContext, TPM_HANDLE parentHandle,
	     DATA_2B *encryptionKey, TPM2B_PUBLIC *objectPublic,
	     PRIVATE_2B *duplicate, ENCRYPTED_SECRET_2B *inSymSeed,
	     TPMT_SYM_DEF_OBJECT *symmetricAlg, PRIVATE_2B *outPrivate,
	     TPM_HANDLE auth, const char *authVal)
{
  Import_In iin;
  Import_Out iout;
  TPM_RC rc;

  iin.parentHandle = parentHandle;
  iin.encryptionKey.t = *encryptionKey;
  iin.objectPublic = *objectPublic;
  iin.duplicate.t = *duplicate;
  iin.inSymSeed.t = *inSymSeed;
  iin.symmetricAlg = *symmetricAlg;

  rc = TSS_Execute (tssContext,
		    (RESPONSE_PARAMETERS *)&iout,
		    (COMMAND_PARAMETERS *)&iin,
		    NULL,
		    TPM_CC_Import,
		    auth, authVal, TPMA_SESSION_DECRYPT,
		    TPM_RH_NULL, NULL, 0);

  *outPrivate = iout.outPrivate.t;

  return rc;
}

static inline TPM_HANDLE
tpm2_handle_int (TSS_CONTEXT *tssContext, TPM_HANDLE h)
{
  (void)tssContext;
  return h;
}

static inline TPM_HANDLE
tpm2_handle_ext (TSS_CONTEXT *tssContext, TPM_HANDLE h)
{
  (void)tssContext;
  return h;
}

static inline int
tpm2_handle_mso (TSS_CONTEXT *tssContext, TPM_HANDLE h, UINT32 mso)
{
  (void)tssContext;
  return (h >> 24) == mso;
}

#endif
