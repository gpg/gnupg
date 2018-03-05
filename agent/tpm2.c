#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <agent.h>
#include <tpm2.h>

#include "../common/i18n.h"
#include "../common/sexp-parse.h"

#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/tsscryptoh.h>

/* List of tss2 functions we use.  This is macro jiggery-pokery:
 * the F argument gives us the ability to run an arbitrary macro over
 * the function list as for each function do macro F */
#define _TSS2_LIST(F)                   \
  F(TSS_Create);                        \
  F(TSS_SetProperty);                   \
  F(TSS_Execute);                       \
  F(TSS_ResponseCode_toString);         \
  F(TPM2B_PUBLIC_Unmarshal);            \
  F(TPM2B_PRIVATE_Unmarshal);           \
  F(TSS_TPM2B_PUBLIC_Marshal);          \
  F(TSS_TPMT_PUBLIC_Marshal);           \
  F(TSS_TPM2B_PRIVATE_Marshal);         \
  F(TSS_UINT16_Marshal);                \
  F(TSS_TPMT_SENSITIVE_Marshal);        \
  F(TSS_SetProperty);                   \
  F(TSS_GetDigestSize);                 \
  F(TSS_Hash_Generate);                 \
  F(TSS_Delete);

/* create static declarations for the function pointers */
#define _DL_DECLARE(func) \
  static typeof(func) *p##func
_TSS2_LIST(_DL_DECLARE);

static const char *tpm2_dir;

/* The TPM builds a small database of active files representing key
 * parameters used for authentication and session encryption.  Make sure
 * they're contained in a separate directory to avoid stepping on any
 * other application uses of the TPM */
static const char *
tpm2_set_unique_tssdir(void)
{
  char *prefix = getenv("XDG_RUNTIME_DIR"), *template,
    *dir;
  int len = 0;

  if (!prefix)
    prefix = "/tmp";

  len = snprintf(NULL, 0, "%s/tss2.XXXXXX", prefix);
  if (len <= 0)
    return NULL;
  template = xtrymalloc(len + 1);
  if (!template)
    return NULL;

  len++;
  len = snprintf(template, len, "%s/tss2.XXXXXX", prefix);

  dir = mkdtemp(template);

  return dir;
}

/* now dynamically load the tss library (if it exists) and resolve the
 * above symbols.  This allows us simply to return 0 for tpm2_init on
 * systems where there is no TPM library */
static int
tpm2_init(void)
{
  static int inited = 0;
  const char *sym;
  void *dl;

  if (inited)
    return 0;

  dl = dlopen(TSS2_LIB, RTLD_LAZY);

  if (!dl)
    {
      log_error("opening of tss2 library failed %s\n", strerror(errno));
      return GPG_ERR_CARD_NOT_PRESENT;
    }

  /* load each symbol pointer and check for existence */
# define _DL_SYM(func)                          \
    sym = #func;                                \
    p##func = dlsym(dl, #func);                 \
      if (p##func == NULL)                      \
        goto out_symfail

  _TSS2_LIST(_DL_SYM);

  tpm2_dir = tpm2_set_unique_tssdir();
  if (!tpm2_dir)
    /* make this non fatal */
    log_error("Failed to set unique TPM directory\n");
  inited = 1;
  return 0;

 out_symfail:
  log_error("Failed to find symbol %s in tss2 library\n", sym);
  return GPG_ERR_CARD_NOT_PRESENT;
}

static void
tpm2_error(TPM_RC rc, char *prefix)
{
  const char *msg, *submsg, *num;

  pTSS_ResponseCode_toString(&msg, &submsg, &num, rc);
  log_error("%s gave TPM2 Error: %s%s%s", prefix, msg, submsg, num);
}

#define _TSS_CHECK(f)           \
  rc = f;                       \
  if (rc != TPM_RC_SUCCESS)     \
    {                           \
      tpm2_error(rc, #f);       \
      return GPG_ERR_CARD;      \
    }

int
tpm2_start(TSS_CONTEXT **tssc)
{
  TPM_RC rc;
  int ret;

  ret = tpm2_init();
  if (ret)
    return ret;

  _TSS_CHECK(pTSS_Create(tssc));
  _TSS_CHECK(pTSS_SetProperty(*tssc, TPM_DATA_DIR, tpm2_dir));
  return 0;
}

void
tpm2_end(TSS_CONTEXT *tssc)
{
  pTSS_Delete(tssc);
}

void
tpm2_flush_handle(TSS_CONTEXT *tssc, TPM_HANDLE h)
{
        FlushContext_In in;

        if (!h)
                return;

        in.flushHandle = h;
        pTSS_Execute(tssc, NULL,
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_FlushContext,
                     TPM_RH_NULL, NULL, 0);
}

static int
tpm2_get_hmac_handle(TSS_CONTEXT *tssc, TPM_HANDLE *handle,
                     TPM_HANDLE salt_key)
{
  TPM_RC rc;
  StartAuthSession_In in;
  StartAuthSession_Out out;
  StartAuthSession_Extra extra;

  memset(&in, 0, sizeof(in));
  memset(&extra, 0 , sizeof(extra));
  in.bind = TPM_RH_NULL;
  in.sessionType = TPM_SE_HMAC;
  in.authHash = TPM_ALG_SHA256;
  in.tpmKey = TPM_RH_NULL;
  in.symmetric.algorithm = TPM_ALG_AES;
  in.symmetric.keyBits.aes = 128;
  in.symmetric.mode.aes = TPM_ALG_CFB;
  if (salt_key) {
    ReadPublic_In rin;
    ReadPublic_Out rout;

    rin.objectHandle = salt_key;
    rc = pTSS_Execute (tssc,
                       (RESPONSE_PARAMETERS *)&rout,
                       (COMMAND_PARAMETERS *)&rin,
                       NULL,
                       TPM_CC_ReadPublic,
                       TPM_RH_NULL, NULL, 0);
    if (rc) {
      tpm2_error(rc, "TPM2_ReadPublic");
      return GPG_ERR_CARD;
    }

    /* don't care what rout returns, the purpose of the operation was
     * to get the public key parameters into the tss so it can
     * construct the salt */
    in.tpmKey = salt_key;
  }
  rc = pTSS_Execute(tssc,
                    (RESPONSE_PARAMETERS *)&out,
                    (COMMAND_PARAMETERS *)&in,
                    (EXTRA_PARAMETERS *)&extra,
                    TPM_CC_StartAuthSession,
                    TPM_RH_NULL, NULL, 0);
  if (rc) {
    tpm2_error(rc, "TPM2_StartAuthSession");
    return GPG_ERR_CARD;
  }

  *handle = out.sessionHandle;

  return 0;
}

static int
tpm2_exec_with_auth(ctrl_t ctrl, TSS_CONTEXT *tssc, int cmd, char *cmd_str,
                    void *out, void *in)
{
  TPM_HANDLE ah;
  struct pin_entry_info_s *pi;
  TPM_RC rc;

  pi = gcry_xmalloc_secure(sizeof(*pi) + MAX_PASSPHRASE_LEN + 10);
  pi->max_length = MAX_PASSPHRASE_LEN;
  pi->min_digits = 0;           /* want a real passphrase */
  pi->max_digits = 16;
  pi->max_tries = 3;
  rc = agent_askpin(ctrl, NULL, "TPM Key Passphrase", NULL, pi, NULL, 0);
  if (rc) {
    gcry_free (pi);
    return rc;
  }

  rc = tpm2_get_hmac_handle(tssc, &ah, 0);
  if (rc)
    return rc;

  rc = pTSS_Execute(tssc, out, in, NULL,
                    cmd,
                    ah, pi->pin, 0,
                    TPM_RH_NULL, NULL, 0);
  gcry_free (pi);
  if (rc) {
    tpm2_error(rc, cmd_str);
    tpm2_flush_handle(tssc, ah);
    switch (rc & 0xFF) {
    case TPM_RC_BAD_AUTH:
    case TPM_RC_AUTH_FAIL:
      return GPG_ERR_BAD_PASSPHRASE;
    default:
      return GPG_ERR_CARD;
    }
  }
  return 0;
}

static gpg_error_t
parse_tpm2_shadow_info (const unsigned char *shadow_info,
                        uint32_t *parent,
                        const char **pub, int *pub_len,
                        const char **priv, int *priv_len)
{
  const unsigned char *s;
  size_t n;
  int i;

  s = shadow_info;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);
  *parent = 0;
  for (i = 0; i < n; i++) {
    *parent *= 10;
    *parent += atoi_1(s+i);
  }

  s += n;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  *pub_len = n;
  *pub = s;

  s += n;
  n = snext (&s);
  if (!n)
    return gpg_error (GPG_ERR_INV_SEXP);

  *priv_len = n;
  *priv = s;

  return 0;
}

int
tpm2_load_key(TSS_CONTEXT *tssc, const unsigned char *shadow_info,
              TPM_HANDLE *key, TPMI_ALG_PUBLIC *type)
{
  uint32_t parent;
  Load_In in;
  Load_Out out;
  const char *pub, *priv;
  int ret, pub_len, priv_len;
  TPM_RC rc;
  BYTE *buf;
  uint32_t size;

  ret = parse_tpm2_shadow_info (shadow_info, &parent, &pub, &pub_len,
                                &priv, &priv_len);
  if (ret)
    return ret;

  in.parentHandle = parent;

  buf = (BYTE *)priv;
  size = priv_len;
  pTPM2B_PRIVATE_Unmarshal(&in.inPrivate, &buf, &size);

  buf = (BYTE *)pub;
  size = pub_len;
  pTPM2B_PUBLIC_Unmarshal(&in.inPublic, &buf, &size, FALSE);

  *type = in.inPublic.publicArea.type;

  rc = pTSS_Execute(tssc,
                    (RESPONSE_PARAMETERS *)&out,
                    (COMMAND_PARAMETERS *)&in,
                    NULL,
                    TPM_CC_Load,
                    TPM_RS_PW, NULL, 0,
                    TPM_RH_NULL, NULL, 0);
  if (rc != TPM_RC_SUCCESS) {
    tpm2_error(rc, "TPM2_Load");
    return GPG_ERR_CARD;
  }

  *key = out.objectHandle;

  return 0;
}

int
tpm2_sign(ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
	  TPMI_ALG_PUBLIC type,
	  const unsigned char *digest, size_t digestlen,
          unsigned char **r_sig, size_t *r_siglen)
{
  Sign_In in;
  Sign_Out out;
  int ret;

  /* The TPM insists on knowing the digest type, so
   * calculate that from the size */
  switch (digestlen) {
  case 20:
    in.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA1;
    break;
  case 32:
    in.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    break;
  case 48:
    in.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA384;
    break;
#ifdef TPM_ALG_SHA512
  case 64:
    in.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA512;
    break;
#endif
  default:
    log_error("Unknown signature digest length, cannot deduce hash type for TPM\n");
    return GPG_ERR_NO_SIGNATURE_SCHEME;
  }
  in.digest.t.size = digestlen;
  memcpy(in.digest.t.buffer, digest, digestlen);
  in.keyHandle = key;
  in.validation.tag = TPM_ST_HASHCHECK;
  in.validation.hierarchy = TPM_RH_NULL;
  in.validation.digest.t.size = 0;

  if (type == TPM_ALG_RSA)
    in.inScheme.scheme = TPM_ALG_RSASSA;
  else if (type == TPM_ALG_ECC)
    in.inScheme.scheme = TPM_ALG_ECDSA;
  else
    return GPG_ERR_PUBKEY_ALGO;


  ret = tpm2_exec_with_auth(ctrl, tssc, TPM_CC_Sign, "TPM2_Sign", &out, &in);
  if (ret)
    return ret;

  if (type == TPM_ALG_RSA)
    *r_siglen = out.signature.signature.rsassa.sig.t.size;
  else if (type == TPM_ALG_ECC)
    *r_siglen = out.signature.signature.ecdsa.signatureR.t.size
      + out.signature.signature.ecdsa.signatureS.t.size;

  *r_sig = xtrymalloc(*r_siglen);
  if (!r_sig)
    return GPG_ERR_ENOMEM;

  if (type == TPM_ALG_RSA)
    {
      memcpy(*r_sig, out.signature.signature.rsassa.sig.t.buffer, *r_siglen);
    }
  else if (type == TPM_ALG_ECC)
    {
      memcpy(*r_sig, out.signature.signature.ecdsa.signatureR.t.buffer,
	     out.signature.signature.ecdsa.signatureR.t.size);
      memcpy(*r_sig + out.signature.signature.ecdsa.signatureR.t.size,
	     out.signature.signature.ecdsa.signatureS.t.buffer,
	     out.signature.signature.ecdsa.signatureS.t.size);
    }

  return 0;
}

static int
sexp_to_tpm2_sensitive_ecc(TPMT_SENSITIVE *s, gcry_sexp_t key)
{
  gcry_mpi_t d;
  gcry_sexp_t l;
  int rc = -1;
  size_t len;

  s->sensitiveType = TPM_ALG_ECC;
  s->seedValue.b.size = 0;

  l = gcry_sexp_find_token (key, "d", 0);
  if (!l)
    return rc;
  d = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l);
  len = sizeof(s->sensitive.ecc.t.buffer);
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, s->sensitive.ecc.t.buffer, len, &len, d);
  s->sensitive.ecc.t.size = len;
  gcry_mpi_release (d);

  return rc;
}

/* try to match the libgcrypt curve names to known TPM parameters.
 *
 * As of 2018 the TCG defined curves are only NIST
 * (192,224,256,384,521) Barreto-Naehring (256,638) and the Chinese
 * SM2 (256), which means only the NIST ones overlap with libgcrypt */
static struct {
  const char *name;
  TPMI_ECC_CURVE c;
} tpm2_curves[] = {
  { "NIST P-192", TPM_ECC_NIST_P192 },
  { "prime192v1", TPM_ECC_NIST_P192 },
  { "secp192r1", TPM_ECC_NIST_P192 },
  { "nistp192", TPM_ECC_NIST_P192 },
  { "NIST P-224", TPM_ECC_NIST_P224 },
  { "secp224r1", TPM_ECC_NIST_P224 },
  { "nistp224", TPM_ECC_NIST_P224 },
  { "NIST P-256", TPM_ECC_NIST_P256 },
  { "prime256v1", TPM_ECC_NIST_P256 },
  { "secp256r1", TPM_ECC_NIST_P256 },
  { "nistp256", TPM_ECC_NIST_P256 },
  { "NIST P-384", TPM_ECC_NIST_P384 },
  { "secp384r1", TPM_ECC_NIST_P384 },
  { "nistp384", TPM_ECC_NIST_P384 },
  { "NIST P-521", TPM_ECC_NIST_P521 },
  { "secp521r1", TPM_ECC_NIST_P521 },
  { "nistp521", TPM_ECC_NIST_P521 },
};

static int
tpm2_ecc_curve (const char *curve_name, TPMI_ECC_CURVE *c)
{
  int i;

  for (i = 0; i < DIM (tpm2_curves); i++)
    if (strcmp (tpm2_curves[i].name, curve_name) == 0)
      break;
  if (i == DIM (tpm2_curves)) {
    log_error ("curve %s does not match any available TPM curves\n", curve_name);
    return GPG_ERR_UNKNOWN_CURVE;
  }

  *c = tpm2_curves[i].c;

  return 0;
}

static int
sexp_to_tpm2_public_ecc(TPMT_PUBLIC *p, gcry_sexp_t key)
{
  const char *q;
  gcry_sexp_t l;
  int rc = GPG_ERR_BAD_PUBKEY;
  size_t len;
  TPMI_ECC_CURVE curve;
  char *curve_name;

  l = gcry_sexp_find_token (key, "curve", 0);
  if (!l)
    return rc;
  curve_name = gcry_sexp_nth_string (l, 1);
  if (!curve_name)
    goto out;
  rc = tpm2_ecc_curve (curve_name, &curve);
  gcry_free (curve_name);
  if (rc)
    goto out;
  gcry_sexp_release(l);

  l = gcry_sexp_find_token (key, "q", 0);
  if (!l)
    return rc;
  q = gcry_sexp_nth_data (l, 1, &len);
  /* This is a point representation, the first byte tells you what
   * type.  The only format we understand is uncompressed (0x04)
   * which has layout 0x04 | x | y */
  if (q[0] != 0x04)
    {
      log_error ("Point format for q is not uncompressed\n");
      goto out;
    }
  q++;
  len--;
  /* now should have to equal sized big endian point numbers */
  if ((len & 0x01) == 1)
    {
      log_error ("Point format for q has incorrect length\n");
      goto out;
    }

  len >>= 1;

  p->type = TPM_ALG_ECC;
  p->nameAlg = TPM_ALG_SHA256;
  p->objectAttributes.val = TPMA_OBJECT_NODA |
    TPMA_OBJECT_SIGN |
    TPMA_OBJECT_DECRYPT |
    TPMA_OBJECT_USERWITHAUTH;
  p->authPolicy.t.size = 0;
  p->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
  p->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
  p->parameters.eccDetail.curveID = curve;
  p->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
  memcpy(p->unique.ecc.x.t.buffer, q, len);
  p->unique.ecc.x.t.size = len;
  memcpy(p->unique.ecc.y.t.buffer, q + len, len);
  p->unique.ecc.y.t.size = len;
 out:
  gcry_sexp_release (l);
  return rc;
}

static int
sexp_to_tpm2_sensitive_rsa(TPMT_SENSITIVE *s, gcry_sexp_t key)
{
  gcry_mpi_t p;
  gcry_sexp_t l;
  int rc = -1;
  size_t len;

  s->sensitiveType = TPM_ALG_RSA;
  s->seedValue.b.size = 0;

  l = gcry_sexp_find_token (key, "p", 0);
  if (!l)
    return rc;
  p = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l);
  len = sizeof(s->sensitive.rsa.t.buffer);
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, s->sensitive.rsa.t.buffer, len, &len, p);
  s->sensitive.rsa.t.size = len;
  gcry_mpi_release (p);

  return rc;
}

static int
sexp_to_tpm2_public_rsa(TPMT_PUBLIC *p, gcry_sexp_t key)
{
  gcry_mpi_t n, e;
  gcry_sexp_t l;
  int rc = -1, i;
  size_t len;
  /* longer than an int */
  unsigned char ebuf[5];
  uint32_t exp = 0;

  p->type = TPM_ALG_RSA;
  p->nameAlg = TPM_ALG_SHA256;
  /* note: all our keys are decrypt only.  This is because
   * we use the TPM2_RSA_Decrypt operation for both signing
   * and decryption (see e_tpm2.c for details) */
  p->objectAttributes.val = TPMA_OBJECT_NODA |
    TPMA_OBJECT_DECRYPT |
    TPMA_OBJECT_SIGN |
    TPMA_OBJECT_USERWITHAUTH;
  p->authPolicy.t.size = 0;
  p->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
  p->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;

  l = gcry_sexp_find_token (key, "n", 0);
  if (!l)
    return rc;
  n = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l);
  len = sizeof(p->unique.rsa.t.buffer);
  p->parameters.rsaDetail.keyBits = gcry_mpi_get_nbits (n);
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, p->unique.rsa.t.buffer, len, &len, n);
  p->unique.rsa.t.size = len;
  gcry_mpi_release (n);
  if (rc)
    return rc;
  rc = -1;
  l = gcry_sexp_find_token (key, "e", 0);
  if (!l)
    return rc;
  e = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l);
  len = sizeof (ebuf);
  rc = gcry_mpi_print (GCRYMPI_FMT_USG, ebuf, len, &len, e);
  gcry_mpi_release (e);
  if (rc)
    return rc;
  if (len > 4)
    return -1;

  /* MPI are simply big endian integers, so convert to uint32 */
  for (i = 0; i < len; i++) {
    exp <<= 8;
    exp += ebuf[i];
  }
  if (exp == 0x10001)
    p->parameters.rsaDetail.exponent = 0;
  else
    p->parameters.rsaDetail.exponent = exp;
  return 0;
}

static int
sexp_to_tpm2(TPMT_PUBLIC *p, TPMT_SENSITIVE *s, gcry_sexp_t s_skey)
{
  gcry_sexp_t l1, l2;
  int rc = -1;

  /* find the value of (private-key */
  l1 = gcry_sexp_nth (s_skey, 1);
  if (!l1)
    return rc;

  l2 = gcry_sexp_find_token (l1, "rsa", 0);
  if (l2) {
    rc = sexp_to_tpm2_public_rsa (p, l2);
    if (!rc)
      rc = sexp_to_tpm2_sensitive_rsa (s, l2);
  } else {
    l2 = gcry_sexp_find_token (l1, "ecc", 0);
    if (!l2)
      goto out;
    rc = sexp_to_tpm2_public_ecc (p, l2);
    if (!rc)
      rc = sexp_to_tpm2_sensitive_ecc (s, l2);
  }

  gcry_sexp_release(l2);

 out:
  gcry_sexp_release(l1);
  return rc;
}

/* copied from TPM implementation code */
static TPM_RC
tpm2_ObjectPublic_GetName(TPM2B_NAME *name,
                          TPMT_PUBLIC *tpmtPublic)
{
  TPM_RC rc = 0;
  uint16_t written = 0;
  TPMT_HA digest;
  uint32_t sizeInBytes;
  uint8_t buffer[MAX_RESPONSE_SIZE];

  /* marshal the TPMT_PUBLIC */
  if (rc == 0) {
    INT32 size = MAX_RESPONSE_SIZE;
    uint8_t *buffer1 = buffer;
    rc = pTSS_TPMT_PUBLIC_Marshal(tpmtPublic, &written, &buffer1, &size);
  }
  /* hash the public area */
  if (rc == 0) {
    sizeInBytes = pTSS_GetDigestSize(tpmtPublic->nameAlg);
    digest.hashAlg = tpmtPublic->nameAlg;       /* Name digest algorithm */
    /* generate the TPMT_HA */
    rc = pTSS_Hash_Generate(&digest,
                            written, buffer,
                            0, NULL);
  }
  if (rc == 0) {
    TPMI_ALG_HASH nameAlgNbo;

    /* copy the digest */
    memcpy(name->t.name + sizeof(TPMI_ALG_HASH), (uint8_t *)&digest.digest, sizeInBytes);
    /* copy the hash algorithm */
    nameAlgNbo = htons(tpmtPublic->nameAlg);
    memcpy(name->t.name, (uint8_t *)&nameAlgNbo, sizeof(TPMI_ALG_HASH));
    /* set the size */
    name->t.size = sizeInBytes + sizeof(TPMI_ALG_HASH);
  }
  return rc;
}

/*
 * Cut down version of Part 4 Supporting Routines 7.6.3.10
 *
 * Hard coded to symmetrically encrypt with aes128 as the inner
 * wrapper and no outer wrapper but with a prototype that allows
 * drop in replacement with a tss equivalent
 */
TPM_RC tpm2_SensitiveToDuplicate(TPMT_SENSITIVE *s,
                                 TPM2B_NAME *name,
                                 TPM_ALG_ID nalg,
                                 TPMT_SYM_DEF_OBJECT *symdef,
                                 TPM2B_DATA *innerkey,
                                 TPM2B_PRIVATE *p)
{
  BYTE *buf = p->t.buffer;

  p->t.size = 0;
  memset(p, 0, sizeof(*p));

  /* hard code AES CFB */
  if (symdef->algorithm == TPM_ALG_AES
      && symdef->mode.aes == TPM_ALG_CFB) {
    TPMT_HA hash;
    const int hlen = pTSS_GetDigestSize(nalg);
    TPM2B *digest = (TPM2B *)buf;
    TPM2B *s2b;
    int32_t size;
    unsigned char null_iv[AES_128_BLOCK_SIZE_BYTES];
    UINT16 bsize, written = 0;
    gcry_cipher_hd_t hd;

    /* WARNING: don't use the static null_iv trick here:
     * the AES routines alter the passed in iv */
    memset(null_iv, 0, sizeof(null_iv));

    /* reserve space for hash before the encrypted sensitive */
    bsize = sizeof(digest->size) + hlen;
    buf += bsize;
    p->t.size += bsize;
    s2b = (TPM2B *)buf;

    /* marshal the digest size */
    buf = (BYTE *)&digest->size;
    bsize = hlen;
    size = 2;
    pTSS_UINT16_Marshal(&bsize, &written, &buf, &size);

    /* marshal the unencrypted sensitive in place */
    size = sizeof(*s);
    bsize = 0;
    buf = s2b->buffer;
    pTSS_TPMT_SENSITIVE_Marshal(s, &bsize, &buf, &size);
    buf = (BYTE *)&s2b->size;
    size = 2;
    pTSS_UINT16_Marshal(&bsize, &written, &buf, &size);

    bsize = bsize + sizeof(s2b->size);
    p->t.size += bsize;

    /* compute hash of unencrypted marshalled sensitive and
     * write to the digest buffer */
    hash.hashAlg = nalg;
    pTSS_Hash_Generate(&hash, bsize, s2b,
                       name->t.size, name->t.name,
                       0, NULL);
    memcpy(digest->buffer, &hash.digest, hlen);
    gcry_cipher_open (&hd, GCRY_CIPHER_AES128,
		      GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
    gcry_cipher_setiv(hd, null_iv, sizeof(null_iv));
    gcry_cipher_setkey(hd, innerkey->b.buffer, innerkey->b.size);
    /* encrypt the hash and sensitive in-place */
    gcry_cipher_encrypt(hd, p->t.buffer, p->t.size, NULL, 0);
    gcry_cipher_close(hd);

  } else if (symdef->algorithm == TPM_ALG_NULL) {
    TPM2B *s2b = (TPM2B *)buf;
    int32_t size = sizeof(*s);
    UINT16 bsize = 0, written = 0;

    buf = s2b->buffer;

    /* marshal the unencrypted sensitive in place */
    pTSS_TPMT_SENSITIVE_Marshal(s, &bsize, &buf, &size);
    buf = (BYTE *)&s2b->size;
    size = 2;
    pTSS_UINT16_Marshal(&bsize, &written, &buf, &size);

    p->b.size += bsize + sizeof(s2b->size);
  } else {
    log_error ("Unknown symmetric algorithm\n");
    return TPM_RC_SYMMETRIC;
  }

  return TPM_RC_SUCCESS;
}

static void
tpm2_encrypt_duplicate(Import_In *iin, TPMT_SENSITIVE *s)
{
  TPM2B_NAME name;
  TPMT_PUBLIC *p = &iin->objectPublic.publicArea;
  const int aes_key_bits = 128;
  const int aes_key_bytes = aes_key_bits/8;

  tpm2_ObjectPublic_GetName(&name, p);
  gcry_randomize(iin->encryptionKey.t.buffer,
                 aes_key_bytes, GCRY_STRONG_RANDOM);
  iin->encryptionKey.t.size = aes_key_bytes;

  /* set random iin.symSeed */
  iin->inSymSeed.t.size = 0;
  iin->symmetricAlg.algorithm = TPM_ALG_AES;
  iin->symmetricAlg.keyBits.aes = aes_key_bits;
  iin->symmetricAlg.mode.aes = TPM_ALG_CFB;

  tpm2_SensitiveToDuplicate(s, &name, p->nameAlg, &iin->symmetricAlg,
                            &iin->encryptionKey, &iin->duplicate);
}

int
tpm2_import_key(ctrl_t ctrl, TSS_CONTEXT *tssc, char *pub, int *pub_len,
                char *priv, int *priv_len, gcry_sexp_t s_skey)
{
  Import_In iin;
  Import_Out iout;
  TPMT_SENSITIVE s;
  TPM_HANDLE ah;
  TPM_RC rc;

  uint32_t size;
  uint16_t len;
  BYTE *buffer;
  int ret;
  char *passphrase;

  iin.parentHandle = TPM2_PARENT;
  ret = sexp_to_tpm2(&iin.objectPublic.publicArea, &s, s_skey);
  if (ret) {
    log_error("Failed to parse Key s-expression: key corrupt?\n");
    return ret;
  }

  /* add an authorization password to the key which the TPM will check */

  ret = agent_ask_new_passphrase (ctrl,  _("Please enter the TPM Authorization passphrase for the key."), &passphrase);
  if (ret)
    return ret;
  s.authValue.b.size = strlen(passphrase);
  memcpy(s.authValue.b.buffer, passphrase, s.authValue.b.size);

  /* We're responsible for securing the data in transmission to the
   * TPM here.  The TPM provides parameter encryption via a session,
   * but only for the first parameter.  For TPM2_Import, the first
   * parameter is a symmetric key used to encrypt the sensitive data,
   * so we must populate this key with random value and encrypt the
   * sensitive data with it */
  tpm2_encrypt_duplicate(&iin, &s);

  /* use salted parameter encryption to hide the key.  First we read
   * the public parameters of the parent key and use them to agree an
   * encryption for the first parameter */
  rc = tpm2_get_hmac_handle(tssc, &ah, TPM2_PARENT);
  if (rc)
    return GPG_ERR_CARD;

  rc = pTSS_Execute(tssc,
                    (RESPONSE_PARAMETERS *)&iout,
                    (COMMAND_PARAMETERS *)&iin,
                    NULL,
                    TPM_CC_Import,
                    ah, NULL, TPMA_SESSION_DECRYPT,
                    TPM_RH_NULL, NULL, 0);
  if (rc) {
    tpm2_error(rc, "TPM2_Import");
    /* failure means auth handle is not flushed */
    tpm2_flush_handle(tssc, ah);
    return GPG_ERR_CARD;
  }

  size = sizeof(TPM2B_PUBLIC);
  buffer = pub;
  len = 0;
  pTSS_TPM2B_PUBLIC_Marshal(&iin.objectPublic,
                            &len, &buffer, &size);
  *pub_len = len;

  size = sizeof(TPM2B_PRIVATE);
  buffer = priv;
  len = 0;
  pTSS_TPM2B_PRIVATE_Marshal(&iout.outPrivate,
                             &len, &buffer, &size);
  *priv_len = len;

  return 0;
}

int
tpm2_ecc_decrypt(ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
		 const char *ciphertext, int ciphertext_len,
		 char **decrypt, size_t *decrypt_len)
{
  ECDH_ZGen_In in;
  ECDH_ZGen_Out out;
  size_t len;
  int ret;

  /* This isn't really a decryption per se.  The ciphertext actually
   * contains an EC Point which we must multiply by the private key number.
   *
   * The reason is to generate a diffe helman agreement on a shared
   * point.  This shared point is then used to generate the per
   * session encryption key.
   */
  if (ciphertext[0] != 0x04)
    {
      log_error ("Decryption Shared Point format is not uncompressed\n");
      return GPG_ERR_ENCODING_PROBLEM;
    }
  if ((ciphertext_len & 0x01) != 1)
    {
      log_error ("Decryption Shared Point has incorrect length\n");
      return GPG_ERR_ENCODING_PROBLEM;
    }
  len = ciphertext_len >> 1;

  in.keyHandle = key;
  memcpy(in.inPoint.point.x.t.buffer, ciphertext + 1, len);
  in.inPoint.point.x.t.size = len;
  memcpy(in.inPoint.point.y.t.buffer, ciphertext + 1 + len, len);
  in.inPoint.point.y.t.size = len;

  ret = tpm2_exec_with_auth(ctrl, tssc, TPM_CC_ECDH_ZGen, "TPM2_ECDH_ZGen",
			    &out, &in);
  if (ret)
    return ret;

  *decrypt_len = out.outPoint.point.x.t.size + out.outPoint.point.y.t.size + 1;
  *decrypt = xtrymalloc(*decrypt_len);
  (*decrypt)[0] = 0x04;
  memcpy(*decrypt + 1, out.outPoint.point.x.t.buffer,
	 out.outPoint.point.x.t.size);
  memcpy(*decrypt + 1 + out.outPoint.point.x.t.size,
	 out.outPoint.point.y.t.buffer,
	 out.outPoint.point.y.t.size);

  return 0;
}

int
tpm2_rsa_decrypt(ctrl_t ctrl, TSS_CONTEXT *tssc, TPM_HANDLE key,
		 const char *ciphertext, int ciphertext_len,
		 char **decrypt, size_t *decrypt_len)
{
  RSA_Decrypt_In in;
  RSA_Decrypt_Out out;
  int ret;

  in.keyHandle = key;
  in.inScheme.scheme = TPM_ALG_RSAES;
  in.cipherText.t.size = ciphertext_len;
  memcpy (in.cipherText.t.buffer, ciphertext, ciphertext_len);
  in.label.t.size = 0;

  ret = tpm2_exec_with_auth(ctrl, tssc, TPM_CC_RSA_Decrypt, "TPM2_RSA_Decrypt",
                            &out, &in);
  if (ret)
    return ret;

  *decrypt_len = out.message.t.size;
  *decrypt = xtrymalloc(out.message.t.size);
  memcpy (*decrypt, out.message.t.buffer, out.message.t.size);

  return 0;
}
