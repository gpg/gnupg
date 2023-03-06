#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include "tkdaemon.h"

#include <gcrypt.h>
#include "../common/util.h"
#include "pkcs11.h"

/* Maximum allowed total data size for VALUE.  */
#define MAXLEN_VALUE 4096

#define ck_function_list _CK_FUNCTION_LIST
#define ck_token_info _CK_TOKEN_INFO
#define ck_attribute _CK_ATTRIBUTE

#define ck_mechanism _CK_MECHANISM
#define parameter pParameter
#define parameter_len ulParameterLen

#define ck_slot_id_t CK_SLOT_ID
#define ck_session_handle_t CK_SESSION_HANDLE
#define ck_notification_t CK_NOTIFICATION
#define ck_flags_t CK_FLAGS
#define ck_object_handle_t CK_OBJECT_HANDLE
#define ck_mechanism_type_t CK_MECHANISM_TYPE

/*
 * d_list -> dev
 *           session -> key_list -> key
 *
 */

/*
 * Major use cases:
 * a few keys (two or three at maximum)
 * with a single device, which only has one slot.
 *
 * So, static fixed allocation is better.
 */
#define MAX_KEYS  10
#define MAX_SLOTS 10

enum key_type {
  KEY_RSA,
  KEY_EC,
  KEY_EDDSA,
};

#define KEY_FLAGS_VALID          (1 << 0)
#define KEY_FLAGS_NO_PUBKEY      (1 << 1)
#define KEY_FLAGS_USAGE_SIGN     (1 << 2)
#define KEY_FLAGS_USAGE_DECRYPT  (1 << 3)

struct key {
  struct token *token;  /* Back pointer.  */
  unsigned long flags;
  int key_type;
  char keygrip[2*KEYGRIP_LEN+1];
  gcry_sexp_t pubkey;
  /* PKCS#11 interface */
  unsigned char label[256];
  unsigned long label_len;
  unsigned char id[256];
  unsigned long id_len;
  ck_object_handle_t p11_keyid;
  ck_mechanism_type_t mechanism;
};

struct token {
  struct cryptoki *ck;   /* Back pointer.  */
  int valid;
  ck_slot_id_t slot_id;
  int login_required;
  ck_session_handle_t session;
  int num_keys;
  struct key key_list[MAX_KEYS];
};

struct cryptoki {
  struct ck_function_list *f;
  int num_slots;
  struct token token_list[MAX_SLOTS];
};

/* Possibly, we will extend this to support multiple PKCS#11 modules.
 * For now, it's only one.
 */
static struct cryptoki ck_instance[1];


static long
get_function_list (struct cryptoki *ck, const char *libname)
{
  unsigned long err = 0;
  unsigned long (*p_func) (struct ck_function_list **);
  void *handle;

  handle = dlopen (libname, RTLD_NOW);
  if (handle == NULL)
    {
      return -1;
    }

  p_func = (CK_C_GetFunctionList)dlsym (handle, "C_GetFunctionList");
  if (p_func == NULL)
    {
      return -1;
    }
  err = p_func (&ck->f);

  if (err || ck->f == NULL)
    {
      return -1;
    }

  err = ck->f->C_Initialize (NULL);
  if (err)
    {
      return -1;
    }

  /* For now, we never call dlclose to unload the LIBNAME */
  return 0;
}

static long
get_slot_list (struct cryptoki *ck,
               unsigned long *num_slot_p,
               ck_slot_id_t *slot_list)
{
  unsigned long err = 0;

  /* Scute requires first call with NULL, to rescan.  */
  err = ck->f->C_GetSlotList (TRUE, NULL, num_slot_p);
  if (err)
    return err;

  err = ck->f->C_GetSlotList (TRUE, slot_list, num_slot_p);
  if (err)
    {
      return err;
    }

  return 0;
}

static long
get_token_info (struct token *token,
                struct ck_token_info *tk_info)
{
  unsigned long err = 0;
  struct cryptoki *ck = token->ck;
  ck_slot_id_t slot_id = token->slot_id;

  err = ck->f->C_GetTokenInfo (slot_id, tk_info);
  if (err)
    {
      return err;
    }

  return 0;
}

/* XXX Implement some useful things to be notified... */
struct p11dev {
  int d;
};

static struct p11dev p11_priv;

static unsigned long
notify_cb (ck_session_handle_t session,
           ck_notification_t event, void *application)
{
  struct p11dev *priv = application;

  (void)priv;
  (void)session;
  (void)event;
  (void)application;
  return 0;
}

static long
open_session (struct token *token)
{
  unsigned long err = 0;
  struct cryptoki *ck = token->ck;
  ck_slot_id_t slot_id = token->slot_id;
  ck_session_handle_t session_handle;
  ck_flags_t session_flags;

  session_flags = CKU_USER;
  // session_flags = session_flags | CKF_RW_SESSION;
  session_flags = session_flags | CKF_SERIAL_SESSION;

  err = ck->f->C_OpenSession (slot_id, session_flags,
                              (void *)&p11_priv, notify_cb, &session_handle);
  if (err)
    {
      log_debug ("open_session: %ld\n", err);
      return -1;
    }

  token->session = session_handle;
  token->valid = 1;
  token->num_keys = 0;

  return 0;
}

static long
close_session (struct token *token)
{
  unsigned long err = 0;
  struct cryptoki *ck = token->ck;

  if (!token->valid)
    return -1;

  err = ck->f->C_CloseSession (token->session);
  if (err)
    {
      return -1;
    }

  return 0;
}

static long
login (struct token *token,
       const unsigned char *pin, int pin_len)
{
  unsigned long err = 0;
  unsigned long user_type = CKU_USER;
  struct cryptoki *ck = token->ck;

  err = ck->f->C_Login (token->session, user_type,
                        (unsigned char *)pin, pin_len);
  if (err)
    {
      return -1;
    }

  return 0;
}

static long
logout (struct token *token)
{
  unsigned long err = 0;
  struct cryptoki *ck = token->ck;

  err = ck->f->C_Logout (token->session);
  if (err)
    {
      return -1;
    }

  return 0;
}


static void
compute_keygrip_rsa (char *keygrip, gcry_sexp_t *r_pubkey,
                     const char *modulus,  unsigned long modulus_len,
                     const char *exponent,  unsigned long exponent_len)
{
  gpg_error_t err;
  gcry_sexp_t s_pkey = NULL;
  const char *format = "(public-key(rsa(n%b)(e%b)))";
  unsigned char grip[20];

  *r_pubkey = NULL;
  err = gcry_sexp_build (&s_pkey, NULL, format,
                         (int)modulus_len, modulus,
                         (int)exponent_len, exponent);
  if (!err && !gcry_pk_get_keygrip (s_pkey, grip))
    err = gpg_error (GPG_ERR_INTERNAL);
  else
    {
      bin2hex (grip, 20, keygrip);
      *r_pubkey = s_pkey;
    }
}

static void
compute_keygrip_ec (char *keygrip, gcry_sexp_t *r_pubkey,
                    const char *curve, const char *ecpoint,
                    unsigned long ecpoint_len)
{
  gpg_error_t err;
  gcry_sexp_t s_pkey = NULL;
  const char *format = "(public-key(ecc(curve %s)(q%b)))";
  unsigned char grip[20];

  *r_pubkey = NULL;
  err = gcry_sexp_build (&s_pkey, NULL, format, curve, (int)ecpoint_len,
                         ecpoint);
  if (!err && !gcry_pk_get_keygrip (s_pkey, grip))
    err = gpg_error (GPG_ERR_INTERNAL);
  else
    {
      bin2hex (grip, 20, keygrip);
      *r_pubkey = s_pkey;
    }
}


static long
examine_public_key (struct token *token, struct key *k, unsigned long keytype,
                    int update_keyid, ck_object_handle_t obj)
{
  unsigned long err = 0;
  struct cryptoki *ck = token->ck;
  unsigned char modulus[1024];
  unsigned char exponent[8];
  unsigned char ecparams[256];
  unsigned char ecpoint[256];
  struct ck_attribute templ[3];
  unsigned long mechanisms[3];
  unsigned char supported;

  if (keytype == CKK_RSA)
    {
      if (update_keyid)
        k->p11_keyid = obj;
      k->key_type = KEY_RSA;

      templ[0].type = CKA_MODULUS;
      templ[0].pValue = (void *)modulus;
      templ[0].ulValueLen = sizeof (modulus);

      templ[1].type = CKA_PUBLIC_EXPONENT;
      templ[1].pValue = (void *)exponent;
      templ[1].ulValueLen = sizeof (exponent);

      err = ck->f->C_GetAttributeValue (token->session, obj, templ, 2);
      if (err)
        {
          k->flags |= KEY_FLAGS_NO_PUBKEY;
          return 1;
        }

      k->flags |= KEY_FLAGS_VALID;
      k->flags &= ~KEY_FLAGS_NO_PUBKEY;
      if ((modulus[0] & 0x80))
        {
          memmove (modulus+1, modulus, templ[0].ulValueLen);
          templ[0].ulValueLen++;
          modulus[0] = 0;
        }

      /* Found a RSA key.  */
      log_debug ("RSA: %ld %ld\n",
                 templ[0].ulValueLen,
                 templ[1].ulValueLen);

      compute_keygrip_rsa (k->keygrip, &k->pubkey,
                           modulus, templ[0].ulValueLen,
                           exponent, templ[1].ulValueLen);

      k->mechanism = CKM_RSA_PKCS;
    }
  else if (keytype == CKK_EC)
    {
      char *curve_oid = NULL;
      const char *curve;

      if (update_keyid)
        k->p11_keyid = obj;
      k->key_type = KEY_EC;

      templ[0].type = CKA_EC_PARAMS;
      templ[0].pValue = ecparams;
      templ[0].ulValueLen = sizeof (ecparams);

      templ[1].type = CKA_EC_POINT;
      templ[1].pValue = (void *)ecpoint;
      templ[1].ulValueLen = sizeof (ecpoint);

      err = ck->f->C_GetAttributeValue (token->session, obj, templ, 2);
      if (err)
        {
          k->flags |= KEY_FLAGS_NO_PUBKEY;
          return 1;
        }

      k->flags |= KEY_FLAGS_VALID;
      k->flags &= ~KEY_FLAGS_NO_PUBKEY;
      /* Found an ECC key.  */
      log_debug ("ECC: %ld %ld\n",
                 templ[0].ulValueLen,
                 templ[1].ulValueLen);

      curve_oid = openpgp_oidbuf_to_str (ecparams+1, templ[0].ulValueLen-1);
      curve = openpgp_oid_to_curve (curve_oid, 1);
      xfree (curve_oid);

      compute_keygrip_ec (k->keygrip, &k->pubkey,
                          curve, ecpoint, templ[1].ulValueLen);

      templ[0].type = CKA_ALLOWED_MECHANISMS;
      templ[0].pValue = (void *)mechanisms;
      templ[0].ulValueLen = sizeof (mechanisms);

      err = ck->f->C_GetAttributeValue (token->session, obj, templ, 1);
      if (!err)
        {
          if (templ[0].ulValueLen)
            {
              /* Scute works well.  */
              log_debug ("mechanism: %lx %ld\n", mechanisms[0], templ[0].ulValueLen);
              k->mechanism = mechanisms[0];
            }
          else
            {
              log_debug ("SoftHSMv2???");
              k->mechanism = CKM_ECDSA;
            }
        }
      else
        {
          /* Yubkey YKCS doesn't offer CKA_ALLOWED_MECHANISMS,
             unfortunately.  */
          log_debug ("Yubikey???");
          k->mechanism = CKM_ECDSA_SHA256;
        }
    }

  templ[0].type = CKA_SIGN;
  templ[0].pValue = (void *)&supported;
  templ[0].ulValueLen = sizeof (supported);

  err = ck->f->C_GetAttributeValue (token->session, obj, templ, 1);
  if (!err)
    {
      /* XXX: Scute has the attribute, but not set.  */
      k->flags |= KEY_FLAGS_USAGE_SIGN;
    }

  templ[0].type = CKA_DECRYPT;
  templ[0].pValue = (void *)&supported;
  templ[0].ulValueLen = sizeof (supported);

  err = ck->f->C_GetAttributeValue (token->session, obj, templ, 1);
  if (!err && supported)
    {
      k->flags |= KEY_FLAGS_USAGE_DECRYPT;
    }

  return 0;
}

static long
detect_private_keys (struct token *token)
{
  unsigned long err = 0;
  struct cryptoki *ck = token->ck;

  struct ck_attribute templ[8];

  unsigned long class;
  unsigned long keytype;

  unsigned long cnt = 0;
  ck_object_handle_t obj;

  class = CKO_PRIVATE_KEY;
  templ[0].type = CKA_CLASS;
  templ[0].pValue = (void *)&class;
  templ[0].ulValueLen = sizeof (class);

  token->num_keys = 0;

  err = ck->f->C_FindObjectsInit (token->session, templ, 1);
  if (!err)
    {
      while (TRUE)
        {
          unsigned long any;
          struct key *k = &token->key_list[cnt]; /* Allocate a key.  */

          k->token = token;
          k->flags = 0;

          /* Portable way to get objects... is get it one by one.  */
          err = ck->f->C_FindObjects (token->session, &obj, 1, &any);
          if (err || any == 0)
            break;

          templ[0].type = CKA_KEY_TYPE;
          templ[0].pValue = &keytype;
          templ[0].ulValueLen = sizeof (keytype);

          templ[1].type = CKA_LABEL;
          templ[1].pValue = (void *)k->label;
          templ[1].ulValueLen = sizeof (k->label) - 1;

          templ[2].type = CKA_ID;
          templ[2].pValue = (void *)k->id;
          templ[2].ulValueLen = sizeof (k->id) - 1;

          err = ck->f->C_GetAttributeValue (token->session, obj, templ, 3);
          if (err)
            {
              continue;
            }

          cnt++;

          k->label_len = templ[1].ulValueLen;
          k->label[k->label_len] = 0;
          k->id_len = templ[2].ulValueLen;
          k->id[k->id_len] = 0;

          log_debug ("slot: %lx handle: %ld label: %s key_type: %ld id: %s\n",
                     token->slot_id, obj, k->label, keytype, k->id);

          if (examine_public_key (token, k, keytype, 1, obj))
            continue;
        }

      token->num_keys = cnt;
      err = ck->f->C_FindObjectsFinal (token->session);
      if (err)
        {
          return -1;
        }
    }
  return 0;
}

static long
check_public_keys (struct token *token)
{
  unsigned long err = 0;
  struct cryptoki *ck = token->ck;

  struct ck_attribute templ[8];

  unsigned char label[256];
  unsigned long class;
  unsigned long keytype;
  unsigned char id[256];

  ck_object_handle_t obj;
  int i;

  class = CKO_PUBLIC_KEY;
  templ[0].type = CKA_CLASS;
  templ[0].pValue = (void *)&class;
  templ[0].ulValueLen = sizeof (class);

  err = ck->f->C_FindObjectsInit (token->session, templ, 1);
  if (!err)
    {
      while (TRUE)
        {
          unsigned long any;
          struct key *k = NULL;

          /* Portable way to get objects... is get it one by one.  */
          err = ck->f->C_FindObjects (token->session, &obj, 1, &any);
          if (err || any == 0)
            break;

          templ[0].type = CKA_LABEL;
          templ[0].pValue = (void *)label;
          templ[0].ulValueLen = sizeof (label);

          templ[1].type = CKA_KEY_TYPE;
          templ[1].pValue = &keytype;
          templ[1].ulValueLen = sizeof (keytype);

          templ[2].type = CKA_ID;
          templ[2].pValue = (void *)id;
          templ[2].ulValueLen = sizeof (id);

          err = ck->f->C_GetAttributeValue (token->session, obj, templ, 3);
          if (err)
            {
              continue;
            }

          label[templ[0].ulValueLen] = 0;
          id[templ[2].ulValueLen] = 0;

          /* Locate matching private key.  */
          for (i = 0; i < token->num_keys; i++)
            {
              k = &token->key_list[i];

              if ((k->flags & KEY_FLAGS_NO_PUBKEY)
                  && k->label_len == templ[0].ulValueLen
                  && memcmp (label, k->label, k->label_len) == 0
                  && ((keytype == CKK_RSA && k->key_type == KEY_RSA)
                      || (keytype == CKK_EC && k->key_type == KEY_EC))
                  && k->id_len == templ[2].ulValueLen
                  && memcmp (id, k->id, k->id_len) == 0)
                break;
            }

          if (i == token->num_keys)
            continue;

          log_debug ("pub: slot: %lx handle: %ld label: %s key_type: %ld id: %s\n",
                  token->slot_id, obj, label, keytype, id);

          if (examine_public_key (token, k, keytype, 0, obj))
            continue;
        }

      err = ck->f->C_FindObjectsFinal (token->session);
      if (err)
        {
          return -1;
        }
    }
  return 0;
}

#if 0
static long
get_certificate (struct token *token)
{
  unsigned long err = 0;
  struct cryptoki *ck = token->ck;

  struct ck_attribute templ[1];

  unsigned long class;
  unsigned char certificate[4096];
  unsigned long cert_len;
  int certificate_available;

  ck_object_handle_t obj;
  int i;

  class = CKO_CERTIFICATE;
  templ[0].type = CKA_CLASS;
  templ[0].pValue = (void *)&class;
  templ[0].ulValueLen = sizeof (class);

  err = ck->f->C_FindObjectsInit (token->session, templ, 1);
  if (!err)
    {
      while (TRUE)
        {
          unsigned long any;

          /* Portable way to get objects... is get it one by one.  */
          err = ck->f->C_FindObjects (token->session, &obj, 1, &any);
          if (err || any == 0)
            break;

          templ[0].type = CKA_VALUE;
          templ[0].pValue = (void *)certificate;
          templ[0].ulValueLen = sizeof (certificate);
          err = ck->f->C_GetAttributeValue (token->session, obj, templ, 1);
          if (err)
            certificate_available = 0;
          else
            {
              certificate_available = 1;
              cert_len = templ[0].ulValueLen;

              puts ("Certificate available:");
              for (i = 0; i < cert_len; i++)
                {
                  printf ("%02x", certificate[i]);
                  if ((i % 16) == 15)
                    puts ("");
                }
              puts ("");
            }
        }

      err = ck->f->C_FindObjectsFinal (token->session);
      if (err)
        {
          return -1;
        }
    }

  return 0;
}
#endif

static long
learn_keys (struct token *token)
{
  int i;

  /* Detect private keys on the token.
   * It's good if it also offers raw public key material.
   */
  detect_private_keys (token);

  /*
   * In some implementations (EC key on SoftHSMv2, for example),
   * attributes for raw public key material is not available in
   * a CKO_PRIVATE_KEY object.
   *
   * We try to examine CKO_PUBLIC_KEY objects, too see if it provides
   * raw public key material in a CKO_PUBLIC_KEY object.
   */
  check_public_keys (token);

  for (i = 0; i < token->num_keys; i++)
    {
      struct key *k = &token->key_list[i];

      if ((k->flags & KEY_FLAGS_NO_PUBKEY))
        k->flags &= ~KEY_FLAGS_NO_PUBKEY;
    }

#if 0
  /* Another way to get raw public key material is get it from the
     certificate, if available. */
  get_certificate (token);
#endif

  return 0;
}


static long
find_key (struct cryptoki *ck, const char *keygrip, struct key **r_key)
{
  int i;
  int j;

  *r_key = NULL;
  for (i = 0; i < ck->num_slots; i++)
    {
      struct token *token = &ck->token_list[i];

      if (!token->valid)
	continue;

      for (j = 0; j < token->num_keys; j++)
        {
          struct key *k = &token->key_list[j];

          if ((k->flags & KEY_FLAGS_VALID) == 0)
            continue;

          if (memcmp (k->keygrip, keygrip, 40) == 0)
            {
              *r_key = k;
              log_debug ("found a key at %d:%d\n", i, j);
              return 0;
            }
        }
    }

  return -1;
}

struct iter_key {
  struct cryptoki *ck;
  int i;
  int j;
  unsigned long mask;
  int st;
};

static void
iter_find_key_setup (struct iter_key *iter, struct cryptoki *ck, int cap)
{
  iter->st = 0;
  iter->ck = ck;
  iter->i = 0;
  iter->j = 0;
  iter->mask = 0;
  if (cap == GCRY_PK_USAGE_SIGN)
    iter->mask |= KEY_FLAGS_USAGE_SIGN;
  else if (cap == GCRY_PK_USAGE_ENCR)
    iter->mask = KEY_FLAGS_USAGE_DECRYPT;
  else
    iter->mask = KEY_FLAGS_USAGE_SIGN | KEY_FLAGS_USAGE_DECRYPT;
}

static int
iter_find_key (struct iter_key *iter, struct key **r_key)
{
  struct cryptoki *ck = iter->ck;
  struct token *token;
  struct key *k;

  *r_key = NULL;

  if (iter->i < ck->num_slots)
    token = &ck->token_list[iter->i];
  else
    token = NULL;

  switch (iter->st)
    while (1)
      {
      case 0:
	if (iter->i < ck->num_slots)
	  {
	    token = &ck->token_list[iter->i++];
	    if (!token->valid)
	      continue;
	  }
	else
	  {
	    iter->st = 2;
	    /*FALLTHROUGH*/
	    default:
	    return 0;
	  }

	iter->j = 0;
	while (1)
	  {
	    /*FALLTHROUGH*/
	  case 1:
	    if (token && iter->j < token->num_keys)
	      {
		k = &token->key_list[iter->j++];
		if ((k->flags & KEY_FLAGS_VALID) && (k->flags & iter->mask))
		  {
		    /* Found */
		    *r_key = k;
		    iter->st = 1;
		    return 1;
		  }
	      }
	    else
	      break;
	  }
      }
}

static gpg_error_t
do_pksign (struct key *key, int hash_algo,
           const unsigned char *u_data, unsigned long u_data_len,
           unsigned char **r_signature,
           unsigned long *r_signature_len)
{
  gpg_error_t err = 0;
  unsigned long r = 0;
  struct token *token = key->token;
  struct cryptoki *ck = token->ck;
  ck_mechanism_type_t mechanism;
  struct ck_mechanism mechanism_struct;
  unsigned char data[1024];
  unsigned long data_len;
  unsigned int nbits;
  unsigned long siglen;
  unsigned char *sig;

  nbits = gcry_pk_get_nbits (key->pubkey);

  mechanism = key->mechanism;
  if (key->key_type == KEY_RSA)
    {
      size_t asnlen = sizeof (data);

      /* It's CKM_RSA_PKCS, it requires that hash algo OID included in
         the data to be signed.  */
      if (!hash_algo)
        return gpg_error (GPG_ERR_DIGEST_ALGO);

      siglen = (nbits+7)/8;
      gcry_md_get_asnoid (hash_algo, data, &asnlen);
      gcry_md_hash_buffer (hash_algo, data+asnlen,
                           u_data, u_data_len);
      data_len = asnlen+gcry_md_get_algo_dlen (hash_algo);
    }
  else if (key->key_type == KEY_EC)
    {
      siglen = ((nbits+7)/8) * 2;
      if (mechanism == CKM_ECDSA)
        {
          /* SoftHSMv2 */
          memcpy (data, u_data, u_data_len);
          data_len = u_data_len;
        }
      else
        {
          if (!hash_algo)
            {
              /* Not specified by user, determine from MECHANISM */
              if (mechanism == CKM_ECDSA_SHA256)
                hash_algo = GCRY_MD_SHA256;
              else if (mechanism == CKM_ECDSA_SHA384)
                hash_algo = GCRY_MD_SHA384;
              else if (mechanism == CKM_ECDSA_SHA384)
                hash_algo = GCRY_MD_SHA512;
              else
                return gpg_error (GPG_ERR_DIGEST_ALGO);
            }

          /* Scute, YKCS11 */
          gcry_md_hash_buffer (hash_algo, data, u_data, u_data_len);
          data_len = gcry_md_get_algo_dlen (hash_algo);
        }
    }
  else if (key->key_type == KEY_EDDSA)
    {
      mechanism = CKM_EDDSA;
      siglen = ((nbits+7)/8)*2;
      memcpy (data, u_data, u_data_len);
      data_len = u_data_len;
    }
  else
    return gpg_error (GPG_ERR_BAD_SECKEY);

  mechanism_struct.mechanism = mechanism;
  mechanism_struct.parameter = NULL;
  mechanism_struct.parameter_len = 0;

  r = ck->f->C_SignInit (token->session, &mechanism_struct,
                         key->p11_keyid);
  if (r)
    {
      log_error ("C_SignInit error: %ld", r);
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }

  sig = xtrymalloc (siglen);
  if (!sig)
    {
      return gpg_error_from_syserror ();
    }

  *r_signature_len = siglen;

  r = ck->f->C_Sign (token->session,
                     data, data_len,
                     sig, r_signature_len);
  if (r)
    {
      xfree (sig);
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }

  *r_signature = sig;

  return err;
}

#define ENVNAME "PKCS11_MODULE"

gpg_error_t
token_slotlist (ctrl_t ctrl, assuan_context_t ctx)
{
  gpg_error_t err = 0;

  long r;
  struct cryptoki *ck = ck_instance;
  unsigned long num_slots = MAX_SLOTS;
  ck_slot_id_t  slot_list[MAX_SLOTS];
  int i;
  int num_tokens = 0;

  const char *module_name;

  (void)ctrl;
  (void)ctx;
  module_name = opt.pkcs11_driver;
  if (!module_name)
    return gpg_error (GPG_ERR_NO_NAME);

  r = get_function_list (ck, module_name);
  if (r)
    {
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }

  r = get_slot_list (ck, &num_slots, slot_list);
  if (r)
    {
      return gpg_error (GPG_ERR_INV_RESPONSE);
    }

  for (i = 0; i < num_slots; i++)
    {
      struct ck_token_info tk_info;
      struct token *token = &ck->token_list[num_tokens]; /* Allocate one token in CK */

      token->ck = ck;
      token->valid = 0;
      token->slot_id = slot_list[i];

      if (get_token_info (token, &tk_info) == 0)
        {
          if ((tk_info.flags & CKF_TOKEN_INITIALIZED) == 0
              || (tk_info.flags & CKF_USER_PIN_LOCKED) != 0)
            continue;

          token->login_required = (tk_info.flags & CKF_LOGIN_REQUIRED);

          r = open_session (token);
          if (r)
            {
              log_error ("Error at open_session: %ld\n", r);
              continue;
            }

#if 0/*INQUIRE PIN and use the pin*/
          /* XXX: Support each PIN for each token.  */
          if (token->login_required && pin)
            login (token, pin, pin_len);
#endif

          num_tokens++;
	  r = learn_keys (token);
        }
    }

  ck->num_slots = num_tokens;

  return err;
}

gpg_error_t
token_sign (ctrl_t ctrl, assuan_context_t ctx,
            const char *keygrip, int hash_algo,
            unsigned char **r_outdata,
            size_t *r_outdatalen)
{
  gpg_error_t err;
  struct key *k;
  struct cryptoki *ck = ck_instance;
  unsigned long r;

  (void)ctrl;
  /* mismatch: size_t for GnuPG, unsigned long for PKCS#11 */
  /* mismatch: application prepare buffer for PKCS#11 */

  r = find_key (ck, keygrip, &k);
  if (r)
    return gpg_error (GPG_ERR_NO_SECKEY);
  else
    {
      const char *cmd;
      unsigned char *value;
      size_t valuelen;

      cmd = "VALUE";
      err = assuan_inquire (ctx, cmd, &value, &valuelen, MAXLEN_VALUE);
      if (err)
        return err;

      err = do_pksign (k, hash_algo, value, valuelen, r_outdata, r_outdatalen);
      wipememory (value, valuelen);
      xfree (value);
      if (err)
        return err;
    }

  return err;
}

gpg_error_t
token_readkey (ctrl_t ctrl, assuan_context_t ctx,
               const char *keygrip, int opt_info,
               unsigned char **r_pk,
               size_t *r_pklen)
{
  gpg_error_t err = 0;
  (void)ctrl;
  return err;
}

gpg_error_t
token_keyinfo (ctrl_t ctrl, const char *keygrip, int opt_data, int cap)
{
  gpg_error_t err = 0;
  struct cryptoki *ck = ck_instance;
  struct key *k;
  const char *usage;

  if (keygrip)
    {
      unsigned long r;

      r = find_key (ck, keygrip, &k);
      if (r)
        return gpg_error (GPG_ERR_NO_SECKEY);

      if ((k->flags & KEY_FLAGS_USAGE_SIGN))
        {
          if ((k->flags & KEY_FLAGS_USAGE_DECRYPT))
            usage = "se";
          else
            usage = "s";
        }
      else
        {
          if ((k->flags & KEY_FLAGS_USAGE_DECRYPT))
            usage = "e";
          else
            usage = "-";
        }

      send_keyinfo (ctrl, opt_data, keygrip,
                    k->label_len ? (const char *)k->label : "-",
                    k->id_len ? (const char *)k->id : "-",
                    usage);
    }
  else
    {
      struct iter_key iter;

      iter_find_key_setup (&iter, ck, cap);
      while (iter_find_key (&iter, &k))
	{
	  if ((k->flags & KEY_FLAGS_USAGE_SIGN))
	    {
	      if ((k->flags & KEY_FLAGS_USAGE_DECRYPT))
		usage = "se";
	      else
		usage = "s";
	    }
	  else
	    {
	      if ((k->flags & KEY_FLAGS_USAGE_DECRYPT))
		usage = "e";
	      else
		usage = "-";
	    }

	  send_keyinfo (ctrl, opt_data, k->keygrip,
			k->label_len ? (const char *)k->label : "-",
			k->id_len ? (const char *)k->id : "-",
			usage);
	}
    }

  return err;
}
