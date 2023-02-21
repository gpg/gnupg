#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <gcrypt.h>

#include "pkcs11.h"

/*
 * For now, we don't COMPUTE_KEYGRIP, assuming Scute.
 * ... which used the ID as keygrip.
 */

#ifdef COMPUTE_KEYGRIP
static void
compute_keygrip_rsa (char *keygrip,
                     const char *modulus,  unsigned long modulus_len,
                     const char *exponent,  unsigned long exponent_len)
{
  ;
}

static void
compute_keygrip_ec (char *keygrip,
                    const char *oid, unsigned long oid_len,
                    const char *ecpoint, unsigned long ecpoing_len)
{
  ;
}
#endif

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
#define KEYGRIP_LEN (40+1)

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

struct key {
  struct token *token;  /* Back pointer.  */
  int valid;
  ck_object_handle_t p11_keyid;
  char keygrip[KEYGRIP_LEN];
  int key_type;
  /* Possibly, ID, LABEL, etc.  */
  /* Allowed mechanisms???  */
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

static struct p11dev priv;

static unsigned long
notify_cb (ck_session_handle_t session,
           ck_notification_t event, void *application)
{
  struct p11dev *priv = application;

  (void)priv;
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
  int option = 0;

  session_flags = CKU_USER;
  // session_flags = session_flags | CKF_RW_SESSION;
  session_flags = session_flags | CKF_SERIAL_SESSION;

  err = ck->f->C_OpenSession (slot_id, session_flags,
                              (void *)&priv, notify_cb, &session_handle);
  if (err)
    {
      printf ("open_session: %d\n", err);
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

static long
detect_key (int try_private, struct token *token)
{
  unsigned long err = 0;
  struct cryptoki *ck = token->ck;

  struct ck_attribute templ[8];

  unsigned char label[256];
  unsigned long class;
  unsigned long key_type;
  unsigned long mechanisms[3];
  unsigned char id[256];
  unsigned char modulus[1024];
  unsigned char exponent[8];
  unsigned char ecparams[256];
  unsigned char ecpoint[256];

  unsigned long cnt = 0;
  ck_object_handle_t obj;
  int i;

  if (try_private)
    class = CKO_PRIVATE_KEY;
  else
    class = CKO_PUBLIC_KEY;
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
          k->valid = 0;

          /* Portable way to get objects... is get it one by one.  */
          err = ck->f->C_FindObjects (token->session, &obj, 1, &any);
          if (err || any == 0)
            break;

          templ[0].type = CKA_LABEL;
          templ[0].pValue = (void *)label;
          templ[0].ulValueLen = sizeof (label);

          templ[1].type = CKA_KEY_TYPE;
          templ[1].pValue = &key_type;
          templ[1].ulValueLen = sizeof (key_type);

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

          printf ("handle: %ld label: %s key_type: %d id: %s\n",
                  obj, label, key_type, id);

          templ[0].type = CKA_ALLOWED_MECHANISMS;
          templ[0].pValue = (void *)mechanisms;
          templ[0].ulValueLen = sizeof (mechanisms);

          if (key_type == CKK_RSA)
            {
              templ[1].type = CKA_MODULUS;
              templ[1].pValue = (void *)modulus;
              templ[1].ulValueLen = sizeof (modulus);

              templ[2].type = CKA_PUBLIC_EXPONENT;
              templ[2].pValue = (void *)exponent;
              templ[2].ulValueLen = sizeof (exponent);

              err = ck->f->C_GetAttributeValue (token->session, obj, templ, 3);
              if (err)
                {
                  continue;
                }

              /* Found a RSA key.  */
              printf ("RSA: %d %d %d\n",
                      templ[0].ulValueLen,
                      templ[1].ulValueLen,
                      templ[2].ulValueLen);
              puts ("Public key:");
              for (i = 0; i < templ[1].ulValueLen; i++)
                {
                  printf ("%02x", modulus[i]);
                  if ((i % 16) == 15)
                    puts ("");
                }
              puts ("");

              k->valid = 1;
              k->p11_keyid = obj;
              k->key_type = KEY_RSA;
#ifdef COMPUTE_KEYGRIP
              compute_keygrip_rsa (k->keygrip,
                                   modulus, templ[0].ulValueLen,
                                   exponent, templ[1].ulValueLen);
#else
              memcpy (k->keygrip, id, 40);
              k->keygrip[40] = 0;
#endif
              cnt++;
            }
          else if (key_type == CKK_EC)
            {
              templ[1].type = CKA_EC_PARAMS;
              templ[1].pValue = ecparams;
              templ[1].ulValueLen = sizeof (ecparams);

              templ[2].type = CKA_EC_POINT;
              templ[2].pValue = (void *)ecpoint;
              templ[2].ulValueLen = sizeof (ecpoint);

              err = ck->f->C_GetAttributeValue (token->session, obj, templ, 3);
              if (err)
                {
                  continue;
                }

              /* Found an ECC key.  */
              printf ("ECC: %d %d %d\n",
                      templ[0].ulValueLen,
                      templ[1].ulValueLen,
                      templ[2].ulValueLen);
              puts ("Public key:");
              for (i = 0; i < templ[2].ulValueLen; i++)
                {
                  printf ("%02x", ecpoint[i]);
                  if ((i % 16) == 15)
                    puts ("");
                }
              puts ("");

              k->valid = 1;
              k->p11_keyid = obj;
              k->key_type = KEY_EC;
#ifdef COMPUTE_KEYGRIP
              compute_keygrip_ec (k->keygrip,
                                  ecparams, templ[1].ulValueLen,
                                  ecpoint, templ[2].ulValueLen);
#else
              memcpy (k->keygrip, id, 40);
              k->keygrip[40] = 0;
#endif
              cnt++;
            }
        }

      token->num_keys = cnt;
      err = ck->f->C_FindObjectsFinal (token->session);
      if (err)
        {
          return -1;
        }
    }
}

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

static long
learn_keys (struct token *token)
{
  unsigned long err = 0;

  detect_key (1, token);
#if 0
  if (token->num_keys == 0)
    detect_key (0, token);
#endif
  get_certificate (token);

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

      for (j = 0; j < token->num_keys; j++)
        {
          struct key *k = &token->key_list[j];

          if (memcmp (k->keygrip, keygrip, 40) == 0)
            {
              *r_key = k;
              return 0;
            }
        }
    }

  return -1;
}

static long
do_pksign (struct key *key,
           const unsigned char *u_data, unsigned long u_data_len,
           unsigned char *r_signature,
           unsigned long *r_signature_len)
{
  unsigned long err = 0;
  struct token *token = key->token;
  struct cryptoki *ck = token->ck;
  ck_mechanism_type_t mechanism;
  struct ck_mechanism mechanism_struct;
  unsigned char data[1024];
  unsigned long data_len;

  if (key->key_type == KEY_RSA)
    {
      size_t asnlen = sizeof (data);

      gcry_md_get_asnoid (GCRY_MD_SHA256, data, &asnlen);
      gcry_md_hash_buffer (GCRY_MD_SHA256, data+asnlen,
                           u_data, u_data_len);
      data_len = asnlen+gcry_md_get_algo_dlen (GCRY_MD_SHA256);

      mechanism = CKM_RSA_PKCS;
    }
  else if (key->key_type == KEY_EC)
    mechanism = CKM_ECDSA_SHA256;
  else if (key->key_type == KEY_EDDSA)
    mechanism = CKM_EDDSA;

  mechanism_struct.mechanism = mechanism;
  mechanism_struct.parameter = NULL;
  mechanism_struct.parameter_len = 0;

  err = ck->f->C_SignInit (token->session, &mechanism_struct,
                           key->p11_keyid);

  err = ck->f->C_Sign (token->session,
                       data, data_len,
                       r_signature, r_signature_len);
  if (err)
    return err;

  return 0;
}


int
main (int argc, const char *argv[])
{
  long r;
  struct cryptoki *ck = ck_instance;
  unsigned long num_slots = MAX_SLOTS;
  ck_slot_id_t  slot_list[MAX_SLOTS];
  int i;
  const unsigned char *pin = NULL;
  int pin_len = -1;
  const char *keygrip = NULL;
  int num_tokens = 0;

  r = get_function_list (ck, argv[1]);
  if (r)
    {
      return 1;
    }

  if (argc >= 3)
    keygrip = argv[2];

  if (argc >= 4)
    {
      pin = argv[3];
      pin_len = strlen (argv[3]);
    }

  r = get_slot_list (ck, &num_slots, slot_list);
  if (r)
    {
      return 1;
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
              printf ("Error at open_session: %d\n", r);
              continue;
            }

          /* XXX: Support each PIN for each token.  */
          if (pin)
            login (token, pin, pin_len);

	  puts ("************");
          num_tokens++;
	  r = learn_keys (token);
        }
    }

  ck->num_slots = num_tokens;

  if (keygrip)
    {
      struct key *k;

      r = find_key (ck, keygrip, &k);
      if (!r)
        {
          unsigned char sig[1024];
          unsigned long siglen = sizeof (sig);

          r = do_pksign (k, "test test", 9, sig, &siglen);
          if (!r)
            {
              int i;

              for (i = 0; i < siglen; i++)
                printf ("%02x", sig[i]);
              puts ("");
            }
        }
    }

  for (i = 0; i < num_slots; i++)
    {
      struct token *token = &ck->token_list[i];

      close_session (token);
    }

  ck->f->C_Finalize (NULL);
  return 0;
}

/*
cc -g -o test_tk pksign.c -lgcrypt
./test_tk /usr/lib/softhsm/libsofthsm2.so <KEYGRIP> 5678
./test_tk /usr/local/lib/x86_64-linux-gnu/scute.so <KEYGRIP>
 */
