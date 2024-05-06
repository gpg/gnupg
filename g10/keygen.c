/* keygen.c - Generate a key pair
 * Copyright (C) 1998-2007, 2009-2011  Free Software Foundation, Inc.
 * Copyright (C) 2014, 2015, 2016  Werner Koch
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
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gpg.h"
#include "../common/util.h"
#include "main.h"
#include "packet.h"
#include "../common/ttyio.h"
#include "options.h"
#include "keydb.h"
#include "trustdb.h"
#include "../common/status.h"
#include "../common/i18n.h"
#include "keyserver-internal.h"
#include "call-agent.h"
#include "pkglue.h"
#include "../common/shareddefs.h"
#include "../common/host2net.h"
#include "../common/mbox-util.h"


/* The default algorithms. You should also check that the value
   is inside the bounds enforced by ask_keysize and gen_xxx.  See also
   get_keysize_range which encodes the allowed ranges.  */
#define DEFAULT_STD_KEY_PARAM  "rsa3072/cert,sign+rsa3072/encr"
#define FUTURE_STD_KEY_PARAM   "ed25519/cert,sign+cv25519/encr"

/* When generating keys using the streamlined key generation dialog,
   use this as a default expiration interval.  */
const char *default_expiration_interval = "3y";

/* Flag bits used during key generation.  */
#define KEYGEN_FLAG_NO_PROTECTION 1
#define KEYGEN_FLAG_TRANSIENT_KEY 2

/* Maximum number of supported algorithm preferences.  */
#define MAX_PREFS 30

enum para_name {
  pKEYTYPE,
  pKEYLENGTH,
  pKEYCURVE,
  pKEYUSAGE,
  pSUBKEYTYPE,
  pSUBKEYLENGTH,
  pSUBKEYCURVE,
  pSUBKEYUSAGE,
  pAUTHKEYTYPE,
  pNAMEREAL,
  pNAMEEMAIL,
  pNAMECOMMENT,
  pPREFERENCES,
  pREVOKER,
  pUSERID,
  pCREATIONDATE,
  pKEYCREATIONDATE, /* Same in seconds since epoch.  */
  pEXPIREDATE,
  pKEYEXPIRE, /* in n seconds */
  pSUBKEYEXPIRE, /* in n seconds */
  pPASSPHRASE,
  pSERIALNO,
  pCARDBACKUPKEY,
  pHANDLE,
  pKEYSERVER,
  pKEYGRIP,
  pSUBKEYGRIP,
};

struct para_data_s {
    struct para_data_s *next;
    int lnr;
    enum para_name key;
    union {
        u32 expire;
        u32 creation;
        unsigned int usage;
        struct revocation_key revkey;
        char value[1];
    } u;
};

struct output_control_s
{
  int lnr;
  int dryrun;
  unsigned int keygen_flags;
  int use_files;
  struct {
    char  *fname;
    char  *newfname;
    IOBUF stream;
    armor_filter_context_t *afx;
  } pub;
};


struct opaque_data_usage_and_pk
{
  unsigned int usage;
  const char *cpl_notation;
  PKT_public_key *pk;
};


static int prefs_initialized = 0;
static byte sym_prefs[MAX_PREFS];
static int nsym_prefs;
static byte hash_prefs[MAX_PREFS];
static int nhash_prefs;
static byte zip_prefs[MAX_PREFS];
static int nzip_prefs;
static int mdc_available,ks_modify;
static int aead_available;


static gpg_error_t parse_algo_usage_expire (ctrl_t ctrl, int for_subkey,
                                     const char *algostr, const char *usagestr,
                                     const char *expirestr,
                                     int *r_algo, unsigned int *r_usage,
                                     u32 *r_expire, unsigned int *r_nbits,
                                     const char **r_curve,
                                     char **r_keygrip);
static void do_generate_keypair (ctrl_t ctrl, struct para_data_s *para,
                                 struct output_control_s *outctrl, int card );
static int write_keyblock (iobuf_t out, kbnode_t node);
static gpg_error_t gen_card_key (int keyno, int algo, int is_primary,
                                 kbnode_t pub_root, u32 *timestamp,
                                 u32 expireval);
static unsigned int get_keysize_range (int algo,
                                       unsigned int *min, unsigned int *max);
static void do_add_notation (PKT_signature *sig,
                             const char *name, const char *value,
                             int critical);



/* Return the algo string for a default new key.  */
const char *
get_default_pubkey_algo (void)
{
  if (opt.def_new_key_algo)
    {
      if (*opt.def_new_key_algo && !strchr (opt.def_new_key_algo, ':'))
        return opt.def_new_key_algo;
      /* To avoid checking that option every time we delay that until
       * here.  The only thing we really need to make sure is that
       * there is no colon in the string so that the --gpgconf-list
       * command won't mess up its output.  */
      log_info (_("invalid value for option '%s'\n"), "--default-new-key-algo");
    }
  return DEFAULT_STD_KEY_PARAM;
}


static void
print_status_key_created (int letter, PKT_public_key *pk, const char *handle)
{
  byte array[MAX_FINGERPRINT_LEN], *s;
  char *buf, *p;
  size_t i, n;

  if (!handle)
    handle = "";

  buf = xmalloc (MAX_FINGERPRINT_LEN*2+31 + strlen (handle) + 1);

  p = buf;
  if (letter || pk)
    {
      *p++ = letter;
      if (pk)
        {
          *p++ = ' ';
          fingerprint_from_pk (pk, array, &n);
          s = array;
          /* Fixme: Use bin2hex */
          for (i=0; i < n ; i++, s++, p += 2)
            snprintf (p, 3, "%02X", *s);
        }
    }
  if (*handle)
    {
      *p++ = ' ';
      for (i=0; handle[i] && i < 100; i++)
        *p++ = isspace ((unsigned int)handle[i])? '_':handle[i];
    }
  *p = 0;
  write_status_text ((letter || pk)?STATUS_KEY_CREATED:STATUS_KEY_NOT_CREATED,
                     buf);
  xfree (buf);
}

static void
print_status_key_not_created (const char *handle)
{
  print_status_key_created (0, NULL, handle);
}



static gpg_error_t
write_uid (kbnode_t root, const char *s)
{
  PACKET *pkt = xmalloc_clear (sizeof *pkt);
  size_t n = strlen (s);

  if (n > MAX_UID_PACKET_LENGTH - 10)
    return gpg_error (GPG_ERR_INV_USER_ID);

  pkt->pkttype = PKT_USER_ID;
  pkt->pkt.user_id = xmalloc_clear (sizeof *pkt->pkt.user_id + n);
  pkt->pkt.user_id->len = n;
  pkt->pkt.user_id->ref = 1;
  strcpy (pkt->pkt.user_id->name, s);
  add_kbnode (root, new_kbnode (pkt));
  return 0;
}

static void
do_add_key_flags (PKT_signature *sig, unsigned int use)
{
    byte buf[1];

    buf[0] = 0;

    /* The spec says that all primary keys MUST be able to certify. */
    if(sig->sig_class!=0x18)
      buf[0] |= 0x01;

    if (use & PUBKEY_USAGE_SIG)
      buf[0] |= 0x02;
    if (use & PUBKEY_USAGE_ENC)
        buf[0] |= 0x04 | 0x08;
    if (use & PUBKEY_USAGE_AUTH)
        buf[0] |= 0x20;

    build_sig_subpkt (sig, SIGSUBPKT_KEY_FLAGS, buf, 1);
}


int
keygen_add_key_expire (PKT_signature *sig, void *opaque)
{
  PKT_public_key *pk = opaque;
  byte buf[8];
  u32  u;

  if (pk->expiredate)
    {
      if (pk->expiredate > pk->timestamp)
        u = pk->expiredate - pk->timestamp;
      else
        u = 1;

      buf[0] = (u >> 24) & 0xff;
      buf[1] = (u >> 16) & 0xff;
      buf[2] = (u >>  8) & 0xff;
      buf[3] = u & 0xff;
      build_sig_subpkt (sig, SIGSUBPKT_KEY_EXPIRE, buf, 4);
    }
  else
    {
      /* Make sure we don't leave a key expiration subpacket lying
         around */
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE);
    }

  return 0;
}


/* Add the key usage (i.e. key flags) in SIG from the public keys
 * pubkey_usage field.  OPAQUE has the public key.  */
int
keygen_add_key_flags (PKT_signature *sig, void *opaque)
{
  PKT_public_key *pk = opaque;

  do_add_key_flags (sig, pk->pubkey_usage);
  return 0;
}


/* This is only used to write the key binding signature.  It is not
 * used for the primary key.  */
static int
keygen_add_key_flags_and_expire (PKT_signature *sig, void *opaque)
{
  struct opaque_data_usage_and_pk *oduap = opaque;

  do_add_key_flags (sig, oduap->usage);
  if (oduap->cpl_notation)
    do_add_notation (sig, "cpl@gnupg.org", oduap->cpl_notation, 0);
  return keygen_add_key_expire (sig, oduap->pk);
}


static int
set_one_pref (int val, int type, const char *item, byte *buf, int *nbuf)
{
    int i;

    for (i=0; i < *nbuf; i++ )
      if (buf[i] == val)
	{
	  log_info (_("preference '%s' duplicated\n"), item);
	  return -1;
        }

    if (*nbuf >= MAX_PREFS)
      {
	if(type==1)
	  log_info(_("too many cipher preferences\n"));
	else if(type==2)
	  log_info(_("too many digest preferences\n"));
	else if(type==3)
	  log_info(_("too many compression preferences\n"));
	else
	  BUG();

        return -1;
      }

    buf[(*nbuf)++] = val;
    return 0;
}

/*
 * Parse the supplied string and use it to set the standard
 * preferences.  The string may be in a form like the one printed by
 * "pref" (something like: "S10 S3 H3 H2 Z2 Z1") or the actual
 * cipher/hash/compress names.  Use NULL to set the default
 * preferences.  Returns: 0 = okay
 */
int
keygen_set_std_prefs (const char *string,int personal)
{
    byte sym[MAX_PREFS], hash[MAX_PREFS], zip[MAX_PREFS];
    int nsym=0, nhash=0, nzip=0, val, rc=0;
    int mdc=1, modify=0; /* mdc defaults on, modify defaults off. */
    int ocb;
    char dummy_string[20*4+1]; /* Enough for 20 items. */

    /* Use OCB as default in GnuPG and de-vs mode.  */
    ocb = GNUPG;

    if (!string || !ascii_strcasecmp (string, "default"))
      {
	if (opt.def_preference_list)
	  string=opt.def_preference_list;
	else
	  {
            int any_compress = 0;
	    dummy_string[0]='\0';

            /* The rationale why we use the order AES256,192,128 is
               for compatibility reasons with PGP.  If gpg would
               define AES128 first, we would get the somewhat
               confusing situation:

                 gpg -r pgpkey -r gpgkey  ---gives--> AES256
                 gpg -r gpgkey -r pgpkey  ---gives--> AES

               Note that by using --personal-cipher-preferences it is
               possible to prefer AES128.
            */

	    /* Make sure we do not add more than 15 items here, as we
	       could overflow the size of dummy_string.  We currently
	       have at most 12. */
	    if ( !openpgp_cipher_test_algo (CIPHER_ALGO_AES256) )
	      strcat(dummy_string,"S9 ");
	    if ( !openpgp_cipher_test_algo (CIPHER_ALGO_AES192) )
	      strcat(dummy_string,"S8 ");
	    if ( !openpgp_cipher_test_algo (CIPHER_ALGO_AES) )
	      strcat(dummy_string,"S7 ");
	    strcat(dummy_string,"S2 "); /* 3DES */

            if (personal)
              {
                /* The default internal hash algo order is:
                 *  SHA-256, SHA-384, SHA-512, SHA-224, SHA-1.
                 */
                if (!openpgp_md_test_algo (DIGEST_ALGO_SHA256))
                  strcat (dummy_string, "H8 ");

                if (!openpgp_md_test_algo (DIGEST_ALGO_SHA384))
                  strcat (dummy_string, "H9 ");

                if (!openpgp_md_test_algo (DIGEST_ALGO_SHA512))
                  strcat (dummy_string, "H10 ");
              }
            else
              {
                /* The default advertised hash algo order is:
                 *  SHA-512, SHA-384, SHA-256, SHA-224, SHA-1.
                 */
                if (!openpgp_md_test_algo (DIGEST_ALGO_SHA512))
                  strcat (dummy_string, "H10 ");

                if (!openpgp_md_test_algo (DIGEST_ALGO_SHA384))
                  strcat (dummy_string, "H9 ");

                if (!openpgp_md_test_algo (DIGEST_ALGO_SHA256))
                  strcat (dummy_string, "H8 ");
              }

            if (!openpgp_md_test_algo (DIGEST_ALGO_SHA224))
	      strcat (dummy_string, "H11 ");

	    strcat (dummy_string, "H2 "); /* SHA-1 */

	    if(!check_compress_algo(COMPRESS_ALGO_ZLIB))
              {
                strcat(dummy_string,"Z2 ");
                any_compress = 1;
              }

	    if(!check_compress_algo(COMPRESS_ALGO_BZIP2))
              {
                strcat(dummy_string,"Z3 ");
                any_compress = 1;
              }

	    if(!check_compress_algo(COMPRESS_ALGO_ZIP))
              {
                strcat(dummy_string,"Z1 ");
                any_compress = 1;
              }

            /* In case we have no compress algo at all, declare that
               we prefer no compresssion.  */
            if (!any_compress)
              strcat(dummy_string,"Z0 ");

            /* Remove the trailing space.  */
            if (*dummy_string && dummy_string[strlen (dummy_string)-1] == ' ')
              dummy_string[strlen (dummy_string)-1] = 0;

	    string=dummy_string;
	  }
      }
    else if (!ascii_strcasecmp (string, "none"))
        string = "";

    if(strlen(string))
      {
	char *prefstringbuf;
        char *tok, *prefstring;

        /* We need a writable string. */
	prefstring = prefstringbuf = xstrdup (string);

	while((tok=strsep(&prefstring," ,")))
	  {
	    if((val=string_to_cipher_algo (tok)))
	      {
		if(set_one_pref(val,1,tok,sym,&nsym))
		  rc=-1;
	      }
	    else if((val=string_to_digest_algo (tok)))
	      {
		if(set_one_pref(val,2,tok,hash,&nhash))
		  rc=-1;
	      }
	    else if((val=string_to_compress_algo(tok))>-1)
	      {
		if(set_one_pref(val,3,tok,zip,&nzip))
		  rc=-1;
	      }
	    else if (!ascii_strcasecmp(tok, "mdc")
                     || !ascii_strcasecmp(tok, "[mdc]"))
	      mdc=1;
	    else if (!ascii_strcasecmp(tok, "no-mdc")
                     || !ascii_strcasecmp(tok, "[no-mdc]"))
	      mdc=0;
	    else if (!ascii_strcasecmp(tok, "ks-modify")
                     || !ascii_strcasecmp(tok, "[ks-modify]"))
	      modify=1;
	    else if (!ascii_strcasecmp(tok,"no-ks-modify")
                     || !ascii_strcasecmp(tok,"[no-ks-modify]"))
	      modify=0;
	    else if (!ascii_strcasecmp(tok,"aead")
                     || !ascii_strcasecmp(tok,"[aead]"))
              ocb = 1;
	    else if (!ascii_strcasecmp(tok,"no-aead")
                     || !ascii_strcasecmp(tok,"[no-aead]"))
              ocb = 0;
	    else
	      {
		log_info (_("invalid item '%s' in preference string\n"),tok);
		rc=-1;
	      }
	  }

	xfree (prefstringbuf);
      }

    if(!rc)
      {
	if(personal)
	  {
	    if(personal==PREFTYPE_SYM)
	      {
		xfree(opt.personal_cipher_prefs);

		if(nsym==0)
		  opt.personal_cipher_prefs=NULL;
		else
		  {
		    int i;

		    opt.personal_cipher_prefs=
		      xmalloc(sizeof(prefitem_t *)*(nsym+1));

		    for (i=0; i<nsym; i++)
		      {
			opt.personal_cipher_prefs[i].type = PREFTYPE_SYM;
			opt.personal_cipher_prefs[i].value = sym[i];
		      }

		    opt.personal_cipher_prefs[i].type = PREFTYPE_NONE;
		    opt.personal_cipher_prefs[i].value = 0;
		  }
	      }
	    else if(personal==PREFTYPE_HASH)
	      {
		xfree(opt.personal_digest_prefs);

		if(nhash==0)
		  opt.personal_digest_prefs=NULL;
		else
		  {
		    int i;

		    opt.personal_digest_prefs=
		      xmalloc(sizeof(prefitem_t *)*(nhash+1));

		    for (i=0; i<nhash; i++)
		      {
			opt.personal_digest_prefs[i].type = PREFTYPE_HASH;
			opt.personal_digest_prefs[i].value = hash[i];
		      }

		    opt.personal_digest_prefs[i].type = PREFTYPE_NONE;
		    opt.personal_digest_prefs[i].value = 0;
		  }
	      }
	    else if(personal==PREFTYPE_ZIP)
	      {
		xfree(opt.personal_compress_prefs);

		if(nzip==0)
		  opt.personal_compress_prefs=NULL;
		else
		  {
		    int i;

		    opt.personal_compress_prefs=
		      xmalloc(sizeof(prefitem_t *)*(nzip+1));

		    for (i=0; i<nzip; i++)
		      {
			opt.personal_compress_prefs[i].type = PREFTYPE_ZIP;
			opt.personal_compress_prefs[i].value = zip[i];
		      }

		    opt.personal_compress_prefs[i].type = PREFTYPE_NONE;
		    opt.personal_compress_prefs[i].value = 0;
		  }
	      }
	  }
	else
	  {
	    memcpy (sym_prefs,  sym,  (nsym_prefs=nsym));
	    memcpy (hash_prefs, hash, (nhash_prefs=nhash));
	    memcpy (zip_prefs,  zip,  (nzip_prefs=nzip));
	    mdc_available = mdc;
            aead_available = ocb;
	    ks_modify = modify;
	    prefs_initialized = 1;
	  }
      }

    return rc;
}


/* Return a fake user ID containing the preferences.  Caller must
   free. */
PKT_user_id *
keygen_get_std_prefs(void)
{
  int i,j=0;
  PKT_user_id *uid=xmalloc_clear(sizeof(PKT_user_id));

  if(!prefs_initialized)
    keygen_set_std_prefs(NULL,0);

  uid->ref=1;

  uid->prefs=xmalloc((sizeof(prefitem_t *)*
		      (nsym_prefs+nhash_prefs+nzip_prefs+1)));

  for(i=0;i<nsym_prefs;i++,j++)
    {
      uid->prefs[j].type=PREFTYPE_SYM;
      uid->prefs[j].value=sym_prefs[i];
    }

  for(i=0;i<nhash_prefs;i++,j++)
    {
      uid->prefs[j].type=PREFTYPE_HASH;
      uid->prefs[j].value=hash_prefs[i];
    }

  for(i=0;i<nzip_prefs;i++,j++)
    {
      uid->prefs[j].type=PREFTYPE_ZIP;
      uid->prefs[j].value=zip_prefs[i];
    }

  uid->prefs[j].type=PREFTYPE_NONE;
  uid->prefs[j].value=0;

  uid->flags.mdc=mdc_available;
  uid->flags.aead=aead_available;
  uid->flags.ks_modify=ks_modify;

  return uid;
}

static void
add_feature_mdc (PKT_signature *sig,int enabled)
{
    const byte *s;
    size_t n;
    int i;
    char *buf;

    s = parse_sig_subpkt (sig->hashed, SIGSUBPKT_FEATURES, &n );
    /* Already set or cleared */
    if (s && n &&
	((enabled && (s[0] & 0x01)) || (!enabled && !(s[0] & 0x01))))
      return;

    if (!s || !n) { /* create a new one */
        n = 1;
        buf = xmalloc_clear (n);
    }
    else {
        buf = xmalloc (n);
        memcpy (buf, s, n);
    }

    if(enabled)
      buf[0] |= 0x01; /* MDC feature */
    else
      buf[0] &= ~0x01;

    /* Are there any bits set? */
    for(i=0;i<n;i++)
      if(buf[i]!=0)
	break;

    if(i==n)
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_FEATURES);
    else
      build_sig_subpkt (sig, SIGSUBPKT_FEATURES, buf, n);

    xfree (buf);
}


static void
add_feature_aead (PKT_signature *sig, int enabled)
{
  const byte *s;
  size_t n;
  int i;
  char *buf;

  s = parse_sig_subpkt (sig->hashed, SIGSUBPKT_FEATURES, &n );
  if (s && n && ((enabled && (s[0] & 0x02)) || (!enabled && !(s[0] & 0x02))))
    return; /* Already set or cleared */

  if (!s || !n)
    { /* Create a new one */
      n = 1;
      buf = xmalloc_clear (n);
    }
  else
    {
      buf = xmalloc (n);
      memcpy (buf, s, n);
    }

  if (enabled)
    buf[0] |= 0x02; /* AEAD supported */
  else
    buf[0] &= ~0x02;

  /* Are there any bits set? */
  for (i=0; i < n; i++)
    if (buf[i])
      break;

  if (i == n)
    delete_sig_subpkt (sig->hashed, SIGSUBPKT_FEATURES);
  else
    build_sig_subpkt (sig, SIGSUBPKT_FEATURES, buf, n);

  xfree (buf);
}


static void
add_keyserver_modify (PKT_signature *sig,int enabled)
{
  const byte *s;
  size_t n;
  int i;
  char *buf;

  /* The keyserver modify flag is a negative flag (i.e. no-modify) */
  enabled=!enabled;

  s = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KS_FLAGS, &n );
  /* Already set or cleared */
  if (s && n &&
      ((enabled && (s[0] & 0x80)) || (!enabled && !(s[0] & 0x80))))
    return;

  if (!s || !n) { /* create a new one */
    n = 1;
    buf = xmalloc_clear (n);
  }
  else {
    buf = xmalloc (n);
    memcpy (buf, s, n);
  }

  if(enabled)
    buf[0] |= 0x80; /* no-modify flag */
  else
    buf[0] &= ~0x80;

  /* Are there any bits set? */
  for(i=0;i<n;i++)
    if(buf[i]!=0)
      break;

  if(i==n)
    delete_sig_subpkt (sig->hashed, SIGSUBPKT_KS_FLAGS);
  else
    build_sig_subpkt (sig, SIGSUBPKT_KS_FLAGS, buf, n);

  xfree (buf);
}


int
keygen_upd_std_prefs (PKT_signature *sig, void *opaque)
{
  (void)opaque;

  if (!prefs_initialized)
    keygen_set_std_prefs (NULL, 0);

  if (nsym_prefs)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_SYM, sym_prefs, nsym_prefs);
  else
    {
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_SYM);
      delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PREF_SYM);
    }

  if (aead_available) /* The only preference is AEAD_ALGO_OCB. */
    build_sig_subpkt (sig, SIGSUBPKT_PREF_AEAD, "\x02", 1);
  else
    {
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_AEAD);
      delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PREF_AEAD);
    }

  if (nhash_prefs)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_HASH, hash_prefs, nhash_prefs);
  else
    {
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_HASH);
      delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PREF_HASH);
    }

  if (nzip_prefs)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_COMPR, zip_prefs, nzip_prefs);
  else
    {
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_COMPR);
      delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PREF_COMPR);
    }

  /* Make sure that the MDC and AEAD feature flags are set as needed.  */
  add_feature_mdc (sig,mdc_available);
  add_feature_aead (sig, aead_available);
  add_keyserver_modify (sig,ks_modify);
  keygen_add_keyserver_url(sig,NULL);

  return 0;
}


/****************
 * Add preference to the self signature packet.
 * This is only called for packets with version > 3.
 */
int
keygen_add_std_prefs (PKT_signature *sig, void *opaque)
{
  PKT_public_key *pk = opaque;

  do_add_key_flags (sig, pk->pubkey_usage);
  keygen_add_key_expire (sig, opaque );
  keygen_upd_std_prefs (sig, opaque);
  keygen_add_keyserver_url (sig,NULL);

  return 0;
}

int
keygen_add_keyserver_url(PKT_signature *sig, void *opaque)
{
  const char *url=opaque;

  if(!url)
    url=opt.def_keyserver_url;

  if(url)
    build_sig_subpkt(sig,SIGSUBPKT_PREF_KS,url,strlen(url));
  else
    delete_sig_subpkt (sig->hashed,SIGSUBPKT_PREF_KS);

  return 0;
}


/* This function is used to add a notations to a signature.  In
 * general the caller should have cleared exiting notations before
 * adding new ones.  For example by calling:
 *
 *  delete_sig_subpkt(sig->hashed,SIGSUBPKT_NOTATION);
 *  delete_sig_subpkt(sig->unhashed,SIGSUBPKT_NOTATION);
 *
 * Only human readable notaions may be added.  NAME and value are
 * expected to be UTF-* strings.
 */
static void
do_add_notation (PKT_signature *sig, const char *name, const char *value,
                 int critical)
{
  unsigned char *buf;
  unsigned int n1,n2;

  n1 = strlen (name);
  n2 = strlen (value);

  buf = xmalloc (8 + n1 + n2);

  buf[0] = 0x80; /* human readable.  */
  buf[1] = buf[2] = buf[3] = 0;
  buf[4] = n1 >> 8;
  buf[5] = n1;
  buf[6] = n2 >> 8;
  buf[7] = n2;
  memcpy (buf+8, name, n1);
  memcpy (buf+8+n1, value, n2);
  build_sig_subpkt (sig,
                    (SIGSUBPKT_NOTATION|(critical?SIGSUBPKT_FLAG_CRITICAL:0)),
                    buf, 8+n1+n2 );
  xfree (buf);
}


int
keygen_add_notations(PKT_signature *sig,void *opaque)
{
  struct notation *notation;

  /* We always start clean */
  delete_sig_subpkt(sig->hashed,SIGSUBPKT_NOTATION);
  delete_sig_subpkt(sig->unhashed,SIGSUBPKT_NOTATION);
  sig->flags.notation=0;

  for(notation=opaque;notation;notation=notation->next)
    if(!notation->flags.ignore)
      {
	unsigned char *buf;
	unsigned int n1,n2;

	n1=strlen(notation->name);
	if(notation->altvalue)
	  n2=strlen(notation->altvalue);
	else if(notation->bdat)
	  n2=notation->blen;
	else
	  n2=strlen(notation->value);

	buf = xmalloc( 8 + n1 + n2 );

	/* human readable or not */
	buf[0] = notation->bdat?0:0x80;
	buf[1] = buf[2] = buf[3] = 0;
	buf[4] = n1 >> 8;
	buf[5] = n1;
	buf[6] = n2 >> 8;
	buf[7] = n2;
	memcpy(buf+8, notation->name, n1 );
	if(notation->altvalue)
	  memcpy(buf+8+n1, notation->altvalue, n2 );
	else if(notation->bdat)
	  memcpy(buf+8+n1, notation->bdat, n2 );
	else
	  memcpy(buf+8+n1, notation->value, n2 );
	build_sig_subpkt( sig, SIGSUBPKT_NOTATION |
			  (notation->flags.critical?SIGSUBPKT_FLAG_CRITICAL:0),
			  buf, 8+n1+n2 );
	xfree(buf);
      }

  return 0;
}


int
keygen_add_revkey (PKT_signature *sig, void *opaque)
{
  struct revocation_key *revkey = opaque;
  byte buf[2+MAX_FINGERPRINT_LEN];

  buf[0] = revkey->class;
  buf[1] = revkey->algid;
  memcpy (&buf[2], revkey->fpr, MAX_FINGERPRINT_LEN);

  build_sig_subpkt (sig, SIGSUBPKT_REV_KEY, buf, 2+MAX_FINGERPRINT_LEN);

  /* All sigs with revocation keys set are nonrevocable.  */
  sig->flags.revocable = 0;
  buf[0] = 0;
  build_sig_subpkt (sig, SIGSUBPKT_REVOCABLE, buf, 1);

  parse_revkeys (sig);

  return 0;
}



/* Create a back-signature.  If TIMESTAMP is not NULL, use it for the
   signature creation time.  */
gpg_error_t
make_backsig (ctrl_t ctrl, PKT_signature *sig, PKT_public_key *pk,
              PKT_public_key *sub_pk, PKT_public_key *sub_psk,
              u32 timestamp, const char *cache_nonce)
{
  gpg_error_t err;
  PKT_signature *backsig;

  cache_public_key (sub_pk);

  err = make_keysig_packet (ctrl, &backsig, pk, NULL, sub_pk, sub_psk, 0x19,
                            0, timestamp, 0, NULL, NULL, cache_nonce);
  if (err)
    log_error ("make_keysig_packet failed for backsig: %s\n",
               gpg_strerror (err));
  else
    {
      /* Get it into a binary packed form. */
      IOBUF backsig_out = iobuf_temp();
      PACKET backsig_pkt;

      init_packet (&backsig_pkt);
      backsig_pkt.pkttype = PKT_SIGNATURE;
      backsig_pkt.pkt.signature = backsig;
      err = build_packet (backsig_out, &backsig_pkt);
      free_packet (&backsig_pkt, NULL);
      if (err)
	log_error ("build_packet failed for backsig: %s\n", gpg_strerror (err));
      else
	{
	  size_t pktlen = 0;
	  byte *buf = iobuf_get_temp_buffer (backsig_out);

	  /* Remove the packet header. */
	  if(buf[0]&0x40)
	    {
	      if (buf[1] < 192)
		{
		  pktlen = buf[1];
		  buf += 2;
		}
	      else if(buf[1] < 224)
		{
		  pktlen = (buf[1]-192)*256;
		  pktlen += buf[2]+192;
		  buf += 3;
		}
	      else if (buf[1] == 255)
		{
                  pktlen = buf32_to_size_t (buf+2);
		  buf += 6;
		}
	      else
		BUG ();
	    }
	  else
	    {
	      int mark = 1;

	      switch (buf[0]&3)
		{
		case 3:
		  BUG ();
		  break;

		case 2:
		  pktlen  = (size_t)buf[mark++] << 24;
		  pktlen |= buf[mark++] << 16;
		  /* fall through */
		case 1:
		  pktlen |= buf[mark++] << 8;
		  /* fall through */
		case 0:
		  pktlen |= buf[mark++];
		}

	      buf += mark;
	    }

	  /* Now make the binary blob into a subpacket.  */
	  build_sig_subpkt (sig, SIGSUBPKT_SIGNATURE, buf, pktlen);

	  iobuf_close (backsig_out);
	}
    }

  return err;
}


/* Write a direct key signature to the first key in ROOT using the key
   PSK.  REVKEY is describes the direct key signature and TIMESTAMP is
   the timestamp to set on the signature.  */
static gpg_error_t
write_direct_sig (ctrl_t ctrl, kbnode_t root, PKT_public_key *psk,
                  struct revocation_key *revkey, u32 timestamp,
                  const char *cache_nonce)
{
  gpg_error_t err;
  PACKET *pkt;
  PKT_signature *sig;
  KBNODE node;
  PKT_public_key *pk;

  if (opt.verbose)
    log_info (_("writing direct signature\n"));

  /* Get the pk packet from the pub_tree. */
  node = find_kbnode (root, PKT_PUBLIC_KEY);
  if (!node)
    BUG ();
  pk = node->pkt->pkt.public_key;

  /* We have to cache the key, so that the verification of the
     signature creation is able to retrieve the public key.  */
  cache_public_key (pk);

  /* Make the signature.  */
  err = make_keysig_packet (ctrl, &sig, pk, NULL,NULL, psk, 0x1F,
                            0, timestamp, 0,
                            keygen_add_revkey, revkey, cache_nonce);
  if (err)
    {
      log_error ("make_keysig_packet failed: %s\n", gpg_strerror (err) );
      return err;
    }

  pkt = xmalloc_clear (sizeof *pkt);
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  add_kbnode (root, new_kbnode (pkt));
  return err;
}



/* Write a self-signature to the first user id in ROOT using the key
   PSK.  USE and TIMESTAMP give the extra data we need for the
   signature.  */
static gpg_error_t
write_selfsigs (ctrl_t ctrl, kbnode_t root, PKT_public_key *psk,
		unsigned int use, u32 timestamp, const char *cache_nonce)
{
  gpg_error_t err;
  PACKET *pkt;
  PKT_signature *sig;
  PKT_user_id *uid;
  KBNODE node;
  PKT_public_key *pk;

  if (opt.verbose)
    log_info (_("writing self signature\n"));

  /* Get the uid packet from the list. */
  node = find_kbnode (root, PKT_USER_ID);
  if (!node)
    BUG(); /* No user id packet in tree.  */
  uid = node->pkt->pkt.user_id;

  /* Get the pk packet from the pub_tree. */
  node = find_kbnode (root, PKT_PUBLIC_KEY);
  if (!node)
    BUG();
  pk = node->pkt->pkt.public_key;

  /* The usage has not yet been set - do it now. */
  pk->pubkey_usage = use;

  /* We have to cache the key, so that the verification of the
     signature creation is able to retrieve the public key.  */
  cache_public_key (pk);

  /* Make the signature.  */
  err = make_keysig_packet (ctrl, &sig, pk, uid, NULL, psk, 0x13,
                            0, timestamp, 0,
                            keygen_add_std_prefs, pk, cache_nonce);
  if (err)
    {
      log_error ("make_keysig_packet failed: %s\n", gpg_strerror (err));
      return err;
    }

  pkt = xmalloc_clear (sizeof *pkt);
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  add_kbnode (root, new_kbnode (pkt));

  return err;
}


/* Write the key binding signature.  If TIMESTAMP is not NULL use the
   signature creation time.  PRI_PSK is the key use for signing.
   SUB_PSK is a key used to create a back-signature; that one is only
   used if USE has the PUBKEY_USAGE_SIG capability.  */
static int
write_keybinding (ctrl_t ctrl, kbnode_t root,
                  PKT_public_key *pri_psk, PKT_public_key *sub_psk,
                  unsigned int use, u32 timestamp, const char *cache_nonce)
{
  gpg_error_t err;
  PACKET *pkt;
  PKT_signature *sig;
  KBNODE node;
  PKT_public_key *pri_pk, *sub_pk;
  struct opaque_data_usage_and_pk oduap;

  if (opt.verbose)
    log_info(_("writing key binding signature\n"));

  /* Get the primary pk packet from the tree.  */
  node = find_kbnode (root, PKT_PUBLIC_KEY);
  if (!node)
    BUG();
  pri_pk = node->pkt->pkt.public_key;

  /* We have to cache the key, so that the verification of the
   * signature creation is able to retrieve the public key.  */
  cache_public_key (pri_pk);

  /* Find the last subkey. */
  sub_pk = NULL;
  for (node = root; node; node = node->next )
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        sub_pk = node->pkt->pkt.public_key;
    }
  if (!sub_pk)
    BUG();

  /* Make the signature.  */
  oduap.usage = use;
  if ((use & PUBKEY_USAGE_ENC)
      && opt.compliance == CO_DE_VS
      && gnupg_rng_is_compliant (CO_DE_VS))
    oduap.cpl_notation = "de-vs";
  else
    oduap.cpl_notation = NULL;
  oduap.pk = sub_pk;
  err = make_keysig_packet (ctrl, &sig, pri_pk, NULL, sub_pk, pri_psk, 0x18,
                            0, timestamp, 0,
                            keygen_add_key_flags_and_expire, &oduap,
                            cache_nonce);
  if (err)
    {
      log_error ("make_keysig_packeto failed: %s\n", gpg_strerror (err));
      return err;
    }

  /* Make a backsig.  */
  if (use & PUBKEY_USAGE_SIG)
    {
      err = make_backsig (ctrl,
                          sig, pri_pk, sub_pk, sub_psk, timestamp, cache_nonce);
      if (err)
        return err;
    }

  pkt = xmalloc_clear ( sizeof *pkt );
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  add_kbnode (root, new_kbnode (pkt) );
  return err;
}


static gpg_error_t
ecckey_from_sexp (gcry_mpi_t *array, gcry_sexp_t sexp, int algo)
{
  gpg_error_t err;
  gcry_sexp_t list, l2;
  char *curve = NULL;
  int i;
  const char *oidstr;
  unsigned int nbits;

  array[0] = NULL;
  array[1] = NULL;
  array[2] = NULL;

  list = gcry_sexp_find_token (sexp, "public-key", 0);
  if (!list)
    return gpg_error (GPG_ERR_INV_OBJ);
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (!list)
    return gpg_error (GPG_ERR_NO_OBJ);

  l2 = gcry_sexp_find_token (list, "curve", 0);
  if (!l2)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }
  curve = gcry_sexp_nth_string (l2, 1);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }
  gcry_sexp_release (l2);
  oidstr = openpgp_curve_to_oid (curve, &nbits, NULL);
  if (!oidstr)
    {
      /* That can't happen because we used one of the curves
         gpg_curve_to_oid knows about.  */
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  err = openpgp_oid_from_str (oidstr, &array[0]);
  if (err)
    goto leave;

  l2 = gcry_sexp_find_token (list, "q", 0);
  if (!l2)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }
  array[1] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l2);
  if (!array[1])
    {
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  gcry_sexp_release (list);

  if (algo == PUBKEY_ALGO_ECDH)
    {
      array[2] = pk_ecdh_default_params (nbits);
      if (!array[2])
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

 leave:
  xfree (curve);
  if (err)
    {
      for (i=0; i < 3; i++)
        {
          gcry_mpi_release (array[i]);
          array[i] = NULL;
        }
    }
  return err;
}


/* Extract key parameters from SEXP and store them in ARRAY.  ELEMS is
   a string where each character denotes a parameter name.  TOPNAME is
   the name of the top element above the elements.  */
static int
key_from_sexp (gcry_mpi_t *array, gcry_sexp_t sexp,
               const char *topname, const char *elems)
{
  gcry_sexp_t list, l2;
  const char *s;
  int i, idx;
  int rc = 0;

  list = gcry_sexp_find_token (sexp, topname, 0);
  if (!list)
    return gpg_error (GPG_ERR_INV_OBJ);
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (!list)
    return gpg_error (GPG_ERR_NO_OBJ);

  for (idx=0,s=elems; *s; s++, idx++)
    {
      l2 = gcry_sexp_find_token (list, s, 1);
      if (!l2)
        {
          rc = gpg_error (GPG_ERR_NO_OBJ); /* required parameter not found */
          goto leave;
        }
      array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l2);
      if (!array[idx])
        {
          rc = gpg_error (GPG_ERR_INV_OBJ); /* required parameter invalid */
          goto leave;
        }
    }
  gcry_sexp_release (list);

 leave:
  if (rc)
    {
      for (i=0; i<idx; i++)
        {
          gcry_mpi_release (array[i]);
          array[i] = NULL;
        }
      gcry_sexp_release (list);
    }
  return rc;
}


/* Create a keyblock using the given KEYGRIP.  ALGO is the OpenPGP
   algorithm of that keygrip.  */
static int
do_create_from_keygrip (ctrl_t ctrl, int algo, const char *hexkeygrip,
                        kbnode_t pub_root, u32 timestamp, u32 expireval,
                        int is_subkey)
{
  int err;
  PACKET *pkt;
  PKT_public_key *pk;
  gcry_sexp_t s_key;
  const char *algoelem;

  if (hexkeygrip[0] == '&')
    hexkeygrip++;

  switch (algo)
    {
    case PUBKEY_ALGO_RSA:       algoelem = "ne"; break;
    case PUBKEY_ALGO_DSA:       algoelem = "pqgy"; break;
    case PUBKEY_ALGO_ELGAMAL_E: algoelem = "pgy"; break;
    case PUBKEY_ALGO_ECDH:
    case PUBKEY_ALGO_ECDSA:     algoelem = ""; break;
    case PUBKEY_ALGO_EDDSA:     algoelem = ""; break;
    default: return gpg_error (GPG_ERR_INTERNAL);
    }


  /* Ask the agent for the public key matching HEXKEYGRIP.  */
  {
    unsigned char *public;

    err = agent_readkey (ctrl, 0, hexkeygrip, &public);
    if (err)
      return err;
    err = gcry_sexp_sscan (&s_key, NULL,
                           public, gcry_sexp_canon_len (public, 0, NULL, NULL));
    xfree (public);
    if (err)
      return err;
  }

  /* Build a public key packet.  */
  pk = xtrycalloc (1, sizeof *pk);
  if (!pk)
    {
      err = gpg_error_from_syserror ();
      gcry_sexp_release (s_key);
      return err;
    }

  pk->timestamp = timestamp;
  pk->version = 4;
  if (expireval)
    pk->expiredate = pk->timestamp + expireval;
  pk->pubkey_algo = algo;

  if (algo == PUBKEY_ALGO_ECDSA
      || algo == PUBKEY_ALGO_EDDSA
      || algo == PUBKEY_ALGO_ECDH )
    err = ecckey_from_sexp (pk->pkey, s_key, algo);
  else
    err = key_from_sexp (pk->pkey, s_key, "public-key", algoelem);
  if (err)
    {
      log_error ("key_from_sexp failed: %s\n", gpg_strerror (err) );
      gcry_sexp_release (s_key);
      free_public_key (pk);
      return err;
    }
  gcry_sexp_release (s_key);

  pkt = xtrycalloc (1, sizeof *pkt);
  if (!pkt)
    {
      err = gpg_error_from_syserror ();
      free_public_key (pk);
      return err;
    }

  pkt->pkttype = is_subkey ? PKT_PUBLIC_SUBKEY : PKT_PUBLIC_KEY;
  pkt->pkt.public_key = pk;
  add_kbnode (pub_root, new_kbnode (pkt));

  return 0;
}


/* Common code for the key generation function gen_xxx.  */
static int
common_gen (const char *keyparms, int algo, const char *algoelem,
            kbnode_t pub_root, u32 timestamp, u32 expireval, int is_subkey,
            int keygen_flags, const char *passphrase,
            char **cache_nonce_addr, char **passwd_nonce_addr)
{
  int err;
  PACKET *pkt;
  PKT_public_key *pk;
  gcry_sexp_t s_key;

  err = agent_genkey (NULL, cache_nonce_addr, passwd_nonce_addr, keyparms,
                      !!(keygen_flags & KEYGEN_FLAG_NO_PROTECTION),
                      passphrase, timestamp,
                      &s_key);
  if (err)
    {
      log_error ("agent_genkey failed: %s\n", gpg_strerror (err) );
      return err;
    }

  pk = xtrycalloc (1, sizeof *pk);
  if (!pk)
    {
      err = gpg_error_from_syserror ();
      gcry_sexp_release (s_key);
      return err;
    }

  pk->timestamp = timestamp;
  pk->version = 4;
  if (expireval)
    pk->expiredate = pk->timestamp + expireval;
  pk->pubkey_algo = algo;

  if (algo == PUBKEY_ALGO_ECDSA
      || algo == PUBKEY_ALGO_EDDSA
      || algo == PUBKEY_ALGO_ECDH )
    err = ecckey_from_sexp (pk->pkey, s_key, algo);
  else
    err = key_from_sexp (pk->pkey, s_key, "public-key", algoelem);
  if (err)
    {
      log_error ("key_from_sexp failed: %s\n", gpg_strerror (err) );
      gcry_sexp_release (s_key);
      free_public_key (pk);
      return err;
    }
  gcry_sexp_release (s_key);

  pkt = xtrycalloc (1, sizeof *pkt);
  if (!pkt)
    {
      err = gpg_error_from_syserror ();
      free_public_key (pk);
      return err;
    }

  pkt->pkttype = is_subkey ? PKT_PUBLIC_SUBKEY : PKT_PUBLIC_KEY;
  pkt->pkt.public_key = pk;
  add_kbnode (pub_root, new_kbnode (pkt));

  return 0;
}


/*
 * Generate an Elgamal key.
 */
static int
gen_elg (int algo, unsigned int nbits, KBNODE pub_root,
         u32 timestamp, u32 expireval, int is_subkey,
         int keygen_flags, const char *passphrase,
         char **cache_nonce_addr, char **passwd_nonce_addr)
{
  int err;
  char *keyparms;
  char nbitsstr[35];

  log_assert (is_ELGAMAL (algo));

  if (nbits < 1024)
    {
      nbits = 2048;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }
  else if (nbits > 4096)
    {
      nbits = 4096;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }

  if ((nbits % 32))
    {
      nbits = ((nbits + 31) / 32) * 32;
      log_info (_("keysize rounded up to %u bits\n"), nbits );
    }

  /* Note that we use transient-key only if no-protection has also
     been enabled.  */
  snprintf (nbitsstr, sizeof nbitsstr, "%u", nbits);
  keyparms = xtryasprintf ("(genkey(%s(nbits %zu:%s)%s))",
                           algo == GCRY_PK_ELG_E ? "openpgp-elg" :
                           algo == GCRY_PK_ELG	 ? "elg" : "x-oops" ,
                           strlen (nbitsstr), nbitsstr,
                           ((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
                            && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
                           "(transient-key)" : "" );
  if (!keyparms)
    err = gpg_error_from_syserror ();
  else
    {
      err = common_gen (keyparms, algo, "pgy",
                        pub_root, timestamp, expireval, is_subkey,
                        keygen_flags, passphrase,
                        cache_nonce_addr, passwd_nonce_addr);
      xfree (keyparms);
    }

  return err;
}


/*
 * Generate an DSA key
 */
static gpg_error_t
gen_dsa (unsigned int nbits, KBNODE pub_root,
         u32 timestamp, u32 expireval, int is_subkey,
         int keygen_flags, const char *passphrase,
         char **cache_nonce_addr, char **passwd_nonce_addr)
{
  int err;
  unsigned int qbits;
  char *keyparms;
  char nbitsstr[35];
  char qbitsstr[35];

  if (nbits < 768)
    {
      nbits = 2048;
      log_info(_("keysize invalid; using %u bits\n"), nbits );
    }
  else if ( nbits > 3072 )
    {
      nbits = 3072;
      log_info(_("keysize invalid; using %u bits\n"), nbits );
    }

  if( (nbits % 64) )
    {
      nbits = ((nbits + 63) / 64) * 64;
      log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

  /* To comply with FIPS rules we round up to the next value unless in
     expert mode.  */
  if (!opt.expert && nbits > 1024 && (nbits % 1024))
    {
      nbits = ((nbits + 1023) / 1024) * 1024;
      log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

  /*
    Figure out a q size based on the key size.  FIPS 180-3 says:

    L = 1024, N = 160
    L = 2048, N = 224
    L = 2048, N = 256
    L = 3072, N = 256

    2048/256 is an odd pair since there is also a 2048/224 and
    3072/256.  Matching sizes is not a very exact science.

    We'll do 256 qbits for nbits over 2047, 224 for nbits over 1024
    but less than 2048, and 160 for 1024 (DSA1).
  */

  if (nbits > 2047)
    qbits = 256;
  else if ( nbits > 1024)
    qbits = 224;
  else
    qbits = 160;

  if (qbits != 160 )
    log_info (_("WARNING: some OpenPGP programs can't"
                " handle a DSA key with this digest size\n"));

  snprintf (nbitsstr, sizeof nbitsstr, "%u", nbits);
  snprintf (qbitsstr, sizeof qbitsstr, "%u", qbits);
  keyparms = xtryasprintf ("(genkey(dsa(nbits %zu:%s)(qbits %zu:%s)%s))",
                           strlen (nbitsstr), nbitsstr,
                           strlen (qbitsstr), qbitsstr,
                           ((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
                            && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
                           "(transient-key)" : "" );
  if (!keyparms)
    err = gpg_error_from_syserror ();
  else
    {
      err = common_gen (keyparms, PUBKEY_ALGO_DSA, "pqgy",
                        pub_root, timestamp, expireval, is_subkey,
                        keygen_flags, passphrase,
                        cache_nonce_addr, passwd_nonce_addr);
      xfree (keyparms);
    }

  return err;
}



/*
 * Generate an ECC key
 */
static gpg_error_t
gen_ecc (int algo, const char *curve, kbnode_t pub_root,
         u32 timestamp, u32 expireval, int is_subkey,
         int keygen_flags, const char *passphrase,
         char **cache_nonce_addr, char **passwd_nonce_addr)
{
  gpg_error_t err;
  char *keyparms;

  log_assert (algo == PUBKEY_ALGO_ECDSA
              || algo == PUBKEY_ALGO_EDDSA
              || algo == PUBKEY_ALGO_ECDH);

  if (!curve || !*curve)
    return gpg_error (GPG_ERR_UNKNOWN_CURVE);

  /* Map the displayed short forms of some curves to their canonical
   * names. */
  if (!ascii_strcasecmp (curve, "cv25519"))
    curve = "Curve25519";
  else if (!ascii_strcasecmp (curve, "ed25519"))
    curve = "Ed25519";

  /* Note that we use the "comp" flag with EdDSA to request the use of
     a 0x40 compression prefix octet.  */
  if (algo == PUBKEY_ALGO_EDDSA)
    keyparms = xtryasprintf
      ("(genkey(ecc(curve %zu:%s)(flags eddsa comp%s)))",
       strlen (curve), curve,
       (((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
         && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
        " transient-key" : ""));
  else if (algo == PUBKEY_ALGO_ECDH && !strcmp (curve, "Curve25519"))
    keyparms = xtryasprintf
      ("(genkey(ecc(curve %zu:%s)(flags djb-tweak comp%s)))",
       strlen (curve), curve,
       (((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
         && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
        " transient-key" : ""));
  else
    keyparms = xtryasprintf
      ("(genkey(ecc(curve %zu:%s)(flags nocomp%s)))",
       strlen (curve), curve,
       (((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
         && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
        " transient-key" : ""));

  if (!keyparms)
    err = gpg_error_from_syserror ();
  else
    {
      err = common_gen (keyparms, algo, "",
                        pub_root, timestamp, expireval, is_subkey,
                        keygen_flags, passphrase,
                        cache_nonce_addr, passwd_nonce_addr);
      xfree (keyparms);
    }

  return err;
}


/*
 * Generate an RSA key.
 */
static int
gen_rsa (int algo, unsigned int nbits, KBNODE pub_root,
         u32 timestamp, u32 expireval, int is_subkey,
         int keygen_flags, const char *passphrase,
         char **cache_nonce_addr, char **passwd_nonce_addr)
{
  int err;
  char *keyparms;
  char nbitsstr[35];
  const unsigned maxsize = (opt.flags.large_rsa ? 8192 : 4096);

  log_assert (is_RSA(algo));

  if (!nbits)
    nbits = get_keysize_range (algo, NULL, NULL);

  if (nbits < 1024)
    {
      nbits = 3072;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }
  else if (nbits > maxsize)
    {
      nbits = maxsize;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }

  if ((nbits % 32))
    {
      nbits = ((nbits + 31) / 32) * 32;
      log_info (_("keysize rounded up to %u bits\n"), nbits );
    }

  snprintf (nbitsstr, sizeof nbitsstr, "%u", nbits);
  keyparms = xtryasprintf ("(genkey(rsa(nbits %zu:%s)%s))",
                           strlen (nbitsstr), nbitsstr,
                           ((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
                            && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
                           "(transient-key)" : "" );
  if (!keyparms)
    err = gpg_error_from_syserror ();
  else
    {
      err = common_gen (keyparms, algo, "ne",
                        pub_root, timestamp, expireval, is_subkey,
                        keygen_flags, passphrase,
                        cache_nonce_addr, passwd_nonce_addr);
      xfree (keyparms);
    }

  return err;
}


/****************
 * check valid days:
 * return 0 on error or the multiplier
 */
static int
check_valid_days( const char *s )
{
    if( !digitp(s) )
	return 0;
    for( s++; *s; s++)
	if( !digitp(s) )
	    break;
    if( !*s )
	return 1;
    if( s[1] )
	return 0; /* e.g. "2323wc" */
    if( *s == 'd' || *s == 'D' )
	return 1;
    if( *s == 'w' || *s == 'W' )
	return 7;
    if( *s == 'm' || *s == 'M' )
	return 30;
    if( *s == 'y' || *s == 'Y' )
	return 365;
    return 0;
}


static void
print_key_flags(int flags)
{
  if(flags&PUBKEY_USAGE_SIG)
    tty_printf("%s ",_("Sign"));

  if(flags&PUBKEY_USAGE_CERT)
    tty_printf("%s ",_("Certify"));

  if(flags&PUBKEY_USAGE_ENC)
    tty_printf("%s ",_("Encrypt"));

  if(flags&PUBKEY_USAGE_AUTH)
    tty_printf("%s ",_("Authenticate"));

  if(flags&PUBKEY_USAGE_RENC)
    tty_printf("%s ", "RENC");
}


/* Ask for the key flags and return them.  CURRENT gives the current
 * usage which should normally be given as 0.  MASK gives the allowed
 * flags.  */
unsigned int
ask_key_flags_with_mask (int algo, int subkey, unsigned int current,
                         unsigned int mask)
{
  /* TRANSLATORS: Please use only plain ASCII characters for the
   * translation.  If this is not possible use single digits.  The
   * string needs to 8 bytes long. Here is a description of the
   * functions:
   *
   *   s = Toggle signing capability
   *   e = Toggle encryption capability
   *   a = Toggle authentication capability
   *   q = Finish
   */
  const char *togglers = _("SsEeAaQq");
  char *answer = NULL;
  const char *s;
  unsigned int possible;

  if ( strlen(togglers) != 8 )
    {
      tty_printf ("NOTE: Bad translation at %s:%d. "
                  "Please report.\n", __FILE__, __LINE__);
      togglers = "11223300";
    }

  /* Mask the possible usage flags.  This is for example used for a
   * card based key.  For ECDH we need to allows additional usages if
   * they are provided.  RENC is not directly poissible here but see
   * below for a workaround. */
  possible = (openpgp_pk_algo_usage (algo) & mask);
  possible &= ~PUBKEY_USAGE_RENC;

  /* However, only primary keys may certify. */
  if (subkey)
    possible &= ~PUBKEY_USAGE_CERT;

  /* Preload the current set with the possible set, without
   * authentication if CURRENT is 0.  If CURRENT is non-zero we mask
   * with all possible usages.  */
  if (current)
    current &= possible;
  else
    current = (possible&~PUBKEY_USAGE_AUTH);

  for (;;)
    {
      tty_printf("\n");
      tty_printf(_("Possible actions for a %s key: "),
                 (algo == PUBKEY_ALGO_ECDSA
                  || algo == PUBKEY_ALGO_EDDSA)
                 ? "ECDSA/EdDSA" : openpgp_pk_algo_name (algo));
      print_key_flags(possible);
      tty_printf("\n");
      tty_printf(_("Current allowed actions: "));
      print_key_flags(current);
      tty_printf("\n\n");

      if(possible&PUBKEY_USAGE_SIG)
	tty_printf(_("   (%c) Toggle the sign capability\n"),
		   togglers[0]);
      if(possible&PUBKEY_USAGE_ENC)
	tty_printf(_("   (%c) Toggle the encrypt capability\n"),
		   togglers[2]);
      if(possible&PUBKEY_USAGE_AUTH)
	tty_printf(_("   (%c) Toggle the authenticate capability\n"),
		   togglers[4]);

      tty_printf(_("   (%c) Finished\n"),togglers[6]);
      tty_printf("\n");

      xfree(answer);
      answer = cpr_get("keygen.flags",_("Your selection? "));
      cpr_kill_prompt();

      if (*answer == '=')
        {
          /* Hack to allow direct entry of the capabilities.  */
          current = 0;
          for (s=answer+1; *s; s++)
            {
              if ((*s == 's' || *s == 'S') && (possible&PUBKEY_USAGE_SIG))
                current |= PUBKEY_USAGE_SIG;
              else if ((*s == 'e' || *s == 'E') && (possible&PUBKEY_USAGE_ENC))
                current |= PUBKEY_USAGE_ENC;
              else if ((*s == 'a' || *s == 'A') && (possible&PUBKEY_USAGE_AUTH))
                current |= PUBKEY_USAGE_AUTH;
              else if (!subkey && *s == 'c')
                {
                  /* Accept 'c' for the primary key because USAGE_CERT
                     will be set anyway.  This is for folks who
                     want to experiment with a cert-only primary key.  */
                  current |= PUBKEY_USAGE_CERT;
                }
              else if ((*s == 'r' || *s == 'R') && (possible&PUBKEY_USAGE_ENC))
                {
                  /* Allow to set RENC or an encryption capable key.
                   * This is on purpose not shown in the menu.  */
                  current |= PUBKEY_USAGE_RENC;
                }
            }
          break;
        }
      else if (strlen(answer)>1)
	tty_printf(_("Invalid selection.\n"));
      else if(*answer=='\0' || *answer==togglers[6] || *answer==togglers[7])
	break;
      else if((*answer==togglers[0] || *answer==togglers[1])
	      && possible&PUBKEY_USAGE_SIG)
	{
	  if(current&PUBKEY_USAGE_SIG)
	    current&=~PUBKEY_USAGE_SIG;
	  else
	    current|=PUBKEY_USAGE_SIG;
	}
      else if((*answer==togglers[2] || *answer==togglers[3])
	      && possible&PUBKEY_USAGE_ENC)
	{
	  if(current&PUBKEY_USAGE_ENC)
	    current&=~PUBKEY_USAGE_ENC;
	  else
	    current|=PUBKEY_USAGE_ENC;
	}
      else if((*answer==togglers[4] || *answer==togglers[5])
	      && possible&PUBKEY_USAGE_AUTH)
	{
	  if(current&PUBKEY_USAGE_AUTH)
	    current&=~PUBKEY_USAGE_AUTH;
	  else
	    current|=PUBKEY_USAGE_AUTH;
	}
      else
	tty_printf(_("Invalid selection.\n"));
    }

  xfree(answer);

  return current;
}


unsigned int
ask_key_flags (int algo, int subkey, unsigned int current)
{
  return ask_key_flags_with_mask (algo, subkey, current, ~0);
}


/* Check whether we have a key for the key with HEXGRIP.  Returns 0 if
   there is no such key or the OpenPGP algo number for the key.  */
static int
check_keygrip (ctrl_t ctrl, const char *hexgrip)
{
  gpg_error_t err;
  unsigned char *public;
  size_t publiclen;
  int algo;

  if (hexgrip[0] == '&')
    hexgrip++;

  err = agent_readkey (ctrl, 0, hexgrip, &public);
  if (err)
    return 0;
  publiclen = gcry_sexp_canon_len (public, 0, NULL, NULL);

  algo = get_pk_algo_from_canon_sexp (public, publiclen);
  xfree (public);

  return map_pk_gcry_to_openpgp (algo);
}



/* Ask for an algorithm.  The function returns the algorithm id to
 * create. If ADDMODE is false the function won't show an option to
 * create the primary and subkey combined and won't set R_USAGE
 * either.  If a combined algorithm has been selected, the subkey
 * algorithm is stored at R_SUBKEY_ALGO.  If R_KEYGRIP is given, the
 * user has the choice to enter the keygrip of an existing key.  That
 * keygrip is then stored at this address.  The caller needs to free
 * it. */
static int
ask_algo (ctrl_t ctrl, int addmode, int *r_subkey_algo, unsigned int *r_usage,
          char **r_keygrip)
{
  gpg_error_t err;
  char *keygrip = NULL;
  char *answer = NULL;
  int algo;
  int dummy_algo;
  char *p;

  if (!r_subkey_algo)
    r_subkey_algo = &dummy_algo;

  tty_printf (_("Please select what kind of key you want:\n"));

#if GPG_USE_RSA
  if (!addmode)
    tty_printf (_("   (%d) RSA and RSA (default)\n"), 1 );
#endif

  if (!addmode && opt.compliance != CO_DE_VS)
    tty_printf (_("   (%d) DSA and Elgamal\n"), 2 );

  if (opt.compliance != CO_DE_VS)
    tty_printf (_("   (%d) DSA (sign only)\n"), 3 );
#if GPG_USE_RSA
  tty_printf (_("   (%d) RSA (sign only)\n"), 4 );
#endif

  if (addmode)
    {
      if (opt.compliance != CO_DE_VS)
        tty_printf (_("   (%d) Elgamal (encrypt only)\n"), 5 );
#if GPG_USE_RSA
      tty_printf (_("   (%d) RSA (encrypt only)\n"), 6 );
#endif
    }
  if (opt.expert)
    {
      if (opt.compliance != CO_DE_VS)
        tty_printf (_("   (%d) DSA (set your own capabilities)\n"), 7 );
#if GPG_USE_RSA
      tty_printf (_("   (%d) RSA (set your own capabilities)\n"), 8 );
#endif
    }

#if GPG_USE_ECDSA || GPG_USE_ECDH || GPG_USE_EDDSA
  if (opt.expert && !addmode)
    tty_printf (_("   (%d) ECC and ECC\n"), 9 );
  if (opt.expert)
    tty_printf (_("  (%d) ECC (sign only)\n"), 10 );
  if (opt.expert)
    tty_printf (_("  (%d) ECC (set your own capabilities)\n"), 11 );
  if (opt.expert && addmode)
    tty_printf (_("  (%d) ECC (encrypt only)\n"), 12 );
#endif

  if (opt.expert && r_keygrip)
    tty_printf (_("  (%d) Existing key\n"), 13 );
  if (r_keygrip)
    tty_printf (_("  (%d) Existing key from card\n"), 14 );

  for (;;)
    {
      *r_usage = 0;
      *r_subkey_algo = 0;
      xfree (answer);
      answer = cpr_get ("keygen.algo", _("Your selection? "));
      cpr_kill_prompt ();
      algo = *answer? atoi (answer) : 1;

      if (opt.compliance == CO_DE_VS
          && (algo == 2 || algo == 3 || algo == 5 || algo == 7))
        {
          tty_printf (_("Invalid selection.\n"));
        }
      else if ((algo == 1 || !strcmp (answer, "rsa+rsa")) && !addmode)
        {
          algo = PUBKEY_ALGO_RSA;
          *r_subkey_algo = PUBKEY_ALGO_RSA;
          break;
	}
      else if ((algo == 2 || !strcmp (answer, "dsa+elg")) && !addmode)
        {
          algo = PUBKEY_ALGO_DSA;
          *r_subkey_algo = PUBKEY_ALGO_ELGAMAL_E;
          break;
	}
      else if (algo == 3 || !strcmp (answer, "dsa"))
        {
          algo = PUBKEY_ALGO_DSA;
          *r_usage = PUBKEY_USAGE_SIG;
          break;
	}
      else if (algo == 4 || !strcmp (answer, "rsa/s"))
        {
          algo = PUBKEY_ALGO_RSA;
          *r_usage = PUBKEY_USAGE_SIG;
          break;
	}
      else if ((algo == 5 || !strcmp (answer, "elg")) && addmode)
        {
          algo = PUBKEY_ALGO_ELGAMAL_E;
          *r_usage = PUBKEY_USAGE_ENC;
          break;
	}
      else if ((algo == 6 || !strcmp (answer, "rsa/e")) && addmode)
        {
          algo = PUBKEY_ALGO_RSA;
          *r_usage = PUBKEY_USAGE_ENC;
          break;
	}
      else if ((algo == 7 || !strcmp (answer, "dsa/*")) && opt.expert)
        {
          algo = PUBKEY_ALGO_DSA;
          *r_usage = ask_key_flags (algo, addmode, 0);
          break;
	}
      else if ((algo == 8 || !strcmp (answer, "rsa/*")) && opt.expert)
        {
          algo = PUBKEY_ALGO_RSA;
          *r_usage = ask_key_flags (algo, addmode, 0);
          break;
	}
      else if ((algo == 9 || !strcmp (answer, "ecc+ecc"))
               && opt.expert && !addmode)
        {
          algo = PUBKEY_ALGO_ECDSA;
          *r_subkey_algo = PUBKEY_ALGO_ECDH;
          break;
	}
      else if ((algo == 10 || !strcmp (answer, "ecc/s")) && opt.expert)
        {
          algo = PUBKEY_ALGO_ECDSA;
          *r_usage = PUBKEY_USAGE_SIG;
          break;
	}
      else if ((algo == 11 || !strcmp (answer, "ecc/*")) && opt.expert)
        {
          algo = PUBKEY_ALGO_ECDSA;
          *r_usage = ask_key_flags (algo, addmode, 0);
          break;
	}
      else if ((algo == 12 || !strcmp (answer, "ecc/e"))
               && opt.expert && addmode)
        {
          algo = PUBKEY_ALGO_ECDH;
          *r_usage = PUBKEY_USAGE_ENC;
          break;
	}
      else if ((algo == 13 || !strcmp (answer, "keygrip"))
               && opt.expert && r_keygrip)
        {
          for (;;)
            {
              xfree (answer);
              answer = cpr_get ("keygen.keygrip", _("Enter the keygrip: "));
              cpr_kill_prompt ();
              trim_spaces (answer);
              if (!*answer)
                {
                  xfree (answer);
                  answer = NULL;
                  continue;
                }

              if (strlen (answer) != 40 &&
                       !(answer[0] == '&' && strlen (answer+1) == 40))
                tty_printf
                  (_("Not a valid keygrip (expecting 40 hex digits)\n"));
              else if (!(algo = check_keygrip (ctrl, answer)) )
                tty_printf (_("No key with this keygrip\n"));
              else
                break; /* Okay.  */
            }
          xfree (keygrip);
          keygrip = answer;
          answer = NULL;
          *r_usage = ask_key_flags (algo, addmode, 0);
          break;
	}
      else if ((algo == 14 || !strcmp (answer, "cardkey")) && r_keygrip)
        {
          char *serialno;
          strlist_t keypairlist, sl;
          int count, selection;

          err = agent_scd_serialno (&serialno, NULL);
          if (err)
            {
              tty_printf (_("error reading the card: %s\n"),
                          gpg_strerror (err));
              goto ask_again;
            }
          tty_printf (_("Serial number of the card: %s\n"), serialno);
          xfree (serialno);

          err = agent_scd_keypairinfo (ctrl, &keypairlist);
          if (err)
            {
              tty_printf (_("error reading the card: %s\n"),
                          gpg_strerror (err));
              goto ask_again;
            }

          do
            {
              tty_printf (_("Available keys:\n"));
              for (count=1,sl=keypairlist; sl; sl = sl->next, count++)
                {
                  gcry_sexp_t s_pkey;
                  char *algostr = NULL;
                  enum gcry_pk_algos algoid = 0;
                  const char *keyref;
                  int any = 0;

                  keyref = strchr (sl->d, ' ');
                  if (keyref)
                    {
                      keyref++;
                      if (!agent_scd_readkey (keyref, &s_pkey))
                        {
                          algostr = pubkey_algo_string (s_pkey, &algoid);
                          gcry_sexp_release (s_pkey);
                        }
                    }
                  /* We use the flags also encode the algo for use
                   * below.  We need to tweak the algo in case
                   * GCRY_PK_ECC is returned becuase pubkey_algo_string
                   * is not aware of the OpenPGP algo mapping.
                   * FIXME: This is an ugly hack. */
                  sl->flags &= 0xff;
                  if (algoid == GCRY_PK_ECC
                      && algostr && !strncmp (algostr, "nistp", 5)
                      && !(sl->flags & GCRY_PK_USAGE_ENCR))
                    sl->flags |= (PUBKEY_ALGO_ECDSA << 8);
                  else if (algoid == GCRY_PK_ECC
                      && algostr && !strncmp (algostr, "brainpool", 9)
                      && !(sl->flags & GCRY_PK_USAGE_ENCR))
                    sl->flags |= (PUBKEY_ALGO_ECDSA << 8);
                  else if (algoid == GCRY_PK_ECC
                           && algostr && !strcmp (algostr, "ed25519")
                           && !(sl->flags & GCRY_PK_USAGE_ENCR))
                    sl->flags = (PUBKEY_ALGO_EDDSA << 8);
                  else
                    sl->flags |= (map_pk_gcry_to_openpgp (algoid) << 8);

                  tty_printf ("   (%d) %s %s", count, sl->d, algostr);
                  if ((sl->flags & GCRY_PK_USAGE_CERT))
                    {
                      tty_printf ("%scert", any?",":" (");
                      any = 1;
                    }
                  if ((sl->flags & GCRY_PK_USAGE_SIGN))
                    {
                      tty_printf ("%ssign", any?",":" (");
                      any = 1;
                    }
                  if ((sl->flags & GCRY_PK_USAGE_AUTH))
                    {
                      tty_printf ("%sauth", any?",":" (");
                      any = 1;
                    }
                  if ((sl->flags & GCRY_PK_USAGE_ENCR))
                    {
                      tty_printf ("%sencr", any?",":" (");
                      any = 1;
                    }
                  tty_printf ("%s\n", any?")":"");
                  xfree (algostr);
                }

              xfree (answer);
              answer = cpr_get ("keygen.cardkey", _("Your selection? "));
              cpr_kill_prompt ();
              trim_spaces (answer);
              selection = atoi (answer);
            }
          while (!(selection > 0 && selection < count));

          for (count=1,sl=keypairlist; sl; sl = sl->next, count++)
            if (count == selection)
              break;
          if (!sl)
            {
              /* Just in case COUNT is zero (no keys).  */
              free_strlist (keypairlist);
              goto ask_again;
            }

          xfree (keygrip);
          keygrip = xstrdup (sl->d);
          if ((p = strchr (keygrip, ' ')))
            *p = 0;
          algo = (sl->flags >>8);
          if (opt.expert)
            *r_usage = ask_key_flags_with_mask (algo, addmode,
                                                (sl->flags & 0xff),
                                                (sl->flags & 0xff));
          else
            {
              *r_usage = (sl->flags & 0xff);
              if (addmode)
                *r_usage &= ~GCRY_PK_USAGE_CERT;
            }
          free_strlist (keypairlist);
          break;
	}
      else
        tty_printf (_("Invalid selection.\n"));

    ask_again:
      ;
    }

  xfree(answer);
  if (r_keygrip)
    *r_keygrip = keygrip;
  return algo;
}


static unsigned int
get_keysize_range (int algo, unsigned int *min, unsigned int *max)
{
  unsigned int def;
  unsigned int dummy1, dummy2;

  if (!min)
    min = &dummy1;
  if (!max)
    max = &dummy2;

  switch(algo)
    {
    case PUBKEY_ALGO_DSA:
      *min = opt.expert? 768 : 1024;
      *max=3072;
      def=2048;
      break;

    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_ECDH:
      *min=256;
      *max=521;
      def=256;
      break;

    case PUBKEY_ALGO_EDDSA:
      *min=255;
      *max=441;
      def=255;
      break;

    default:
      *min = opt.compliance == CO_DE_VS ? 2048: 1024;
      *max = 4096;
      def = 3072;
      break;
    }

  return def;
}


/* Return a fixed up keysize depending on ALGO.  */
static unsigned int
fixup_keysize (unsigned int nbits, int algo, int silent)
{
  if (algo == PUBKEY_ALGO_DSA && (nbits % 64))
    {
      nbits = ((nbits + 63) / 64) * 64;
      if (!silent)
        tty_printf (_("rounded up to %u bits\n"), nbits);
    }
  else if (algo == PUBKEY_ALGO_EDDSA)
    {
      if (nbits != 255 && nbits != 441)
        {
          if (nbits < 256)
            nbits = 255;
          else
            nbits = 441;
          if (!silent)
            tty_printf (_("rounded to %u bits\n"), nbits);
        }
    }
  else if (algo == PUBKEY_ALGO_ECDH || algo == PUBKEY_ALGO_ECDSA)
    {
      if (nbits != 256 && nbits != 384 && nbits != 521)
        {
          if (nbits < 256)
            nbits = 256;
          else if (nbits < 384)
            nbits = 384;
          else
            nbits = 521;
          if (!silent)
            tty_printf (_("rounded to %u bits\n"), nbits);
        }
    }
  else if ((nbits % 32))
    {
      nbits = ((nbits + 31) / 32) * 32;
      if (!silent)
        tty_printf (_("rounded up to %u bits\n"), nbits );
    }

  return nbits;
}


/* Ask for the key size.  ALGO is the algorithm.  If PRIMARY_KEYSIZE
   is not 0, the function asks for the size of the encryption
   subkey. */
static unsigned
ask_keysize (int algo, unsigned int primary_keysize)
{
  unsigned int nbits;
  unsigned int min, def, max;
  int for_subkey = !!primary_keysize;
  int autocomp = 0;

  def = get_keysize_range (algo, &min, &max);

  if (primary_keysize && !opt.expert)
    {
      /* Deduce the subkey size from the primary key size.  */
      if (algo == PUBKEY_ALGO_DSA && primary_keysize > 3072)
        nbits = 3072; /* For performance reasons we don't support more
                         than 3072 bit DSA.  However we won't see this
                         case anyway because DSA can't be used as an
                         encryption subkey ;-). */
      else
        nbits = primary_keysize;
      autocomp = 1;
      goto leave;
    }

  tty_printf(_("%s keys may be between %u and %u bits long.\n"),
	     openpgp_pk_algo_name (algo), min, max);

  for (;;)
    {
      char *prompt, *answer;

      if (for_subkey)
        prompt = xasprintf (_("What keysize do you want "
                              "for the subkey? (%u) "), def);
      else
        prompt = xasprintf (_("What keysize do you want? (%u) "), def);
      answer = cpr_get ("keygen.size", prompt);
      cpr_kill_prompt ();
      nbits = *answer? atoi (answer): def;
      xfree(prompt);
      xfree(answer);

      if(nbits<min || nbits>max)
	tty_printf(_("%s keysizes must be in the range %u-%u\n"),
		   openpgp_pk_algo_name (algo), min, max);
      else
	break;
    }

  tty_printf (_("Requested keysize is %u bits\n"), nbits);

 leave:
  nbits = fixup_keysize (nbits, algo, autocomp);
  return nbits;
}


/* Ask for the curve.  ALGO is the selected algorithm which this
   function may adjust.  Returns a const string of the name of the
   curve.  */
const char *
ask_curve (int *algo, int *subkey_algo, const char *current)
{
  /* NB: We always use a complete algo list so that we have stable
     numbers in the menu regardless on how Gpg was configured.  */
  struct {
    const char *name;
    const char* eddsa_curve; /* Corresponding EdDSA curve.  */
    const char *pretty_name;
    unsigned int supported : 1;   /* Supported by gpg.     */
    unsigned int de_vs : 1;       /* Allowed in CO_DE_VS.  */
    unsigned int expert_only : 1; /* Only with --expert    */
    unsigned int available : 1;   /* Available in Libycrypt (runtime checked) */
  } curves[] = {
#if GPG_USE_ECDSA || GPG_USE_ECDH
# define MY_USE_ECDSADH 1
#else
# define MY_USE_ECDSADH 0
#endif
    { "Curve25519",      "Ed25519", "Curve 25519", !!GPG_USE_EDDSA, 0, 0, 0 },
    { "Curve448",        "Ed448",   "Curve 448",   0/*reserved*/  , 0, 1, 0 },
    { "NIST P-256",      NULL, NULL,               MY_USE_ECDSADH,  0, 1, 0 },
    { "NIST P-384",      NULL, NULL,               MY_USE_ECDSADH,  0, 0, 0 },
    { "NIST P-521",      NULL, NULL,               MY_USE_ECDSADH,  0, 1, 0 },
    { "brainpoolP256r1", NULL, "Brainpool P-256",  MY_USE_ECDSADH,  1, 1, 0 },
    { "brainpoolP384r1", NULL, "Brainpool P-384",  MY_USE_ECDSADH,  1, 1, 0 },
    { "brainpoolP512r1", NULL, "Brainpool P-512",  MY_USE_ECDSADH,  1, 1, 0 },
    { "secp256k1",       NULL, NULL,               MY_USE_ECDSADH,  0, 1, 0 },
  };
#undef MY_USE_ECDSADH
  int idx;
  char *answer;
  const char *result = NULL;
  gcry_sexp_t keyparms;

  tty_printf (_("Please select which elliptic curve you want:\n"));

  keyparms = NULL;
  for (idx=0; idx < DIM(curves); idx++)
    {
      int rc;

      curves[idx].available = 0;
      if (!curves[idx].supported)
        continue;

      if (opt.compliance==CO_DE_VS)
        {
          if (!curves[idx].de_vs)
            continue; /* Not allowed.  */
        }
      else if (!opt.expert && curves[idx].expert_only)
        continue;

      /* We need to switch from the ECDH name of the curve to the
         EDDSA name of the curve if we want a signing key.  */
      gcry_sexp_release (keyparms);
      rc = gcry_sexp_build (&keyparms, NULL,
                            "(public-key(ecc(curve %s)))",
                            curves[idx].eddsa_curve? curves[idx].eddsa_curve
                            /**/                   : curves[idx].name);
      if (rc)
        continue;
      if (!gcry_pk_get_curve (keyparms, 0, NULL))
        continue;
      if (subkey_algo && curves[idx].eddsa_curve)
        {
          /* Both Curve 25519 (or 448) keys are to be created.  Check that
             Libgcrypt also supports the real Curve25519 (or 448).  */
          gcry_sexp_release (keyparms);
          rc = gcry_sexp_build (&keyparms, NULL,
                                "(public-key(ecc(curve %s)))",
                                 curves[idx].name);
          if (rc)
            continue;
          if (!gcry_pk_get_curve (keyparms, 0, NULL))
            continue;
        }

      curves[idx].available = 1;
      tty_printf ("   (%d) %s\n", idx + 1,
                  curves[idx].pretty_name?
                  curves[idx].pretty_name:curves[idx].name);
    }
  gcry_sexp_release (keyparms);


  for (;;)
    {
      answer = cpr_get ("keygen.curve", _("Your selection? "));
      cpr_kill_prompt ();
      idx = *answer? atoi (answer) : 1;
      if (!*answer && current)
        {
          xfree(answer);
          return NULL;
        }
      else if (*answer && !idx)
        {
          /* See whether the user entered the name of the curve.  */
          for (idx=0; idx < DIM(curves); idx++)
            {
              if (!opt.expert && curves[idx].expert_only)
                continue;
              if (!stricmp (curves[idx].name, answer)
                  || (curves[idx].pretty_name
                      && !stricmp (curves[idx].pretty_name, answer)))
                break;
            }
          if (idx == DIM(curves))
            idx = -1;
        }
      else
        idx--;
      xfree(answer);
      answer = NULL;
      if (idx < 0 || idx >= DIM (curves) || !curves[idx].available)
        tty_printf (_("Invalid selection.\n"));
      else
        {
          /* If the user selected a signing algorithm and Curve25519
             we need to set the algo to EdDSA and update the curve name.
             If switching away from EdDSA, we need to set the algo back
             to ECDSA. */
          if (*algo == PUBKEY_ALGO_ECDSA || *algo == PUBKEY_ALGO_EDDSA)
            {
              if (curves[idx].eddsa_curve)
                {
                  if (subkey_algo && *subkey_algo == PUBKEY_ALGO_ECDSA)
                    *subkey_algo = PUBKEY_ALGO_EDDSA;
                  *algo = PUBKEY_ALGO_EDDSA;
                  result = curves[idx].eddsa_curve;
                }
              else
                {
                  if (subkey_algo && *subkey_algo == PUBKEY_ALGO_EDDSA)
                    *subkey_algo = PUBKEY_ALGO_ECDSA;
                  *algo = PUBKEY_ALGO_ECDSA;
                  result = curves[idx].name;
                }
            }
          else
            result = curves[idx].name;
          break;
        }
    }

  if (!result)
    result = curves[0].name;

  return result;
}


/****************
 * Parse an expire string and return its value in seconds.
 * Returns (u32)-1 on error.
 * This isn't perfect since scan_isodatestr returns unix time, and
 * OpenPGP actually allows a 32-bit time *plus* a 32-bit offset.
 * Because of this, we only permit setting expirations up to 2106, but
 * OpenPGP could theoretically allow up to 2242.  I think we'll all
 * just cope for the next few years until we get a 64-bit time_t or
 * similar.
 */
u32
parse_expire_string (const char *string)
{
  int mult;
  u32 seconds;
  u32 abs_date = 0;
  u32 curtime = make_timestamp ();
  uint64_t tt;
  uint64_t tmp64;

  if (!string || !*string || !strcmp (string, "none")
      || !strcmp (string, "never") || !strcmp (string, "-"))
    seconds = 0;
  else if (!strncmp (string, "seconds=", 8))
    seconds = scan_secondsstr (string+8);
  else if ((abs_date = scan_isodatestr(string))
           && (abs_date+86400/2) > curtime)
    seconds = (abs_date+86400/2) - curtime;
  else if ((tt = isotime2epoch_u64 (string)) != (uint64_t)(-1))
    {
      tmp64 = tt - curtime;
      if (tmp64 >= (u32)(-1))
        seconds = (u32)(-1) - 1;  /* cap value.  */
      else
        seconds = (u32)tmp64;
    }
  else if ((mult = check_valid_days (string)))
    {
      tmp64 = scan_secondsstr (string) * 86400L * mult;
      if (tmp64 >= (u32)(-1))
        seconds = (u32)(-1) - 1;  /* cap value.  */
      else
        seconds = (u32)tmp64;
    }
  else
    seconds = (u32)(-1);

  return seconds;
}

/* Parse a Creation-Date string which is either "1986-04-26" or
   "19860426T042640".  Returns 0 on error. */
static u32
parse_creation_string (const char *string)
{
  u32 seconds;

  if (!*string)
    seconds = 0;
  else if ( !strncmp (string, "seconds=", 8) )
    seconds = scan_secondsstr (string+8);
  else if ( !(seconds = scan_isodatestr (string)))
    {
      uint64_t tmp = isotime2epoch_u64 (string);
      if (tmp == (uint64_t)(-1))
        seconds = 0;
      else if (tmp > (u32)(-1))
        seconds = 0;
      else
        seconds = tmp;
    }
  return seconds;
}


/* object == 0 for a key, and 1 for a sig */
u32
ask_expire_interval(int object,const char *def_expire)
{
    u32 interval;
    char *answer;

    switch(object)
      {
      case 0:
	if(def_expire)
	  BUG();
	tty_printf(_("Please specify how long the key should be valid.\n"
		     "         0 = key does not expire\n"
		     "      <n>  = key expires in n days\n"
		     "      <n>w = key expires in n weeks\n"
		     "      <n>m = key expires in n months\n"
		     "      <n>y = key expires in n years\n"));
	break;

      case 1:
	if(!def_expire)
	  BUG();
	tty_printf(_("Please specify how long the signature should be valid.\n"
		     "         0 = signature does not expire\n"
		     "      <n>  = signature expires in n days\n"
		     "      <n>w = signature expires in n weeks\n"
		     "      <n>m = signature expires in n months\n"
		     "      <n>y = signature expires in n years\n"));
	break;

      default:
	BUG();
      }

    /* Note: The elgamal subkey for DSA has no expiration date because
     * it must be signed with the DSA key and this one has the expiration
     * date */

    answer = NULL;
    for(;;)
      {
	u32 curtime;

	xfree(answer);
	if(object==0)
	  answer = cpr_get("keygen.valid",_("Key is valid for? (0) "));
	else
	  {
	    char *prompt;

	    prompt = xasprintf (_("Signature is valid for? (%s) "), def_expire);
	    answer = cpr_get("siggen.valid",prompt);
	    xfree(prompt);

	    if(*answer=='\0')
	      answer=xstrdup(def_expire);
	  }
	cpr_kill_prompt();
	trim_spaces(answer);
        curtime = make_timestamp ();
	interval = parse_expire_string( answer );
	if( interval == (u32)-1 )
	  {
	    tty_printf(_("invalid value\n"));
	    continue;
	  }

	if( !interval )
	  {
            tty_printf((object==0)
                       ? _("Key does not expire at all\n")
                       : _("Signature does not expire at all\n"));
	  }
	else
	  {
	    tty_printf(object==0
		       ? _("Key expires at %s\n")
		       : _("Signature expires at %s\n"),
		       asctimestamp((ulong)(curtime + interval) ) );
#if SIZEOF_TIME_T <= 4 && !defined (HAVE_UNSIGNED_TIME_T)
	    if ( (time_t)((ulong)(curtime+interval)) < 0 )
	      tty_printf (_("Your system can't display dates beyond 2038.\n"
                            "However, it will be correctly handled up to"
                            " 2106.\n"));
            else
#endif /*SIZEOF_TIME_T*/
              if ( (time_t)((unsigned long)(curtime+interval)) < curtime )
                {
                  tty_printf (_("invalid value\n"));
                  continue;
                }
	  }

	if( cpr_enabled() || cpr_get_answer_is_yes("keygen.valid.okay",
						   _("Is this correct? (y/N) ")) )
	  break;
      }

    xfree(answer);
    return interval;
}

u32
ask_expiredate()
{
    u32 x = ask_expire_interval(0,NULL);
    return x? make_timestamp() + x : 0;
}



static PKT_user_id *
uid_from_string (const char *string)
{
  size_t n;
  PKT_user_id *uid;

  n = strlen (string);
  uid = xmalloc_clear (sizeof *uid + n);
  uid->len = n;
  strcpy (uid->name, string);
  uid->ref = 1;
  return uid;
}


/* Return true if the user id UID already exists in the keyblock.  */
static int
uid_already_in_keyblock (kbnode_t keyblock, const char *uid)
{
  PKT_user_id *uidpkt = uid_from_string (uid);
  kbnode_t node;
  int result = 0;

  for (node=keyblock; node && !result; node=node->next)
    if (!is_deleted_kbnode (node)
        && node->pkt->pkttype == PKT_USER_ID
        && !cmp_user_ids (uidpkt, node->pkt->pkt.user_id))
      result = 1;
  free_user_id (uidpkt);
  return result;
}


/* Ask for a user ID.  With a MODE of 1 an extra help prompt is
   printed for use during a new key creation.  If KEYBLOCK is not NULL
   the function prevents the creation of an already existing user
   ID.  IF FULL is not set some prompts are not shown.  */
static char *
ask_user_id (int mode, int full, KBNODE keyblock)
{
    char *answer;
    char *aname, *acomment, *amail, *uid;

    if ( !mode )
      {
        /* TRANSLATORS: This is the new string telling the user what
           gpg is now going to do (i.e. ask for the parts of the user
           ID).  Note that if you do not translate this string, a
           different string will be used, which might still have
           a correct translation.  */
	const char *s1 =
          N_("\n"
             "GnuPG needs to construct a user ID to identify your key.\n"
             "\n");
        const char *s2 = _(s1);

        if (!strcmp (s1, s2))
          {
            /* There is no translation for the string thus we to use
               the old info text.  gettext has no way to tell whether
               a translation is actually available, thus we need to
               to compare again. */
            /* TRANSLATORS: This string is in general not anymore used
               but you should keep your existing translation.  In case
               the new string is not translated this old string will
               be used. */
            const char *s3 = N_("\n"
"You need a user ID to identify your key; "
                                        "the software constructs the user ID\n"
"from the Real Name, Comment and Email Address in this form:\n"
"    \"Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>\"\n\n");
            const char *s4 = _(s3);
            if (strcmp (s3, s4))
              s2 = s3; /* A translation exists - use it. */
          }
        tty_printf ("%s", s2) ;
      }
    uid = aname = acomment = amail = NULL;
    for(;;) {
	char *p;
	int fail=0;

	if( !aname ) {
	    for(;;) {
		xfree(aname);
		aname = cpr_get("keygen.name",_("Real name: "));
		trim_spaces(aname);
		cpr_kill_prompt();

		if( opt.allow_freeform_uid )
		    break;

		if( strpbrk( aname, "<>" ) )
                  {
		    tty_printf(_("Invalid character in name\n"));
		    tty_printf(_("The characters '%s' and '%s' may not "
                                 "appear in name\n"), "<", ">");
                  }
		else if( digitp(aname) )
		    tty_printf(_("Name may not start with a digit\n"));
		else if (*aname && strlen (aname) < 5)
                  {
		    tty_printf(_("Name must be at least 5 characters long\n"));
                    /* However, we allow an empty name.  */
                  }
		else
		    break;
	    }
	}
	if( !amail ) {
	    for(;;) {
		xfree(amail);
		amail = cpr_get("keygen.email",_("Email address: "));
		trim_spaces(amail);
		cpr_kill_prompt();
		if( !*amail || opt.allow_freeform_uid )
		    break;   /* no email address is okay */
		else if ( !is_valid_mailbox (amail) )
                    tty_printf(_("Not a valid email address\n"));
		else
		    break;
	    }
	}
	if (!acomment) {
          if (full) {
	    for(;;) {
		xfree(acomment);
		acomment = cpr_get("keygen.comment",_("Comment: "));
		trim_spaces(acomment);
		cpr_kill_prompt();
		if( !*acomment )
		    break;   /* no comment is okay */
		else if( strpbrk( acomment, "()" ) )
		    tty_printf(_("Invalid character in comment\n"));
		else
		    break;
	    }
          }
          else {
            xfree (acomment);
            acomment = xstrdup ("");
          }
	}


	xfree(uid);
	uid = p = xmalloc(strlen(aname)+strlen(amail)+strlen(acomment)+12+10);
        if (!*aname && *amail && !*acomment && !random_is_faked ())
          { /* Empty name and comment but with mail address.  Use
               simplified form with only the non-angle-bracketed mail
               address.  */
            p = stpcpy (p, amail);
          }
        else
          {
            p = stpcpy (p, aname );
            if (*acomment)
              p = stpcpy(stpcpy(stpcpy(p," ("), acomment),")");
            if (*amail)
              p = stpcpy(stpcpy(stpcpy(p," <"), amail),">");
          }

	/* Append a warning if the RNG is switched into fake mode.  */
        if ( random_is_faked ()  )
          strcpy(p, " (insecure!)" );

	/* print a note in case that UTF8 mapping has to be done */
	for(p=uid; *p; p++ ) {
	    if( *p & 0x80 ) {
		tty_printf(_("You are using the '%s' character set.\n"),
			   get_native_charset() );
		break;
	    }
	}

	tty_printf(_("You selected this USER-ID:\n    \"%s\"\n\n"), uid);

	if( !*amail && !opt.allow_freeform_uid
	    && (strchr( aname, '@' ) || strchr( acomment, '@'))) {
	    fail = 1;
            tty_printf(_("Please don't put the email address "
                         "into the real name or the comment\n") );
	}

        if (!fail && keyblock)
          {
            if (uid_already_in_keyblock (keyblock, uid))
              {
                tty_printf (_("Such a user ID already exists on this key!\n"));
                fail = 1;
              }
          }

	for(;;) {
            /* TRANSLATORS: These are the allowed answers in
               lower and uppercase.  Below you will find the matching
               string which should be translated accordingly and the
               letter changed to match the one in the answer string.

                 n = Change name
                 c = Change comment
                 e = Change email
                 o = Okay (ready, continue)
                 q = Quit
             */
	    const char *ansstr = _("NnCcEeOoQq");

	    if( strlen(ansstr) != 10 )
		BUG();
	    if( cpr_enabled() ) {
                answer = xstrdup (ansstr + (fail?8:6));
		answer[1] = 0;
	    }
            else if (full) {
		answer = cpr_get("keygen.userid.cmd", fail?
		  _("Change (N)ame, (C)omment, (E)mail or (Q)uit? ") :
		  _("Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? "));
		cpr_kill_prompt();
            }
            else {
		answer = cpr_get("keygen.userid.cmd", fail?
		  _("Change (N)ame, (E)mail, or (Q)uit? ") :
		  _("Change (N)ame, (E)mail, or (O)kay/(Q)uit? "));
		cpr_kill_prompt();
	    }
	    if( strlen(answer) > 1 )
		;
	    else if( *answer == ansstr[0] || *answer == ansstr[1] ) {
		xfree(aname); aname = NULL;
		break;
	    }
	    else if( *answer == ansstr[2] || *answer == ansstr[3] ) {
		xfree(acomment); acomment = NULL;
		break;
	    }
	    else if( *answer == ansstr[4] || *answer == ansstr[5] ) {
		xfree(amail); amail = NULL;
		break;
	    }
	    else if( *answer == ansstr[6] || *answer == ansstr[7] ) {
		if( fail ) {
		    tty_printf(_("Please correct the error first\n"));
		}
		else {
		    xfree(aname); aname = NULL;
		    xfree(acomment); acomment = NULL;
		    xfree(amail); amail = NULL;
		    break;
		}
	    }
	    else if( *answer == ansstr[8] || *answer == ansstr[9] ) {
		xfree(aname); aname = NULL;
		xfree(acomment); acomment = NULL;
		xfree(amail); amail = NULL;
		xfree(uid); uid = NULL;
		break;
	    }
	    xfree(answer);
	}
	xfree(answer);
	if (!amail && !acomment)
	    break;
	xfree(uid); uid = NULL;
    }
    if( uid ) {
	char *p = native_to_utf8( uid );
	xfree( uid );
	uid = p;
    }
    return uid;
}


/* Basic key generation.  Here we divert to the actual generation
   routines based on the requested algorithm.  */
static int
do_create (int algo, unsigned int nbits, const char *curve, KBNODE pub_root,
           u32 timestamp, u32 expiredate, int is_subkey,
           int keygen_flags, const char *passphrase,
           char **cache_nonce_addr, char **passwd_nonce_addr)
{
  gpg_error_t err;

  /* Fixme: The entropy collecting message should be moved to a
     libgcrypt progress handler.  */
  if (!opt.batch)
    tty_printf (_(
"We need to generate a lot of random bytes. It is a good idea to perform\n"
"some other action (type on the keyboard, move the mouse, utilize the\n"
"disks) during the prime generation; this gives the random number\n"
"generator a better chance to gain enough entropy.\n") );

  if (algo == PUBKEY_ALGO_ELGAMAL_E)
    err = gen_elg (algo, nbits, pub_root, timestamp, expiredate, is_subkey,
                   keygen_flags, passphrase,
                   cache_nonce_addr, passwd_nonce_addr);
  else if (algo == PUBKEY_ALGO_DSA)
    err = gen_dsa (nbits, pub_root, timestamp, expiredate, is_subkey,
                   keygen_flags, passphrase,
                   cache_nonce_addr, passwd_nonce_addr);
  else if (algo == PUBKEY_ALGO_ECDSA
           || algo == PUBKEY_ALGO_EDDSA
           || algo == PUBKEY_ALGO_ECDH)
    err = gen_ecc (algo, curve, pub_root, timestamp, expiredate, is_subkey,
                   keygen_flags, passphrase,
                   cache_nonce_addr, passwd_nonce_addr);
  else if (algo == PUBKEY_ALGO_RSA)
    err = gen_rsa (algo, nbits, pub_root, timestamp, expiredate, is_subkey,
                   keygen_flags, passphrase,
                   cache_nonce_addr, passwd_nonce_addr);
  else
    BUG();

  return err;
}


/* Generate a new user id packet or return NULL if canceled.  If
   KEYBLOCK is not NULL the function prevents the creation of an
   already existing user ID.  If UIDSTR is not NULL the user is not
   asked but UIDSTR is used to create the user id packet; if the user
   id already exists NULL is returned.  UIDSTR is expected to be utf-8
   encoded and should have already been checked for a valid length
   etc.  */
PKT_user_id *
generate_user_id (KBNODE keyblock, const char *uidstr)
{
  PKT_user_id *uid;
  char *p;

  if (uidstr)
    {
      if (uid_already_in_keyblock (keyblock, uidstr))
        return NULL;  /* Already exists.  */
      uid = uid_from_string (uidstr);
    }
  else
    {
      p = ask_user_id (1, 1, keyblock);
      if (!p)
        return NULL;  /* Canceled. */
      uid = uid_from_string (p);
      xfree (p);
    }
  return uid;
}


/* Helper for parse_key_parameter_string for one part of the
 * specification string; i.e.  ALGO/FLAGS.  If STRING is NULL or empty
 * success is returned.  On error an error code is returned.  Note
 * that STRING may be modified by this function.  NULL may be passed
 * for any parameter.  FOR_SUBKEY shall be true if this is used as a
 * subkey.  If CLEAR_CERT is set a default CERT usage will be cleared;
 * this is useful if for example the default algorithm is used for a
 * subkey.  */
static gpg_error_t
parse_key_parameter_part (ctrl_t ctrl,
                          char *string, int for_subkey, int clear_cert,
                          int *r_algo, unsigned int *r_size,
                          unsigned int *r_keyuse,
                          char const **r_curve,
                          char **r_keygrip)
{
  gpg_error_t err;
  char *flags;
  int algo;
  char *endp;
  const char *curve = NULL;
  int ecdh_or_ecdsa = 0;
  unsigned int size;
  int keyuse;
  int i;
  const char *s;
  int from_card = 0;
  char *keygrip = NULL;

  if (!string || !*string)
    return 0; /* Success.  */

  flags = strchr (string, '/');
  if (flags)
    *flags++ = 0;

  algo = 0;
  if (!ascii_strcasecmp (string, "card"))
    from_card = 1;
  else if (strlen (string) >= 3 && (digitp (string+3) || !string[3]))
    {
      if (!ascii_memcasecmp (string, "rsa", 3))
        algo = PUBKEY_ALGO_RSA;
      else if (!ascii_memcasecmp (string, "dsa", 3))
        algo = PUBKEY_ALGO_DSA;
      else if (!ascii_memcasecmp (string, "elg", 3))
        algo = PUBKEY_ALGO_ELGAMAL_E;
    }

  if (from_card)
    ; /* We need the flags before we can figure out the key to use.  */
  else if (algo)
    {
      if (!string[3])
        size = get_keysize_range (algo, NULL, NULL);
      else
        {
          size = strtoul (string+3, &endp, 10);
          if (size < 512 || size > 16384 || *endp)
            return gpg_error (GPG_ERR_INV_VALUE);
        }
    }
  else if ((curve = openpgp_is_curve_supported (string, &algo, &size)))
    {
      if (!algo)
        {
          algo = PUBKEY_ALGO_ECDH; /* Default ECC algorithm.  */
          ecdh_or_ecdsa = 1;       /* We may need to switch the algo.  */
        }
    }
  else
    return gpg_error (GPG_ERR_UNKNOWN_CURVE);

  /* Parse the flags.  */
  keyuse = 0;
  if (flags)
    {
      char **tokens = NULL;

      tokens = strtokenize (flags, ",");
      if (!tokens)
        return gpg_error_from_syserror ();

      for (i=0; (s = tokens[i]); i++)
        {
          if (!*s)
            ;
          else if (!ascii_strcasecmp (s, "sign"))
            keyuse |= PUBKEY_USAGE_SIG;
          else if (!ascii_strcasecmp (s, "encrypt")
                   || !ascii_strcasecmp (s, "encr"))
            keyuse |= PUBKEY_USAGE_ENC;
          else if (!ascii_strcasecmp (s, "auth"))
            keyuse |= PUBKEY_USAGE_AUTH;
          else if (!ascii_strcasecmp (s, "cert"))
            keyuse |= PUBKEY_USAGE_CERT;
          else if (!ascii_strcasecmp (s, "ecdsa") && !from_card)
            {
              if (algo == PUBKEY_ALGO_ECDH || algo == PUBKEY_ALGO_ECDSA)
                algo = PUBKEY_ALGO_ECDSA;
              else
                {
                  xfree (tokens);
                  return gpg_error (GPG_ERR_INV_FLAG);
                }
              ecdh_or_ecdsa = 0;
            }
          else if (!ascii_strcasecmp (s, "ecdh") && !from_card)
            {
              if (algo == PUBKEY_ALGO_ECDH || algo == PUBKEY_ALGO_ECDSA)
                algo = PUBKEY_ALGO_ECDH;
              else
                {
                  xfree (tokens);
                  return gpg_error (GPG_ERR_INV_FLAG);
                }
              ecdh_or_ecdsa = 0;
            }
          else if (!ascii_strcasecmp (s, "eddsa") && !from_card)
            {
              /* Not required but we allow it for consistency.  */
              if (algo == PUBKEY_ALGO_EDDSA)
                ;
              else
                {
                  xfree (tokens);
                  return gpg_error (GPG_ERR_INV_FLAG);
                }
            }
          else
            {
              xfree (tokens);
              return gpg_error (GPG_ERR_UNKNOWN_FLAG);
            }
        }

      xfree (tokens);
    }

  /* If not yet decided switch between ecdh and ecdsa unless we want
   * to read the algo from the current card.  */
  if (from_card)
    {
      strlist_t keypairlist, sl;
      char *reqkeyref;

      if (!keyuse)
        keyuse = (for_subkey? PUBKEY_USAGE_ENC
                  /* */     : (PUBKEY_USAGE_CERT|PUBKEY_USAGE_SIG));

      /* Access the card to make sure we have one and to show the S/N.  */
      {
        char *serialno;

        err = agent_scd_serialno (&serialno, NULL);
        if (err)
          {
            log_error (_("error reading the card: %s\n"), gpg_strerror (err));
            return err;
          }
        if (!opt.quiet)
          log_info (_("Serial number of the card: %s\n"), serialno);
        xfree (serialno);
      }

      err = agent_scd_keypairinfo (ctrl, &keypairlist);
      if (err)
        {
          log_error (_("error reading the card: %s\n"), gpg_strerror (err));
          return err;
        }
      agent_scd_getattr_one ((keyuse & (PUBKEY_USAGE_SIG|PUBKEY_USAGE_CERT))
                             ? "$SIGNKEYID":"$ENCRKEYID", &reqkeyref);

      algo = 0; /* Should already be the case.  */
      for (sl=keypairlist; sl && !algo; sl = sl->next)
        {
          gcry_sexp_t s_pkey;
          char *algostr = NULL;
          enum gcry_pk_algos algoid = 0;
          const char *keyref;

          if (!reqkeyref)
            continue; /* Card does not provide the info (skip all).  */

          keyref = strchr (sl->d, ' ');
          if (!keyref)
            continue; /* Ooops.  */
          keyref++;
          if (strcmp (reqkeyref, keyref))
            continue;  /* This is not the requested keyref.  */

          if ((keyuse & (PUBKEY_USAGE_SIG|PUBKEY_USAGE_CERT))
              && (sl->flags & (GCRY_PK_USAGE_SIGN|GCRY_PK_USAGE_CERT)))
            ; /* Okay */
          else if ((keyuse & PUBKEY_USAGE_ENC)
                   && (sl->flags & GCRY_PK_USAGE_ENCR))
            ; /* Okay */
          else
            continue; /* Not usable for us.  */

          if (agent_scd_readkey (keyref, &s_pkey))
            continue;  /* Could not read the key.  */

          algostr = pubkey_algo_string (s_pkey, &algoid);
          gcry_sexp_release (s_pkey);


          /* Map to OpenPGP algo number.
           * We need to tweak the algo in case GCRY_PK_ECC is returned
           * because pubkey_algo_string is not aware of the OpenPGP
           * algo mapping.  FIXME: This is an ugly hack. */
          if (algoid == GCRY_PK_ECC
              && algostr && !strncmp (algostr, "nistp", 5)
              && !(sl->flags & GCRY_PK_USAGE_ENCR))
            algo = PUBKEY_ALGO_ECDSA;
          else if (algoid == GCRY_PK_ECC
                   && algostr && !strcmp (algostr, "ed25519")
                   && !(sl->flags & GCRY_PK_USAGE_ENCR))
            algo = PUBKEY_ALGO_EDDSA;
          else
            algo = map_pk_gcry_to_openpgp (algoid);

          xfree (algostr);
          xfree (keygrip);
          keygrip = xtrystrdup (sl->d);
          if (!keygrip)
            {
              err = gpg_error_from_syserror ();
              xfree (reqkeyref);
              free_strlist (keypairlist);
              return err;
            }
          if ((endp = strchr (keygrip, ' ')))
            *endp = 0;
        }

      xfree (reqkeyref);
      free_strlist (keypairlist);
      if (!algo || !keygrip)
        {
          err = gpg_error (GPG_ERR_PUBKEY_ALGO);
          log_error ("no usable key on the card: %s\n", gpg_strerror (err));
          xfree (keygrip);
          return err;
        }
    }
  else if (ecdh_or_ecdsa && keyuse)
    algo = (keyuse & PUBKEY_USAGE_ENC)? PUBKEY_ALGO_ECDH : PUBKEY_ALGO_ECDSA;
  else if (ecdh_or_ecdsa)
    algo = for_subkey? PUBKEY_ALGO_ECDH : PUBKEY_ALGO_ECDSA;

  /* Set or fix key usage.  */
  if (!keyuse)
    {
      if (algo == PUBKEY_ALGO_ECDSA || algo == PUBKEY_ALGO_EDDSA
          || algo == PUBKEY_ALGO_DSA)
        keyuse = PUBKEY_USAGE_SIG;
      else if (algo == PUBKEY_ALGO_RSA)
        keyuse = for_subkey? PUBKEY_USAGE_ENC : PUBKEY_USAGE_SIG;
      else
        keyuse = PUBKEY_USAGE_ENC;
    }
  else if (algo == PUBKEY_ALGO_ECDSA || algo == PUBKEY_ALGO_EDDSA
           || algo == PUBKEY_ALGO_DSA)
    {
      keyuse &= ~PUBKEY_USAGE_ENC; /* Forbid encryption.  */
    }
  else if (algo == PUBKEY_ALGO_ECDH || algo == PUBKEY_ALGO_ELGAMAL_E)
    {
      keyuse = PUBKEY_USAGE_ENC;   /* Allow only encryption.  */
    }

  /* Make sure a primary key can certify.  */
  if (!for_subkey)
    keyuse |= PUBKEY_USAGE_CERT;

  /* But if requested remove th cert usage.  */
  if (clear_cert)
    keyuse &= ~PUBKEY_USAGE_CERT;

  /* Check that usage is actually possible.  */
  if (/**/((keyuse & (PUBKEY_USAGE_SIG|PUBKEY_USAGE_AUTH|PUBKEY_USAGE_CERT))
           && !pubkey_get_nsig (algo))
       || ((keyuse & PUBKEY_USAGE_ENC)
           && !pubkey_get_nenc (algo))
       || (for_subkey && (keyuse & PUBKEY_USAGE_CERT)))
    {
      xfree (keygrip);
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  /* Return values.  */
  if (r_algo)
    *r_algo = algo;
  if (r_size)
    {
      unsigned int min, def, max;

      /* Make sure the keysize is in the allowed range.  */
      def = get_keysize_range (algo, &min, &max);
      if (!size)
        size = def;
      else if (size < min)
        size = min;
      else if (size > max)
        size = max;

      *r_size = fixup_keysize (size, algo, 1);
    }

  if (r_keyuse)
    *r_keyuse = keyuse;
  if (r_curve)
    *r_curve = curve;

  if (r_keygrip)
    *r_keygrip = keygrip;
  else
    xfree (keygrip);

  return 0;
}

/* Parse and return the standard key generation parameter.
 * The string is expected to be in this format:
 *
 *   ALGO[/FLAGS][+SUBALGO[/FLAGS]]
 *
 * Here ALGO is a string in the same format as printed by the
 * keylisting.  For example:
 *
 *   rsa3072 := RSA with 3072 bit.
 *   dsa2048 := DSA with 2048 bit.
 *   elg2048 := Elgamal with 2048 bit.
 *   ed25519 := EDDSA using curve Ed25519.
 *   cv25519 := ECDH using curve Curve25519.
 *   nistp256:= ECDSA or ECDH using curve NIST P-256
 *
 * All strings with an unknown prefix are considered an elliptic
 * curve.  Curves which have no implicit algorithm require that FLAGS
 * is given to select whether ECDSA or ECDH is used; this can either
 * be done using an algorithm keyword or usage keywords.
 *
 * FLAGS is a comma delimited string of keywords:
 *
 *   cert := Allow usage Certify
 *   sign := Allow usage Sign
 *   encr := Allow usage Encrypt
 *   auth := Allow usage Authentication
 *   encrypt := Alias for "encr"
 *   ecdsa := Use algorithm ECDSA.
 *   eddsa := Use algorithm EdDSA.
 *   ecdh  := Use algorithm ECDH.
 *
 * There are several defaults and fallbacks depending on the
 * algorithm.  PART can be used to select which part of STRING is
 * used:
 *   -1 := Both parts
 *    0 := Only the part of the primary key
 *    1 := If there is one part parse that one, if there are
 *         two parts parse the part which best matches the
 *         SUGGESTED_USE or in case that can't be evaluated the second part.
 *         Always return using the args for the primary key (R_ALGO,....).
 *
 */
gpg_error_t
parse_key_parameter_string (ctrl_t ctrl,
                            const char *string, int part,
                            unsigned int suggested_use,
                            int *r_algo, unsigned int *r_size,
                            unsigned int *r_keyuse,
                            char const **r_curve,
                            char **r_keygrip,
                            int *r_subalgo, unsigned int *r_subsize,
                            unsigned int *r_subkeyuse,
                            char const **r_subcurve,
                            char **r_subkeygrip)
{
  gpg_error_t err = 0;
  char *primary, *secondary;

  if (r_algo)
    *r_algo = 0;
  if (r_size)
    *r_size = 0;
  if (r_keyuse)
    *r_keyuse = 0;
  if (r_curve)
    *r_curve = NULL;
  if (r_keygrip)
    *r_keygrip = NULL;
  if (r_subalgo)
    *r_subalgo = 0;
  if (r_subsize)
    *r_subsize = 0;
  if (r_subkeyuse)
    *r_subkeyuse = 0;
  if (r_subcurve)
    *r_subcurve = NULL;
  if (r_subkeygrip)
    *r_subkeygrip = NULL;

  if (!string || !*string
      || !ascii_strcasecmp (string, "default") || !strcmp (string, "-"))
    string = get_default_pubkey_algo ();
  else if (!ascii_strcasecmp (string, "future-default")
           || !ascii_strcasecmp (string, "futuredefault"))
    string = FUTURE_STD_KEY_PARAM;
  else if (!ascii_strcasecmp (string, "card"))
    string = "card/cert,sign+card/encr";

  primary = xstrdup (string);
  secondary = strchr (primary, '+');
  if (secondary)
    *secondary++ = 0;
  if (part == -1 || part == 0)
    {
      err = parse_key_parameter_part (ctrl, primary,
                                      0, 0, r_algo, r_size,
                                      r_keyuse, r_curve, r_keygrip);
      if (!err && part == -1)
        err = parse_key_parameter_part (ctrl, secondary,
                                        1, 0, r_subalgo, r_subsize,
                                        r_subkeyuse, r_subcurve,
                                        r_subkeygrip);
    }
  else if (part == 1)
    {
      /* If we have SECONDARY, use that part.  If there is only one
       * part consider this to be the subkey algo.  In case a
       * SUGGESTED_USE has been given and the usage of the secondary
       * part does not match SUGGESTED_USE try again using the primary
       * part.  Noet thar when falling back to the primary key we need
       * to force clearing the cert usage. */
      if (secondary)
        {
          err = parse_key_parameter_part (ctrl, secondary,
                                          1, 0,
                                          r_algo, r_size, r_keyuse, r_curve,
                                          r_keygrip);
          if (!err && suggested_use && r_keyuse && !(suggested_use & *r_keyuse))
            err = parse_key_parameter_part (ctrl, primary,
                                            1, 1 /*(clear cert)*/,
                                            r_algo, r_size, r_keyuse, r_curve,
                                            r_keygrip);
        }
      else
        err = parse_key_parameter_part (ctrl, primary,
                                        1, 0,
                                        r_algo, r_size, r_keyuse, r_curve,
                                        r_keygrip);
    }

  xfree (primary);

  return err;
}



/* Append R to the linked list PARA.  */
static void
append_to_parameter (struct para_data_s *para, struct para_data_s *r)
{
  log_assert (para);
  while (para->next)
    para = para->next;
  para->next = r;
}

/* Release the parameter list R.  */
static void
release_parameter_list (struct para_data_s *r)
{
  struct para_data_s *r2;

  for (; r ; r = r2)
    {
      r2 = r->next;
      if (r->key == pPASSPHRASE && *r->u.value)
        wipememory (r->u.value, strlen (r->u.value));
      xfree (r);
    }
}

/* Return the N-th parameter of name KEY from PARA.  An IDX of 0
 * returns the first and so on.  */
static struct para_data_s *
get_parameter_idx (struct para_data_s *para, enum para_name key,
                   unsigned int idx)
{
  struct para_data_s *r;

  for(r = para; r; r = r->next)
    if (r->key == key)
      {
        if (!idx)
          return r;
        idx--;
      }
  return NULL;
}

/* Return the first parameter of name KEY from PARA.  */
static struct para_data_s *
get_parameter (struct para_data_s *para, enum para_name key)
{
  return get_parameter_idx (para, key, 0);
}

static const char *
get_parameter_value( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return (r && *r->u.value)? r->u.value : NULL;
}


/* This is similar to get_parameter_value but also returns the empty
   string.  This is required so that quick_generate_keypair can use an
   empty Passphrase to specify no-protection.  */
static const char *
get_parameter_passphrase (struct para_data_s *para)
{
  struct para_data_s *r = get_parameter (para, pPASSPHRASE);
  return r ? r->u.value : NULL;
}


static int
get_parameter_algo (ctrl_t ctrl, struct para_data_s *para, enum para_name key,
                    int *r_default)
{
  int i;
  struct para_data_s *r = get_parameter( para, key );

  if (r_default)
    *r_default = 0;

  if (!r)
    return -1;

  /* Note that we need to handle the ECC algorithms specified as
     strings directly because Libgcrypt folds them all to ECC.  */
  if (!ascii_strcasecmp (r->u.value, "default"))
    {
      /* Note: If you change this default algo, remember to change it
       * also in gpg.c:gpgconf_list.  */
      /* FIXME: We only allow the algo here and have a separate thing
       * for the curve etc.  That is a ugly but demanded for backward
       * compatibility with the batch key generation.  It would be
       * better to make full use of parse_key_parameter_string.  */
      parse_key_parameter_string (ctrl, NULL, 0, 0,
                                  &i, NULL, NULL, NULL, NULL,
                                  NULL, NULL, NULL, NULL, NULL);
      if (r_default)
        *r_default = 1;
    }
  else if (digitp (r->u.value))
    i = atoi( r->u.value );
  else if (!strcmp (r->u.value, "ELG-E")
           || !strcmp (r->u.value, "ELG"))
    i = PUBKEY_ALGO_ELGAMAL_E;
  else if (!ascii_strcasecmp (r->u.value, "EdDSA"))
    i = PUBKEY_ALGO_EDDSA;
  else if (!ascii_strcasecmp (r->u.value, "ECDSA"))
    i = PUBKEY_ALGO_ECDSA;
  else if (!ascii_strcasecmp (r->u.value, "ECDH"))
    i = PUBKEY_ALGO_ECDH;
  else
    i = map_pk_gcry_to_openpgp (gcry_pk_map_name (r->u.value));

  if (i == PUBKEY_ALGO_RSA_E || i == PUBKEY_ALGO_RSA_S)
    i = 0; /* we don't want to allow generation of these algorithms */
  return i;
}


/* Parse a usage string.  The usage keywords "auth", "sign", "encr"
 * may be delimited by space, tab, or comma.  On error -1 is returned
 * instead of the usage flags.  */
static int
parse_usagestr (const char *usagestr)
{
  gpg_error_t err;
  char **tokens = NULL;
  const char *s;
  int i;
  unsigned int use = 0;

  tokens = strtokenize (usagestr, " \t,");
  if (!tokens)
    {
      err = gpg_error_from_syserror ();
      log_error ("strtokenize failed: %s\n", gpg_strerror (err));
      return -1;
    }

  for (i=0; (s = tokens[i]); i++)
    {
      if (!*s)
        ;
      else if (!ascii_strcasecmp (s, "sign"))
        use |= PUBKEY_USAGE_SIG;
      else if (!ascii_strcasecmp (s, "encrypt")
                || !ascii_strcasecmp (s, "encr"))
        use |= PUBKEY_USAGE_ENC;
      else if (!ascii_strcasecmp (s, "auth"))
        use |= PUBKEY_USAGE_AUTH;
      else if (!ascii_strcasecmp (s, "cert"))
        use |= PUBKEY_USAGE_CERT;
      else if (!ascii_strcasecmp (s, "renc"))
        use |= PUBKEY_USAGE_RENC;
      else if (!ascii_strcasecmp (s, "time"))
        use |= PUBKEY_USAGE_TIME;
      else if (!ascii_strcasecmp (s, "group"))
        use |= PUBKEY_USAGE_GROUP;
      else
        {
          xfree (tokens);
          return -1; /* error */
        }
    }

  xfree (tokens);
  return use;
}


/*
 * Parse the usage parameter and set the keyflags.  Returns -1 on
 * error, 0 for no usage given or 1 for usage available.
 */
static int
parse_parameter_usage (const char *fname,
                       struct para_data_s *para, enum para_name key)
{
  struct para_data_s *r = get_parameter( para, key );
  int i;

  if (!r)
    return 0; /* none (this is an optional parameter)*/

  i = parse_usagestr (r->u.value);
  if (i == -1)
    {
      log_error ("%s:%d: invalid usage list\n", fname, r->lnr );
      return -1; /* error */
    }

  r->u.usage = i;
  return 1;
}


/* Parse the revocation key specified by NAME, check that the public
 * key exists (so that we can get the required public key algorithm),
 * and return a parameter wit the revocation key information.  On
 * error print a diagnostic and return NULL.  */
static struct para_data_s *
prepare_desig_revoker (ctrl_t ctrl, const char *name)
{
  gpg_error_t err;
  struct para_data_s *para = NULL;
  KEYDB_SEARCH_DESC desc;
  int sensitive = 0;
  struct revocation_key revkey;
  PKT_public_key *revoker_pk = NULL;
  size_t fprlen;

  if (!ascii_strncasecmp (name, "sensitive:", 10) && !spacep (name+10))
    {
      name += 10;
      sensitive = 1;
    }

  if (classify_user_id (name, &desc, 1)
      || desc.mode != KEYDB_SEARCH_MODE_FPR)
    {
      log_info (_("\"%s\" is not a fingerprint\n"), name);
      err = gpg_error (GPG_ERR_INV_NAME);
      goto leave;
    }

  revoker_pk = xcalloc (1, sizeof *revoker_pk);
  revoker_pk->req_usage = PUBKEY_USAGE_CERT;
  err = get_pubkey_byname (ctrl, GET_PUBKEY_NO_AKL,
                           NULL, revoker_pk, name, NULL, NULL, 1);
  if (err)
    goto leave;

  fingerprint_from_pk (revoker_pk, revkey.fpr, &fprlen);
  if (fprlen != 20)
    {
      log_info (_("cannot appoint a PGP 2.x style key as a "
                  "designated revoker\n"));
      err = gpg_error (GPG_ERR_UNUSABLE_PUBKEY);
      goto leave;
    }
  revkey.class = 0x80;
  if (sensitive)
    revkey.class |= 0x40;
  revkey.algid = revoker_pk->pubkey_algo;

  para = xcalloc (1, sizeof *para);
  para->key = pREVOKER;
  memcpy (&para->u.revkey, &revkey, sizeof revkey);

 leave:
  if (err)
    log_error ("invalid revocation key '%s': %s\n", name, gpg_strerror (err));
  free_public_key (revoker_pk);
  return para;
}


/* Parse a pREVOKER parameter into its dedicated parts.  */
static int
parse_revocation_key (const char *fname,
		      struct para_data_s *para, enum para_name key)
{
  struct para_data_s *r = get_parameter( para, key );
  struct revocation_key revkey;
  char *pn;
  int i;

  if( !r )
    return 0; /* none (this is an optional parameter) */

  pn = r->u.value;

  revkey.class=0x80;
  revkey.algid=atoi(pn);
  if(!revkey.algid)
    goto fail;

  /* Skip to the fpr */
  while(*pn && *pn!=':')
    pn++;

  if(*pn!=':')
    goto fail;

  pn++;

  for(i=0;i<MAX_FINGERPRINT_LEN && *pn;i++,pn+=2)
    {
      int c=hextobyte(pn);
      if(c==-1)
	goto fail;

      revkey.fpr[i]=c;
    }

  /* skip to the tag */
  while(*pn && *pn!='s' && *pn!='S')
    pn++;

  if(ascii_strcasecmp(pn,"sensitive")==0)
    revkey.class|=0x40;

  memcpy(&r->u.revkey,&revkey,sizeof(struct revocation_key));

  return 0;

  fail:
  log_error("%s:%d: invalid revocation key\n", fname, r->lnr );
  return -1; /* error */
}


static u32
get_parameter_u32( struct para_data_s *para, enum para_name key )
{
  struct para_data_s *r = get_parameter( para, key );

  if( !r )
    return 0;
  if( r->key == pKEYCREATIONDATE )
    return r->u.creation;
  if( r->key == pKEYEXPIRE || r->key == pSUBKEYEXPIRE )
    return r->u.expire;
  if( r->key == pKEYUSAGE || r->key == pSUBKEYUSAGE )
    return r->u.usage;

  return (unsigned int)strtoul( r->u.value, NULL, 10 );
}

static unsigned int
get_parameter_uint( struct para_data_s *para, enum para_name key )
{
    return get_parameter_u32( para, key );
}

static struct revocation_key *
get_parameter_revkey (struct para_data_s *para, enum para_name key,
                      unsigned int idx)
{
  struct para_data_s *r = get_parameter_idx (para, key, idx);
  return r? &r->u.revkey : NULL;
}

static int
proc_parameter_file (ctrl_t ctrl, struct para_data_s *para, const char *fname,
                     struct output_control_s *outctrl, int card )
{
  struct para_data_s *r;
  const char *s1, *s2, *s3;
  size_t n;
  char *p;
  strlist_t sl;
  int is_default = 0;
  int have_user_id = 0;
  int err, algo;

  /* Check that we have all required parameters. */
  r = get_parameter( para, pKEYTYPE );
  if(r)
    {
      algo = get_parameter_algo (ctrl, para, pKEYTYPE, &is_default);
      if (openpgp_pk_test_algo2 (algo, PUBKEY_USAGE_SIG))
	{
	  log_error ("%s:%d: invalid algorithm\n", fname, r->lnr );
	  return -1;
	}
    }
  else
    {
      log_error ("%s: no Key-Type specified\n",fname);
      return -1;
    }

  err = parse_parameter_usage (fname, para, pKEYUSAGE);
  if (!err)
    {
      /* Default to algo capabilities if key-usage is not provided and
         no default algorithm has been requested.  */
      r = xmalloc_clear(sizeof(*r));
      r->key = pKEYUSAGE;
      r->u.usage = (is_default
                    ? (PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG)
                    : openpgp_pk_algo_usage(algo));
      append_to_parameter (para, r);
    }
  else if (err == -1)
    return -1;
  else
    {
      r = get_parameter (para, pKEYUSAGE);
      if (r && (r->u.usage & ~openpgp_pk_algo_usage (algo)))
        {
          log_error ("%s:%d: specified Key-Usage not allowed for algo %d\n",
                     fname, r->lnr, algo);
          return -1;
        }
    }

  is_default = 0;
  r = get_parameter( para, pSUBKEYTYPE );
  if(r)
    {
      algo = get_parameter_algo (ctrl, para, pSUBKEYTYPE, &is_default);
      if (openpgp_pk_test_algo (algo))
	{
	  log_error ("%s:%d: invalid algorithm\n", fname, r->lnr );
	  return -1;
	}

      err = parse_parameter_usage (fname, para, pSUBKEYUSAGE);
      if (!err)
	{
	  /* Default to algo capabilities if subkey-usage is not
	     provided */
	  r = xmalloc_clear (sizeof(*r));
	  r->key = pSUBKEYUSAGE;
	  r->u.usage = (is_default
                        ? PUBKEY_USAGE_ENC
                        : openpgp_pk_algo_usage (algo));
          append_to_parameter (para, r);
	}
      else if (err == -1)
	return -1;
      else
        {
          r = get_parameter (para, pSUBKEYUSAGE);
          if (r && (r->u.usage & ~openpgp_pk_algo_usage (algo)))
            {
              log_error ("%s:%d: specified Subkey-Usage not allowed"
                         " for algo %d\n", fname, r->lnr, algo);
              return -1;
            }
        }
    }


  if( get_parameter_value( para, pUSERID ) )
    have_user_id=1;
  else
    {
      /* create the formatted user ID */
      s1 = get_parameter_value( para, pNAMEREAL );
      s2 = get_parameter_value( para, pNAMECOMMENT );
      s3 = get_parameter_value( para, pNAMEEMAIL );
      if( s1 || s2 || s3 )
	{
	  n = (s1?strlen(s1):0) + (s2?strlen(s2):0) + (s3?strlen(s3):0);
	  r = xmalloc_clear( sizeof *r + n + 20 );
	  r->key = pUSERID;
	  p = r->u.value;
	  if( s1 )
	    p = stpcpy(p, s1 );
	  if( s2 )
	    p = stpcpy(stpcpy(stpcpy(p," ("), s2 ),")");
	  if( s3 )
            {
              /* If we have only the email part, do not add the space
               * and the angle brackets.  */
              if (*r->u.value)
                p = stpcpy(stpcpy(stpcpy(p," <"), s3 ),">");
              else
                p = stpcpy (p, s3);
            }
          append_to_parameter (para, r);
	  have_user_id=1;
	}
    }

  if(!have_user_id)
    {
      log_error("%s: no User-ID specified\n",fname);
      return -1;
    }

  /* Set preferences, if any. */
  keygen_set_std_prefs(get_parameter_value( para, pPREFERENCES ), 0);

  /* Set keyserver, if any. */
  s1=get_parameter_value( para, pKEYSERVER );
  if(s1)
    {
      struct keyserver_spec *spec;

      spec = parse_keyserver_uri (s1, 1);
      if(spec)
	{
	  free_keyserver_spec(spec);
	  opt.def_keyserver_url=s1;
	}
      else
	{
          r = get_parameter (para, pKEYSERVER);
	  log_error("%s:%d: invalid keyserver url\n", fname, r->lnr );
	  return -1;
	}
    }

  /* Set revoker from parameter file, if any.  Must be done first so
   * that we don't find a parameter set via prepare_desig_revoker.  */
  if (parse_revocation_key (fname, para, pREVOKER))
    return -1;

  /* Check and append revokers from the config file.  */
  for (sl = opt.desig_revokers; sl; sl = sl->next)
    {
      r = prepare_desig_revoker (ctrl, sl->d);
      if (!r)
        return -1;
      append_to_parameter (para, r);
     }


  /* Make KEYCREATIONDATE from Creation-Date.  */
  r = get_parameter (para, pCREATIONDATE);
  if (r && *r->u.value)
    {
      u32 seconds;

      seconds = parse_creation_string (r->u.value);
      if (!seconds)
	{
	  log_error ("%s:%d: invalid creation date\n", fname, r->lnr );
	  return -1;
	}
      r->u.creation = seconds;
      r->key = pKEYCREATIONDATE;  /* Change that entry. */
    }

  /* Make KEYEXPIRE from Expire-Date.  */
  r = get_parameter( para, pEXPIREDATE );
  if( r && *r->u.value )
    {
      u32 seconds;

      seconds = parse_expire_string( r->u.value );
      if( seconds == (u32)-1 )
	{
	  log_error("%s:%d: invalid expire date\n", fname, r->lnr );
	  return -1;
	}
      r->u.expire = seconds;
      r->key = pKEYEXPIRE;  /* change hat entry */
      /* also set it for the subkey */
      r = xmalloc_clear( sizeof *r + 20 );
      r->key = pSUBKEYEXPIRE;
      r->u.expire = seconds;
      append_to_parameter (para, r);
    }

  do_generate_keypair (ctrl, para, outctrl, card );
  return 0;
}


/****************
 * Kludge to allow non interactive key generation controlled
 * by a parameter file.
 * Note, that string parameters are expected to be in UTF-8
 */
static void
read_parameter_file (ctrl_t ctrl, const char *fname )
{
    static struct { const char *name;
		    enum para_name key;
    } keywords[] = {
	{ "Key-Type",       pKEYTYPE},
	{ "Key-Length",     pKEYLENGTH },
	{ "Key-Curve",      pKEYCURVE },
	{ "Key-Usage",      pKEYUSAGE },
	{ "Subkey-Type",    pSUBKEYTYPE },
	{ "Subkey-Length",  pSUBKEYLENGTH },
	{ "Subkey-Curve",   pSUBKEYCURVE },
	{ "Subkey-Usage",   pSUBKEYUSAGE },
	{ "Name-Real",      pNAMEREAL },
	{ "Name-Email",     pNAMEEMAIL },
	{ "Name-Comment",   pNAMECOMMENT },
	{ "Expire-Date",    pEXPIREDATE },
	{ "Creation-Date",  pCREATIONDATE },
	{ "Passphrase",     pPASSPHRASE },
	{ "Preferences",    pPREFERENCES },
	{ "Revoker",        pREVOKER },
        { "Handle",         pHANDLE },
        { "Keyserver",      pKEYSERVER },
        { "Keygrip",        pKEYGRIP },
        { "Key-Grip",       pKEYGRIP },
        { "Subkey-grip",    pSUBKEYGRIP },
        { NULL, 0 }
    };
    IOBUF fp;
    byte *line;
    unsigned int maxlen, nline;
    char *p;
    int lnr;
    const char *err = NULL;
    struct para_data_s *para, *r;
    int i;
    struct output_control_s outctrl;

    memset( &outctrl, 0, sizeof( outctrl ) );
    outctrl.pub.afx = new_armor_context ();

    if( !fname || !*fname)
      fname = "-";

    fp = iobuf_open (fname);
    if (fp && is_secured_file (iobuf_get_fd (fp)))
      {
        iobuf_close (fp);
        fp = NULL;
        gpg_err_set_errno (EPERM);
      }
    if (!fp) {
      log_error (_("can't open '%s': %s\n"), fname, strerror(errno) );
      return;
    }
    iobuf_ioctl (fp, IOBUF_IOCTL_NO_CACHE, 1, NULL);

    lnr = 0;
    err = NULL;
    para = NULL;
    maxlen = 1024;
    line = NULL;
    nline = 0;
    while ( iobuf_read_line (fp, &line, &nline, &maxlen) ) {
	char *keyword, *value;

	lnr++;
	if( !maxlen ) {
	    err = "line too long";
	    break;
	}
	for( p = line; isspace(*(byte*)p); p++ )
	    ;
	if( !*p || *p == '#' )
	    continue;
	keyword = p;
	if( *keyword == '%' ) {
	    for( ; !isspace(*(byte*)p); p++ )
		;
	    if( *p )
		*p++ = 0;
	    for( ; isspace(*(byte*)p); p++ )
		;
	    value = p;
	    trim_trailing_ws( value, strlen(value) );
	    if( !ascii_strcasecmp( keyword, "%echo" ) )
		log_info("%s\n", value );
	    else if( !ascii_strcasecmp( keyword, "%dry-run" ) )
		outctrl.dryrun = 1;
	    else if( !ascii_strcasecmp( keyword, "%ask-passphrase" ) )
              ; /* Dummy for backward compatibility. */
	    else if( !ascii_strcasecmp( keyword, "%no-ask-passphrase" ) )
	      ; /* Dummy for backward compatibility. */
	    else if( !ascii_strcasecmp( keyword, "%no-protection" ) )
                outctrl.keygen_flags |= KEYGEN_FLAG_NO_PROTECTION;
	    else if( !ascii_strcasecmp( keyword, "%transient-key" ) )
                outctrl.keygen_flags |= KEYGEN_FLAG_TRANSIENT_KEY;
	    else if( !ascii_strcasecmp( keyword, "%commit" ) ) {
		outctrl.lnr = lnr;
		if (proc_parameter_file (ctrl, para, fname, &outctrl, 0 ))
                  print_status_key_not_created
                    (get_parameter_value (para, pHANDLE));
		release_parameter_list( para );
		para = NULL;
	    }
	    else if( !ascii_strcasecmp( keyword, "%pubring" ) ) {
		if( outctrl.pub.fname && !strcmp( outctrl.pub.fname, value ) )
		    ; /* still the same file - ignore it */
		else {
		    xfree( outctrl.pub.newfname );
		    outctrl.pub.newfname = xstrdup( value );
		    outctrl.use_files = 1;
		}
	    }
	    else if( !ascii_strcasecmp( keyword, "%secring" ) ) {
              /* Ignore this command.  */
	    }
	    else
		log_info("skipping control '%s' (%s)\n", keyword, value );


	    continue;
	}


	if( !(p = strchr( p, ':' )) || p == keyword ) {
	    err = "missing colon";
	    break;
	}
	if( *p )
	    *p++ = 0;
	for( ; isspace(*(byte*)p); p++ )
	    ;
	if( !*p ) {
	    err = "missing argument";
	    break;
	}
	value = p;
	trim_trailing_ws( value, strlen(value) );

	for(i=0; keywords[i].name; i++ ) {
	    if( !ascii_strcasecmp( keywords[i].name, keyword ) )
		break;
	}
	if( !keywords[i].name ) {
	    err = "unknown keyword";
	    break;
	}
	if( keywords[i].key != pKEYTYPE && !para ) {
	    err = "parameter block does not start with \"Key-Type\"";
	    break;
	}

	if( keywords[i].key == pKEYTYPE && para ) {
	    outctrl.lnr = lnr;
	    if (proc_parameter_file (ctrl, para, fname, &outctrl, 0 ))
              print_status_key_not_created
                (get_parameter_value (para, pHANDLE));
	    release_parameter_list( para );
	    para = NULL;
	}
	else {
	    for( r = para; r; r = r->next ) {
		if( r->key == keywords[i].key )
		    break;
	    }
	    if( r ) {
		err = "duplicate keyword";
		break;
	    }
	}
	r = xmalloc_clear( sizeof *r + strlen( value ) );
	r->lnr = lnr;
	r->key = keywords[i].key;
	strcpy( r->u.value, value );
	r->next = para;
	para = r;
    }
    if( err )
	log_error("%s:%d: %s\n", fname, lnr, err );
    else if( iobuf_error (fp) ) {
	log_error("%s:%d: read error\n", fname, lnr);
    }
    else if( para ) {
	outctrl.lnr = lnr;
	if (proc_parameter_file (ctrl, para, fname, &outctrl, 0 ))
          print_status_key_not_created (get_parameter_value (para, pHANDLE));
    }

    if( outctrl.use_files ) { /* close open streams */
	iobuf_close( outctrl.pub.stream );

        /* Must invalidate that ugly cache to actually close it.  */
        if (outctrl.pub.fname)
          iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE,
                       0, (char*)outctrl.pub.fname);

	xfree( outctrl.pub.fname );
	xfree( outctrl.pub.newfname );
    }

    xfree (line);
    release_parameter_list( para );
    iobuf_close (fp);
    release_armor_context (outctrl.pub.afx);
}


/* Helper for quick_generate_keypair.  */
static struct para_data_s *
quickgen_set_para (struct para_data_s *para, int for_subkey,
                   int algo, int nbits, const char *curve, unsigned int use,
                   const char *keygrip)
{
  struct para_data_s *r;

  r = xmalloc_clear (sizeof *r + 50);
  r->key = for_subkey? pSUBKEYUSAGE :  pKEYUSAGE;
  if (use)
    snprintf (r->u.value, 30, "%s%s%s%s%s%s%s",
              (use & PUBKEY_USAGE_ENC)?  "encr " : "",
              (use & PUBKEY_USAGE_SIG)?  "sign " : "",
              (use & PUBKEY_USAGE_AUTH)? "auth " : "",
              (use & PUBKEY_USAGE_CERT)? "cert " : "",
              (use & PUBKEY_USAGE_RENC)? "renc " : "",
              (use & PUBKEY_USAGE_TIME)? "time " : "",
              (use & PUBKEY_USAGE_GROUP)?"group ": "");
  else
    strcpy (r->u.value, for_subkey ? "encr" : "sign");
  r->next = para;
  para = r;
  r = xmalloc_clear (sizeof *r + 20);
  r->key = for_subkey? pSUBKEYTYPE : pKEYTYPE;
  snprintf (r->u.value, 20, "%d", algo);
  r->next = para;
  para = r;

  if (keygrip)
    {
      r = xmalloc_clear (sizeof *r + strlen (keygrip));
      r->key = for_subkey? pSUBKEYGRIP : pKEYGRIP;
      strcpy (r->u.value, keygrip);
      r->next = para;
      para = r;
    }
  else if (curve)
    {
      r = xmalloc_clear (sizeof *r + strlen (curve));
      r->key = for_subkey? pSUBKEYCURVE : pKEYCURVE;
      strcpy (r->u.value, curve);
      r->next = para;
      para = r;
    }
  else
    {
      r = xmalloc_clear (sizeof *r + 20);
      r->key = for_subkey? pSUBKEYLENGTH : pKEYLENGTH;
      sprintf (r->u.value, "%u", nbits);
      r->next = para;
      para = r;
    }

  return para;
}


/*
 * Unattended generation of a standard key.
 */
void
quick_generate_keypair (ctrl_t ctrl, const char *uid, const char *algostr,
                        const char *usagestr, const char *expirestr)
{
  gpg_error_t err;
  struct para_data_s *para = NULL;
  struct para_data_s *r;
  struct output_control_s outctrl;
  int use_tty;

  memset (&outctrl, 0, sizeof outctrl);

  use_tty = (!opt.batch && !opt.answer_yes
             && !*algostr && !*usagestr && !*expirestr
             && !cpr_enabled ()
             && gnupg_isatty (fileno (stdin))
             && gnupg_isatty (fileno (stdout))
             && gnupg_isatty (fileno (stderr)));

  r = xmalloc_clear (sizeof *r + strlen (uid));
  r->key = pUSERID;
  strcpy (r->u.value, uid);
  r->next = para;
  para = r;

  uid = trim_spaces (r->u.value);
  if (!*uid || (!opt.allow_freeform_uid && !is_valid_user_id (uid)))
    {
      log_error (_("Key generation failed: %s\n"),
                 gpg_strerror (GPG_ERR_INV_USER_ID));
      goto leave;
    }

  /* If gpg is directly used on the console ask whether a key with the
     given user id shall really be created.  */
  if (use_tty)
    {
      tty_printf (_("About to create a key for:\n    \"%s\"\n\n"), uid);
      if (!cpr_get_answer_is_yes_def ("quick_keygen.okay",
                                      _("Continue? (Y/n) "), 1))
        goto leave;
    }

  /* Check whether such a user ID already exists.  */
  {
    KEYDB_HANDLE kdbhd;
    KEYDB_SEARCH_DESC desc;

    memset (&desc, 0, sizeof desc);
    desc.mode = KEYDB_SEARCH_MODE_EXACT;
    desc.u.name = uid;

    kdbhd = keydb_new ();
    if (!kdbhd)
      goto leave;

    err = keydb_search (kdbhd, &desc, 1, NULL);
    keydb_release (kdbhd);
    if (gpg_err_code (err) != GPG_ERR_NOT_FOUND)
      {
        log_info (_("A key for \"%s\" already exists\n"), uid);
        if (opt.answer_yes)
          ;
        else if (!use_tty
                 || !cpr_get_answer_is_yes_def ("quick_keygen.force",
                                                _("Create anyway? (y/N) "), 0))
          {
            write_status_error ("genkey", gpg_error (304));
            log_inc_errorcount ();  /* we used log_info */
            goto leave;
          }
        log_info (_("creating anyway\n"));
      }
  }

  if (!*expirestr || strcmp (expirestr, "-") == 0)
    expirestr = default_expiration_interval;

  if ((!*algostr || !ascii_strcasecmp (algostr, "default")
       || !ascii_strcasecmp (algostr, "future-default")
       || !ascii_strcasecmp (algostr, "futuredefault")
       || !ascii_strcasecmp (algostr, "card"))
      && (!*usagestr || !ascii_strcasecmp (usagestr, "default")
          || !strcmp (usagestr, "-")))
    {
      /* Use default key parameters.  */
      int algo, subalgo;
      unsigned int size, subsize;
      unsigned int keyuse, subkeyuse;
      const char *curve, *subcurve;
      char *keygrip, *subkeygrip;

      err = parse_key_parameter_string (ctrl, algostr, -1, 0,
                                        &algo, &size, &keyuse, &curve,
                                        &keygrip,
                                        &subalgo, &subsize, &subkeyuse,
                                        &subcurve, &subkeygrip);
      if (err)
        {
          log_error (_("Key generation failed: %s\n"), gpg_strerror (err));
          goto leave;
        }

      para = quickgen_set_para (para, 0, algo, size, curve, keyuse,
                                keygrip);
      if (subalgo)
        para = quickgen_set_para (para, 1,
                                  subalgo, subsize, subcurve, subkeyuse,
                                  subkeygrip);
      if (*expirestr)
        {
          u32 expire;

          expire = parse_expire_string (expirestr);
          if (expire == (u32)-1 )
            {
              err = gpg_error (GPG_ERR_INV_VALUE);
              log_error (_("Key generation failed: %s\n"), gpg_strerror (err));
              goto leave;
            }
          r = xmalloc_clear (sizeof *r + 20);
          r->key = pKEYEXPIRE;
          r->u.expire = expire;
          r->next = para;
          para = r;
        }

      xfree (keygrip);
      xfree (subkeygrip);
    }
  else
    {
      /* Extended unattended mode.  Creates only the primary key. */
      int algo;
      unsigned int use;
      u32 expire;
      unsigned int nbits;
      const char *curve;
      char *keygrip;

      err = parse_algo_usage_expire (ctrl, 0, algostr, usagestr, expirestr,
                                     &algo, &use, &expire, &nbits, &curve,
                                     &keygrip);
      if (err)
        {
          log_error (_("Key generation failed: %s\n"), gpg_strerror (err) );
          goto leave;
        }

      para = quickgen_set_para (para, 0, algo, nbits, curve, use,
                                keygrip);
      r = xmalloc_clear (sizeof *r + 20);
      r->key = pKEYEXPIRE;
      r->u.expire = expire;
      r->next = para;
      para = r;

      xfree (keygrip);
    }

  /* If the pinentry loopback mode is not and we have a static
     passphrase (i.e. set with --passphrase{,-fd,-file} while in batch
     mode), we use that passphrase for the new key.  */
  if (opt.pinentry_mode != PINENTRY_MODE_LOOPBACK
      && have_static_passphrase ())
    {
      const char *s = get_static_passphrase ();

      r = xmalloc_clear (sizeof *r + strlen (s));
      r->key = pPASSPHRASE;
      strcpy (r->u.value, s);
      r->next = para;
      para = r;
    }

  proc_parameter_file (ctrl, para, "[internal]", &outctrl, 0);

 leave:
  release_parameter_list (para);
}


/*
 * Generate a keypair (fname is only used in batch mode) If
 * CARD_SERIALNO is not NULL the function will create the keys on an
 * OpenPGP Card.  If CARD_BACKUP_KEY has been set and CARD_SERIALNO is
 * NOT NULL, the encryption key for the card is generated on the host,
 * imported to the card and a backup file created by gpg-agent.  If
 * FULL is not set only the basic prompts are used (except for batch
 * mode).
 */
void
generate_keypair (ctrl_t ctrl, int full, const char *fname,
                  const char *card_serialno, int card_backup_key)
{
  gpg_error_t err;
  unsigned int nbits;
  char *uid = NULL;
  int algo;
  unsigned int use;
  int both = 0;
  u32 expire;
  struct para_data_s *para = NULL;
  struct para_data_s *r;
  struct output_control_s outctrl;

#ifndef ENABLE_CARD_SUPPORT
  (void)card_backup_key;
#endif

  memset( &outctrl, 0, sizeof( outctrl ) );

  if (opt.batch && card_serialno)
    {
      /* We don't yet support unattended key generation with a card
       * serial number. */
      log_error (_("can't do this in batch mode\n"));
      print_further_info ("key generation with card serial number");
      return;
    }

  if (opt.batch)
    {
      read_parameter_file (ctrl, fname);
      return;
    }

  if (card_serialno)
    {
#ifdef ENABLE_CARD_SUPPORT
      struct agent_card_info_s info;

      memset (&info, 0, sizeof (info));
      err = agent_scd_getattr ("KEY-ATTR", &info);
      if (err)
        {
          log_error (_("error getting current key info: %s\n"),
                     gpg_strerror (err));
          return;
        }

      r = xcalloc (1, sizeof *r + strlen (card_serialno) );
      r->key = pSERIALNO;
      strcpy( r->u.value, card_serialno);
      r->next = para;
      para = r;

      r = xcalloc (1, sizeof *r + 20 );
      r->key = pKEYTYPE;
      sprintf( r->u.value, "%d", info.key_attr[0].algo );
      r->next = para;
      para = r;
      r = xcalloc (1, sizeof *r + 20 );
      r->key = pKEYUSAGE;
      strcpy (r->u.value, "sign");
      r->next = para;
      para = r;

      r = xcalloc (1, sizeof *r + 20 );
      r->key = pSUBKEYTYPE;
      sprintf( r->u.value, "%d", info.key_attr[1].algo );
      r->next = para;
      para = r;
      r = xcalloc (1, sizeof *r + 20 );
      r->key = pSUBKEYUSAGE;
      strcpy (r->u.value, "encrypt");
      r->next = para;
      para = r;
      if (info.key_attr[1].algo == PUBKEY_ALGO_RSA)
        {
          r = xcalloc (1, sizeof *r + 20 );
          r->key = pSUBKEYLENGTH;
          sprintf( r->u.value, "%u", info.key_attr[1].nbits);
          r->next = para;
          para = r;
        }
      else if (info.key_attr[1].algo == PUBKEY_ALGO_ECDSA
               || info.key_attr[1].algo == PUBKEY_ALGO_EDDSA
               || info.key_attr[1].algo == PUBKEY_ALGO_ECDH)
        {
          r = xcalloc (1, sizeof *r + strlen (info.key_attr[1].curve));
          r->key = pSUBKEYCURVE;
          strcpy (r->u.value, info.key_attr[1].curve);
          r->next = para;
          para = r;
        }

      r = xcalloc (1, sizeof *r + 20 );
      r->key = pAUTHKEYTYPE;
      sprintf( r->u.value, "%d", info.key_attr[2].algo );
      r->next = para;
      para = r;

      if (card_backup_key)
        {
          r = xcalloc (1, sizeof *r + 1);
          r->key = pCARDBACKUPKEY;
          strcpy (r->u.value, "1");
          r->next = para;
          para = r;
        }
#endif /*ENABLE_CARD_SUPPORT*/
    }
  else if (full)  /* Full featured key generation.  */
    {
      int subkey_algo;
      char *key_from_hexgrip = NULL;

      algo = ask_algo (ctrl, 0, &subkey_algo, &use, &key_from_hexgrip);
      if (key_from_hexgrip)
        {
          r = xmalloc_clear( sizeof *r + 20 );
          r->key = pKEYTYPE;
          sprintf( r->u.value, "%d", algo);
          r->next = para;
          para = r;

          if (use)
            {
              r = xmalloc_clear( sizeof *r + 25 );
              r->key = pKEYUSAGE;
              sprintf( r->u.value, "%s%s%s",
                       (use & PUBKEY_USAGE_SIG)? "sign ":"",
                       (use & PUBKEY_USAGE_ENC)? "encrypt ":"",
                       (use & PUBKEY_USAGE_AUTH)? "auth":"" );
              r->next = para;
              para = r;
            }

          r = xmalloc_clear( sizeof *r + 40 );
          r->key = pKEYGRIP;
          strcpy (r->u.value, key_from_hexgrip);
          r->next = para;
          para = r;

          xfree (key_from_hexgrip);
        }
      else
        {
          const char *curve = NULL;

          if (subkey_algo)
            {
              /* Create primary and subkey at once.  */
              both = 1;
              if (algo == PUBKEY_ALGO_ECDSA
                  || algo == PUBKEY_ALGO_EDDSA
                  || algo == PUBKEY_ALGO_ECDH)
                {
                  curve = ask_curve (&algo, &subkey_algo, NULL);
                  r = xmalloc_clear( sizeof *r + 20 );
                  r->key = pKEYTYPE;
                  sprintf( r->u.value, "%d", algo);
                  r->next = para;
                  para = r;
                  nbits = 0;
                  r = xmalloc_clear (sizeof *r + strlen (curve));
                  r->key = pKEYCURVE;
                  strcpy (r->u.value, curve);
                  r->next = para;
                  para = r;
                }
              else
                {
                  r = xmalloc_clear( sizeof *r + 20 );
                  r->key = pKEYTYPE;
                  sprintf( r->u.value, "%d", algo);
                  r->next = para;
                  para = r;
                  nbits = ask_keysize (algo, 0);
                  r = xmalloc_clear( sizeof *r + 20 );
                  r->key = pKEYLENGTH;
                  sprintf( r->u.value, "%u", nbits);
                  r->next = para;
                  para = r;
                }
              r = xmalloc_clear( sizeof *r + 20 );
              r->key = pKEYUSAGE;
              strcpy( r->u.value, "sign" );
              r->next = para;
              para = r;

              r = xmalloc_clear( sizeof *r + 20 );
              r->key = pSUBKEYTYPE;
              sprintf( r->u.value, "%d", subkey_algo);
              r->next = para;
              para = r;
              r = xmalloc_clear( sizeof *r + 20 );
              r->key = pSUBKEYUSAGE;
              strcpy( r->u.value, "encrypt" );
              r->next = para;
              para = r;

              if (algo == PUBKEY_ALGO_ECDSA
                  || algo == PUBKEY_ALGO_EDDSA
                  || algo == PUBKEY_ALGO_ECDH)
                {
                  if (algo == PUBKEY_ALGO_EDDSA
                      && subkey_algo == PUBKEY_ALGO_ECDH)
                    {
                      /* Need to switch to a different curve for the
                         encryption key.  */
                      curve = "Curve25519";
                    }
                  r = xmalloc_clear (sizeof *r + strlen (curve));
                  r->key = pSUBKEYCURVE;
                  strcpy (r->u.value, curve);
                  r->next = para;
                  para = r;
                }
            }
          else /* Create only a single key.  */
            {
              /* For ECC we need to ask for the curve before storing the
                 algo because ask_curve may change the algo.  */
              if (algo == PUBKEY_ALGO_ECDSA
                  || algo == PUBKEY_ALGO_EDDSA
                  || algo == PUBKEY_ALGO_ECDH)
                {
                  curve = ask_curve (&algo, NULL, NULL);
                  r = xmalloc_clear (sizeof *r + strlen (curve));
                  r->key = pKEYCURVE;
                  strcpy (r->u.value, curve);
                  r->next = para;
                  para = r;
                }

              r = xmalloc_clear( sizeof *r + 20 );
              r->key = pKEYTYPE;
              sprintf( r->u.value, "%d", algo );
              r->next = para;
              para = r;

              if (use)
                {
                  r = xmalloc_clear( sizeof *r + 25 );
                  r->key = pKEYUSAGE;
                  sprintf( r->u.value, "%s%s%s",
                           (use & PUBKEY_USAGE_SIG)? "sign ":"",
                           (use & PUBKEY_USAGE_ENC)? "encrypt ":"",
                           (use & PUBKEY_USAGE_AUTH)? "auth":"" );
                  r->next = para;
                  para = r;
                }
              nbits = 0;
            }

          if (algo == PUBKEY_ALGO_ECDSA
              || algo == PUBKEY_ALGO_EDDSA
              || algo == PUBKEY_ALGO_ECDH)
            {
              /* The curve has already been set.  */
            }
          else
            {
              nbits = ask_keysize (both? subkey_algo : algo, nbits);
              r = xmalloc_clear( sizeof *r + 20 );
              r->key = both? pSUBKEYLENGTH : pKEYLENGTH;
              sprintf( r->u.value, "%u", nbits);
              r->next = para;
              para = r;
            }
        }
    }
  else /* Default key generation.  */
    {
      int subalgo;
      unsigned int size, subsize;
      unsigned int keyuse, subkeyuse;
      const char *curve, *subcurve;
      char *keygrip, *subkeygrip;

      tty_printf ( _("Note: Use \"%s %s\""
                     " for a full featured key generation dialog.\n"),
#if USE_GPG2_HACK
                   GPG_NAME "2"
#else
                   GPG_NAME
#endif
                   , "--full-generate-key" );

      err = parse_key_parameter_string (ctrl, NULL, -1, 0,
                                        &algo, &size, &keyuse, &curve,
                                        &keygrip,
                                        &subalgo, &subsize,
                                        &subkeyuse, &subcurve,
                                        &subkeygrip);
      if (err)
        {
          log_error (_("Key generation failed: %s\n"), gpg_strerror (err));
          return;
        }
      para = quickgen_set_para (para, 0,
                                algo, size, curve, keyuse,
                                keygrip);
      if (subalgo)
        para = quickgen_set_para (para, 1,
                                  subalgo, subsize, subcurve, subkeyuse,
                                  subkeygrip);

      xfree (keygrip);
      xfree (subkeygrip);
    }


  expire = full? ask_expire_interval (0, NULL)
               : parse_expire_string (default_expiration_interval);
  r = xcalloc (1, sizeof *r + 20);
  r->key = pKEYEXPIRE;
  r->u.expire = expire;
  r->next = para;
  para = r;
  r = xcalloc (1, sizeof *r + 20);
  r->key = pSUBKEYEXPIRE;
  r->u.expire = expire;
  r->next = para;
  para = r;

  uid = ask_user_id (0, full, NULL);
  if (!uid)
    {
      log_error(_("Key generation canceled.\n"));
      release_parameter_list( para );
      return;
    }
  r = xcalloc (1, sizeof *r + strlen (uid));
  r->key = pUSERID;
  strcpy (r->u.value, uid);
  r->next = para;
  para = r;

  proc_parameter_file (ctrl, para, "[internal]", &outctrl, !!card_serialno);
  release_parameter_list (para);
}


/* Create and delete a dummy packet to start off a list of kbnodes. */
static void
start_tree(KBNODE *tree)
{
  PACKET *pkt;

  pkt=xmalloc_clear(sizeof(*pkt));
  pkt->pkttype=PKT_NONE;
  *tree=new_kbnode(pkt);
  delete_kbnode(*tree);
}


/* Write the *protected* secret key to the file.  */
static gpg_error_t
card_write_key_to_backup_file (PKT_public_key *sk, const char *backup_dir)
{
  gpg_error_t err = 0;
  int rc;
  char keyid_buffer[2 * 8 + 1];
  char name_buffer[50];
  char *fname;
  IOBUF fp;
  mode_t oldmask;
  PACKET *pkt = NULL;

  format_keyid (pk_keyid (sk), KF_LONG, keyid_buffer, sizeof (keyid_buffer));
  snprintf (name_buffer, sizeof name_buffer, "sk_%s.gpg", keyid_buffer);

  fname = make_filename (backup_dir, name_buffer, NULL);
  /* Note that the umask call is not anymore needed because
     iobuf_create now takes care of it.  However, it does not harm
     and thus we keep it.  */
  oldmask = umask (077);
  if (is_secured_filename (fname))
    {
      fp = NULL;
      gpg_err_set_errno (EPERM);
    }
  else
    fp = iobuf_create (fname, 1);
  umask (oldmask);
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("can't create backup file '%s': %s\n"), fname, strerror (errno) );
      goto leave;
    }

  pkt = xcalloc (1, sizeof *pkt);
  pkt->pkttype = PKT_SECRET_KEY;
  pkt->pkt.secret_key = sk;

  rc = build_packet (fp, pkt);
  if (rc)
    {
      log_error ("build packet failed: %s\n", gpg_strerror (rc));
      iobuf_cancel (fp);
    }
  else
    {
      char *fprbuf;

      iobuf_close (fp);
      iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)fname);
      log_info (_("Note: backup of card key saved to '%s'\n"), fname);

      fprbuf = hexfingerprint (sk, NULL, 0);
      if (!fprbuf)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      write_status_text_and_buffer (STATUS_BACKUP_KEY_CREATED, fprbuf,
                                    fname, strlen (fname), 0);
      xfree (fprbuf);
    }

 leave:
  xfree (pkt);
  xfree (fname);
  return err;
}


/* Store key to card and make a backup file in OpenPGP format.  */
static gpg_error_t
card_store_key_with_backup (ctrl_t ctrl, PKT_public_key *sub_psk,
                            const char *backup_dir)
{
  PKT_public_key *sk;
  gnupg_isotime_t timestamp;
  gpg_error_t err;
  char *hexgrip;
  int rc;
  struct agent_card_info_s info;
  gcry_cipher_hd_t cipherhd = NULL;
  char *cache_nonce = NULL;
  void *kek = NULL;
  size_t keklen;
  char *ecdh_param_str = NULL;

  sk = copy_public_key (NULL, sub_psk);
  if (!sk)
    return gpg_error_from_syserror ();

  epoch2isotime (timestamp, (time_t)sk->timestamp);
  if (sk->pubkey_algo == PUBKEY_ALGO_ECDH)
    {
      ecdh_param_str = ecdh_param_str_from_pk (sk);
      if (!ecdh_param_str)
        {
          free_public_key (sk);
          return gpg_error_from_syserror ();
        }
    }
  err = hexkeygrip_from_pk (sk, &hexgrip);
  if (err)
    {
      xfree (ecdh_param_str);
      free_public_key (sk);
      return err;
    }

  memset(&info, 0, sizeof (info));
  rc = agent_scd_getattr ("SERIALNO", &info);
  if (rc)
    {
      xfree (ecdh_param_str);
      free_public_key (sk);
      return (gpg_error_t)rc;
    }

  rc = agent_keytocard (hexgrip, 2, 1, info.serialno,
                        timestamp, ecdh_param_str);
  xfree (info.serialno);
  if (rc)
    {
      err = (gpg_error_t)rc;
      goto leave;
    }

  err = agent_keywrap_key (ctrl, 1, &kek, &keklen);
  if (err)
    {
      log_error ("error getting the KEK: %s\n", gpg_strerror (err));
      goto leave;
    }

  err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (!err)
    err = gcry_cipher_setkey (cipherhd, kek, keklen);
  if (err)
    {
      log_error ("error setting up an encryption context: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  err = receive_seckey_from_agent (ctrl, cipherhd, 0,
                                   &cache_nonce, hexgrip, sk);
  if (err)
    {
      log_error ("error getting secret key from agent: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  err = card_write_key_to_backup_file (sk, backup_dir);
  if (err)
    log_error ("writing card key to backup file: %s\n", gpg_strerror (err));
  else
    {
      /* Remove secret key data in agent side.  We use force 2 here to
       * allow overwriting of the temporary private key.  */
      agent_scd_learn (NULL, 2);
    }

 leave:
  xfree (ecdh_param_str);
  xfree (cache_nonce);
  gcry_cipher_close (cipherhd);
  xfree (kek);
  xfree (hexgrip);
  free_public_key (sk);
  return err;
}


static void
do_generate_keypair (ctrl_t ctrl, struct para_data_s *para,
		     struct output_control_s *outctrl, int card)
{
  gpg_error_t err;
  KBNODE pub_root = NULL;
  const char *s;
  PKT_public_key *pri_psk = NULL;
  PKT_public_key *sub_psk = NULL;
  struct revocation_key *revkey;
  int did_sub = 0;
  u32 timestamp;
  char *cache_nonce = NULL;
  int algo;
  u32 expire;
  const char *key_from_hexgrip = NULL;
  unsigned int idx;

  if (outctrl->dryrun)
    {
      log_info("dry-run mode - key generation skipped\n");
      return;
    }

  if ( outctrl->use_files )
    {
      if ( outctrl->pub.newfname )
        {
          iobuf_close(outctrl->pub.stream);
          outctrl->pub.stream = NULL;
          if (outctrl->pub.fname)
            iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE,
                         0, (char*)outctrl->pub.fname);
          xfree( outctrl->pub.fname );
          outctrl->pub.fname =  outctrl->pub.newfname;
          outctrl->pub.newfname = NULL;

          if (is_secured_filename (outctrl->pub.fname) )
            {
              outctrl->pub.stream = NULL;
              gpg_err_set_errno (EPERM);
            }
          else
            outctrl->pub.stream = iobuf_create (outctrl->pub.fname, 0);
          if (!outctrl->pub.stream)
            {
              log_error(_("can't create '%s': %s\n"), outctrl->pub.newfname,
                        strerror(errno) );
              return;
            }
          if (opt.armor)
            {
              outctrl->pub.afx->what = 1;
              push_armor_filter (outctrl->pub.afx, outctrl->pub.stream);
            }
        }
      log_assert( outctrl->pub.stream );
      if (opt.verbose)
        log_info (_("writing public key to '%s'\n"), outctrl->pub.fname );
    }


  /* We create the packets as a tree of kbnodes.  Because the
     structure we create is known in advance we simply generate a
     linked list.  The first packet is a dummy packet which we flag as
     deleted.  The very first packet must always be a KEY packet.  */

  start_tree (&pub_root);

  timestamp = get_parameter_u32 (para, pKEYCREATIONDATE);
  if (!timestamp)
    timestamp = make_timestamp ();

  /* Note that, depending on the backend (i.e. the used scdaemon
     version), the card key generation may update TIMESTAMP for each
     key.  Thus we need to pass TIMESTAMP to all signing function to
     make sure that the binding signature is done using the timestamp
     of the corresponding (sub)key and not that of the primary key.
     An alternative implementation could tell the signing function the
     node of the subkey but that is more work than just to pass the
     current timestamp.  */

  algo = get_parameter_algo (ctrl, para, pKEYTYPE, NULL );
  expire = get_parameter_u32( para, pKEYEXPIRE );
  key_from_hexgrip = get_parameter_value (para, pKEYGRIP);
  if (key_from_hexgrip)
    err = do_create_from_keygrip (ctrl, algo, key_from_hexgrip,
                                  pub_root, timestamp, expire, 0);
  else if (!card)
    err = do_create (algo,
                     get_parameter_uint( para, pKEYLENGTH ),
                     get_parameter_value (para, pKEYCURVE),
                     pub_root,
                     timestamp,
                     expire, 0,
                     outctrl->keygen_flags,
                     get_parameter_passphrase (para),
                     &cache_nonce, NULL);
  else
    err = gen_card_key (1, algo,
                        1, pub_root, &timestamp,
                        expire);

  /* Get the pointer to the generated public key packet.  */
  if (!err)
    {
      pri_psk = pub_root->next->pkt->pkt.public_key;
      log_assert (pri_psk);

      /* Make sure a few fields are correctly set up before going
         further.  */
      pri_psk->flags.primary = 1;
      keyid_from_pk (pri_psk, NULL);
      /* We don't use pk_keyid to get keyid, because it also asserts
         that main_keyid is set!  */
      keyid_copy (pri_psk->main_keyid, pri_psk->keyid);
    }

  /* Write all signatures specifying designated revokers.  */
  for (idx=0;
       !err && (revkey = get_parameter_revkey (para, pREVOKER, idx));
       idx++)
    err = write_direct_sig (ctrl, pub_root, pri_psk,
                            revkey, timestamp, cache_nonce);

  if (!err && (s = get_parameter_value (para, pUSERID)))
    {
      err = write_uid (pub_root, s );
      if (!err)
        err = write_selfsigs (ctrl, pub_root, pri_psk,
                              get_parameter_uint (para, pKEYUSAGE), timestamp,
                              cache_nonce);
    }

  /* Write the auth key to the card before the encryption key.  This
     is a partial workaround for a PGP bug (as of this writing, all
     versions including 8.1), that causes it to try and encrypt to
     the most recent subkey regardless of whether that subkey is
     actually an encryption type.  In this case, the auth key is an
     RSA key so it succeeds. */

  if (!err && card && get_parameter (para, pAUTHKEYTYPE))
    {
      err = gen_card_key (3, get_parameter_algo (ctrl, para,
                                                 pAUTHKEYTYPE, NULL ),
                          0, pub_root, &timestamp, expire);
      if (!err)
        err = write_keybinding (ctrl, pub_root, pri_psk, NULL,
                                PUBKEY_USAGE_AUTH, timestamp, cache_nonce);
    }

  if (!err && get_parameter (para, pSUBKEYTYPE))
    {
      int subkey_algo = get_parameter_algo (ctrl, para, pSUBKEYTYPE, NULL);

      s = NULL;
      key_from_hexgrip = get_parameter_value (para, pSUBKEYGRIP);
      if (key_from_hexgrip)
        err = do_create_from_keygrip (ctrl, subkey_algo, key_from_hexgrip,
                                      pub_root, timestamp,
                                      get_parameter_u32 (para, pSUBKEYEXPIRE),
                                      1);
      else if (!card || (s = get_parameter_value (para, pCARDBACKUPKEY)))
        {
          err = do_create (subkey_algo,
                           get_parameter_uint (para, pSUBKEYLENGTH),
                           get_parameter_value (para, pSUBKEYCURVE),
                           pub_root,
                           timestamp,
                           get_parameter_u32 (para, pSUBKEYEXPIRE), 1,
                           s ? KEYGEN_FLAG_NO_PROTECTION : outctrl->keygen_flags,
                           get_parameter_passphrase (para),
                           &cache_nonce, NULL);
          /* Get the pointer to the generated public subkey packet.  */
          if (!err)
            {
              kbnode_t node;

              for (node = pub_root; node; node = node->next)
                if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
                  sub_psk = node->pkt->pkt.public_key;
              log_assert (sub_psk);

              if (s)
                err = card_store_key_with_backup (ctrl,
                                                  sub_psk, gnupg_homedir ());
            }
        }
      else
        {
          err = gen_card_key (2, subkey_algo, 0, pub_root, &timestamp, expire);
        }

      if (!err)
        err = write_keybinding (ctrl, pub_root, pri_psk, sub_psk,
                                get_parameter_uint (para, pSUBKEYUSAGE),
                                timestamp, cache_nonce);
      did_sub = 1;
    }

  if (!err && outctrl->use_files)  /* Direct write to specified files.  */
    {
      err = write_keyblock (outctrl->pub.stream, pub_root);
      if (err)
        log_error ("can't write public key: %s\n", gpg_strerror (err));
    }
  else if (!err) /* Write to the standard keyrings.  */
    {
      KEYDB_HANDLE pub_hd;

      pub_hd = keydb_new ();
      if (!pub_hd)
        err = gpg_error_from_syserror ();
      else
        {
          err = keydb_locate_writable (pub_hd);
          if (err)
            log_error (_("no writable public keyring found: %s\n"),
                       gpg_strerror (err));
        }

      if (!err && opt.verbose)
        {
          log_info (_("writing public key to '%s'\n"),
                    keydb_get_resource_name (pub_hd));
        }

      if (!err)
        {
          err = keydb_insert_keyblock (pub_hd, pub_root);
          if (err)
            log_error (_("error writing public keyring '%s': %s\n"),
                       keydb_get_resource_name (pub_hd), gpg_strerror (err));
        }

      keydb_release (pub_hd);

      if (!err)
        {
          int no_enc_rsa;
          PKT_public_key *pk;

          no_enc_rsa = ((get_parameter_algo (ctrl, para, pKEYTYPE, NULL)
                         == PUBKEY_ALGO_RSA)
                        && get_parameter_uint (para, pKEYUSAGE)
                        && !((get_parameter_uint (para, pKEYUSAGE)
                              & PUBKEY_USAGE_ENC)) );

          pk = find_kbnode (pub_root, PKT_PUBLIC_KEY)->pkt->pkt.public_key;

	  update_ownertrust (ctrl, pk,
                             ((get_ownertrust (ctrl, pk) & ~TRUST_MASK)
                              | TRUST_ULTIMATE ));

          gen_standard_revoke (ctrl, pk, cache_nonce);

          /* Get rid of the first empty packet.  */
          commit_kbnode (&pub_root);

          if (!opt.batch)
            {
              tty_printf (_("public and secret key created and signed.\n") );
              tty_printf ("\n");
              merge_keys_and_selfsig (ctrl, pub_root);

              list_keyblock_direct (ctrl, pub_root, 0, 1,
                                    opt.fingerprint || opt.with_fingerprint,
                                    1);
            }


          if (!opt.batch
              && (get_parameter_algo (ctrl, para,
                                      pKEYTYPE, NULL) == PUBKEY_ALGO_DSA
                  || no_enc_rsa )
              && !get_parameter (para, pSUBKEYTYPE) )
            {
              tty_printf(_("Note that this key cannot be used for "
                           "encryption.  You may want to use\n"
                           "the command \"--edit-key\" to generate a "
                           "subkey for this purpose.\n") );
            }
        }
    }

  if (err)
    {
      if (opt.batch)
        log_error ("key generation failed: %s\n", gpg_strerror (err) );
      else
        tty_printf (_("Key generation failed: %s\n"), gpg_strerror (err) );
      write_status_error (card? "card_key_generate":"key_generate", err);
      print_status_key_not_created ( get_parameter_value (para, pHANDLE) );
    }
  else
    {
      PKT_public_key *pk = find_kbnode (pub_root,
                                        PKT_PUBLIC_KEY)->pkt->pkt.public_key;
      print_status_key_created (did_sub? 'B':'P', pk,
                                get_parameter_value (para, pHANDLE));
    }

  release_kbnode (pub_root);
  xfree (cache_nonce);
}


static gpg_error_t
parse_algo_usage_expire (ctrl_t ctrl, int for_subkey,
                         const char *algostr, const char *usagestr,
                         const char *expirestr,
                         int *r_algo, unsigned int *r_usage, u32 *r_expire,
                         unsigned int *r_nbits, const char **r_curve,
                         char **r_keygrip)
{
  gpg_error_t err;
  int algo;
  unsigned int use, nbits;
  u32 expire;
  int wantuse;
  const char *curve = NULL;

  *r_curve = NULL;
  if (r_keygrip)
    *r_keygrip = NULL;

  nbits = 0;

  /* Parse the algo string.  */
  if (algostr && *algostr == '&' && strlen (algostr) == 41)
    {
      /* Take algo from existing key.  */
      algo = check_keygrip (ctrl, algostr+1);
      /* FIXME: We need the curve name as well.  */
      return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }

  err = parse_key_parameter_string (ctrl, algostr, for_subkey? 1 : 0,
                                    usagestr? parse_usagestr (usagestr):0,
                                    &algo, &nbits, &use, &curve,
                                    r_keygrip,
                                    NULL, NULL, NULL, NULL, NULL);
  if (err)
    {
      if (r_keygrip)
        {
          xfree (*r_keygrip);
          *r_keygrip = NULL;
        }
      return err;
    }

  /* Parse the usage string.  */
  if (!usagestr || !*usagestr
      || !ascii_strcasecmp (usagestr, "default") || !strcmp (usagestr, "-"))
    ; /* Keep usage from parse_key_parameter_string.  */
  else if ((wantuse = parse_usagestr (usagestr)) != -1)
    use = wantuse;
  else
    {
      if (r_keygrip)
        {
          xfree (*r_keygrip);
          *r_keygrip = NULL;
        }
      return gpg_error (GPG_ERR_INV_VALUE);
    }

  /* Make sure a primary key has the CERT usage.  */
  if (!for_subkey)
    use |= PUBKEY_USAGE_CERT;

  /* Check that usage is possible.  NB: We have the same check in
   * parse_key_parameter_string but need it here again in case the
   * separate usage value has been given. */
  if (/**/((use & (PUBKEY_USAGE_SIG|PUBKEY_USAGE_AUTH|PUBKEY_USAGE_CERT))
           && !pubkey_get_nsig (algo))
       || ((use & PUBKEY_USAGE_ENC)
           && !pubkey_get_nenc (algo))
       || (for_subkey && (use & PUBKEY_USAGE_CERT)))
    {
      if (r_keygrip)
        {
          xfree (*r_keygrip);
          *r_keygrip = NULL;
        }
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  /* Parse the expire string.  */
  expire = parse_expire_string (expirestr);
  if (expire == (u32)-1 )
    {
      if (r_keygrip)
        {
          xfree (*r_keygrip);
          *r_keygrip = NULL;
        }
      return gpg_error (GPG_ERR_INV_VALUE);
    }

  if (curve)
    *r_curve = curve;
  *r_algo = algo;
  *r_usage = use;
  *r_expire = expire;
  *r_nbits = nbits;
  return 0;
}


/* Add a new subkey to an existing key.  Returns 0 if a new key has
   been generated and put into the keyblocks.  If any of ALGOSTR,
   USAGESTR, or EXPIRESTR is NULL interactive mode is used. */
gpg_error_t
generate_subkeypair (ctrl_t ctrl, kbnode_t keyblock, const char *algostr,
                     const char *usagestr, const char *expirestr)
{
  gpg_error_t err = 0;
  int interactive;
  kbnode_t node;
  PKT_public_key *pri_psk = NULL;
  PKT_public_key *sub_psk = NULL;
  int algo;
  unsigned int use;
  u32 expire;
  unsigned int nbits = 0;
  const char *curve = NULL;
  u32 cur_time;
  char *key_from_hexgrip = NULL;
  char *hexgrip = NULL;
  char *serialno = NULL;
  char *cache_nonce = NULL;
  char *passwd_nonce = NULL;

  interactive = (!algostr || !usagestr || !expirestr);

  /* Break out the primary key.  */
  node = find_kbnode (keyblock, PKT_PUBLIC_KEY);
  if (!node)
    {
      log_error ("Oops; primary key missing in keyblock!\n");
      err = gpg_error (GPG_ERR_BUG);
      goto leave;
    }
  pri_psk = node->pkt->pkt.public_key;

  cur_time = make_timestamp ();

  if (pri_psk->timestamp > cur_time)
    {
      ulong d = pri_psk->timestamp - cur_time;
      log_info ( d==1 ? _("key has been created %lu second "
                          "in future (time warp or clock problem)\n")
                 : _("key has been created %lu seconds "
                     "in future (time warp or clock problem)\n"), d );
      if (!opt.ignore_time_conflict)
        {
          err = gpg_error (GPG_ERR_TIME_CONFLICT);
          goto leave;
        }
    }

  if (pri_psk->version < 4)
    {
      log_info (_("Note: creating subkeys for v3 keys "
                  "is not OpenPGP compliant\n"));
      err = gpg_error (GPG_ERR_CONFLICT);
      goto leave;
    }

  err = hexkeygrip_from_pk (pri_psk, &hexgrip);
  if (err)
    goto leave;
  if (agent_get_keyinfo (NULL, hexgrip, &serialno, NULL))
    {
      if (interactive)
        tty_printf (_("Secret parts of primary key are not available.\n"));
      else
        log_info (  _("Secret parts of primary key are not available.\n"));
      err = gpg_error (GPG_ERR_NO_SECKEY);
      goto leave;
    }
  if (serialno)
    {
      if (interactive)
        tty_printf (_("Secret parts of primary key are stored on-card.\n"));
      else
        log_info (  _("Secret parts of primary key are stored on-card.\n"));
    }

  if (interactive)
    {
      algo = ask_algo (ctrl, 1, NULL, &use, &key_from_hexgrip);
      log_assert (algo);

      if (key_from_hexgrip)
        nbits = 0;
      else if (algo == PUBKEY_ALGO_ECDSA
               || algo == PUBKEY_ALGO_EDDSA
               || algo == PUBKEY_ALGO_ECDH)
        curve = ask_curve (&algo, NULL, NULL);
      else
        nbits = ask_keysize (algo, 0);

      expire = ask_expire_interval (0, NULL);
      if (!cpr_enabled() && !cpr_get_answer_is_yes("keygen.sub.okay",
                                                   _("Really create? (y/N) ")))
        {
          err = gpg_error (GPG_ERR_CANCELED);
          goto leave;
        }
    }
  else /* Unattended mode.  */
    {
      err = parse_algo_usage_expire (ctrl, 1, algostr, usagestr, expirestr,
                                     &algo, &use, &expire, &nbits, &curve,
                                     &key_from_hexgrip);
      if (err)
        goto leave;
    }

  /* Verify the passphrase now so that we get a cache item for the
   * primary key passphrase.  The agent also returns a passphrase
   * nonce, which we can use to set the passphrase for the subkey to
   * that of the primary key.  */
  {
    char *desc = gpg_format_keydesc (ctrl, pri_psk, FORMAT_KEYDESC_NORMAL, 1);
    err = agent_passwd (ctrl, hexgrip, desc, 1 /*=verify*/,
                        &cache_nonce, &passwd_nonce);
    xfree (desc);
    if (gpg_err_code (err) == GPG_ERR_NOT_IMPLEMENTED
        && gpg_err_source (err) == GPG_ERR_SOURCE_GPGAGENT)
      err = 0;  /* Very likely that the key is on a card.  */
    if (err)
      goto leave;
  }

  /* Start creation.  */
  if (key_from_hexgrip)
    {
      err = do_create_from_keygrip (ctrl, algo, key_from_hexgrip,
                                    keyblock, cur_time, expire, 1);
    }
  else
    {
      const char *passwd;

      /* If the pinentry loopback mode is not and we have a static
         passphrase (i.e. set with --passphrase{,-fd,-file} while in batch
         mode), we use that passphrase for the new subkey.  */
      if (opt.pinentry_mode != PINENTRY_MODE_LOOPBACK
          && have_static_passphrase ())
        passwd = get_static_passphrase ();
      else
        passwd = NULL;

      err = do_create (algo, nbits, curve,
                       keyblock, cur_time, expire, 1, 0,
                       passwd, &cache_nonce, &passwd_nonce);
    }
  if (err)
    goto leave;

  /* Get the pointer to the generated public subkey packet.  */
  for (node = keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
      sub_psk = node->pkt->pkt.public_key;

  /* Write the binding signature.  */
  err = write_keybinding (ctrl, keyblock, pri_psk, sub_psk, use, cur_time,
                          cache_nonce);
  if (err)
    goto leave;

  print_status_key_created ('S', sub_psk, NULL);


 leave:
  xfree (key_from_hexgrip);
  xfree (hexgrip);
  xfree (serialno);
  xfree (cache_nonce);
  xfree (passwd_nonce);
  if (err)
    log_error (_("Key generation failed: %s\n"), gpg_strerror (err) );
  return err;
}


#ifdef ENABLE_CARD_SUPPORT
/* Generate a subkey on a card. */
gpg_error_t
generate_card_subkeypair (ctrl_t ctrl, kbnode_t pub_keyblock,
                          int keyno, const char *serialno)
{
  gpg_error_t err = 0;
  kbnode_t node;
  PKT_public_key *pri_pk = NULL;
  unsigned int use;
  u32 expire;
  u32 cur_time;
  struct para_data_s *para = NULL;
  PKT_public_key *sub_pk = NULL;
  int algo;
  struct agent_card_info_s info;

  log_assert (keyno >= 1 && keyno <= 3);

  memset (&info, 0, sizeof (info));
  err = agent_scd_getattr ("KEY-ATTR", &info);
  if (err)
    {
      log_error (_("error getting current key info: %s\n"), gpg_strerror (err));
      return err;
    }
  algo = info.key_attr[keyno-1].algo;

  para = xtrycalloc (1, sizeof *para + strlen (serialno) );
  if (!para)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  para->key = pSERIALNO;
  strcpy (para->u.value, serialno);

  /* Break out the primary secret key */
  node = find_kbnode (pub_keyblock, PKT_PUBLIC_KEY);
  if (!node)
    {
      log_error ("Oops; public key lost!\n");
      err = gpg_error (GPG_ERR_INTERNAL);
      goto leave;
    }
  pri_pk = node->pkt->pkt.public_key;

  cur_time = make_timestamp();
  if (pri_pk->timestamp > cur_time)
    {
      ulong d = pri_pk->timestamp - cur_time;
      log_info (d==1 ? _("key has been created %lu second "
                         "in future (time warp or clock problem)\n")
                     : _("key has been created %lu seconds "
                         "in future (time warp or clock problem)\n"), d );
	if (!opt.ignore_time_conflict)
          {
	    err = gpg_error (GPG_ERR_TIME_CONFLICT);
	    goto leave;
          }
    }

  if (pri_pk->version < 4)
    {
      log_info (_("Note: creating subkeys for v3 keys "
                  "is not OpenPGP compliant\n"));
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  expire = ask_expire_interval (0, NULL);
  if (keyno == 1)
    use = PUBKEY_USAGE_SIG;
  else if (keyno == 2)
    use = PUBKEY_USAGE_ENC;
  else
    use = PUBKEY_USAGE_AUTH;
  if (!cpr_enabled() && !cpr_get_answer_is_yes("keygen.cardsub.okay",
                                               _("Really create? (y/N) ")))
    {
      err = gpg_error (GPG_ERR_CANCELED);
      goto leave;
    }

  /* Note, that depending on the backend, the card key generation may
     update CUR_TIME.  */
  err = gen_card_key (keyno, algo, 0, pub_keyblock, &cur_time, expire);
  /* Get the pointer to the generated public subkey packet.  */
  if (!err)
    {
      for (node = pub_keyblock; node; node = node->next)
        if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
          sub_pk = node->pkt->pkt.public_key;
      log_assert (sub_pk);
      err = write_keybinding (ctrl, pub_keyblock, pri_pk, sub_pk,
                              use, cur_time, NULL);
    }

 leave:
  if (err)
    log_error (_("Key generation failed: %s\n"), gpg_strerror (err) );
  else
    print_status_key_created ('S', sub_pk, NULL);
  release_parameter_list (para);
  return err;
}
#endif /* !ENABLE_CARD_SUPPORT */

/*
 * Write a keyblock to an output stream
 */
static int
write_keyblock( IOBUF out, KBNODE node )
{
  for( ; node ; node = node->next )
    {
      if(!is_deleted_kbnode(node))
	{
	  int rc = build_packet( out, node->pkt );
	  if( rc )
	    {
	      log_error("build_packet(%d) failed: %s\n",
			node->pkt->pkttype, gpg_strerror (rc) );
	      return rc;
	    }
	}
    }

  return 0;
}


/* Note that timestamp is an in/out arg. */
static gpg_error_t
gen_card_key (int keyno, int algo, int is_primary, kbnode_t pub_root,
              u32 *timestamp, u32 expireval)
{
#ifdef ENABLE_CARD_SUPPORT
  gpg_error_t err;
  PACKET *pkt;
  PKT_public_key *pk;
  char keyid[10];
  unsigned char *public;
  gcry_sexp_t s_key;

  snprintf (keyid, DIM(keyid), "OPENPGP.%d", keyno);

  pk = xtrycalloc (1, sizeof *pk );
  if (!pk)
    return gpg_error_from_syserror ();
  pkt = xtrycalloc (1, sizeof *pkt);
  if (!pkt)
    {
      xfree (pk);
      return gpg_error_from_syserror ();
    }

  /* Note: SCD knows the serialnumber, thus there is no point in passing it.  */
  err = agent_scd_genkey (keyno, 1, timestamp);
  /*  The code below is not used because we force creation of
   *  the a card key (3rd arg).
   * if (gpg_err_code (rc) == GPG_ERR_EEXIST)
   *   {
   *     tty_printf ("\n");
   *     log_error ("WARNING: key does already exists!\n");
   *     tty_printf ("\n");
   *     if ( cpr_get_answer_is_yes( "keygen.card.replace_key",
   *                                 _("Replace existing key? ")))
   *       rc = agent_scd_genkey (keyno, 1, timestamp);
   *   }
  */
  if (err)
    {
      log_error ("key generation failed: %s\n", gpg_strerror (err));
      xfree (pkt);
      xfree (pk);
      return err;
    }

  /* Send the READKEY command so that the agent creates a shadow key for
     card key.  We need to do that now so that we are able to create
     the self-signatures. */
  err = agent_readkey (NULL, 1, keyid, &public);
  if (err)
    return err;
  err = gcry_sexp_sscan (&s_key, NULL, public,
                         gcry_sexp_canon_len (public, 0, NULL, NULL));
  xfree (public);
  if (err)
    return err;

  if (algo == PUBKEY_ALGO_RSA)
    err = key_from_sexp (pk->pkey, s_key, "public-key", "ne");
  else if (algo == PUBKEY_ALGO_ECDSA
           || algo == PUBKEY_ALGO_EDDSA
           || algo == PUBKEY_ALGO_ECDH )
    err = ecckey_from_sexp (pk->pkey, s_key, algo);
  else
    err = gpg_error (GPG_ERR_PUBKEY_ALGO);
  gcry_sexp_release (s_key);

  if (err)
    {
      log_error ("key_from_sexp failed: %s\n", gpg_strerror (err) );
      free_public_key (pk);
      return err;
    }

  pk->timestamp = *timestamp;
  pk->version = 4;
  if (expireval)
    pk->expiredate = pk->timestamp + expireval;
  pk->pubkey_algo = algo;

  pkt->pkttype = is_primary ? PKT_PUBLIC_KEY : PKT_PUBLIC_SUBKEY;
  pkt->pkt.public_key = pk;
  add_kbnode (pub_root, new_kbnode (pkt));

  return 0;
#else
  (void)keyno;
  (void)is_primary;
  (void)pub_root;
  (void)timestamp;
  (void)expireval;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
#endif /*!ENABLE_CARD_SUPPORT*/
}
