/* keygen.c - generate a key pair
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "util.h"
#include "main.h"
#include "packet.h"
#include "cipher.h"
#include "ttyio.h"
#include "options.h"
#include "keydb.h"
#include "trustdb.h"
#include "status.h"
#include "i18n.h"
#include "cardglue.h"
#include "keyserver-internal.h"

#define MAX_PREFS 30 

enum para_name {
  pKEYTYPE,
  pKEYLENGTH,
  pKEYUSAGE,
  pSUBKEYTYPE,
  pSUBKEYLENGTH,
  pSUBKEYUSAGE,
  pAUTHKEYTYPE,
  pNAMEREAL,
  pNAMEEMAIL,
  pNAMECOMMENT,
  pPREFERENCES,
  pREVOKER,
  pUSERID,
  pEXPIREDATE,
  pCREATETIME, /* in n seconds */
  pKEYEXPIRE, /* in n seconds */
  pSUBKEYEXPIRE, /* in n seconds */
  pPASSPHRASE,
  pPASSPHRASE_DEK,
  pPASSPHRASE_S2K,
  pSERIALNO,
  pBACKUPENCDIR,
  pHANDLE,
  pKEYSERVER
};

struct para_data_s {
    struct para_data_s *next;
    int lnr;
    enum para_name key;
    union {
        DEK *dek;
        STRING2KEY *s2k;
        u32 create;
        u32 expire;
        unsigned int usage;
        struct revocation_key revkey;
        char value[1];
    } u;
};

struct output_control_s {
    int lnr;
    int dryrun;
    int use_files;
    struct {
	char  *fname;
	char  *newfname;
	IOBUF stream;
	armor_filter_context_t afx;
    } pub;
    struct {
	char  *fname;
	char  *newfname;
	IOBUF stream;
	armor_filter_context_t afx;
    } sec;
};


struct opaque_data_usage_and_pk {
    unsigned int usage;
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

static void do_generate_keypair( struct para_data_s *para,
				 struct output_control_s *outctrl,
				 u32 timestamp, int card );
static int  write_keyblock( IOBUF out, KBNODE node );
static int gen_card_key (int algo, int keyno, int is_primary,
                         KBNODE pub_root, KBNODE sec_root,
			 PKT_secret_key **ret_sk,
                         u32 expireval, struct para_data_s *para);
static int gen_card_key_with_backup (int algo, int keyno, int is_primary,
                                     KBNODE pub_root, KBNODE sec_root,
                                     u32 expireval, struct para_data_s *para,
                                     const char *backup_dir);


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
      *p++ = ' ';
      fingerprint_from_pk (pk, array, &n);
      s = array;
      for (i=0; i < n ; i++, s++, p += 2)
        sprintf (p, "%02X", *s);
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



static void
write_uid( KBNODE root, const char *s )
{
    PACKET *pkt = xmalloc_clear(sizeof *pkt );
    size_t n = strlen(s);

    pkt->pkttype = PKT_USER_ID;
    pkt->pkt.user_id = xmalloc_clear( sizeof *pkt->pkt.user_id + n - 1 );
    pkt->pkt.user_id->len = n;
    pkt->pkt.user_id->ref = 1;
    strcpy(pkt->pkt.user_id->name, s);
    add_kbnode( root, new_kbnode( pkt ) );
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

    if (!buf[0]) 
        return;

    build_sig_subpkt (sig, SIGSUBPKT_KEY_FLAGS, buf, 1);
}


int
keygen_add_key_expire( PKT_signature *sig, void *opaque )
{
    PKT_public_key *pk = opaque;
    byte buf[8];
    u32  u;

    if( pk->expiredate ) {
        if(pk->expiredate > pk->timestamp)
	  u= pk->expiredate - pk->timestamp;
	else
	  u= 1;

	buf[0] = (u >> 24) & 0xff;
	buf[1] = (u >> 16) & 0xff;
	buf[2] = (u >>	8) & 0xff;
	buf[3] = u & 0xff;
	build_sig_subpkt( sig, SIGSUBPKT_KEY_EXPIRE, buf, 4 );
    }
    else
      {
	/* Make sure we don't leave a key expiration subpacket lying
	   around */
	delete_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE);
      }

    return 0;
}

static int
keygen_add_key_flags_and_expire (PKT_signature *sig, void *opaque)
{
    struct opaque_data_usage_and_pk *oduap = opaque;

    do_add_key_flags (sig, oduap->usage);
    return keygen_add_key_expire (sig, oduap->pk);
}

static int
set_one_pref (int val, int type, const char *item, byte *buf, int *nbuf)
{
    int i;

    for (i=0; i < *nbuf; i++ )
      if (buf[i] == val)
	{
	  log_info (_("preference `%s' duplicated\n"), item);
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
    char dummy_string[45+1]; /* Enough for 15 items. */

    if (!string || !ascii_strcasecmp (string, "default"))
      {
	if (opt.def_preference_list)
	  string=opt.def_preference_list;
	else
	  {
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
	    if(!check_cipher_algo(CIPHER_ALGO_AES256))
	      strcat(dummy_string,"S9 ");
	    if(!check_cipher_algo(CIPHER_ALGO_AES192))
	      strcat(dummy_string,"S8 ");
	    if(!check_cipher_algo(CIPHER_ALGO_AES))
	      strcat(dummy_string,"S7 ");
	    if(!check_cipher_algo(CIPHER_ALGO_CAST5))
	      strcat(dummy_string,"S3 ");
	    strcat(dummy_string,"S2 "); /* 3DES */
	    /* If we have it, IDEA goes *after* 3DES so it won't be
	       used unless we're encrypting along with a V3 key.
	       Ideally, we would only put the S1 preference in if the
	       key was RSA and <=2048 bits, as that is what won't
	       break PGP2, but that is difficult with the current
	       code, and not really worth checking as a non-RSA <=2048
	       bit key wouldn't be usable by PGP2 anyway. -dms */
	    if(!check_cipher_algo(CIPHER_ALGO_IDEA))
	      strcat(dummy_string,"S1 ");

	    /* SHA-1 */
	    strcat(dummy_string,"H2 ");

	    if(!check_digest_algo(DIGEST_ALGO_SHA256))
	      strcat(dummy_string,"H8 ");

	    /* RIPEMD160 */
	    strcat(dummy_string,"H3 ");

	    /* ZLIB */
	    strcat(dummy_string,"Z2 ");

	    if(!check_compress_algo(COMPRESS_ALGO_BZIP2))
	      strcat(dummy_string,"Z3 ");

	    /* ZIP */
	    strcat(dummy_string,"Z1");

	    string=dummy_string;
	  }
      }
    else if (!ascii_strcasecmp (string, "none"))
        string = "";

    if(strlen(string))
      {
	char *tok,*prefstring;

	prefstring=xstrdup(string); /* need a writable string! */

	while((tok=strsep(&prefstring," ,")))
	  {
	    if((val=string_to_cipher_algo(tok)))
	      {
		if(set_one_pref(val,1,tok,sym,&nsym))
		  rc=-1;
	      }
	    else if((val=string_to_digest_algo(tok)))
	      {
		if(set_one_pref(val,2,tok,hash,&nhash))
		  rc=-1;
	      }
	    else if((val=string_to_compress_algo(tok))>-1)
	      {
		if(set_one_pref(val,3,tok,zip,&nzip))
		  rc=-1;
	      }
	    else if (ascii_strcasecmp(tok,"mdc")==0)
	      mdc=1;
	    else if (ascii_strcasecmp(tok,"no-mdc")==0)
	      mdc=0;
	    else if (ascii_strcasecmp(tok,"ks-modify")==0)
	      modify=1;
	    else if (ascii_strcasecmp(tok,"no-ks-modify")==0)
	      modify=0;
	    else
	      {
		log_info (_("invalid item `%s' in preference string\n"),tok);

		/* Complain if IDEA is not available. */
		if(ascii_strcasecmp(tok,"s1")==0
		   || ascii_strcasecmp(tok,"idea")==0)
		  idea_cipher_warn(1);

		rc=-1;
	      }
	  }

	xfree(prefstring);
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
	    ks_modify = modify;
	    prefs_initialized = 1;
	  }
      }

    return rc;
}

/* Return a fake user ID containing the preferences.  Caller must
   free. */
PKT_user_id *keygen_get_std_prefs(void)
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
keygen_upd_std_prefs( PKT_signature *sig, void *opaque )
{
    if (!prefs_initialized)
        keygen_set_std_prefs (NULL, 0);

    if (nsym_prefs) 
        build_sig_subpkt (sig, SIGSUBPKT_PREF_SYM, sym_prefs, nsym_prefs);
    else
      {
        delete_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_SYM);
        delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PREF_SYM);
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

    /* Make sure that the MDC feature flag is set if needed */
    add_feature_mdc (sig,mdc_available);
    add_keyserver_modify (sig,ks_modify);
    keygen_add_keyserver_url(sig,NULL);

    return 0;
}


/****************
 * Add preference to the self signature packet.
 * This is only called for packets with version > 3.

 */
int
keygen_add_std_prefs( PKT_signature *sig, void *opaque )
{
    PKT_public_key *pk = opaque;

    do_add_key_flags (sig, pk->pubkey_usage);
    keygen_add_key_expire( sig, opaque );
    keygen_upd_std_prefs (sig, opaque);
    keygen_add_keyserver_url(sig,NULL);

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
keygen_add_revkey(PKT_signature *sig, void *opaque)
{
  struct revocation_key *revkey=opaque;
  byte buf[2+MAX_FINGERPRINT_LEN];

  buf[0]=revkey->class;
  buf[1]=revkey->algid;
  memcpy(&buf[2],revkey->fpr,MAX_FINGERPRINT_LEN);

  build_sig_subpkt(sig,SIGSUBPKT_REV_KEY,buf,2+MAX_FINGERPRINT_LEN);

  /* All sigs with revocation keys set are nonrevocable */
  sig->flags.revocable=0;
  buf[0] = 0;
  build_sig_subpkt( sig, SIGSUBPKT_REVOCABLE, buf, 1 );

  parse_revkeys(sig);

  return 0;
}

int
make_backsig(PKT_signature *sig,PKT_public_key *pk,
 	     PKT_public_key *sub_pk,PKT_secret_key *sub_sk)
{
  PKT_signature *backsig;
  int rc;

  cache_public_key(sub_pk);

  rc=make_keysig_packet(&backsig,pk,NULL,sub_pk,sub_sk,0x19,0,0,
			sub_pk->timestamp,0,NULL,NULL);
  if(rc)
    log_error("make_keysig_packet failed for backsig: %s\n",g10_errstr(rc));
  else
    {
      /* get it into a binary packed form. */
      IOBUF backsig_out=iobuf_temp();
      PACKET backsig_pkt;
 
      init_packet(&backsig_pkt);
      backsig_pkt.pkttype=PKT_SIGNATURE;
      backsig_pkt.pkt.signature=backsig;
      rc=build_packet(backsig_out,&backsig_pkt);
      free_packet(&backsig_pkt);
      if(rc)
	log_error("build_packet failed for backsig: %s\n",g10_errstr(rc));
      else
	{
	  size_t pktlen=0;
	  byte *buf=iobuf_get_temp_buffer(backsig_out);
 
	  /* Remove the packet header */
	  if(buf[0]&0x40)
	    {
	      if(buf[1]<192)
		{
		  pktlen=buf[1];
		  buf+=2;
		}
	      else if(buf[1]<224)
		{
		  pktlen=(buf[1]-192)*256;
		  pktlen+=buf[2]+192;
		  buf+=3;
		}
	      else if(buf[1]==255)
		{
		  pktlen =buf[2] << 24;
		  pktlen|=buf[3] << 16;
		  pktlen|=buf[4] << 8;
		  pktlen|=buf[5];
		  buf+=6;
		}
	      else
		BUG();
	    }
	  else
	    {
	      int mark=1;
 
	      switch(buf[0]&3)
		{
		case 3:
		  BUG();
		  break;
 
		case 2:
		  pktlen =buf[mark++] << 24;
		  pktlen|=buf[mark++] << 16;
 
		case 1:
		  pktlen|=buf[mark++] << 8;
 
		case 0:
		  pktlen|=buf[mark++];
		}
 
	      buf+=mark;
	    }
 
	  /* now make the binary blob into a subpacket */
	  build_sig_subpkt(sig,SIGSUBPKT_SIGNATURE,buf,pktlen);

	  iobuf_close(backsig_out);
	}
    }
 
  return rc;
}


static int
write_direct_sig( KBNODE root, KBNODE pub_root, PKT_secret_key *sk,
		  struct revocation_key *revkey )
{
    PACKET *pkt;
    PKT_signature *sig;
    int rc=0;
    KBNODE node;
    PKT_public_key *pk;

    if( opt.verbose )
	log_info(_("writing direct signature\n"));

    /* get the pk packet from the pub_tree */
    node = find_kbnode( pub_root, PKT_PUBLIC_KEY );
    if( !node )
	BUG();
    pk = node->pkt->pkt.public_key;

    /* we have to cache the key, so that the verification of the signature
     * creation is able to retrieve the public key */
    cache_public_key (pk);

    /* and make the signature */
    rc = make_keysig_packet(&sig,pk,NULL,NULL,sk,0x1F,0,0,pk->timestamp,0,
			    keygen_add_revkey,revkey);
    if( rc ) {
	log_error("make_keysig_packet failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    pkt = xmalloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_SIGNATURE;
    pkt->pkt.signature = sig;
    add_kbnode( root, new_kbnode( pkt ) );
    return rc;
}

static int
write_selfsigs( KBNODE sec_root, KBNODE pub_root, PKT_secret_key *sk,
		unsigned int use )
{
    PACKET *pkt;
    PKT_signature *sig;
    PKT_user_id *uid;
    int rc=0;
    KBNODE node;
    PKT_public_key *pk;

    if( opt.verbose )
	log_info(_("writing self signature\n"));

    /* get the uid packet from the list */
    node = find_kbnode( pub_root, PKT_USER_ID );
    if( !node )
	BUG(); /* no user id packet in tree */
    uid = node->pkt->pkt.user_id;
    /* get the pk packet from the pub_tree */
    node = find_kbnode( pub_root, PKT_PUBLIC_KEY );
    if( !node )
	BUG();
    pk = node->pkt->pkt.public_key;
    pk->pubkey_usage = use;
    /* we have to cache the key, so that the verification of the signature
     * creation is able to retrieve the public key */
    cache_public_key (pk);

    /* and make the signature */
    rc = make_keysig_packet( &sig, pk, uid, NULL, sk, 0x13, 0, 0,
			     pk->timestamp, 0, keygen_add_std_prefs, pk );
    if( rc ) {
	log_error("make_keysig_packet failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    pkt = xmalloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_SIGNATURE;
    pkt->pkt.signature = sig;
    add_kbnode( sec_root, new_kbnode( pkt ) );

    pkt = xmalloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_SIGNATURE;
    pkt->pkt.signature = copy_signature(NULL,sig);
    add_kbnode( pub_root, new_kbnode( pkt ) );
    return rc;
}

static int
write_keybinding( KBNODE root, KBNODE pub_root,
		  PKT_secret_key *pri_sk, PKT_secret_key *sub_sk,
                  unsigned int use )
{
    PACKET *pkt;
    PKT_signature *sig;
    int rc=0;
    KBNODE node;
    PKT_public_key *pri_pk, *sub_pk;
    struct opaque_data_usage_and_pk oduap;

    if( opt.verbose )
	log_info(_("writing key binding signature\n"));

    /* get the pk packet from the pub_tree */
    node = find_kbnode( pub_root, PKT_PUBLIC_KEY );
    if( !node )
	BUG();
    pri_pk = node->pkt->pkt.public_key;
    /* we have to cache the key, so that the verification of the signature
     * creation is able to retrieve the public key */
    cache_public_key (pri_pk);
 
    /* find the last subkey */
    sub_pk = NULL;
    for(node=pub_root; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    sub_pk = node->pkt->pkt.public_key;
    }
    if( !sub_pk )
	BUG();

    /* and make the signature */
    oduap.usage = use;
    oduap.pk = sub_pk;
    rc=make_keysig_packet(&sig, pri_pk, NULL, sub_pk, pri_sk, 0x18, 0, 0,
			  sub_pk->timestamp, 0,
			  keygen_add_key_flags_and_expire, &oduap );
    if( rc ) {
	log_error("make_keysig_packet failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    /* make a backsig */
    if(use&PUBKEY_USAGE_SIG)
      {
	rc=make_backsig(sig,pri_pk,sub_pk,sub_sk);
	if(rc)
	  return rc;
      }

    pkt = xmalloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_SIGNATURE;
    pkt->pkt.signature = sig;
    add_kbnode( root, new_kbnode( pkt ) );
    return rc;
}


static int
gen_elg(int algo, unsigned nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	STRING2KEY *s2k, PKT_secret_key **ret_sk, u32 timestamp,
	u32 expireval, int is_subkey)
{
    int rc;
    PACKET *pkt;
    PKT_secret_key *sk;
    PKT_public_key *pk;
    MPI skey[4];
    MPI *factors;

    assert( is_ELGAMAL(algo) );

    if( nbits < 512 ) {
	nbits = 1024;
	log_info(_("keysize invalid; using %u bits\n"), nbits );
    }

    if( (nbits % 32) ) {
	nbits = ((nbits + 31) / 32) * 32;
	log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

    rc = pubkey_generate( algo, nbits, skey, &factors );
    if( rc ) {
	log_error("pubkey_generate failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    sk = xmalloc_clear( sizeof *sk );
    pk = xmalloc_clear( sizeof *pk );
    sk->timestamp = pk->timestamp = timestamp;
    sk->version = pk->version = 4;
    if( expireval )
      sk->expiredate = pk->expiredate = sk->timestamp + expireval;

    sk->pubkey_algo = pk->pubkey_algo = algo;
		       pk->pkey[0] = mpi_copy( skey[0] );
		       pk->pkey[1] = mpi_copy( skey[1] );
		       pk->pkey[2] = mpi_copy( skey[2] );
    sk->skey[0] = skey[0];
    sk->skey[1] = skey[1];
    sk->skey[2] = skey[2];
    sk->skey[3] = skey[3];
    sk->is_protected = 0;
    sk->protect.algo = 0;

    sk->csum = checksum_mpi( sk->skey[3] );
    if( ret_sk ) /* return an unprotected version of the sk */
	*ret_sk = copy_secret_key( NULL, sk );

    if( dek ) {
	sk->protect.algo = dek->algo;
	sk->protect.s2k = *s2k;
	rc = protect_secret_key( sk, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_key(pk);
	    free_secret_key(sk);
	    return rc;
	}
    }

    pkt = xmalloc_clear(sizeof *pkt);
    pkt->pkttype = is_subkey ? PKT_PUBLIC_SUBKEY : PKT_PUBLIC_KEY;
    pkt->pkt.public_key = pk;
    add_kbnode(pub_root, new_kbnode( pkt ));

    /* don't know whether it makes sense to have the factors, so for now
     * we store them in the secret keyring (but they are not secret) */
    pkt = xmalloc_clear(sizeof *pkt);
    pkt->pkttype = is_subkey ? PKT_SECRET_SUBKEY : PKT_SECRET_KEY;
    pkt->pkt.secret_key = sk;
    add_kbnode(sec_root, new_kbnode( pkt ));

    return 0;
}


/****************
 * Generate a DSA key
 */
static int
gen_dsa(unsigned int nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	STRING2KEY *s2k, PKT_secret_key **ret_sk, u32 timestamp,
	u32 expireval, int is_subkey)
{
    int rc;
    PACKET *pkt;
    PKT_secret_key *sk;
    PKT_public_key *pk;
    MPI skey[5];
    MPI *factors;
    unsigned int qbits;

    if( nbits < 512 || (!opt.flags.dsa2 && nbits > 1024))
      {
	nbits = 1024;
	log_info(_("keysize invalid; using %u bits\n"), nbits );
      }
    else if(nbits>3072)
      {
	nbits = 3072;
	log_info(_("keysize invalid; using %u bits\n"), nbits );
      }

    if(nbits % 64)
      {
	nbits = ((nbits + 63) / 64) * 64;
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
      
      We'll do 256 qbits for nbits over 2048, 224 for nbits over 1024
      but less than 2048, and 160 for 1024 (DSA1).
    */

    if(nbits>2048)
      qbits=256;
    else if(nbits>1024)
      qbits=224;
    else
      qbits=160;

    if(qbits!=160)
      log_info("WARNING: some OpenPGP programs can't"
	       " handle a DSA key with this digest size\n");

    rc = dsa2_generate( PUBKEY_ALGO_DSA, nbits, qbits, skey, &factors );
    if( rc )
      {
	log_error("dsa2_generate failed: %s\n", g10_errstr(rc) );
	return rc;
      }

    sk = xmalloc_clear( sizeof *sk );
    pk = xmalloc_clear( sizeof *pk );
    sk->timestamp = pk->timestamp = timestamp;
    sk->version = pk->version = 4;
    if( expireval )
      sk->expiredate = pk->expiredate = sk->timestamp + expireval;

    sk->pubkey_algo = pk->pubkey_algo = PUBKEY_ALGO_DSA;
		       pk->pkey[0] = mpi_copy( skey[0] );
		       pk->pkey[1] = mpi_copy( skey[1] );
		       pk->pkey[2] = mpi_copy( skey[2] );
		       pk->pkey[3] = mpi_copy( skey[3] );
    sk->skey[0] = skey[0];
    sk->skey[1] = skey[1];
    sk->skey[2] = skey[2];
    sk->skey[3] = skey[3];
    sk->skey[4] = skey[4];
    sk->is_protected = 0;
    sk->protect.algo = 0;

    sk->csum = checksum_mpi ( sk->skey[4] );
    if( ret_sk ) /* return an unprotected version of the sk */
	*ret_sk = copy_secret_key( NULL, sk );

    if( dek ) {
	sk->protect.algo = dek->algo;
	sk->protect.s2k = *s2k;
	rc = protect_secret_key( sk, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_key(pk);
	    free_secret_key(sk);
	    return rc;
	}
    }

    pkt = xmalloc_clear(sizeof *pkt);
    pkt->pkttype = is_subkey ? PKT_PUBLIC_SUBKEY : PKT_PUBLIC_KEY;
    pkt->pkt.public_key = pk;
    add_kbnode(pub_root, new_kbnode( pkt ));

    /* don't know whether it makes sense to have the factors, so for now
     * we store them in the secret keyring (but they are not secret)
     * p = 2 * q * f1 * f2 * ... * fn
     * We store only f1 to f_n-1;  fn can be calculated because p and q
     * are known.
     */
    pkt = xmalloc_clear(sizeof *pkt);
    pkt->pkttype = is_subkey ? PKT_SECRET_SUBKEY : PKT_SECRET_KEY;
    pkt->pkt.secret_key = sk;
    add_kbnode(sec_root, new_kbnode( pkt ));

    return 0;
}


/* 
 * Generate an RSA key.
 */
static int
gen_rsa(int algo, unsigned nbits, KBNODE pub_root, KBNODE sec_root, DEK *dek,
	STRING2KEY *s2k, PKT_secret_key **ret_sk, u32 timestamp,
	u32 expireval, int is_subkey)
{
    int rc;
    PACKET *pkt;
    PKT_secret_key *sk;
    PKT_public_key *pk;
    MPI skey[6];
    MPI *factors;

    assert( is_RSA(algo) );

    if( nbits < 1024 ) {
	nbits = 1024;
	log_info(_("keysize invalid; using %u bits\n"), nbits );
    }

    if( (nbits % 32) ) {
	nbits = ((nbits + 31) / 32) * 32;
	log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

    rc = pubkey_generate( algo, nbits, skey, &factors );
    if( rc ) {
	log_error("pubkey_generate failed: %s\n", g10_errstr(rc) );
	return rc;
    }

    sk = xmalloc_clear( sizeof *sk );
    pk = xmalloc_clear( sizeof *pk );
    sk->timestamp = pk->timestamp = timestamp;
    sk->version = pk->version = 4;
    if( expireval )
      sk->expiredate = pk->expiredate = sk->timestamp + expireval;

    sk->pubkey_algo = pk->pubkey_algo = algo;
		       pk->pkey[0] = mpi_copy( skey[0] );
		       pk->pkey[1] = mpi_copy( skey[1] );
    sk->skey[0] = skey[0];
    sk->skey[1] = skey[1];
    sk->skey[2] = skey[2];
    sk->skey[3] = skey[3];
    sk->skey[4] = skey[4];
    sk->skey[5] = skey[5];
    sk->is_protected = 0;
    sk->protect.algo = 0;

    sk->csum  = checksum_mpi (sk->skey[2] );
    sk->csum += checksum_mpi (sk->skey[3] );
    sk->csum += checksum_mpi (sk->skey[4] );
    sk->csum += checksum_mpi (sk->skey[5] );
    if( ret_sk ) /* return an unprotected version of the sk */
	*ret_sk = copy_secret_key( NULL, sk );

    if( dek ) {
	sk->protect.algo = dek->algo;
	sk->protect.s2k = *s2k;
	rc = protect_secret_key( sk, dek );
	if( rc ) {
	    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
	    free_public_key(pk);
	    free_secret_key(sk);
	    return rc;
	}
    }

    pkt = xmalloc_clear(sizeof *pkt);
    pkt->pkttype = is_subkey ? PKT_PUBLIC_SUBKEY : PKT_PUBLIC_KEY;
    pkt->pkt.public_key = pk;
    add_kbnode(pub_root, new_kbnode( pkt ));

    pkt = xmalloc_clear(sizeof *pkt);
    pkt->pkttype = is_subkey ? PKT_SECRET_SUBKEY : PKT_SECRET_KEY;
    pkt->pkt.secret_key = sk;
    add_kbnode(sec_root, new_kbnode( pkt ));

    return 0;
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
}


/* Returns the key flags */
static unsigned int
ask_key_flags(int algo,int subkey)
{
  /* TRANSLATORS: Please use only plain ASCII characters for the
     translation.  If this is not possible use single digits.  Here is
     a description of the fucntions:

       s = Toggle signing capability
       e = Toggle encryption capability
       a = Toggle authentication capability
       q = Finish
  */
  const char *togglers=_("SsEeAaQq");
  char *answer=NULL;
  unsigned int current=0;
  unsigned int possible=openpgp_pk_algo_usage(algo);

  if ( strlen(togglers) != 8 )
    {
      tty_printf ("NOTE: Bad translation at %s:%d. "
                  "Please report.\n", __FILE__, __LINE__);
      togglers = "11223300";
    }

  /* Only primary keys may certify. */
  if(subkey)
    possible&=~PUBKEY_USAGE_CERT;

  /* Preload the current set with the possible set, minus
     authentication, since nobody really uses auth yet. */
  current=possible&~PUBKEY_USAGE_AUTH;

  for(;;)
    {
      tty_printf("\n");
      tty_printf(_("Possible actions for a %s key: "),
		 pubkey_algo_to_string(algo));
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

      if(strlen(answer)>1)
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


/****************
 * Returns: 0 to create both a DSA and a Elgamal key.
 *          and only if key flags are to be written the desired usage.
 */
static int
ask_algo (int addmode, unsigned int *r_usage)
{
    char *answer;
    int algo;

    *r_usage = 0;
    tty_printf(_("Please select what kind of key you want:\n"));
    if( !addmode )
	tty_printf(_("   (%d) DSA and Elgamal (default)\n"), 1 );
    tty_printf(    _("   (%d) DSA (sign only)\n"), 2 );
    if (opt.expert)
      tty_printf(  _("   (%d) DSA (set your own capabilities)\n"), 3 );
    if( addmode )
	tty_printf(_("   (%d) Elgamal (encrypt only)\n"), 4 );
    tty_printf(    _("   (%d) RSA (sign only)\n"), 5 );
    if (addmode)
        tty_printf(_("   (%d) RSA (encrypt only)\n"), 6 );
    if (opt.expert)
      tty_printf(  _("   (%d) RSA (set your own capabilities)\n"), 7 );

    for(;;) {
	answer = cpr_get("keygen.algo",_("Your selection? "));
	cpr_kill_prompt();
	algo = *answer? atoi(answer): 1;
	xfree(answer);
	if( algo == 1 && !addmode ) {
	    algo = 0;	/* create both keys */
	    break;
	}
	else if( algo == 7 && opt.expert ) {
	    algo = PUBKEY_ALGO_RSA;
	    *r_usage=ask_key_flags(algo,addmode);
	    break;
	}
	else if( algo == 6 && addmode ) {
	    algo = PUBKEY_ALGO_RSA;
            *r_usage = PUBKEY_USAGE_ENC;
	    break;
	}
	else if( algo == 5 ) {
	    algo = PUBKEY_ALGO_RSA;
            *r_usage = PUBKEY_USAGE_SIG;
	    break;
	}
	else if( algo == 4 && addmode ) {
	    algo = PUBKEY_ALGO_ELGAMAL_E;
            *r_usage = PUBKEY_USAGE_ENC;
	    break;
	}
	else if( algo == 3 && opt.expert ) {
	    algo = PUBKEY_ALGO_DSA;
	    *r_usage=ask_key_flags(algo,addmode);
	    break;
	}
	else if( algo == 2 ) {
	    algo = PUBKEY_ALGO_DSA;
            *r_usage = PUBKEY_USAGE_SIG;
	    break;
	}
	else
	    tty_printf(_("Invalid selection.\n"));
    }

    return algo;
}


static unsigned
ask_keysize( int algo )
{
  unsigned nbits,min,def=2048,max=4096;

  if(opt.expert)
    min=512;
  else
    min=1024;

  switch(algo)
    {
    case PUBKEY_ALGO_DSA:
      if(opt.flags.dsa2)
	{
	  def=1024;
	  max=3072;
	}
      else
	{
	  tty_printf(_("DSA keypair will have %u bits.\n"),1024);
	  return 1024;
	}
      break;

    case PUBKEY_ALGO_RSA:
      min=1024;
      break;
    }

  tty_printf(_("%s keys may be between %u and %u bits long.\n"),
	     pubkey_algo_to_string(algo),min,max);

  for(;;)
    {
      char *prompt,*answer;

#define PROMPTSTRING _("What keysize do you want? (%u) ")

      prompt=xmalloc(strlen(PROMPTSTRING)+20);
      sprintf(prompt,PROMPTSTRING,def);

#undef PROMPTSTRING

      answer = cpr_get("keygen.size",prompt);
      cpr_kill_prompt();
      nbits = *answer? atoi(answer): def;
      xfree(prompt);
      xfree(answer);
      
      if(nbits<min || nbits>max)
	tty_printf(_("%s keysizes must be in the range %u-%u\n"),
		   pubkey_algo_to_string(algo),min,max);
      else
	break;
    }

  tty_printf(_("Requested keysize is %u bits\n"), nbits );

  if( algo == PUBKEY_ALGO_DSA && (nbits % 64) )
    {
      nbits = ((nbits + 63) / 64) * 64;
      tty_printf(_("rounded up to %u bits\n"), nbits );
    }
  else if( (nbits % 32) )
    {
      nbits = ((nbits + 31) / 32) * 32;
      tty_printf(_("rounded up to %u bits\n"), nbits );
    }

  return nbits;
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
parse_expire_string(u32 timestamp,const char *string)
{
    int mult;
    u32 seconds,abs_date=0;

    if( !*string )
      seconds = 0;
    else if ( !strncmp (string, "seconds=", 8) )
      seconds = atoi (string+8);
    else if( (abs_date = scan_isodatestr(string)) && abs_date > timestamp )
      seconds = abs_date - timestamp;
    else if( (mult=check_valid_days(string)) )
      seconds = atoi(string) * 86400L * mult;
    else
      seconds=(u32)-1;

    return seconds;
}

/* object == 0 for a key, and 1 for a sig */
u32
ask_expire_interval(u32 timestamp,int object,const char *def_expire)
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
	xfree(answer);
	if(object==0)
	  answer = cpr_get("keygen.valid",_("Key is valid for? (0) "));
	else
	  {
	    char *prompt;

#define PROMPTSTRING _("Signature is valid for? (%s) ")
	    /* This will actually end up larger than necessary because
	       of the 2 bytes for '%s' */
	    prompt=xmalloc(strlen(PROMPTSTRING)+strlen(def_expire)+1);
	    sprintf(prompt,PROMPTSTRING,def_expire);
#undef PROMPTSTRING

	    answer = cpr_get("siggen.valid",prompt);
	    xfree(prompt);

	    if(*answer=='\0')
	      answer=xstrdup(def_expire);
	  }
	cpr_kill_prompt();
	trim_spaces(answer);
	interval = parse_expire_string( timestamp, answer );
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
		       asctimestamp((ulong)(timestamp + interval) ) );
	    /* FIXME: This check yields warning on alhas: Write a
	       configure check and to this check here only for 32 bit
	       machines */
	    if( (time_t)((ulong)(timestamp+interval)) < 0 )
	      tty_printf(_("Your system can't display dates beyond 2038.\n"
			   "However, it will be correctly handled up to 2106.\n"));
	  }

	if( cpr_enabled() || cpr_get_answer_is_yes("keygen.valid.okay",
						   _("Is this correct? (y/N) ")) )
	  break;
      }

    xfree(answer);
    return interval;
}

static char *
ask_user_id( int mode )
{
    char *answer;
    char *aname, *acomment, *amail, *uid;

    if( !mode )
	tty_printf( _("\n"
"You need a user ID to identify your key; "
                                        "the software constructs the user ID\n"
"from the Real Name, Comment and Email Address in this form:\n"
"    \"Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>\"\n\n") );
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
		    tty_printf(_("Invalid character in name\n"));
		else if( digitp(aname) )
		    tty_printf(_("Name may not start with a digit\n"));
		else if( strlen(aname) < 5 )
		    tty_printf(_("Name must be at least 5 characters long\n"));
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
	if( !acomment ) {
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


	xfree(uid);
	uid = p = xmalloc(strlen(aname)+strlen(amail)+strlen(acomment)+12+10);
	p = stpcpy(p, aname );
	if( *acomment )
	    p = stpcpy(stpcpy(stpcpy(p," ("), acomment),")");
	if( *amail )
	    p = stpcpy(stpcpy(stpcpy(p," <"), amail),">");

	/* append a warning if we do not have dev/random
	 * or it is switched into  quick testmode */
	if( quick_random_gen(-1) )
	    strcpy(p, " (INSECURE!)" );

	/* print a note in case that UTF8 mapping has to be done */
	for(p=uid; *p; p++ ) {
	    if( *p & 0x80 ) {
		tty_printf(_("You are using the `%s' character set.\n"),
			   get_native_charset() );
		break;
	    }
	}

	tty_printf(_("You selected this USER-ID:\n    \"%s\"\n\n"), uid);
	/* fixme: add a warning if this user-id already exists */
	if( !*amail && !opt.allow_freeform_uid
	    && (strchr( aname, '@' ) || strchr( acomment, '@'))) {
	    fail = 1;
	    tty_printf(_("Please don't put the email address "
			  "into the real name or the comment\n") );
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
		answer = xstrdup(ansstr+6);
		answer[1] = 0;
	    }
	    else {
		answer = cpr_get("keygen.userid.cmd", fail?
		  _("Change (N)ame, (C)omment, (E)mail or (Q)uit? ") :
		  _("Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? "));
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
	if( !amail && !acomment && !amail )
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


/* FIXME: We need a way to cancel this prompt. */
static DEK *
do_ask_passphrase( STRING2KEY **ret_s2k )
{
    DEK *dek = NULL;
    STRING2KEY *s2k;
    const char *errtext = NULL;

    tty_printf(_("You need a Passphrase to protect your secret key.\n\n") );

    s2k = xmalloc_secure( sizeof *s2k );
    for(;;) {
	s2k->mode = opt.s2k_mode;
	s2k->hash_algo = S2K_DIGEST_ALGO;
	dek = passphrase_to_dek( NULL, 0, opt.s2k_cipher_algo, s2k,2,
                                 errtext, NULL);
	if( !dek ) {
	    errtext = N_("passphrase not correctly repeated; try again");
	    tty_printf(_("%s.\n"), _(errtext));
	}
	else if( !dek->keylen ) {
	    xfree(dek); dek = NULL;
	    xfree(s2k); s2k = NULL;
	    tty_printf(_(
	    "You don't want a passphrase - this is probably a *bad* idea!\n"
	    "I will do it anyway.  You can change your passphrase at any time,\n"
	    "using this program with the option \"--edit-key\".\n\n"));
	    break;
	}
	else
	    break; /* okay */
    }
    *ret_s2k = s2k;
    return dek;
}


static int
do_create( int algo, unsigned int nbits, KBNODE pub_root, KBNODE sec_root,
	   DEK *dek, STRING2KEY *s2k, PKT_secret_key **sk, u32 timestamp,
	   u32 expiredate, int is_subkey )
{
  int rc=0;

  if( !opt.batch )
    tty_printf(_(
"We need to generate a lot of random bytes. It is a good idea to perform\n"
"some other action (type on the keyboard, move the mouse, utilize the\n"
"disks) during the prime generation; this gives the random number\n"
"generator a better chance to gain enough entropy.\n") );

  if( algo == PUBKEY_ALGO_ELGAMAL_E )
    rc = gen_elg(algo, nbits, pub_root, sec_root, dek, s2k, sk, timestamp,
		 expiredate, is_subkey);
  else if( algo == PUBKEY_ALGO_DSA )
    rc = gen_dsa(nbits, pub_root, sec_root, dek, s2k, sk, timestamp,
		 expiredate, is_subkey);
  else if( algo == PUBKEY_ALGO_RSA )
    rc = gen_rsa(algo, nbits, pub_root, sec_root, dek, s2k, sk, timestamp,
		 expiredate, is_subkey);
  else
    BUG();

  return rc;
}


/****************
 * Generate a new user id packet, or return NULL if canceled
 */
PKT_user_id *
generate_user_id()
{
    PKT_user_id *uid;
    char *p;
    size_t n;

    p = ask_user_id( 1 );
    if( !p )
	return NULL;
    n = strlen(p);
    uid = xmalloc_clear( sizeof *uid + n );
    uid->len = n;
    strcpy(uid->name, p);
    uid->ref = 1;
    return uid;
}


static void
release_parameter_list( struct para_data_s *r )
{
    struct para_data_s *r2;

    for( ; r ; r = r2 ) {
	r2 = r->next;
	if( r->key == pPASSPHRASE_DEK )
	    xfree( r->u.dek );
	else if( r->key == pPASSPHRASE_S2K )
	    xfree( r->u.s2k );

	xfree(r);
    }
}

static struct para_data_s *
get_parameter( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r;

    for( r = para; r && r->key != key; r = r->next )
	;
    return r;
}

static const char *
get_parameter_value( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return (r && *r->u.value)? r->u.value : NULL;
}

static int
get_parameter_algo( struct para_data_s *para, enum para_name key )
{
    int i;
    struct para_data_s *r = get_parameter( para, key );
    if( !r )
	return -1;
    if( digitp( r->u.value ) )
	i = atoi( r->u.value );
    else
        i = string_to_pubkey_algo( r->u.value );
    if (i == PUBKEY_ALGO_RSA_E || i == PUBKEY_ALGO_RSA_S)
      i = 0; /* we don't want to allow generation of these algorithms */
    return i;
}

/* 
 * parse the usage parameter and set the keyflags.  Return true on error.
 */
static int
parse_parameter_usage (const char *fname,
                       struct para_data_s *para, enum para_name key)
{
    struct para_data_s *r = get_parameter( para, key );
    char *p, *pn;
    unsigned int use;

    if( !r )
	return 0; /* none (this is an optional parameter)*/
    
    use = 0;
    pn = r->u.value;
    while ( (p = strsep (&pn, " \t,")) ) {
        if ( !*p)
            ;
        else if ( !ascii_strcasecmp (p, "sign") )
            use |= PUBKEY_USAGE_SIG;
        else if ( !ascii_strcasecmp (p, "encrypt") )
            use |= PUBKEY_USAGE_ENC;
        else if ( !ascii_strcasecmp (p, "auth") )
            use |= PUBKEY_USAGE_AUTH;
        else {
            log_error("%s:%d: invalid usage list\n", fname, r->lnr );
            return -1; /* error */
        }
    }
    r->u.usage = use;
    return 1;
}

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
    if( r->key == pKEYEXPIRE || r->key == pSUBKEYEXPIRE )
	return r->u.expire;
    if( r->key == pKEYUSAGE || r->key == pSUBKEYUSAGE )
	return r->u.usage;
    if( r->key == pCREATETIME )
	return r->u.create;

    return (unsigned int)strtoul( r->u.value, NULL, 10 );
}

static unsigned int
get_parameter_uint( struct para_data_s *para, enum para_name key )
{
    return get_parameter_u32( para, key );
}

static DEK *
get_parameter_dek( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return r? r->u.dek : NULL;
}

static STRING2KEY *
get_parameter_s2k( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return r? r->u.s2k : NULL;
}

static struct revocation_key *
get_parameter_revkey( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return r? &r->u.revkey : NULL;
}

static int
proc_parameter_file( struct para_data_s *para, const char *fname,
                     struct output_control_s *outctrl, int card )
{
  struct para_data_s *r;
  const char *s1, *s2, *s3;
  size_t n;
  char *p;
  int have_user_id=0,err,algo;
  u32 timestamp;

  /* If we were told a creation time from outside, use it.  Otherwise
     look at the clock. */
  timestamp=get_parameter_u32( para, pCREATETIME );
  if(!timestamp)
    timestamp=make_timestamp();

  /* Check that we have all required parameters. */
  r = get_parameter( para, pKEYTYPE );
  if(r)
    {
      algo=get_parameter_algo(para,pKEYTYPE);
      if(check_pubkey_algo2(algo,PUBKEY_USAGE_SIG))
	{
	  log_error("%s:%d: invalid algorithm\n", fname, r->lnr );
	  return -1;
	}
    }
  else
    {
      log_error("%s: no Key-Type specified\n",fname);
      return -1;
    }

  err=parse_parameter_usage (fname, para, pKEYUSAGE);
  if(err==0)
    {
      /* Default to algo capabilities if key-usage is not provided */
      r=xmalloc_clear(sizeof(*r));
      r->key=pKEYUSAGE;
      r->u.usage=openpgp_pk_algo_usage(algo);
      r->next=para;
      para=r;
    }
  else if(err==-1)
    return -1;

  r = get_parameter( para, pSUBKEYTYPE );
  if(r)
    {
      algo=get_parameter_algo( para, pSUBKEYTYPE);
      if(check_pubkey_algo(algo))
	{
	  log_error("%s:%d: invalid algorithm\n", fname, r->lnr );
	  return -1;
	}

      err=parse_parameter_usage (fname, para, pSUBKEYUSAGE);
      if(err==0)
	{
	  /* Default to algo capabilities if subkey-usage is not
	     provided */
	  r=xmalloc_clear(sizeof(*r));
	  r->key=pSUBKEYUSAGE;
	  r->u.usage=openpgp_pk_algo_usage(algo);
	  r->next=para;
	  para=r;
	}
      else if(err==-1)
	return -1;
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
	    p = stpcpy(stpcpy(stpcpy(p," <"), s3 ),">");
	  r->next = para;
	  para = r;
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

      spec=parse_keyserver_uri(s1,1,NULL,0);
      if(spec)
	{
	  free_keyserver_spec(spec);
	  opt.def_keyserver_url=s1;
	}
      else
	{
	  log_error("%s:%d: invalid keyserver url\n", fname, r->lnr );
	  return -1;
	}
    }

  /* Set revoker, if any. */
  if (parse_revocation_key (fname, para, pREVOKER))
    return -1;

  /* make DEK and S2K from the Passphrase */
  r = get_parameter( para, pPASSPHRASE );
  if( r && *r->u.value ) {
    /* we have a plain text passphrase - create a DEK from it.
     * It is a little bit ridiculous to keep it ih secure memory
     * but becuase we do this alwasy, why not here */
    STRING2KEY *s2k;
    DEK *dek;

    s2k = xmalloc_secure( sizeof *s2k );
    s2k->mode = opt.s2k_mode;
    s2k->hash_algo = S2K_DIGEST_ALGO;
    set_next_passphrase( r->u.value );
    dek = passphrase_to_dek( NULL, 0, opt.s2k_cipher_algo, s2k, 2,
			     NULL, NULL);
    set_next_passphrase( NULL );
    assert( dek );
    memset( r->u.value, 0, strlen(r->u.value) );

    r = xmalloc_clear( sizeof *r );
    r->key = pPASSPHRASE_S2K;
    r->u.s2k = s2k;
    r->next = para;
    para = r;
    r = xmalloc_clear( sizeof *r );
    r->key = pPASSPHRASE_DEK;
    r->u.dek = dek;
    r->next = para;
    para = r;
  }

  /* make KEYEXPIRE from Expire-Date */
  r = get_parameter( para, pEXPIREDATE );
  if( r && *r->u.value )
    {
      u32 seconds;

      seconds = parse_expire_string( timestamp, r->u.value );
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
      r->next = para;
      para = r;
    }

  if( !!outctrl->pub.newfname ^ !!outctrl->sec.newfname ) {
    log_error("%s:%d: only one ring name is set\n", fname, outctrl->lnr );
    return -1;
  }

  do_generate_keypair( para, outctrl, timestamp, card );
  return 0;
}


/****************
 * Kludge to allow non interactive key generation controlled
 * by a parameter file.
 * Note, that string parameters are expected to be in UTF-8
 */
static void
read_parameter_file( const char *fname )
{
    static struct { const char *name;
		    enum para_name key;
    } keywords[] = {
	{ "Key-Type",       pKEYTYPE},
	{ "Key-Length",     pKEYLENGTH },
	{ "Key-Usage",      pKEYUSAGE },
	{ "Subkey-Type",    pSUBKEYTYPE },
	{ "Subkey-Length",  pSUBKEYLENGTH },
	{ "Subkey-Usage",   pSUBKEYUSAGE },
	{ "Name-Real",      pNAMEREAL },
	{ "Name-Email",     pNAMEEMAIL },
	{ "Name-Comment",   pNAMECOMMENT },
	{ "Expire-Date",    pEXPIREDATE },
	{ "Passphrase",     pPASSPHRASE },
	{ "Preferences",    pPREFERENCES },
	{ "Revoker",        pREVOKER },
        { "Handle",         pHANDLE },
	{ "Keyserver",      pKEYSERVER },
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

    if( !fname || !*fname)
      fname = "-";

    fp = iobuf_open (fname);
    if (fp && is_secured_file (iobuf_get_fd (fp)))
      {
        iobuf_close (fp);
        fp = NULL;
        errno = EPERM;
      }
    if (!fp) {
      log_error (_("can't open `%s': %s\n"), fname, strerror(errno) );
      return;
    }
    iobuf_ioctl (fp, 3, 1, NULL); /* No file caching. */

    lnr = 0;
    err = NULL;
    para = NULL;
    maxlen = 1024;
    line = NULL;
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
	    else if( !ascii_strcasecmp( keyword, "%commit" ) ) {
		outctrl.lnr = lnr;
		if (proc_parameter_file( para, fname, &outctrl, 0 ))
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
		if( outctrl.sec.fname && !strcmp( outctrl.sec.fname, value ) )
		    ; /* still the same file - ignore it */
		else {
		   xfree( outctrl.sec.newfname );
		   outctrl.sec.newfname = xstrdup( value );
		   outctrl.use_files = 1;
		}
	    }
	    else
		log_info("skipping control `%s' (%s)\n", keyword, value );


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
	    if (proc_parameter_file( para, fname, &outctrl, 0 ))
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
	if (proc_parameter_file( para, fname, &outctrl, 0 ))
          print_status_key_not_created (get_parameter_value (para, pHANDLE));
    }

    if( outctrl.use_files ) { /* close open streams */
	iobuf_close( outctrl.pub.stream );
	iobuf_close( outctrl.sec.stream );

        /* Must invalidate that ugly cache to actually close it.  */
        if (outctrl.pub.fname)
          iobuf_ioctl (NULL, 2, 0, (char*)outctrl.pub.fname);
        if (outctrl.sec.fname)
          iobuf_ioctl (NULL, 2, 0, (char*)outctrl.sec.fname);

	xfree( outctrl.pub.fname );
	xfree( outctrl.pub.newfname );
	xfree( outctrl.sec.fname );
	xfree( outctrl.sec.newfname );
    }

    release_parameter_list( para );
    iobuf_close (fp);
}


/*
 * Generate a keypair (fname is only used in batch mode) If
 * CARD_SERIALNO is not NULL the fucntion will create the keys on an
 * OpenPGP Card.  If BACKUP_ENCRYPTION_DIR has been set and
 * CARD_SERIALNO is NOT NULL, the encryption key for the card gets
 * generate in software, imported to the card and a backup file
 * written to directory given by this argument .
 */
void
generate_keypair (const char *fname, const char *card_serialno, 
                  const char *backup_encryption_dir)
{
  unsigned int nbits;
  char *uid = NULL;
  DEK *dek;
  STRING2KEY *s2k;
  int algo;
  unsigned int use;
  int both = 0;
  u32 timestamp,expire;
  struct para_data_s *para = NULL;
  struct para_data_s *r;
  struct output_control_s outctrl;
  
  memset( &outctrl, 0, sizeof( outctrl ) );
  
  if (opt.batch && card_serialno)
    {
      /* We don't yet support unattended key generation. */
      log_error (_("can't do this in batch mode\n"));
      return;
    }
  
  if (opt.batch)
    {
      read_parameter_file( fname );
      return;
    }

  timestamp=make_timestamp();
  r = xmalloc_clear( sizeof *r );
  r->key = pCREATETIME;
  r->u.create = timestamp;
  r->next = para;
  para = r;

  if (card_serialno)
    {
#ifdef ENABLE_CARD_SUPPORT
      r = xcalloc (1, sizeof *r + strlen (card_serialno) );
      r->key = pSERIALNO;
      strcpy( r->u.value, card_serialno);
      r->next = para;
      para = r;
       
      algo = PUBKEY_ALGO_RSA;
       
      r = xcalloc (1, sizeof *r + 20 );
      r->key = pKEYTYPE;
      sprintf( r->u.value, "%d", algo );
      r->next = para;
      para = r;
      r = xcalloc (1, sizeof *r + 20 );
      r->key = pKEYUSAGE;
      strcpy (r->u.value, "sign");
      r->next = para;
      para = r;
       
      r = xcalloc (1, sizeof *r + 20 );
      r->key = pSUBKEYTYPE;
      sprintf( r->u.value, "%d", algo );
      r->next = para;
      para = r;
      r = xcalloc (1, sizeof *r + 20 );
      r->key = pSUBKEYUSAGE;
      strcpy (r->u.value, "encrypt");
      r->next = para;
      para = r;
       
      r = xcalloc (1, sizeof *r + 20 );
      r->key = pAUTHKEYTYPE;
      sprintf( r->u.value, "%d", algo );
      r->next = para;
      para = r;

      if (backup_encryption_dir)
        {
          r = xcalloc (1, sizeof *r + strlen (backup_encryption_dir) );
          r->key = pBACKUPENCDIR;
          strcpy (r->u.value, backup_encryption_dir);
          r->next = para;
          para = r;
        }
#endif /*ENABLE_CARD_SUPPORT*/
    }
  else
    {
      algo = ask_algo( 0, &use );
      if( !algo )
        { /* default: DSA with ElG subkey of the specified size */
          both = 1;
          r = xmalloc_clear( sizeof *r + 20 );
          r->key = pKEYTYPE;
          sprintf( r->u.value, "%d", PUBKEY_ALGO_DSA );
          r->next = para;
          para = r;
	  nbits = ask_keysize( PUBKEY_ALGO_DSA );
	  r = xmalloc_clear( sizeof *r + 20 );
	  r->key = pKEYLENGTH;
	  sprintf( r->u.value, "%u", nbits);
	  r->next = para;
	  para = r;
          r = xmalloc_clear( sizeof *r + 20 );
          r->key = pKEYUSAGE;
          strcpy( r->u.value, "sign" );
          r->next = para;
          para = r;
           
          algo = PUBKEY_ALGO_ELGAMAL_E;
          r = xmalloc_clear( sizeof *r + 20 );
          r->key = pSUBKEYTYPE;
          sprintf( r->u.value, "%d", algo );
          r->next = para;
          para = r;
          r = xmalloc_clear( sizeof *r + 20 );
          r->key = pSUBKEYUSAGE;
          strcpy( r->u.value, "encrypt" );
          r->next = para;
          para = r;
        }
      else 
        {
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
           
        }

      nbits = ask_keysize( algo );
      r = xmalloc_clear( sizeof *r + 20 );
      r->key = both? pSUBKEYLENGTH : pKEYLENGTH;
      sprintf( r->u.value, "%u", nbits);
      r->next = para;
      para = r;
    }
   
  expire = ask_expire_interval(timestamp,0,NULL);
  r = xmalloc_clear( sizeof *r + 20 );
  r->key = pKEYEXPIRE;
  r->u.expire = expire;
  r->next = para;
  para = r;
  r = xmalloc_clear( sizeof *r + 20 );
  r->key = pSUBKEYEXPIRE;
  r->u.expire = expire;
  r->next = para;
  para = r;

  uid = ask_user_id(0);
  if( !uid ) 
    {
      log_error(_("Key generation canceled.\n"));
      release_parameter_list( para );
      return;
    }
  r = xmalloc_clear( sizeof *r + strlen(uid) );
  r->key = pUSERID;
  strcpy( r->u.value, uid );
  r->next = para;
  para = r;
    
  dek = card_serialno? NULL : do_ask_passphrase( &s2k );
  if( dek )
    {
      r = xmalloc_clear( sizeof *r );
      r->key = pPASSPHRASE_DEK;
      r->u.dek = dek;
      r->next = para;
      para = r;
      r = xmalloc_clear( sizeof *r );
      r->key = pPASSPHRASE_S2K;
      r->u.s2k = s2k;
      r->next = para;
      para = r;
    }
    
  proc_parameter_file( para, "[internal]", &outctrl, !!card_serialno);
  release_parameter_list( para );
}


#ifdef ENABLE_CARD_SUPPORT
/* Generate a raw key and return it as a secret key packet.  The
   function will ask for the passphrase and return a protected as well
   as an unprotected copy of a new secret key packet.  0 is returned
   on success and the caller must then free the returned values.  */
static int
generate_raw_key (int algo, unsigned int nbits, u32 created_at,
                  PKT_secret_key **r_sk_unprotected,
                  PKT_secret_key **r_sk_protected)
{
  int rc;
  DEK *dek = NULL;
  STRING2KEY *s2k = NULL;
  PKT_secret_key *sk = NULL;
  int i;
  size_t nskey, npkey;

  npkey = pubkey_get_npkey (algo);
  nskey = pubkey_get_nskey (algo);
  assert (nskey <= PUBKEY_MAX_NSKEY && npkey < nskey);

  if (nbits < 512)
    {
      nbits = 512;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }

  if ((nbits % 32)) 
    {
      nbits = ((nbits + 31) / 32) * 32;
      log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

  dek = do_ask_passphrase (&s2k);

  sk = xmalloc_clear (sizeof *sk);
  sk->timestamp = created_at;
  sk->version = 4;
  sk->pubkey_algo = algo;

  rc = pubkey_generate (algo, nbits, sk->skey, NULL);
  if (rc)
    {
      log_error("pubkey_generate failed: %s\n", g10_errstr(rc) );
      goto leave;
    }

  for (i=npkey; i < nskey; i++)
    sk->csum += checksum_mpi (sk->skey[i]);

  if (r_sk_unprotected) 
    *r_sk_unprotected = copy_secret_key (NULL, sk);

  if (dek)
    {
      sk->protect.algo = dek->algo;
      sk->protect.s2k = *s2k;
      rc = protect_secret_key (sk, dek);
      if (rc)
        {
          log_error ("protect_secret_key failed: %s\n", g10_errstr(rc));
          goto leave;
	}
    }
  if (r_sk_protected)
    {
      *r_sk_protected = sk;
      sk = NULL;
    }

 leave:
  if (sk)
    free_secret_key (sk);
  xfree (dek);
  xfree (s2k);
  return rc;
}
#endif /* ENABLE_CARD_SUPPORT */

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

static void
do_generate_keypair( struct para_data_s *para,struct output_control_s *outctrl,
		     u32 timestamp,int card )
{
    KBNODE pub_root = NULL;
    KBNODE sec_root = NULL;
    PKT_secret_key *pri_sk = NULL, *sub_sk = NULL;
    const char *s;
    struct revocation_key *revkey;
    int rc;
    int did_sub = 0;

    if( outctrl->dryrun )
      {
	log_info("dry-run mode - key generation skipped\n");
	return;
      }

    if( outctrl->use_files ) {
	if( outctrl->pub.newfname ) {
	    iobuf_close(outctrl->pub.stream);
	    outctrl->pub.stream = NULL;
            if (outctrl->pub.fname)
              iobuf_ioctl (NULL, 2, 0, (char*)outctrl->pub.fname);
	    xfree( outctrl->pub.fname );
	    outctrl->pub.fname =  outctrl->pub.newfname;
	    outctrl->pub.newfname = NULL;

            if (is_secured_filename (outctrl->pub.fname) ) {
                outctrl->pub.stream = NULL;
                errno = EPERM;
            }
            else
                outctrl->pub.stream = iobuf_create( outctrl->pub.fname );
	    if( !outctrl->pub.stream ) {
		log_error(_("can't create `%s': %s\n"), outctrl->pub.newfname,
						     strerror(errno) );
		return;
	    }
	    if( opt.armor ) {
		outctrl->pub.afx.what = 1;
		iobuf_push_filter( outctrl->pub.stream, armor_filter,
						    &outctrl->pub.afx );
	    }
	}
	if( outctrl->sec.newfname ) {
            mode_t oldmask;

	    iobuf_close(outctrl->sec.stream);
	    outctrl->sec.stream = NULL;
            if (outctrl->sec.fname)
              iobuf_ioctl (NULL, 2, 0, (char*)outctrl->sec.fname);
	    xfree( outctrl->sec.fname );
	    outctrl->sec.fname =  outctrl->sec.newfname;
	    outctrl->sec.newfname = NULL;

	    oldmask = umask (077);
            if (is_secured_filename (outctrl->sec.fname) ) {
                outctrl->sec.stream = NULL;
                errno = EPERM;
            }
            else
                outctrl->sec.stream = iobuf_create( outctrl->sec.fname );
            umask (oldmask);
	    if( !outctrl->sec.stream ) {
		log_error(_("can't create `%s': %s\n"), outctrl->sec.newfname,
						     strerror(errno) );
		return;
	    }
	    if( opt.armor ) {
		outctrl->sec.afx.what = 5;
		iobuf_push_filter( outctrl->sec.stream, armor_filter,
						    &outctrl->sec.afx );
	    }
	}
	assert( outctrl->pub.stream );
	assert( outctrl->sec.stream );
        if( opt.verbose ) {
            log_info(_("writing public key to `%s'\n"), outctrl->pub.fname );
            if (card)
              log_info (_("writing secret key stub to `%s'\n"),
                        outctrl->sec.fname);
            else
              log_info(_("writing secret key to `%s'\n"), outctrl->sec.fname );
        }
    }


    /* we create the packets as a tree of kbnodes. Because the
     * structure we create is known in advance we simply generate a
     * linked list.  The first packet is a dummy packet which we flag
     * as deleted.  The very first packet must always be a KEY packet.
     */
    
    start_tree(&pub_root);
    start_tree(&sec_root);

    if (!card)
      {
        rc = do_create( get_parameter_algo( para, pKEYTYPE ),
                        get_parameter_uint( para, pKEYLENGTH ),
                        pub_root, sec_root,
                        get_parameter_dek( para, pPASSPHRASE_DEK ),
                        get_parameter_s2k( para, pPASSPHRASE_S2K ),
                        &pri_sk,
			timestamp,
                        get_parameter_u32( para, pKEYEXPIRE ), 0 );
      }
    else
      {
        rc = gen_card_key (PUBKEY_ALGO_RSA, 1, 1, pub_root, sec_root, NULL,
                           get_parameter_u32 (para, pKEYEXPIRE), para);
        if (!rc)
          {
            pri_sk = sec_root->next->pkt->pkt.secret_key;
            assert (pri_sk);
          }
      }

    if(!rc && (revkey=get_parameter_revkey(para,pREVOKER)))
      {
	rc=write_direct_sig(pub_root,pub_root,pri_sk,revkey);
	if(!rc)
	  write_direct_sig(sec_root,pub_root,pri_sk,revkey);
      }

    if( !rc && (s=get_parameter_value(para, pUSERID)) )
      {
	write_uid(pub_root, s );
	if( !rc )
	  write_uid(sec_root, s );

	if( !rc )
	  rc = write_selfsigs(sec_root, pub_root, pri_sk,
			      get_parameter_uint (para, pKEYUSAGE));
      }

    /* Write the auth key to the card before the encryption key.  This
       is a partial workaround for a PGP bug (as of this writing, all
       versions including 8.1), that causes it to try and encrypt to
       the most recent subkey regardless of whether that subkey is
       actually an encryption type.  In this case, the auth key is an
       RSA key so it succeeds. */

    if (!rc && card && get_parameter (para, pAUTHKEYTYPE))
      {
        rc = gen_card_key (PUBKEY_ALGO_RSA, 3, 0, pub_root, sec_root, NULL,
                           get_parameter_u32 (para, pKEYEXPIRE), para);
        
        if (!rc)
          rc = write_keybinding (pub_root, pub_root, pri_sk, sub_sk, PUBKEY_USAGE_AUTH);
        if (!rc)
          rc = write_keybinding (sec_root, pub_root, pri_sk, sub_sk, PUBKEY_USAGE_AUTH);
      }

    if( !rc && get_parameter( para, pSUBKEYTYPE ) )
      {
        if (!card)
          {
            rc = do_create( get_parameter_algo( para, pSUBKEYTYPE ),
                            get_parameter_uint( para, pSUBKEYLENGTH ),
                            pub_root, sec_root,
                            get_parameter_dek( para, pPASSPHRASE_DEK ),
                            get_parameter_s2k( para, pPASSPHRASE_S2K ),
                            &sub_sk,
			    timestamp,
                            get_parameter_u32( para, pSUBKEYEXPIRE ), 1 );
          }
        else
          {
            if ((s = get_parameter_value (para, pBACKUPENCDIR)))
              {
                /* A backup of the encryption key has been requested.
                   Generate the key i software and import it then to
                   the card.  Write a backup file. */
                rc = gen_card_key_with_backup (PUBKEY_ALGO_RSA, 2, 0,
                                               pub_root, sec_root,
                                               get_parameter_u32 (para,
                                                                  pKEYEXPIRE),
                                               para, s);
              }
            else
              rc = gen_card_key (PUBKEY_ALGO_RSA, 2, 0, pub_root, sec_root,
				 NULL,
                                 get_parameter_u32 (para, pKEYEXPIRE), para);
          }

        if( !rc )
          rc = write_keybinding(pub_root, pub_root, pri_sk, sub_sk,
                                get_parameter_uint (para, pSUBKEYUSAGE));
        if( !rc )
          rc = write_keybinding(sec_root, pub_root, pri_sk, sub_sk,
                                get_parameter_uint (para, pSUBKEYUSAGE));
        did_sub = 1;
      }

    if( !rc && outctrl->use_files ) { /* direct write to specified files */
	rc = write_keyblock( outctrl->pub.stream, pub_root );
	if( rc )
	    log_error("can't write public key: %s\n", g10_errstr(rc) );
	if( !rc ) {
	    rc = write_keyblock( outctrl->sec.stream, sec_root );
	    if( rc )
		log_error("can't write secret key: %s\n", g10_errstr(rc) );
	}

    }
    else if( !rc ) { /* write to the standard keyrings */
	KEYDB_HANDLE pub_hd = keydb_new (0);
	KEYDB_HANDLE sec_hd = keydb_new (1);

        /* FIXME: we may have to create the keyring first */
        rc = keydb_locate_writable (pub_hd, NULL);
        if (rc) 
    	    log_error (_("no writable public keyring found: %s\n"),
                       g10_errstr (rc));

        if (!rc) {  
            rc = keydb_locate_writable (sec_hd, NULL);
            if (rc) 
                log_error (_("no writable secret keyring found: %s\n"),
                           g10_errstr (rc));
        }

        if (!rc && opt.verbose) {
            log_info(_("writing public key to `%s'\n"),
                     keydb_get_resource_name (pub_hd));
            if (card)
              log_info (_("writing secret key stub to `%s'\n"),
                        keydb_get_resource_name (sec_hd));
            else
              log_info(_("writing secret key to `%s'\n"),
                       keydb_get_resource_name (sec_hd));
        }

        if (!rc) {
	    rc = keydb_insert_keyblock (pub_hd, pub_root);
            if (rc)
                log_error (_("error writing public keyring `%s': %s\n"),
                           keydb_get_resource_name (pub_hd), g10_errstr(rc));
        }

        if (!rc) {
	    rc = keydb_insert_keyblock (sec_hd, sec_root);
            if (rc)
                log_error (_("error writing secret keyring `%s': %s\n"),
                           keydb_get_resource_name (pub_hd), g10_errstr(rc));
        }

        keydb_release (pub_hd);
        keydb_release (sec_hd);

	if (!rc) {
            int no_enc_rsa =
                get_parameter_algo(para, pKEYTYPE) == PUBKEY_ALGO_RSA
                && get_parameter_uint( para, pKEYUSAGE )
                && !(get_parameter_uint( para,pKEYUSAGE) & PUBKEY_USAGE_ENC);
            PKT_public_key *pk = find_kbnode (pub_root, 
                                    PKT_PUBLIC_KEY)->pkt->pkt.public_key;

	    keyid_from_pk(pk,pk->main_keyid);
	    register_trusted_keyid(pk->main_keyid);

	    update_ownertrust (pk,
			       ((get_ownertrust (pk) & ~TRUST_MASK)
				| TRUST_ULTIMATE ));

	    if (!opt.batch) {
                tty_printf(_("public and secret key created and signed.\n") );
		tty_printf("\n");
		list_keyblock(pub_root,0,1,NULL);
            }
            

	    if( !opt.batch
		&& ( get_parameter_algo( para, pKEYTYPE ) == PUBKEY_ALGO_DSA
                     || no_enc_rsa )
		&& !get_parameter( para, pSUBKEYTYPE ) )
	    {
		tty_printf(_("Note that this key cannot be used for "
			     "encryption.  You may want to use\n"
			     "the command \"--edit-key\" to generate a "
			     "subkey for this purpose.\n") );
	    }
	}
    }

    if( rc ) {
	if( opt.batch )
	    log_error("key generation failed: %s\n", g10_errstr(rc) );
	else
	    tty_printf(_("Key generation failed: %s\n"), g10_errstr(rc) );
        print_status_key_not_created ( get_parameter_value (para, pHANDLE) );
    }
    else {
        PKT_public_key *pk = find_kbnode (pub_root, 
                                    PKT_PUBLIC_KEY)->pkt->pkt.public_key;
        print_status_key_created (did_sub? 'B':'P', pk,
                                  get_parameter_value (para, pHANDLE));
    }
    release_kbnode( pub_root );
    release_kbnode( sec_root );

    if( pri_sk && !card) /* the unprotected  secret key unless we have a */
      free_secret_key(pri_sk); /* shallow copy in card mode. */
    if( sub_sk )
	free_secret_key(sub_sk);
}


/****************
 * add a new subkey to an existing key.
 * Returns true if a new key has been generated and put into the keyblocks.
 */
int
generate_subkeypair( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    int okay=0, rc=0;
    KBNODE node;
    PKT_secret_key *pri_sk = NULL, *sub_sk = NULL;
    int algo;
    unsigned int use;
    u32 expire;
    unsigned nbits;
    char *passphrase = NULL;
    DEK *dek = NULL;
    STRING2KEY *s2k = NULL;
    u32 timestamp;
    int ask_pass = 0;

    /* break out the primary secret key */
    node = find_kbnode( sec_keyblock, PKT_SECRET_KEY );
    if( !node ) {
	log_error("Oops; secret key not found anymore!\n");
	goto leave;
    }

    /* make a copy of the sk to keep the protected one in the keyblock */
    pri_sk = copy_secret_key( NULL, node->pkt->pkt.secret_key );

    timestamp = make_timestamp();
    if( pri_sk->timestamp > timestamp ) {
	ulong d = pri_sk->timestamp - timestamp;
	log_info( d==1 ? _("key has been created %lu second "
			   "in future (time warp or clock problem)\n")
		       : _("key has been created %lu seconds "
			   "in future (time warp or clock problem)\n"), d );
	if( !opt.ignore_time_conflict ) {
	    rc = G10ERR_TIME_CONFLICT;
	    goto leave;
	}
    }

    if (pri_sk->version < 4) {
        log_info (_("NOTE: creating subkeys for v3 keys "
                    "is not OpenPGP compliant\n"));
	goto leave;
    }

    if (pri_sk->is_protected && pri_sk->protect.s2k.mode == 1001) {
        tty_printf(_("Secret parts of primary key are not available.\n"));
        rc = G10ERR_NO_SECKEY;
        goto leave;
    }


    /* Unprotect to get the passphrase.  */
    switch( is_secret_key_protected( pri_sk ) ) {
      case -1:
	rc = G10ERR_PUBKEY_ALGO;
	break;
      case 0:
	tty_printf(_("This key is not protected.\n"));
	break;
      case -2:
        tty_printf(_("Secret parts of primary key are stored on-card.\n"));
        ask_pass = 1;
        break;
      default:
        tty_printf(_("Key is protected.\n"));
        rc = check_secret_key( pri_sk, 0 );
        if( !rc )
            passphrase = get_last_passphrase();
        break;
    }
    if( rc )
	goto leave;

    algo = ask_algo( 1, &use );
    assert(algo);
    nbits = ask_keysize( algo );
    expire = ask_expire_interval(timestamp,0,NULL);
    if( !cpr_enabled() && !cpr_get_answer_is_yes("keygen.sub.okay",
						  _("Really create? (y/N) ")))
	goto leave;

    if (ask_pass)
        dek = do_ask_passphrase (&s2k);
    else if (passphrase) {
	s2k = xmalloc_secure( sizeof *s2k );
	s2k->mode = opt.s2k_mode;
	s2k->hash_algo = S2K_DIGEST_ALGO;
	set_next_passphrase( passphrase );
	dek = passphrase_to_dek( NULL, 0, opt.s2k_cipher_algo, s2k, 2,
                                 NULL, NULL );
    }

    rc = do_create( algo, nbits, pub_keyblock, sec_keyblock,
		    dek, s2k, &sub_sk, timestamp, expire, 1 );
    if( !rc )
	rc = write_keybinding(pub_keyblock, pub_keyblock, pri_sk, sub_sk, use);
    if( !rc )
	rc = write_keybinding(sec_keyblock, pub_keyblock, pri_sk, sub_sk, use);
    if( !rc ) {
	okay = 1;
        write_status_text (STATUS_KEY_CREATED, "S");
    }

  leave:
    if( rc )
	log_error(_("Key generation failed: %s\n"), g10_errstr(rc) );
    xfree( passphrase );
    xfree( dek );
    xfree( s2k );
    /* release the copy of the (now unprotected) secret keys */
    if( pri_sk )
	free_secret_key(pri_sk);
    if( sub_sk )
	free_secret_key(sub_sk);
    set_next_passphrase( NULL );
    return okay;
}


#ifdef ENABLE_CARD_SUPPORT
/* Generate a subkey on a card. */
int
generate_card_subkeypair (KBNODE pub_keyblock, KBNODE sec_keyblock,
                          int keyno, const char *serialno)
{
  int okay=0, rc=0;
  KBNODE node;
  PKT_secret_key *pri_sk = NULL, *sub_sk;
  int algo;
  unsigned int use;
  u32 timestamp,expire;
  char *passphrase = NULL;
  struct para_data_s *para = NULL;

  assert (keyno >= 1 && keyno <= 3);

  para = xcalloc (1, sizeof *para + strlen (serialno) );
  para->key = pSERIALNO;
  strcpy (para->u.value, serialno);

  /* Break out the primary secret key */
  node = find_kbnode( sec_keyblock, PKT_SECRET_KEY );
  if(!node)
    {
      log_error("Oops; secret key not found anymore!\n");
      goto leave;
    }

  /* Make a copy of the sk to keep the protected one in the keyblock */
  pri_sk = copy_secret_key (NULL, node->pkt->pkt.secret_key);

  timestamp = make_timestamp();
  if (pri_sk->timestamp > timestamp)
    {
      ulong d = pri_sk->timestamp - timestamp;
      log_info (d==1 ? _("key has been created %lu second "
                         "in future (time warp or clock problem)\n")
                     : _("key has been created %lu seconds "
                         "in future (time warp or clock problem)\n"), d );
	if (!opt.ignore_time_conflict)
          {
	    rc = G10ERR_TIME_CONFLICT;
	    goto leave;
          }
    }

  if (pri_sk->version < 4)
    {
      log_info (_("NOTE: creating subkeys for v3 keys "
                  "is not OpenPGP compliant\n"));
      goto leave;
    }

  /* Unprotect to get the passphrase. */
  switch( is_secret_key_protected (pri_sk) )
    {
    case -1:
      rc = G10ERR_PUBKEY_ALGO;
      break;
    case 0:
      tty_printf("This key is not protected.\n");
      break;
    default:
      tty_printf("Key is protected.\n");
      rc = check_secret_key( pri_sk, 0 );
      if (!rc)
        passphrase = get_last_passphrase();
      break;
    }
  if (rc)
    goto leave;

  algo = PUBKEY_ALGO_RSA;
  expire = ask_expire_interval (timestamp,0,NULL);
  if (keyno == 1)
    use = PUBKEY_USAGE_SIG;
  else if (keyno == 2)
    use = PUBKEY_USAGE_ENC;
  else
    use = PUBKEY_USAGE_AUTH;
  if (!cpr_enabled() && !cpr_get_answer_is_yes("keygen.cardsub.okay",
                                               _("Really create? (y/N) ")))
    goto leave;

  if (passphrase)
    set_next_passphrase (passphrase);
  rc = gen_card_key (algo, keyno, 0, pub_keyblock, sec_keyblock,
		     &sub_sk, expire, para);
  if (!rc)
    rc = write_keybinding (pub_keyblock, pub_keyblock, pri_sk, sub_sk, use);
  if (!rc)
    rc = write_keybinding (sec_keyblock, pub_keyblock, pri_sk, sub_sk, use);
  if (!rc)
    {
      okay = 1;
      write_status_text (STATUS_KEY_CREATED, "S");
    }

 leave:
  if (rc)
    log_error (_("Key generation failed: %s\n"), g10_errstr(rc) );
  xfree (passphrase);
  /* Release the copy of the (now unprotected) secret keys. */
  if (pri_sk)
    free_secret_key (pri_sk);
  set_next_passphrase( NULL );
  release_parameter_list (para);
  return okay;
}
#endif /* !ENABLE_CARD_SUPPORT */


/****************
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
			node->pkt->pkttype, g10_errstr(rc) );
	      return G10ERR_WRITE_FILE;
	    }
	}
    }

  return 0;
}


static int
gen_card_key (int algo, int keyno, int is_primary,
              KBNODE pub_root, KBNODE sec_root, PKT_secret_key **ret_sk,
              u32 expireval, struct para_data_s *para)
{
#ifdef ENABLE_CARD_SUPPORT
  int rc;
  const char *s;
  struct agent_card_genkey_s info;
  PACKET *pkt;
  PKT_secret_key *sk;
  PKT_public_key *pk;

  assert (algo == PUBKEY_ALGO_RSA);
  
  /* Fixme: We don't have the serialnumber available, thus passing NULL. */
  rc = agent_scd_genkey (&info, keyno, 1, NULL);
/*    if (gpg_err_code (rc) == GPG_ERR_EEXIST) */
/*      { */
/*        tty_printf ("\n"); */
/*        log_error ("WARNING: key does already exists!\n"); */
/*        tty_printf ("\n"); */
/*        if ( cpr_get_answer_is_yes( "keygen.card.replace_key", */
/*                                    _("Replace existing key? "))) */
/*          rc = agent_scd_genkey (&info, keyno, 1); */
/*      } */

  if (rc)
    {
      log_error ("key generation failed: %s\n", gpg_strerror (rc));
      return rc;
    }
  if ( !info.n || !info.e )
    {
      log_error ("communication error with SCD\n");
      mpi_free (info.n);
      mpi_free (info.e);
      return gpg_error (GPG_ERR_GENERAL);
    }
  

  pk = xcalloc (1, sizeof *pk );
  sk = xcalloc (1, sizeof *sk );
  sk->timestamp = pk->timestamp = info.created_at;
  sk->version = pk->version = 4;
  if (expireval)
      sk->expiredate = pk->expiredate = pk->timestamp + expireval;
  sk->pubkey_algo = pk->pubkey_algo = algo;
  pk->pkey[0] = info.n;
  pk->pkey[1] = info.e; 
  sk->skey[0] = mpi_copy (pk->pkey[0]);
  sk->skey[1] = mpi_copy (pk->pkey[1]);
  sk->skey[2] = mpi_set_opaque (NULL, xstrdup ("dummydata"), 10);
  sk->is_protected = 1;
  sk->protect.s2k.mode = 1002;
  s = get_parameter_value (para, pSERIALNO);
  if (s)
    {
      for (sk->protect.ivlen=0; sk->protect.ivlen < 16 && *s && s[1];
           sk->protect.ivlen++, s += 2)
        sk->protect.iv[sk->protect.ivlen] = xtoi_2 (s);
    }

  if( ret_sk )
    *ret_sk = sk;

  pkt = xcalloc (1,sizeof *pkt);
  pkt->pkttype = is_primary ? PKT_PUBLIC_KEY : PKT_PUBLIC_SUBKEY;
  pkt->pkt.public_key = pk;
  add_kbnode(pub_root, new_kbnode( pkt ));

  pkt = xcalloc (1,sizeof *pkt);
  pkt->pkttype = is_primary ? PKT_SECRET_KEY : PKT_SECRET_SUBKEY;
  pkt->pkt.secret_key = sk;
  add_kbnode(sec_root, new_kbnode( pkt ));

  return 0;
#else
  return -1;
#endif /*!ENABLE_CARD_SUPPORT*/
}



static int
gen_card_key_with_backup (int algo, int keyno, int is_primary,
                          KBNODE pub_root, KBNODE sec_root,
                          u32 expireval, struct para_data_s *para,
                          const char *backup_dir)
{
#ifdef ENABLE_CARD_SUPPORT
  int rc;
  const char *s;
  PACKET *pkt;
  PKT_secret_key *sk, *sk_unprotected, *sk_protected;
  PKT_public_key *pk;
  size_t n;
  int i;

  sk_unprotected = NULL;
  sk_protected = NULL;
  rc = generate_raw_key (algo, 1024, make_timestamp (),
                         &sk_unprotected, &sk_protected);
  if (rc)
    return rc;

  /* First, store the key to the card. */
  rc = save_unprotected_key_to_card (sk_unprotected, keyno);
  if (rc)
    {
      log_error (_("storing key onto card failed: %s\n"), g10_errstr (rc));
      free_secret_key (sk_unprotected);
      free_secret_key (sk_protected);
      return rc;
    }

  /* Get rid of the secret key parameters and store the serial numer. */
  sk = sk_unprotected;
  n = pubkey_get_nskey (sk->pubkey_algo);
  for (i=pubkey_get_npkey (sk->pubkey_algo); i < n; i++)
    {
      mpi_free (sk->skey[i]);
      sk->skey[i] = NULL;
    }
  i = pubkey_get_npkey (sk->pubkey_algo);
  sk->skey[i] = mpi_set_opaque (NULL, xstrdup ("dummydata"), 10);
  sk->is_protected = 1;
  sk->protect.s2k.mode = 1002;
  s = get_parameter_value (para, pSERIALNO);
  assert (s);
  for (sk->protect.ivlen=0; sk->protect.ivlen < 16 && *s && s[1];
       sk->protect.ivlen++, s += 2)
    sk->protect.iv[sk->protect.ivlen] = xtoi_2 (s);

  /* Now write the *protected* secret key to the file.  */
  {
    char name_buffer[50];
    char *fname;
    IOBUF fp;
    mode_t oldmask;

    keyid_from_sk (sk, NULL);
    sprintf (name_buffer,"sk_%08lX%08lX.gpg",
             (ulong)sk->keyid[0], (ulong)sk->keyid[1]);

    fname = make_filename (backup_dir, name_buffer, NULL);
    oldmask = umask (077);
    if (is_secured_filename (fname))
      {
        fp = NULL;
        errno = EPERM;
      }
    else
      fp = iobuf_create (fname);
    umask (oldmask);
    if (!fp) 
      {
	log_error (_("can't create backup file `%s': %s\n"),
                   fname, strerror(errno) );
        xfree (fname);
        free_secret_key (sk_unprotected);
        free_secret_key (sk_protected);
        return G10ERR_OPEN_FILE;
      }

    pkt = xcalloc (1, sizeof *pkt);
    pkt->pkttype = PKT_SECRET_KEY;
    pkt->pkt.secret_key = sk_protected;
    sk_protected = NULL;

    rc = build_packet (fp, pkt);
    if (rc)
      {
        log_error("build packet failed: %s\n", g10_errstr(rc) );
        iobuf_cancel (fp);
      }
    else
      {
        byte array[MAX_FINGERPRINT_LEN];
        char *fprbuf, *p;
       
        iobuf_close (fp);
        iobuf_ioctl (NULL, 2, 0, (char*)fname);
        log_info (_("NOTE: backup of card key saved to `%s'\n"), fname);

        fingerprint_from_sk (sk, array, &n);
        p = fprbuf = xmalloc (MAX_FINGERPRINT_LEN*2 + 1 + 1);
        for (i=0; i < n ; i++, p += 2)
          sprintf (p, "%02X", array[i]);
        *p++ = ' ';
        *p = 0;

        write_status_text_and_buffer (STATUS_BACKUP_KEY_CREATED,
                                      fprbuf,
                                      fname, strlen (fname),
                                      0);
        xfree (fprbuf);
      }
    free_packet (pkt);
    xfree (pkt);
    xfree (fname);
    if (rc)
      {
        free_secret_key (sk_unprotected);
        return rc;
      }
  }

  /* Create the public key from the secret key. */
  pk = xcalloc (1, sizeof *pk );
  pk->timestamp = sk->timestamp;
  pk->version = sk->version;
  if (expireval)
      pk->expiredate = sk->expiredate = sk->timestamp + expireval;
  pk->pubkey_algo = sk->pubkey_algo;
  n = pubkey_get_npkey (sk->pubkey_algo);
  for (i=0; i < n; i++)
    pk->pkey[i] = mpi_copy (sk->skey[i]);

  /* Build packets and add them to the node lists.  */
  pkt = xcalloc (1,sizeof *pkt);
  pkt->pkttype = is_primary ? PKT_PUBLIC_KEY : PKT_PUBLIC_SUBKEY;
  pkt->pkt.public_key = pk;
  add_kbnode(pub_root, new_kbnode( pkt ));

  pkt = xcalloc (1,sizeof *pkt);
  pkt->pkttype = is_primary ? PKT_SECRET_KEY : PKT_SECRET_SUBKEY;
  pkt->pkt.secret_key = sk;
  add_kbnode(sec_root, new_kbnode( pkt ));

  return 0;
#else
  return -1;
#endif /*!ENABLE_CARD_SUPPORT*/
}


#ifdef ENABLE_CARD_SUPPORT
int
save_unprotected_key_to_card (PKT_secret_key *sk, int keyno)
{
  int rc;
  unsigned char *rsa_n = NULL;
  unsigned char *rsa_e = NULL;
  unsigned char *rsa_p = NULL;
  unsigned char *rsa_q = NULL;
  unsigned int rsa_n_len, rsa_e_len, rsa_p_len, rsa_q_len;
  unsigned char *sexp = NULL;
  unsigned char *p;
  char numbuf[55], numbuf2[50];

  assert (is_RSA (sk->pubkey_algo));
  assert (!sk->is_protected);

  /* Copy the parameters into straight buffers. */
  rsa_n = mpi_get_secure_buffer (sk->skey[0], &rsa_n_len, NULL);
  rsa_e = mpi_get_secure_buffer (sk->skey[1], &rsa_e_len, NULL);
  rsa_p = mpi_get_secure_buffer (sk->skey[3], &rsa_p_len, NULL);
  rsa_q = mpi_get_secure_buffer (sk->skey[4], &rsa_q_len, NULL);
  if (!rsa_n || !rsa_e || !rsa_p || !rsa_q)
    {
      rc = G10ERR_INV_ARG;
      goto leave;
    }

  /* Put the key into an S-expression. */
  sexp = p = xmalloc_secure (30
                             + rsa_n_len + rsa_e_len + rsa_p_len + rsa_q_len
                             + 4*sizeof (numbuf) + 25 + sizeof(numbuf) + 20);

  p = stpcpy (p,"(11:private-key(3:rsa(1:n");
  sprintf (numbuf, "%u:", rsa_n_len);
  p = stpcpy (p, numbuf);
  memcpy (p, rsa_n, rsa_n_len);
  p += rsa_n_len;

  sprintf (numbuf, ")(1:e%u:", rsa_e_len);
  p = stpcpy (p, numbuf);
  memcpy (p, rsa_e, rsa_e_len);
  p += rsa_e_len;

  sprintf (numbuf, ")(1:p%u:", rsa_p_len);
  p = stpcpy (p, numbuf);
  memcpy (p, rsa_p, rsa_p_len);
  p += rsa_p_len;

  sprintf (numbuf, ")(1:q%u:", rsa_q_len);
  p = stpcpy (p, numbuf);
  memcpy (p, rsa_q, rsa_q_len);
  p += rsa_q_len;

  p = stpcpy (p,"))(10:created-at");
  sprintf (numbuf2, "%lu", (unsigned long)sk->timestamp);
  sprintf (numbuf, "%lu:", (unsigned long)strlen (numbuf2));
  p = stpcpy (stpcpy (stpcpy (p, numbuf), numbuf2), "))");

  /* Fixme: Unfortunately we don't have the serialnumber available -
     thus we can't pass it down to the agent. */ 
  rc = agent_scd_writekey (keyno, NULL, sexp, p - sexp);

 leave:
  xfree (sexp);
  xfree (rsa_n);
  xfree (rsa_e);
  xfree (rsa_p);
  xfree (rsa_q);
  return rc;
}
#endif /*ENABLE_CARD_SUPPORT*/
