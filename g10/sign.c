/* sign.c - sign data
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
#include <errno.h>
#include <assert.h>
#include <unistd.h> /* need sleep() */

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "filter.h"
#include "ttyio.h"
#include "trustdb.h"
#include "status.h"
#include "i18n.h"
#include "cardglue.h"


#ifdef HAVE_DOSISH_SYSTEM
#define LF "\r\n"
void __stdcall Sleep(ulong);
#define sleep(a)  Sleep((a)*1000)
#else
#define LF "\n"
#endif

static int recipient_digest_algo=0;

/****************
 * Create notations and other stuff.  It is assumed that the stings in
 * STRLIST are already checked to contain only printable data and have
 * a valid NAME=VALUE format.
 */
static void
mk_notation_policy_etc( PKT_signature *sig,
			PKT_public_key *pk, PKT_secret_key *sk )
{
    const char *string;
    char *s=NULL;
    STRLIST pu=NULL;
    struct notation *nd=NULL;
    struct expando_args args;

    assert(sig->version>=4);

    memset(&args,0,sizeof(args));
    args.pk=pk;
    args.sk=sk;

    /* notation data */
    if(IS_SIG(sig) && opt.sig_notations)
      nd=opt.sig_notations;
    else if( IS_CERT(sig) && opt.cert_notations )
      nd=opt.cert_notations;

    if(nd)
      {
	struct notation *i;

	for(i=nd;i;i=i->next)
	  {
	    i->altvalue=pct_expando(i->value,&args);
	    if(!i->altvalue)
	      log_error(_("WARNING: unable to %%-expand notation "
			  "(too large).  Using unexpanded.\n"));
	  }

	keygen_add_notations(sig,nd);

	for(i=nd;i;i=i->next)
	  {
	    xfree(i->altvalue);
	    i->altvalue=NULL;
	  }
      }

    /* set policy URL */
    if( IS_SIG(sig) && opt.sig_policy_url )
      pu=opt.sig_policy_url;
    else if( IS_CERT(sig) && opt.cert_policy_url )
      pu=opt.cert_policy_url;

    for(;pu;pu=pu->next)
      {
        string = pu->d;

	s=pct_expando(string,&args);
	if(!s)
	  {
	    log_error(_("WARNING: unable to %%-expand policy URL "
			"(too large).  Using unexpanded.\n"));
	    s=xstrdup(string);
	  }

	build_sig_subpkt(sig,SIGSUBPKT_POLICY|
			 ((pu->flags & 1)?SIGSUBPKT_FLAG_CRITICAL:0),
			 s,strlen(s));

	xfree(s);
      }

    /* preferred keyserver URL */
    if( IS_SIG(sig) && opt.sig_keyserver_url )
      pu=opt.sig_keyserver_url;

    for(;pu;pu=pu->next)
      {
        string = pu->d;

	s=pct_expando(string,&args);
	if(!s)
	  {
	    log_error(_("WARNING: unable to %%-expand preferred keyserver URL"
			" (too large).  Using unexpanded.\n"));
	    s=xstrdup(string);
	  }

	build_sig_subpkt(sig,SIGSUBPKT_PREF_KS|
			 ((pu->flags & 1)?SIGSUBPKT_FLAG_CRITICAL:0),
			 s,strlen(s));

	xfree(s);
      }
}


/*
 * Helper to hash a user ID packet.  
 */
static void
hash_uid (MD_HANDLE md, int sigversion, const PKT_user_id *uid)
{
    if ( sigversion >= 4 ) {
        byte buf[5];

	if(uid->attrib_data) {
	  buf[0] = 0xd1;	           /* indicates an attribute packet */
	  buf[1] = uid->attrib_len >> 24;  /* always use 4 length bytes */
	  buf[2] = uid->attrib_len >> 16;
	  buf[3] = uid->attrib_len >>  8;
	  buf[4] = uid->attrib_len;
	}
	else {
	  buf[0] = 0xb4;	    /* indicates a userid packet */
	  buf[1] = uid->len >> 24;  /* always use 4 length bytes */
	  buf[2] = uid->len >> 16;
	  buf[3] = uid->len >>  8;
	  buf[4] = uid->len;
	}
        md_write( md, buf, 5 );
    }

    if(uid->attrib_data)
      md_write (md, uid->attrib_data, uid->attrib_len );
    else
      md_write (md, uid->name, uid->len );
}


/*
 * Helper to hash some parts from the signature
 */
static void
hash_sigversion_to_magic (MD_HANDLE md, const PKT_signature *sig)
{
    if (sig->version >= 4) 
        md_putc (md, sig->version);
    md_putc (md, sig->sig_class);
    if (sig->version < 4) {
        u32 a = sig->timestamp;
        md_putc (md, (a >> 24) & 0xff );
        md_putc (md, (a >> 16) & 0xff );
        md_putc (md, (a >>  8) & 0xff );
        md_putc (md,  a	       & 0xff );
    }
    else {
        byte buf[6];
        size_t n;
        
        md_putc (md, sig->pubkey_algo);
        md_putc (md, sig->digest_algo);
        if (sig->hashed) {
            n = sig->hashed->len;
            md_putc (md, (n >> 8) );
            md_putc (md,  n       );
            md_write (md, sig->hashed->data, n );
            n += 6;
        }
        else {
            md_putc (md, 0);  /* always hash the length of the subpacket*/
            md_putc (md, 0);
            n = 6;
        }
        /* add some magic */
        buf[0] = sig->version;
        buf[1] = 0xff;
        buf[2] = n >> 24; /* hmmm, n is only 16 bit, so this is always 0 */
        buf[3] = n >> 16;
        buf[4] = n >>  8;
        buf[5] = n;
        md_write (md, buf, 6);
    }
}


static int
do_sign( PKT_secret_key *sk, PKT_signature *sig,
	 MD_HANDLE md, int digest_algo )
{
    MPI frame;
    byte *dp;
    int rc;

    if( sk->timestamp > sig->timestamp ) {
	ulong d = sk->timestamp - sig->timestamp;
	log_info( d==1 ? _("key has been created %lu second "
			   "in future (time warp or clock problem)\n")
		       : _("key has been created %lu seconds "
			   "in future (time warp or clock problem)\n"), d );
	if( !opt.ignore_time_conflict )
	    return G10ERR_TIME_CONFLICT;
    }


    print_pubkey_algo_note(sk->pubkey_algo);

    if( !digest_algo )
	digest_algo = md_get_algo(md);

    print_digest_algo_note( digest_algo );
    dp = md_read( md, digest_algo );
    sig->digest_algo = digest_algo;
    sig->digest_start[0] = dp[0];
    sig->digest_start[1] = dp[1];
    if (sk->is_protected && sk->protect.s2k.mode == 1002) 
      { 
#ifdef ENABLE_CARD_SUPPORT
        unsigned char *rbuf;
        size_t rbuflen;
        char *snbuf;
        
        snbuf = serialno_and_fpr_from_sk (sk->protect.iv,
                                          sk->protect.ivlen, sk);
        rc = agent_scd_pksign (snbuf, digest_algo,
                               md_read (md, digest_algo),
                               md_digest_length (digest_algo),
                               &rbuf, &rbuflen);
        xfree (snbuf);
        if (!rc)
          {
            sig->data[0] = mpi_alloc ( mpi_nlimb_hint_from_nbytes (rbuflen) );
            mpi_set_buffer (sig->data[0], rbuf, rbuflen, 0);
            xfree (rbuf);
          }
#else
        return G10ERR_UNSUPPORTED;
#endif /* ENABLE_CARD_SUPPORT */
      }
    else 
      {
        frame = encode_md_value( NULL, sk, md, digest_algo );
        if (!frame)
          return G10ERR_GENERAL;
        rc = pubkey_sign( sk->pubkey_algo, sig->data, frame, sk->skey );
        mpi_free(frame);
      }

    if (!rc && !opt.no_sig_create_check) {
        /* check that the signature verification worked and nothing is
         * fooling us e.g. by a bug in the signature create
         * code or by deliberately introduced faults. */
        PKT_public_key *pk = xmalloc_clear (sizeof *pk);

        if( get_pubkey( pk, sig->keyid ) )
            rc = G10ERR_NO_PUBKEY;
        else {
	    frame = encode_md_value (pk, NULL, md, sig->digest_algo );
            if (!frame)
                rc = G10ERR_GENERAL;
            else
                rc = pubkey_verify (pk->pubkey_algo, frame,
                                    sig->data, pk->pkey );
            mpi_free (frame);
        }
        if (rc)
            log_error (_("checking created signature failed: %s\n"),
                         g10_errstr (rc));
        free_public_key (pk);
    }
    if( rc )
	log_error(_("signing failed: %s\n"), g10_errstr(rc) );
    else {
	if( opt.verbose ) {
	    char *ustr = get_user_id_string_native (sig->keyid);
	    log_info(_("%s/%s signature from: \"%s\"\n"),
		     pubkey_algo_to_string(sk->pubkey_algo),
		     digest_algo_to_string(sig->digest_algo),
		     ustr );
	    xfree(ustr);
	}
    }
    return rc;
}


int
complete_sig( PKT_signature *sig, PKT_secret_key *sk, MD_HANDLE md )
{
    int rc=0;

    if( !(rc=check_secret_key( sk, 0 )) )
	rc = do_sign( sk, sig, md, 0 );
    return rc;
}

static int
match_dsa_hash(unsigned int qbytes)
{
  if(qbytes<=20)
    return DIGEST_ALGO_SHA1;
#ifdef USE_SHA256
  if(qbytes<=28)
    return DIGEST_ALGO_SHA224;
  if(qbytes<=32)
    return DIGEST_ALGO_SHA256;
#endif
#ifdef USE_SHA512
  if(qbytes<=48)
    return DIGEST_ALGO_SHA384;
  if(qbytes<=64)
    return DIGEST_ALGO_SHA512;
#endif
  return DEFAULT_DIGEST_ALGO;
  /* DEFAULT_DIGEST_ALGO will certainly fail, but it's the best wrong
     answer we have if the larger SHAs aren't there. */
}


/*
  First try --digest-algo.  If that isn't set, see if the recipient
  has a preferred algorithm (which is also filtered through
  --preferred-digest-prefs).  If we're making a signature without a
  particular recipient (i.e. signing, rather than signing+encrypting)
  then take the first algorithm in --preferred-digest-prefs that is
  usable for the pubkey algorithm.  If --preferred-digest-prefs isn't
  set, then take the OpenPGP default (i.e. SHA-1).

  Possible improvement: Use the highest-ranked usable algorithm from
  the signing key prefs either before or after using the personal
  list?
*/

static int
hash_for(PKT_secret_key *sk)
{
  if( opt.def_digest_algo )
    return opt.def_digest_algo;
  else if( recipient_digest_algo )
    return recipient_digest_algo;
  else if(sk->pubkey_algo==PUBKEY_ALGO_DSA)
    {
      unsigned int qbytes=mpi_get_nbits(sk->skey[1])/8;

      /* It's a DSA key, so find a hash that is the same size as q or
	 larger.  If q is 160, assume it is an old DSA key and use a
	 160-bit hash unless --enable-dsa2 is set, in which case act
	 like a new DSA key that just happens to have a 160-bit q
	 (i.e. allow truncation).  If q is not 160, by definition it
	 must be a new DSA key. */

      if(opt.personal_digest_prefs)
	{
	  prefitem_t *prefs;

	  if(qbytes!=20 || opt.flags.dsa2)
	    {
	      for(prefs=opt.personal_digest_prefs;prefs->type;prefs++)
		if(md_digest_length(prefs->value)>=qbytes)
		  return prefs->value;
	    }
	  else
	    {
	      for(prefs=opt.personal_digest_prefs;prefs->type;prefs++)
		if(md_digest_length(prefs->value)==qbytes)
		  return prefs->value;
	    }
	}

      return match_dsa_hash(qbytes);
    }
  else if(sk->is_protected && sk->protect.s2k.mode==1002)
    {
      /* The sk lives on a smartcard, and current smartcards only
	 handle SHA-1 and RIPEMD/160.  This is correct now, but may
	 need revision as the cards add algorithms. */

      if(opt.personal_digest_prefs)
	{
	  prefitem_t *prefs;

	  for(prefs=opt.personal_digest_prefs;prefs->type;prefs++)
	    if(prefs->value==DIGEST_ALGO_SHA1
	       || prefs->value==DIGEST_ALGO_RMD160)
	      return prefs->value;
	}

      return DIGEST_ALGO_SHA1;
    }
  else if(PGP2 && sk->pubkey_algo == PUBKEY_ALGO_RSA && sk->version < 4 )
    {
      /* Old-style PGP only understands MD5 */
      return DIGEST_ALGO_MD5;
    }
  else if( opt.personal_digest_prefs )
    {
      /* It's not DSA, so we can use whatever the first hash algorithm
	 is in the pref list */
      return opt.personal_digest_prefs[0].value;
    }
  else
    return DEFAULT_DIGEST_ALGO;
}

static int
only_old_style( SK_LIST sk_list )
{
    SK_LIST sk_rover = NULL;
    int old_style = 0;

    /* if there are only old style capable key we use the old sytle */
    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	PKT_secret_key *sk = sk_rover->sk;
	if( sk->pubkey_algo == PUBKEY_ALGO_RSA && sk->version < 4 )
	    old_style = 1;
	else
	    return 0;
    }
    return old_style;
}


static void
print_status_sig_created ( PKT_secret_key *sk, PKT_signature *sig, int what )
{
    byte array[MAX_FINGERPRINT_LEN], *p;
    char buf[100+MAX_FINGERPRINT_LEN*2];
    size_t i, n;

    sprintf(buf, "%c %d %d %02x %lu ",
	    what, sig->pubkey_algo, sig->digest_algo, sig->sig_class,
	    (ulong)sig->timestamp );

    fingerprint_from_sk( sk, array, &n );
    p = buf + strlen(buf);
    for(i=0; i < n ; i++ )
	sprintf(p+2*i, "%02X", array[i] );

    write_status_text( STATUS_SIG_CREATED, buf );
}


/*
 * Loop over the secret certificates in SK_LIST and build the one pass
 * signature packets.  OpenPGP says that the data should be bracket by
 * the onepass-sig and signature-packet; so we build these onepass
 * packet here in reverse order 
 */
static int
write_onepass_sig_packets (SK_LIST sk_list, IOBUF out, int sigclass )
{
    int skcount;
    SK_LIST sk_rover;

    for (skcount=0, sk_rover=sk_list; sk_rover; sk_rover = sk_rover->next)
        skcount++;

    for (; skcount; skcount--) {
        PKT_secret_key *sk;
        PKT_onepass_sig *ops;
        PACKET pkt;
        int i, rc;
        
        for (i=0, sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
            if (++i == skcount)
                break;
        }

        sk = sk_rover->sk;
        ops = xmalloc_clear (sizeof *ops);
        ops->sig_class = sigclass;
        ops->digest_algo = hash_for (sk);
        ops->pubkey_algo = sk->pubkey_algo;
        keyid_from_sk (sk, ops->keyid);
        ops->last = (skcount == 1);
        
        init_packet(&pkt);
        pkt.pkttype = PKT_ONEPASS_SIG;
        pkt.pkt.onepass_sig = ops;
        rc = build_packet (out, &pkt);
        free_packet (&pkt);
        if (rc) {
            log_error ("build onepass_sig packet failed: %s\n",
                       g10_errstr(rc));
            return rc;
        }
    }

    return 0;
}

/*
 * Helper to write the plaintext (literal data) packet
 */
static int
write_plaintext_packet (IOBUF out, IOBUF inp, const char *fname,
			int ptmode, u32 timestamp)
{
    PKT_plaintext *pt = NULL;
    u32 filesize;
    int rc = 0;

    if (!opt.no_literal)
      pt=setup_plaintext_name(fname,inp);

    /* try to calculate the length of the data */
    if ( !iobuf_is_pipe_filename (fname) && *fname )
      {
        off_t tmpsize;
        int overflow;

        if( !(tmpsize = iobuf_get_filelength(inp, &overflow))
            && !overflow )
	  log_info (_("WARNING: `%s' is an empty file\n"), fname);

        /* We can't encode the length of very large files because
           OpenPGP uses only 32 bit for file sizes.  So if the size of
           a file is larger than 2^32 minus some bytes for packet
           headers, we switch to partial length encoding. */
        if ( tmpsize < (IOBUF_FILELENGTH_LIMIT - 65536) )
          filesize = tmpsize;
        else
          filesize = 0;

        /* Because the text_filter modifies the length of the
         * data, it is not possible to know the used length
         * without a double read of the file - to avoid that
         * we simple use partial length packets. */
        if ( ptmode == 't' )
	  filesize = 0;
      }
    else
      filesize = opt.set_filesize? opt.set_filesize : 0; /* stdin */

    if (!opt.no_literal) {
        PACKET pkt;

        pt->timestamp = timestamp;
        pt->mode = ptmode;
        pt->len = filesize;
        pt->new_ctb = !pt->len && !RFC1991;
        pt->buf = inp;
        init_packet(&pkt);
        pkt.pkttype = PKT_PLAINTEXT;
        pkt.pkt.plaintext = pt;
        /*cfx.datalen = filesize? calc_packet_length( &pkt ) : 0;*/
        if( (rc = build_packet (out, &pkt)) )
            log_error ("build_packet(PLAINTEXT) failed: %s\n",
                       g10_errstr(rc) );
        pt->buf = NULL;
    }
    else {
        byte copy_buffer[4096];
        int  bytes_copied;

        while ((bytes_copied = iobuf_read(inp, copy_buffer, 4096)) != -1)
            if (iobuf_write(out, copy_buffer, bytes_copied) == -1) {
                rc = G10ERR_WRITE_FILE;
                log_error ("copying input to output failed: %s\n",
                           g10_errstr(rc));
                break;
            }
        wipememory(copy_buffer,4096); /* burn buffer */
    }
    /* fixme: it seems that we never freed pt/pkt */
    
    return rc;
}

/*
 * Write the signatures from the SK_LIST to OUT. HASH must be a non-finalized
 * hash which will not be changes here.
 */
static int
write_signature_packets (SK_LIST sk_list, IOBUF out, MD_HANDLE hash,
                         int sigclass, u32 timestamp, u32 duration,
			 int status_letter)
{
    SK_LIST sk_rover;

    /* loop over the secret certificates */
    for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next) {
	PKT_secret_key *sk;
	PKT_signature *sig;
	MD_HANDLE md;
        int rc;

	sk = sk_rover->sk;

	/* build the signature packet */
	sig = xmalloc_clear (sizeof *sig);
	if(opt.force_v3_sigs || RFC1991)
	  sig->version=3;
	else if(duration || opt.sig_policy_url
		|| opt.sig_notations || opt.sig_keyserver_url)
	  sig->version=4;
	else
	  sig->version=sk->version;
	keyid_from_sk (sk, sig->keyid);
	sig->digest_algo = hash_for(sk);
	sig->pubkey_algo = sk->pubkey_algo;
	if(timestamp)
	  sig->timestamp = timestamp;
	else
	  sig->timestamp = make_timestamp();
	if(duration)
	  sig->expiredate = sig->timestamp+duration;
	sig->sig_class = sigclass;

	md = md_copy (hash);

	if (sig->version >= 4)
	  {
	    build_sig_subpkt_from_sig (sig);
	    mk_notation_policy_etc (sig, NULL, sk);
	  }

        hash_sigversion_to_magic (md, sig);
	md_final (md);

	rc = do_sign( sk, sig, md, hash_for (sk) );
	md_close (md);

	if( !rc ) { /* and write it */
            PACKET pkt;

	    init_packet(&pkt);
	    pkt.pkttype = PKT_SIGNATURE;
	    pkt.pkt.signature = sig;
	    rc = build_packet (out, &pkt);
	    if (!rc && is_status_enabled()) {
		print_status_sig_created ( sk, sig, status_letter);
	    }
	    free_packet (&pkt);
	    if (rc)
		log_error ("build signature packet failed: %s\n",
                           g10_errstr(rc) );
	}
	if( rc )
	    return rc;;
    }

    return 0;
}

/****************
 * Sign the files whose names are in FILENAME.
 * If DETACHED has the value true,
 * make a detached signature.  If FILENAMES->d is NULL read from stdin
 * and ignore the detached mode.  Sign the file with all secret keys
 * which can be taken from LOCUSR, if this is NULL, use the default one
 * If ENCRYPTFLAG is true, use REMUSER (or ask if it is NULL) to encrypt the
 * signed data for these users.
 * If OUTFILE is not NULL; this file is used for output and the function
 * does not ask for overwrite permission; output is then always
 * uncompressed, non-armored and in binary mode.
 */
int
sign_file( STRLIST filenames, int detached, STRLIST locusr,
	   int encryptflag, STRLIST remusr, const char *outfile )
{
    const char *fname;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    md_filter_context_t mfx;
    text_filter_context_t tfx;
    progress_filter_context_t pfx;
    encrypt_filter_context_t efx;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    int rc = 0;
    PK_LIST pk_list = NULL;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    int multifile = 0;
    u32 create_time=make_timestamp(),duration=0;

    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &mfx, 0, sizeof mfx);
    memset( &efx, 0, sizeof efx);
    init_packet( &pkt );

    if( filenames ) {
	fname = filenames->d;
	multifile = !!filenames->next;
    }
    else
	fname = NULL;

    if( fname && filenames->next && (!detached || encryptflag) )
	log_bug("multiple files can only be detached signed");

    if(encryptflag==2
       && (rc=setup_symkey(&efx.symkey_s2k,&efx.symkey_dek)))
      goto leave;

    if(!opt.force_v3_sigs && !RFC1991)
      {
	if(opt.ask_sig_expire && !opt.batch)
	  duration=ask_expire_interval(create_time,1,opt.def_sig_expire);
	else
	  duration=parse_expire_string(create_time,opt.def_sig_expire);
      }

    if( (rc=build_sk_list( locusr, &sk_list, 1, PUBKEY_USAGE_SIG )) )
	goto leave;

    if(PGP2 && !only_old_style(sk_list))
      {
	log_info(_("you can only detach-sign with PGP 2.x style keys "
		   "while in --pgp2 mode\n"));
	compliance_failure();
      }

    if(encryptflag && (rc=build_pk_list( remusr, &pk_list, PUBKEY_USAGE_ENC )))
      goto leave;

    /* prepare iobufs */
    if( multifile )  /* have list of filenames */
	inp = NULL; /* we do it later */
    else {
      inp = iobuf_open(fname);
      if (inp && is_secured_file (iobuf_get_fd (inp)))
        {
          iobuf_close (inp);
          inp = NULL;
          errno = EPERM;
        }
      if( !inp ) {
	    log_error(_("can't open `%s': %s\n"), fname? fname: "[stdin]",
		      strerror(errno) );
	    rc = G10ERR_OPEN_FILE;
	    goto leave;
	}

        handle_progress (&pfx, inp, fname);
    }

    if( outfile ) {
        if (is_secured_filename ( outfile )) {
            out = NULL;
            errno = EPERM;
        }
        else
            out = iobuf_create( outfile );
	if( !out )
	  {
	    log_error(_("can't create `%s': %s\n"), outfile, strerror(errno) );
	    rc = G10ERR_CREATE_FILE;
	    goto leave;
	  }
	else if( opt.verbose )
	    log_info(_("writing to `%s'\n"), outfile );
    }
    else if( (rc = open_outfile( fname, opt.armor? 1: detached? 2:0, &out )))
	goto leave;

    /* prepare to calculate the MD over the input */
    if( opt.textmode && !outfile && !multifile )
      {
	memset( &tfx, 0, sizeof tfx);
	iobuf_push_filter( inp, text_filter, &tfx );
      }

    mfx.md = md_open(0, 0);
    if (DBG_HASHING)
	md_start_debug (mfx.md, "sign");

    /* If we're encrypting and signing, it is reasonable to pick the
       hash algorithm to use out of the recepient key prefs.  This is
       best effort only, as in a DSA2 and smartcard world there are
       cases where we cannot please everyone with a single hash (DSA2
       wants >160 and smartcards want =160).  In the future this could
       be more complex with different hashes for each sk, but the
       current design requires a single hash for all SKs. */
    if(pk_list)
      {
	if(opt.def_digest_algo)
	  {
	    if(!opt.expert &&
	       select_algo_from_prefs(pk_list,PREFTYPE_HASH,
				      opt.def_digest_algo,
				      NULL)!=opt.def_digest_algo)
	  log_info(_("WARNING: forcing digest algorithm %s (%d)"
		     " violates recipient preferences\n"),
		   digest_algo_to_string(opt.def_digest_algo),
		   opt.def_digest_algo);
	  }
	else
	  {
	    union pref_hint hint;
	    int algo,smartcard=0;

	    hint.digest_length=0;

	    /* Of course, if the recipient asks for something
	       unreasonable (like the wrong hash for a DSA key) then
	       don't do it.  Check all sk's - if any are DSA or live
	       on a smartcard, then the hash has restrictions and we
	       may not be able to give the recipient what they want.
	       For DSA, pass a hint for the largest q we have.  Note
	       that this means that a q>160 key will override a q=160
	       key and force the use of truncation for the q=160 key.
	       The alternative would be to ignore the recipient prefs
	       completely and get a different hash for each DSA key in
	       hash_for().  The override behavior here is more or less
	       reasonable as it is under the control of the user which
	       keys they sign with for a given message and the fact
	       that the message with multiple signatures won't be
	       usable on an implementation that doesn't understand
	       DSA2 anyway. */

	    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next )
	      {
		if(sk_rover->sk->pubkey_algo==PUBKEY_ALGO_DSA)
		  {
		    int temp_hashlen=mpi_get_nbits(sk_rover->sk->skey[1])/8;

		    /* Pick a hash that is large enough for our
		       largest q */

		    if(hint.digest_length<temp_hashlen)
		      hint.digest_length=temp_hashlen;
		  }
		else if(sk_rover->sk->is_protected
			&& sk_rover->sk->protect.s2k.mode==1002)
		  smartcard=1;
	      }

	    /* Current smartcards only do 160-bit hashes.  If we have
	       to have a >160-bit hash, then we can't use the
	       recipient prefs as we'd need both =160 and >160 at the
	       same time and recipient prefs currently require a
	       single hash for all signatures.  All this may well have
	       to change as the cards add algorithms. */

	    if(!smartcard || (smartcard && hint.digest_length==20))
	      if((algo=
		  select_algo_from_prefs(pk_list,PREFTYPE_HASH,-1,&hint))>0)
		recipient_digest_algo=algo;
	  }
      }

    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	PKT_secret_key *sk = sk_rover->sk;
	md_enable(mfx.md, hash_for(sk));
    }

    if( !multifile )
	iobuf_push_filter( inp, md_filter, &mfx );

    if( detached && !encryptflag && !RFC1991 )
	afx.what = 2;

    if( opt.armor && !outfile  )
	iobuf_push_filter( out, armor_filter, &afx );

    if( encryptflag ) {
	efx.pk_list = pk_list;
	/* fixme: set efx.cfx.datalen if known */
	iobuf_push_filter( out, encrypt_filter, &efx );
    }

    if( opt.compress_algo && !outfile && ( !detached || opt.compress_sigs) )
      {
        int compr_algo=opt.compress_algo;

	/* If not forced by user */
	if(compr_algo==-1)
	  {
	    /* If we're not encrypting, then select_algo_from_prefs
	       will fail and we'll end up with the default.  If we are
	       encrypting, select_algo_from_prefs cannot fail since
	       there is an assumed preference for uncompressed data.
	       Still, if it did fail, we'll also end up with the
	       default. */
 
	    if((compr_algo=
		select_algo_from_prefs(pk_list,PREFTYPE_ZIP,-1,NULL))==-1)
	      compr_algo=default_compress_algo();
	  }
 	else if(!opt.expert && pk_list
 		&& select_algo_from_prefs(pk_list,PREFTYPE_ZIP,
					  compr_algo,NULL)!=compr_algo)
 	  log_info(_("WARNING: forcing compression algorithm %s (%d)"
 		     " violates recipient preferences\n"),
 		   compress_algo_to_string(compr_algo),compr_algo);

	/* algo 0 means no compression */
	if( compr_algo )
	  push_compress_filter(out,&zfx,compr_algo);
      }

    /* Write the one-pass signature packets if needed */
    if (!detached && !RFC1991) {
        rc = write_onepass_sig_packets (sk_list, out,
                                        opt.textmode && !outfile ? 0x01:0x00);
        if (rc)
            goto leave;
    }

    write_status (STATUS_BEGIN_SIGNING);

    /* Setup the inner packet. */
    if( detached ) {
	if( multifile ) {
	    STRLIST sl;

	    if( opt.verbose )
		log_info(_("signing:") );
	    /* must walk reverse trough this list */
	    for( sl = strlist_last(filenames); sl;
			sl = strlist_prev( filenames, sl ) ) {
                inp = iobuf_open(sl->d);
                if (inp && is_secured_file (iobuf_get_fd (inp)))
                  {
                    iobuf_close (inp);
                    inp = NULL;
                    errno = EPERM;
                  }
		if( !inp )
		  {
		    log_error(_("can't open `%s': %s\n"),
			      sl->d,strerror(errno));
		    rc = G10ERR_OPEN_FILE;
		    goto leave;
		  }
                handle_progress (&pfx, inp, sl->d);
		if( opt.verbose )
		    fprintf(stderr, " `%s'", sl->d );
		if(opt.textmode)
		  {
		    memset( &tfx, 0, sizeof tfx);
		    iobuf_push_filter( inp, text_filter, &tfx );
		  }
		iobuf_push_filter( inp, md_filter, &mfx );
		while( iobuf_get(inp) != -1 )
		    ;
		iobuf_close(inp); inp = NULL;
	    }
	    if( opt.verbose )
		putc( '\n', stderr );
	}
	else {
	    /* read, so that the filter can calculate the digest */
	    while( iobuf_get(inp) != -1 )
		;
	}
    }
    else {
        rc = write_plaintext_packet (out, inp, fname,
                                     opt.textmode && !outfile ? 't':'b',
				     create_time);
    }

    /* catch errors from above */
    if (rc)
	goto leave;

    /* write the signatures */
    rc = write_signature_packets (sk_list, out, mfx.md,
                                  opt.textmode && !outfile? 0x01 : 0x00,
				  create_time, duration, detached ? 'D':'S');
    if( rc )
        goto leave;


  leave:
    if( rc )
	iobuf_cancel(out);
    else {
	iobuf_close(out);
        if (encryptflag)
            write_status( STATUS_END_ENCRYPTION );
    }
    iobuf_close(inp);
    md_close( mfx.md );
    release_sk_list( sk_list );
    release_pk_list( pk_list );
    recipient_digest_algo=0;
    return rc;
}



/****************
 * make a clear signature. note that opt.armor is not needed
 */
int
clearsign_file( const char *fname, STRLIST locusr, const char *outfile )
{
    armor_filter_context_t afx;
    progress_filter_context_t pfx;
    MD_HANDLE textmd = NULL;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    int rc = 0;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    int old_style = RFC1991;
    int only_md5 = 0;
    u32 create_time=make_timestamp(),duration=0;

    memset( &afx, 0, sizeof afx);
    init_packet( &pkt );

    if(!opt.force_v3_sigs && !RFC1991)
      {
	if(opt.ask_sig_expire && !opt.batch)
	  duration=ask_expire_interval(create_time,1,opt.def_sig_expire);
	else
	  duration=parse_expire_string(create_time,opt.def_sig_expire);
      }

    if( (rc=build_sk_list( locusr, &sk_list, 1, PUBKEY_USAGE_SIG )) )
	goto leave;

    if( !old_style && !duration )
	old_style = only_old_style( sk_list );

    if(PGP2 && !only_old_style(sk_list))
      {
	log_info(_("you can only clearsign with PGP 2.x style keys "
		   "while in --pgp2 mode\n"));
	compliance_failure();
      }

    /* prepare iobufs */
    inp = iobuf_open(fname);
    if (inp && is_secured_file (iobuf_get_fd (inp)))
      {
        iobuf_close (inp);
        inp = NULL;
        errno = EPERM;
      }
    if( !inp ) {
	log_error(_("can't open `%s': %s\n"), fname? fname: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }
    handle_progress (&pfx, inp, fname);

    if( outfile ) {
        if (is_secured_filename (outfile) ) {
            outfile = NULL;
            errno = EPERM;
        }
        else 
            out = iobuf_create( outfile );
	if( !out )
	  {
	    log_error(_("can't create `%s': %s\n"), outfile, strerror(errno) );
	    rc = G10ERR_CREATE_FILE;
	    goto leave;
	  }
	else if( opt.verbose )
	    log_info(_("writing to `%s'\n"), outfile );
    }
    else if( (rc = open_outfile( fname, 1, &out )) )
	goto leave;

    iobuf_writestr(out, "-----BEGIN PGP SIGNED MESSAGE-----" LF );

    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	PKT_secret_key *sk = sk_rover->sk;
	if( hash_for(sk) == DIGEST_ALGO_MD5 )
	    only_md5 = 1;
	else {
	    only_md5 = 0;
	    break;
	}
    }

    if( !(old_style && only_md5) ) {
	const char *s;
	int any = 0;
	byte hashs_seen[256];

	memset( hashs_seen, 0, sizeof hashs_seen );
	iobuf_writestr(out, "Hash: " );
	for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	    PKT_secret_key *sk = sk_rover->sk;
	    int i = hash_for(sk);

	    if( !hashs_seen[ i & 0xff ] ) {
		s = digest_algo_to_string( i );
		if( s ) {
		    hashs_seen[ i & 0xff ] = 1;
		    if( any )
			iobuf_put(out, ',' );
		    iobuf_writestr(out, s );
		    any = 1;
		}
	    }
	}
	assert(any);
	iobuf_writestr(out, LF );
    }

    if( opt.not_dash_escaped )
      iobuf_writestr( out,
		  "NotDashEscaped: You need GnuPG to verify this message" LF );
    iobuf_writestr(out, LF );

    textmd = md_open(0, 0);
    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	PKT_secret_key *sk = sk_rover->sk;
	md_enable(textmd, hash_for(sk));
    }
    if ( DBG_HASHING )
	md_start_debug( textmd, "clearsign" );
    copy_clearsig_text( out, inp, textmd, !opt.not_dash_escaped,
			opt.escape_from, (old_style && only_md5) );
    /* fixme: check for read errors */

    /* now write the armor */
    afx.what = 2;
    iobuf_push_filter( out, armor_filter, &afx );

    /* write the signatures */
    rc=write_signature_packets (sk_list, out, textmd, 0x01,
				create_time, duration, 'C');
    if( rc )
        goto leave;

  leave:
    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    iobuf_close(inp);
    md_close( textmd );
    release_sk_list( sk_list );
    return rc;
}

/*
 * Sign and conventionally encrypt the given file.
 * FIXME: Far too much code is duplicated - revamp the whole file.
 */
int
sign_symencrypt_file (const char *fname, STRLIST locusr)
{
    armor_filter_context_t afx;
    progress_filter_context_t pfx;
    compress_filter_context_t zfx;
    md_filter_context_t mfx;
    text_filter_context_t tfx;
    cipher_filter_context_t cfx;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    STRING2KEY *s2k = NULL;
    int rc = 0;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    int algo;
    u32 create_time=make_timestamp(),duration=0;

    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &mfx, 0, sizeof mfx);
    memset( &tfx, 0, sizeof tfx);
    memset( &cfx, 0, sizeof cfx);
    init_packet( &pkt );

    if(!opt.force_v3_sigs && !RFC1991)
      {
	if(opt.ask_sig_expire && !opt.batch)
	  duration=ask_expire_interval(create_time,1,opt.def_sig_expire);
	else
	  duration=parse_expire_string(create_time,opt.def_sig_expire);
      }

    rc = build_sk_list (locusr, &sk_list, 1, PUBKEY_USAGE_SIG);
    if (rc) 
	goto leave;

    /* prepare iobufs */
    inp = iobuf_open(fname);
    if (inp && is_secured_file (iobuf_get_fd (inp)))
      {
        iobuf_close (inp);
        inp = NULL;
        errno = EPERM;
      }
    if( !inp ) {
	log_error(_("can't open `%s': %s\n"), 
                  fname? fname: "[stdin]", strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }
    handle_progress (&pfx, inp, fname);

    /* prepare key */
    s2k = xmalloc_clear( sizeof *s2k );
    s2k->mode = RFC1991? 0:opt.s2k_mode;
    s2k->hash_algo = S2K_DIGEST_ALGO;

    algo = default_cipher_algo();
    if (!opt.quiet || !opt.batch)
        log_info (_("%s encryption will be used\n"),
		    cipher_algo_to_string(algo) );
    cfx.dek = passphrase_to_dek( NULL, 0, algo, s2k, 2, NULL, NULL);

    if (!cfx.dek || !cfx.dek->keylen) {
        rc = G10ERR_PASSPHRASE;
        log_error(_("error creating passphrase: %s\n"), g10_errstr(rc) );
        goto leave;
    }

    /* We have no way to tell if the recipient can handle messages
       with an MDC, so this defaults to no.  Perhaps in a few years,
       this can be defaulted to yes.  Note that like regular
       encrypting, --force-mdc overrides --disable-mdc. */
    if(opt.force_mdc)
      cfx.dek->use_mdc=1;

    /* now create the outfile */
    rc = open_outfile (fname, opt.armor? 1:0, &out);
    if (rc)
	goto leave;

    /* prepare to calculate the MD over the input */
    if (opt.textmode)
	iobuf_push_filter (inp, text_filter, &tfx);
    mfx.md = md_open(0, 0);
    if ( DBG_HASHING )
	md_start_debug (mfx.md, "symc-sign");

    for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next) {
	PKT_secret_key *sk = sk_rover->sk;
	md_enable (mfx.md, hash_for (sk));
    }

    iobuf_push_filter (inp, md_filter, &mfx);

    /* Push armor output filter */
    if (opt.armor)
	iobuf_push_filter (out, armor_filter, &afx);

    /* Write the symmetric key packet */
    /*(current filters: armor)*/
    if (!RFC1991) {
	PKT_symkey_enc *enc = xmalloc_clear( sizeof *enc );
	enc->version = 4;
	enc->cipher_algo = cfx.dek->algo;
	enc->s2k = *s2k;
	pkt.pkttype = PKT_SYMKEY_ENC;
	pkt.pkt.symkey_enc = enc;
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build symkey packet failed: %s\n", g10_errstr(rc) );
	xfree(enc);
    }

    /* Push the encryption filter */
    iobuf_push_filter( out, cipher_filter, &cfx );

    /* Push the compress filter */
    if (default_compress_algo())
      push_compress_filter(out,&zfx,default_compress_algo());

    /* Write the one-pass signature packets */
    /*(current filters: zip - encrypt - armor)*/
    if (!RFC1991) {
        rc = write_onepass_sig_packets (sk_list, out,
                                        opt.textmode? 0x01:0x00);
        if (rc)
            goto leave;
    }

    write_status (STATUS_BEGIN_SIGNING);

    /* Pipe data through all filters; i.e. write the signed stuff */
    /*(current filters: zip - encrypt - armor)*/
    rc = write_plaintext_packet (out, inp, fname, opt.textmode ? 't':'b',
				 create_time);
    if (rc)
	goto leave;
    
    /* Write the signatures */
    /*(current filters: zip - encrypt - armor)*/
    rc = write_signature_packets (sk_list, out, mfx.md,
				  opt.textmode? 0x01 : 0x00,
				  create_time, duration, 'S');
    if( rc )
        goto leave;


  leave:
    if( rc )
	iobuf_cancel(out);
    else {
	iobuf_close(out);
        write_status( STATUS_END_ENCRYPTION );
    }
    iobuf_close(inp);
    release_sk_list( sk_list );
    md_close( mfx.md );
    xfree(cfx.dek);
    xfree(s2k);
    return rc;
}


/****************
 * Create a signature packet for the given public key certificate and
 * the user id and return it in ret_sig. User signature class SIGCLASS
 * user-id is not used (and may be NULL if sigclass is 0x20) If
 * DIGEST_ALGO is 0 the function selects an appropriate one.
 * SIGVERSION gives the minimal required signature packet version;
 * this is needed so that special properties like local sign are not
 * applied (actually: dropped) when a v3 key is used.  TIMESTAMP is
 * the timestamp to use for the signature. 0 means "now" */
int
make_keysig_packet( PKT_signature **ret_sig, PKT_public_key *pk,
		    PKT_user_id *uid, PKT_public_key *subpk,
		    PKT_secret_key *sk,
		    int sigclass, int digest_algo,
                    int sigversion, u32 timestamp, u32 duration,
		    int (*mksubpkt)(PKT_signature *, void *), void *opaque
		   )
{
    PKT_signature *sig;
    int rc=0;
    MD_HANDLE md;

    assert( (sigclass >= 0x10 && sigclass <= 0x13) || sigclass == 0x1F
	    || sigclass == 0x20 || sigclass == 0x18 || sigclass == 0x19
	    || sigclass == 0x30 || sigclass == 0x28 );

    if (opt.force_v4_certs)
        sigversion = 4;

    if (sigversion < sk->version)
        sigversion = sk->version;

    /* If you are making a signature on a v4 key using your v3 key, it
       doesn't make sense to generate a v3 sig.  After all, no v3-only
       PGP implementation could understand the v4 key in the first
       place.  Note that this implies that a signature on an attribute
       uid is usually going to be v4 as well, since they are not
       generally found on v3 keys. */
    if (sigversion < pk->version)
        sigversion = pk->version;

    if( !digest_algo )
      {
	/* Basically, this means use SHA1 always unless it's a v3 RSA
	   key making a v3 cert (use MD5), or the user specified
	   something (use whatever they said), or it's DSA (use the
	   best match).  They still can't pick an inappropriate hash
	   for DSA or the signature will fail.  Note that this still
	   allows the caller of make_keysig_packet to override the
	   user setting if it must. */

	if(opt.cert_digest_algo)
	  digest_algo=opt.cert_digest_algo;
	else if(sk->pubkey_algo==PUBKEY_ALGO_RSA
		&& pk->version<4 && sigversion<4)
	  digest_algo = DIGEST_ALGO_MD5;
	else if(sk->pubkey_algo==PUBKEY_ALGO_DSA)
	  digest_algo = match_dsa_hash(mpi_get_nbits(sk->skey[1])/8);
	else
	  digest_algo = DIGEST_ALGO_SHA1;
      }

    md = md_open( digest_algo, 0 );

    /* hash the public key certificate */
    hash_public_key( md, pk );

    if( sigclass == 0x18 || sigclass == 0x19 || sigclass == 0x28 )
      {
	/* hash the subkey binding/backsig/revocation */
	hash_public_key( md, subpk );
      }
    else if( sigclass != 0x1F && sigclass != 0x20 )
      {
	/* hash the user id */
        hash_uid (md, sigversion, uid);
      }
    /* and make the signature packet */
    sig = xmalloc_clear( sizeof *sig );
    sig->version = sigversion;
    sig->flags.exportable=1;
    sig->flags.revocable=1;
    keyid_from_sk( sk, sig->keyid );
    sig->pubkey_algo = sk->pubkey_algo;
    sig->digest_algo = digest_algo;
    if(timestamp)
      sig->timestamp=timestamp;
    else
      sig->timestamp=make_timestamp();
    if(duration)
      sig->expiredate=sig->timestamp+duration;
    sig->sig_class = sigclass;
    if( sig->version >= 4 )
      {
	build_sig_subpkt_from_sig( sig );
	mk_notation_policy_etc( sig, pk, sk );
      }

    /* Crucial that the call to mksubpkt comes LAST before the calls
       to finalize the sig as that makes it possible for the mksubpkt
       function to get a reliable pointer to the subpacket area. */
    if( sig->version >= 4 && mksubpkt )
	rc = (*mksubpkt)( sig, opaque );

    if( !rc ) {
        hash_sigversion_to_magic (md, sig);
	md_final(md);

	rc = complete_sig( sig, sk, md );
    }

    md_close( md );
    if( rc )
	free_seckey_enc( sig );
    else
	*ret_sig = sig;
    return rc;
}



/****************
 * Create a new signature packet based on an existing one.
 * Only user ID signatures are supported for now.
 * TODO: Merge this with make_keysig_packet.
 */
int
update_keysig_packet( PKT_signature **ret_sig,
                      PKT_signature *orig_sig,
                      PKT_public_key *pk,
                      PKT_user_id *uid, 
                      PKT_public_key *subpk,
                      PKT_secret_key *sk,
                      int (*mksubpkt)(PKT_signature *, void *),
                      void *opaque )
{
    PKT_signature *sig;
    int rc=0;
    MD_HANDLE md;

    if ((!orig_sig || !pk || !sk)
	|| (orig_sig->sig_class >= 0x10 && orig_sig->sig_class <= 0x13 && !uid)
	|| (orig_sig->sig_class == 0x18 && !subpk))
      return G10ERR_GENERAL;

    md = md_open( orig_sig->digest_algo, 0 );

    /* hash the public key certificate and the user id */
    hash_public_key( md, pk );

    if( orig_sig->sig_class == 0x18 )
      hash_public_key( md, subpk );
    else
      hash_uid (md, orig_sig->version, uid);

    /* create a new signature packet */
    sig = copy_signature (NULL, orig_sig);
 
    /* We need to create a new timestamp so that new sig expiration
       calculations are done correctly... */
    sig->timestamp=make_timestamp();

    /* ... but we won't make a timestamp earlier than the existing
       one. */
    while(sig->timestamp<=orig_sig->timestamp)
      {
	sleep(1);
	sig->timestamp=make_timestamp();
      }

    /* Note that already expired sigs will remain expired (with a
       duration of 1) since build-packet.c:build_sig_subpkt_from_sig
       detects this case. */

    if( sig->version >= 4 )
      {
	/* Put the updated timestamp into the sig.  Note that this
	   will automagically lower any sig expiration dates to
	   correctly correspond to the differences in the timestamps
	   (i.e. the duration will shrink). */
	build_sig_subpkt_from_sig( sig );

	if (mksubpkt)
	  rc = (*mksubpkt)(sig, opaque);
      }

    if (!rc) {
        hash_sigversion_to_magic (md, sig);
	md_final(md);

	rc = complete_sig( sig, sk, md );
    }

    md_close (md);
    if( rc )
	free_seckey_enc (sig);
    else
	*ret_sig = sig;
    return rc;
}
