/* encode.c - encode data
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006 Free Software Foundation, Inc.
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

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "filter.h"
#include "trustdb.h"
#include "i18n.h"
#include "status.h"

static int encode_simple( const char *filename, int mode, int use_seskey );
static int write_pubkey_enc_from_list( PK_LIST pk_list, DEK *dek, IOBUF out );

/****************
 * Encode FILENAME with only the symmetric cipher.  Take input from
 * stdin if FILENAME is NULL.
 */
int
encode_symmetric( const char *filename )
{
    return encode_simple( filename, 1, 0 );
}

/****************
 * Encode FILENAME as a literal data packet only. Take input from
 * stdin if FILENAME is NULL.
 */
int
encode_store( const char *filename )
{
    return encode_simple( filename, 0, 0 );
}

static void
encode_seskey( DEK *dek, DEK **seskey, byte *enckey )
{
    CIPHER_HANDLE hd;
    byte buf[33];

    assert ( dek->keylen <= 32 );
    if(!*seskey)
      {
	*seskey=xmalloc_clear(sizeof(DEK));
	(*seskey)->keylen=dek->keylen;
	(*seskey)->algo=dek->algo;
	make_session_key(*seskey);
	/*log_hexdump( "thekey", c->key, c->keylen );*/
      }

    buf[0] = (*seskey)->algo;
    memcpy( buf + 1, (*seskey)->key, (*seskey)->keylen );
    
    hd = cipher_open( dek->algo, CIPHER_MODE_CFB, 1 );
    cipher_setkey( hd, dek->key, dek->keylen );
    cipher_setiv( hd, NULL, 0 );
    cipher_encrypt( hd, buf, buf, (*seskey)->keylen + 1 );
    cipher_close( hd );

    memcpy( enckey, buf, (*seskey)->keylen + 1 );
    wipememory( buf, sizeof buf ); /* burn key */
}

/* We try very hard to use a MDC */
static int
use_mdc(PK_LIST pk_list,int algo)
{
  /* RFC-1991 and 2440 don't have MDC */
  if(RFC1991 || RFC2440)
    return 0;

  /* --force-mdc overrides --disable-mdc */
  if(opt.force_mdc)
    return 1;

  if(opt.disable_mdc)
    return 0;

  /* Do the keys really support MDC? */

  if(select_mdc_from_pklist(pk_list))
    return 1;
  
  /* The keys don't support MDC, so now we do a bit of a hack - if any
     of the AESes or TWOFISH are in the prefs, we assume that the user
     can handle a MDC.  This is valid for PGP 7, which can handle MDCs
     though it will not generate them.  2440bis allows this, by the
     way. */

  if(select_algo_from_prefs(pk_list,PREFTYPE_SYM,
			    CIPHER_ALGO_AES,NULL)==CIPHER_ALGO_AES)
    return 1;

  if(select_algo_from_prefs(pk_list,PREFTYPE_SYM,
			    CIPHER_ALGO_AES192,NULL)==CIPHER_ALGO_AES192)
    return 1;

  if(select_algo_from_prefs(pk_list,PREFTYPE_SYM,
			    CIPHER_ALGO_AES256,NULL)==CIPHER_ALGO_AES256)
    return 1;

  if(select_algo_from_prefs(pk_list,PREFTYPE_SYM,
			    CIPHER_ALGO_TWOFISH,NULL)==CIPHER_ALGO_TWOFISH)
    return 1;

  /* Last try.  Use MDC for the modern ciphers. */

  if(cipher_get_blocksize(algo)!=8)
    return 1;

  return 0; /* No MDC */
}

/* We don't want to use use_seskey yet because older gnupg versions
   can't handle it, and there isn't really any point unless we're
   making a message that can be decrypted by a public key or
   passphrase. */
static int
encode_simple( const char *filename, int mode, int use_seskey )
{
    IOBUF inp, out;
    PACKET pkt;
    PKT_plaintext *pt = NULL;
    STRING2KEY *s2k = NULL;
    byte enckey[33];
    int rc = 0;
    int seskeylen = 0;
    u32 filesize;
    cipher_filter_context_t cfx;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    text_filter_context_t tfx;
    progress_filter_context_t pfx;
    int do_compress = !RFC1991 && default_compress_algo();

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &tfx, 0, sizeof tfx);
    init_packet(&pkt);
    
    /* prepare iobufs */
    inp = iobuf_open(filename);
    if (inp)
      iobuf_ioctl (inp,3,1,NULL); /* disable fd caching */
    if (inp && is_secured_file (iobuf_get_fd (inp)))
      {
        iobuf_close (inp);
        inp = NULL;
        errno = EPERM;
      }
    if( !inp ) {
	log_error(_("can't open `%s': %s\n"), filename? filename: "[stdin]",
                  strerror(errno) );
	return G10ERR_OPEN_FILE;
    }

    handle_progress (&pfx, inp, filename);

    if( opt.textmode )
	iobuf_push_filter( inp, text_filter, &tfx );

    /* Due the the fact that we use don't use an IV to encrypt the
       session key we can't use the new mode with RFC1991 because
       it has no S2K salt. RFC1991 always uses simple S2K. */
    if ( RFC1991 && use_seskey )
        use_seskey = 0;
    
    cfx.dek = NULL;
    if( mode ) {
	s2k = xmalloc_clear( sizeof *s2k );
	s2k->mode = RFC1991? 0:opt.s2k_mode;
	s2k->hash_algo=S2K_DIGEST_ALGO;
	cfx.dek = passphrase_to_dek( NULL, 0,
				     default_cipher_algo(), s2k, 2,
                                     NULL, NULL);
	if( !cfx.dek || !cfx.dek->keylen ) {
	    rc = G10ERR_PASSPHRASE;
	    xfree(cfx.dek);
	    xfree(s2k);
	    iobuf_close(inp);
	    log_error(_("error creating passphrase: %s\n"), g10_errstr(rc) );
	    return rc;
	}
        if (use_seskey && s2k->mode != 1 && s2k->mode != 3) {
            use_seskey = 0;
            log_info (_("can't use a symmetric ESK packet "
                        "due to the S2K mode\n"));
        }

        if ( use_seskey )
	  {
	    DEK *dek = NULL;
            seskeylen = cipher_get_keylen( default_cipher_algo() ) / 8;
            encode_seskey( cfx.dek, &dek, enckey );
            xfree( cfx.dek ); cfx.dek = dek;
	  }

	if(opt.verbose)
	  log_info(_("using cipher %s\n"),
		   cipher_algo_to_string(cfx.dek->algo));

	cfx.dek->use_mdc=use_mdc(NULL,cfx.dek->algo);
    }

    if (do_compress && cfx.dek && cfx.dek->use_mdc
	&& is_file_compressed(filename, &rc))
      {
        if (opt.verbose)
          log_info(_("`%s' already compressed\n"), filename);
        do_compress = 0;        
      }

    if( rc || (rc = open_outfile( filename, opt.armor? 1:0, &out )) ) {
	iobuf_cancel(inp);
	xfree(cfx.dek);
	xfree(s2k);
	return rc;
    }

    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );

    if( s2k && !RFC1991 ) {
	PKT_symkey_enc *enc = xmalloc_clear( sizeof *enc + seskeylen + 1 );
	enc->version = 4;
	enc->cipher_algo = cfx.dek->algo;
	enc->s2k = *s2k;
        if ( use_seskey && seskeylen ) {
            enc->seskeylen = seskeylen + 1; /* algo id */
            memcpy( enc->seskey, enckey, seskeylen + 1 );
        }
	pkt.pkttype = PKT_SYMKEY_ENC;
	pkt.pkt.symkey_enc = enc;
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build symkey packet failed: %s\n", g10_errstr(rc) );
	xfree(enc);
    }

    if (!opt.no_literal)
      pt=setup_plaintext_name(filename,inp);

    /* Note that PGP 5 has problems decrypting symmetrically encrypted
       data if the file length is in the inner packet. It works when
       only partial length headers are use.  In the past, we always
       used partial body length here, but since PGP 2, PGP 6, and PGP
       7 need the file length, and nobody should be using PGP 5
       nowadays anyway, this is now set to the file length.  Note also
       that this only applies to the RFC-1991 style symmetric
       messages, and not the RFC-2440 style.  PGP 6 and 7 work with
       either partial length or fixed length with the new style
       messages. */

    if ( !iobuf_is_pipe_filename (filename) && *filename && !opt.textmode )
      {
        off_t tmpsize;
        int overflow;

	if ( !(tmpsize = iobuf_get_filelength(inp, &overflow))
             && !overflow )
          log_info(_("WARNING: `%s' is an empty file\n"), filename );
        /* We can't encode the length of very large files because
           OpenPGP uses only 32 bit for file sizes.  So if the the
           size of a file is larger than 2^32 minus some bytes for
           packet headers, we switch to partial length encoding. */
        if ( tmpsize < (IOBUF_FILELENGTH_LIMIT - 65536) )
          filesize = tmpsize;
        else
          filesize = 0;
      }
    else
      filesize = opt.set_filesize ? opt.set_filesize : 0; /* stdin */

    if (!opt.no_literal) {
	pt->timestamp = make_timestamp();
	pt->mode = opt.textmode? 't' : 'b';
	pt->len = filesize;
	pt->new_ctb = !pt->len && !RFC1991;
	pt->buf = inp;
	pkt.pkttype = PKT_PLAINTEXT;
	pkt.pkt.plaintext = pt;
	cfx.datalen = filesize && !do_compress ? calc_packet_length( &pkt ) : 0;
    }
    else
      {
        cfx.datalen = filesize && !do_compress ? filesize : 0;
        pkt.pkttype = 0;
        pkt.pkt.generic = NULL;
      }

    /* register the cipher filter */
    if( mode )
	iobuf_push_filter( out, cipher_filter, &cfx );
    /* register the compress filter */
    if( do_compress )
      {
        if (cfx.dek && cfx.dek->use_mdc)
          zfx.new_ctb = 1;
	push_compress_filter(out,&zfx,default_compress_algo());
      }

    /* do the work */
    if (!opt.no_literal) {
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build_packet failed: %s\n", g10_errstr(rc) );
    }
    else {
	/* user requested not to create a literal packet,
	 * so we copy the plain data */
	byte copy_buffer[4096];
	int  bytes_copied;
	while ((bytes_copied = iobuf_read(inp, copy_buffer, 4096)) != -1)
	    if (iobuf_write(out, copy_buffer, bytes_copied) == -1) {
		rc = G10ERR_WRITE_FILE;
		log_error("copying input to output failed: %s\n", g10_errstr(rc) );
		break;
	    }
	wipememory(copy_buffer, 4096); /* burn buffer */
    }

    /* finish the stuff */
    iobuf_close(inp);
    if (rc)
	iobuf_cancel(out);
    else {
	iobuf_close(out); /* fixme: check returncode */
        if (mode)
            write_status( STATUS_END_ENCRYPTION );
    }
    if (pt)
	pt->buf = NULL;
    free_packet(&pkt);
    xfree(cfx.dek);
    xfree(s2k);
    return rc;
}

int
setup_symkey(STRING2KEY **symkey_s2k,DEK **symkey_dek)
{
  *symkey_s2k=xmalloc_clear(sizeof(STRING2KEY));
  (*symkey_s2k)->mode = opt.s2k_mode;
  (*symkey_s2k)->hash_algo = S2K_DIGEST_ALGO;

  *symkey_dek=passphrase_to_dek(NULL,0,opt.s2k_cipher_algo,
				*symkey_s2k,2,NULL,NULL);
  if(!*symkey_dek || !(*symkey_dek)->keylen)
    {
      xfree(*symkey_dek);
      xfree(*symkey_s2k);
      return G10ERR_PASSPHRASE;
    }

  return 0;
}

static int
write_symkey_enc(STRING2KEY *symkey_s2k,DEK *symkey_dek,DEK *dek,IOBUF out)
{
  int rc,seskeylen=cipher_get_keylen(dek->algo)/8;

  PKT_symkey_enc *enc;
  byte enckey[33];
  PACKET pkt;

  enc=xmalloc_clear(sizeof(PKT_symkey_enc)+seskeylen+1);
  encode_seskey(symkey_dek,&dek,enckey);

  enc->version = 4;
  enc->cipher_algo = opt.s2k_cipher_algo;
  enc->s2k = *symkey_s2k;
  enc->seskeylen = seskeylen + 1; /* algo id */
  memcpy( enc->seskey, enckey, seskeylen + 1 );

  pkt.pkttype = PKT_SYMKEY_ENC;
  pkt.pkt.symkey_enc = enc;

  if((rc=build_packet(out,&pkt)))
    log_error("build symkey_enc packet failed: %s\n",g10_errstr(rc));

  xfree(enc);
  return rc;
}

/****************
 * Encrypt the file with the given userids (or ask if none
 * is supplied).
 */
int
encode_crypt( const char *filename, STRLIST remusr, int use_symkey )
{
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    PKT_plaintext *pt = NULL;
    DEK *symkey_dek = NULL;
    STRING2KEY *symkey_s2k = NULL;
    int rc = 0, rc2 = 0;
    u32 filesize;
    cipher_filter_context_t cfx;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    text_filter_context_t tfx;
    progress_filter_context_t pfx;
    PK_LIST pk_list,work_list;
    int do_compress = opt.compress_algo && !RFC1991;

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &tfx, 0, sizeof tfx);
    init_packet(&pkt);

    if(use_symkey
       && (rc=setup_symkey(&symkey_s2k,&symkey_dek)))
      return rc;

    if( (rc=build_pk_list( remusr, &pk_list, PUBKEY_USAGE_ENC)) )
	return rc;

    if(PGP2) {
      for(work_list=pk_list; work_list; work_list=work_list->next)
	if(!(is_RSA(work_list->pk->pubkey_algo) &&
	     nbits_from_pk(work_list->pk)<=2048))
	  {
	    log_info(_("you can only encrypt to RSA keys of 2048 bits or "
		       "less in --pgp2 mode\n"));
	    compliance_failure();
	    break;
	  }
    }

    /* prepare iobufs */
    inp = iobuf_open(filename);
    if (inp)
      iobuf_ioctl (inp,3,1,NULL); /* disable fd caching */
    if (inp && is_secured_file (iobuf_get_fd (inp)))
      {
        iobuf_close (inp);
        inp = NULL;
        errno = EPERM;
      }
    if( !inp ) {
	log_error(_("can't open `%s': %s\n"), filename? filename: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }
    else if( opt.verbose )
	log_info(_("reading from `%s'\n"), filename? filename: "[stdin]");

    handle_progress (&pfx, inp, filename);

    if( opt.textmode )
	iobuf_push_filter( inp, text_filter, &tfx );

    if( (rc = open_outfile( filename, opt.armor? 1:0, &out )) )
	goto leave;

    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );

    /* create a session key */
    cfx.dek = xmalloc_secure_clear (sizeof *cfx.dek);
    if( !opt.def_cipher_algo ) { /* try to get it from the prefs */
	cfx.dek->algo = select_algo_from_prefs(pk_list,PREFTYPE_SYM,-1,NULL);
	/* The only way select_algo_from_prefs can fail here is when
           mixing v3 and v4 keys, as v4 keys have an implicit
           preference entry for 3DES, and the pk_list cannot be empty.
           In this case, use 3DES anyway as it's the safest choice -
           perhaps the v3 key is being used in an OpenPGP
           implementation and we know that the implementation behind
           any v4 key can handle 3DES. */
	if( cfx.dek->algo == -1 ) {
	    cfx.dek->algo = CIPHER_ALGO_3DES;

	    if( PGP2 ) {
	      log_info(_("unable to use the IDEA cipher for all of the keys "
			 "you are encrypting to.\n"));
	      compliance_failure();
	    }
	}
    }
    else {
      if(!opt.expert &&
	 select_algo_from_prefs(pk_list,PREFTYPE_SYM,
				opt.def_cipher_algo,NULL)!=opt.def_cipher_algo)
	log_info(_("WARNING: forcing symmetric cipher %s (%d)"
		   " violates recipient preferences\n"),
		 cipher_algo_to_string(opt.def_cipher_algo),
		 opt.def_cipher_algo);

      cfx.dek->algo = opt.def_cipher_algo;
    }

    cfx.dek->use_mdc=use_mdc(pk_list,cfx.dek->algo);

    /* Only do the is-file-already-compressed check if we are using a
       MDC.  This forces compressed files to be re-compressed if we do
       not have a MDC to give some protection against chosen
       ciphertext attacks. */

    if (do_compress && cfx.dek->use_mdc && is_file_compressed(filename, &rc2) )
      {
        if (opt.verbose)
          log_info(_("`%s' already compressed\n"), filename);
        do_compress = 0;        
      }
    if (rc2)
      {
        rc = rc2;
        goto leave;
      }

    make_session_key( cfx.dek );
    if( DBG_CIPHER )
	log_hexdump("DEK is: ", cfx.dek->key, cfx.dek->keylen );

    rc = write_pubkey_enc_from_list( pk_list, cfx.dek, out );
    if( rc  )
	goto leave;

    /* We put the passphrase (if any) after any public keys as this
       seems to be the most useful on the recipient side - there is no
       point in prompting a user for a passphrase if they have the
       secret key needed to decrypt. */
    if(use_symkey && (rc=write_symkey_enc(symkey_s2k,symkey_dek,cfx.dek,out)))
      goto leave;

    if (!opt.no_literal)
      pt=setup_plaintext_name(filename,inp);

    if (!iobuf_is_pipe_filename (filename) && *filename && !opt.textmode )
      {
        off_t tmpsize;
        int overflow;

	if ( !(tmpsize = iobuf_get_filelength(inp, &overflow))
             && !overflow )
          log_info(_("WARNING: `%s' is an empty file\n"), filename );
        /* We can't encode the length of very large files because
           OpenPGP uses only 32 bit for file sizes.  So if the the
           size of a file is larger than 2^32 minus some bytes for
           packet headers, we switch to partial length encoding. */
        if (tmpsize < (IOBUF_FILELENGTH_LIMIT - 65536) )
          filesize = tmpsize;
        else
          filesize = 0;
      }
    else
      filesize = opt.set_filesize ? opt.set_filesize : 0; /* stdin */

    if (!opt.no_literal) {
	pt->timestamp = make_timestamp();
	pt->mode = opt.textmode ? 't' : 'b';
	pt->len = filesize;
	pt->new_ctb = !pt->len && !RFC1991;
	pt->buf = inp;
	pkt.pkttype = PKT_PLAINTEXT;
	pkt.pkt.plaintext = pt;
	cfx.datalen = filesize && !do_compress? calc_packet_length( &pkt ) : 0;
    }
    else
	cfx.datalen = filesize && !do_compress ? filesize : 0;

    /* register the cipher filter */
    iobuf_push_filter( out, cipher_filter, &cfx );

    /* register the compress filter */
    if( do_compress ) {
	int compr_algo = opt.compress_algo;

	if(compr_algo==-1)
	  {
	    if((compr_algo=
		select_algo_from_prefs(pk_list,PREFTYPE_ZIP,-1,NULL))==-1)
	      compr_algo=DEFAULT_COMPRESS_ALGO;
	    /* Theoretically impossible to get here since uncompressed
	       is implicit. */
	  }
	else if(!opt.expert &&
		select_algo_from_prefs(pk_list,PREFTYPE_ZIP,
				       compr_algo,NULL)!=compr_algo)
	  log_info(_("WARNING: forcing compression algorithm %s (%d)"
		     " violates recipient preferences\n"),
		   compress_algo_to_string(compr_algo),compr_algo);

	/* algo 0 means no compression */
	if( compr_algo )
	  {
            if (cfx.dek && cfx.dek->use_mdc)
              zfx.new_ctb = 1;
	    push_compress_filter(out,&zfx,compr_algo);
	  }
    }

    /* do the work */
    if (!opt.no_literal) {
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build_packet failed: %s\n", g10_errstr(rc) );
    }
    else {
	/* user requested not to create a literal packet, so we copy
           the plain data */
	byte copy_buffer[4096];
	int  bytes_copied;
	while ((bytes_copied = iobuf_read(inp, copy_buffer, 4096)) != -1)
	    if (iobuf_write(out, copy_buffer, bytes_copied) == -1) {
		rc = G10ERR_WRITE_FILE;
		log_error("copying input to output failed: %s\n",
                          g10_errstr(rc) );
		break;
	    }
	wipememory(copy_buffer, 4096); /* burn buffer */
    }

    /* finish the stuff */
  leave:
    iobuf_close(inp);
    if( rc )
	iobuf_cancel(out);
    else {
	iobuf_close(out); /* fixme: check returncode */
        write_status( STATUS_END_ENCRYPTION );
    }
    if( pt )
	pt->buf = NULL;
    free_packet(&pkt);
    xfree(cfx.dek);
    xfree(symkey_dek);
    xfree(symkey_s2k);
    release_pk_list( pk_list );
    return rc;
}




/****************
 * Filter to do a complete public key encryption.
 */
int
encrypt_filter( void *opaque, int control,
	       IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    encrypt_filter_context_t *efx = opaque;
    int rc=0;

    if( control == IOBUFCTRL_UNDERFLOW ) { /* decrypt */
	BUG(); /* not used */
    }
    else if( control == IOBUFCTRL_FLUSH ) { /* encrypt */
	if( !efx->header_okay ) {
	    efx->cfx.dek = xmalloc_secure_clear( sizeof *efx->cfx.dek );

	    if( !opt.def_cipher_algo  ) { /* try to get it from the prefs */
		efx->cfx.dek->algo =
		  select_algo_from_prefs(efx->pk_list,PREFTYPE_SYM,-1,NULL);
		if( efx->cfx.dek->algo == -1 ) {
                    /* because 3DES is implicitly in the prefs, this can only
                     * happen if we do not have any public keys in the list */
		    efx->cfx.dek->algo = DEFAULT_CIPHER_ALGO;
                }
	    }
	    else {
	      if(!opt.expert &&
		 select_algo_from_prefs(efx->pk_list,PREFTYPE_SYM,
					opt.def_cipher_algo,
					NULL)!=opt.def_cipher_algo)
		log_info(_("forcing symmetric cipher %s (%d) "
			   "violates recipient preferences\n"),
			 cipher_algo_to_string(opt.def_cipher_algo),
			 opt.def_cipher_algo);

	      efx->cfx.dek->algo = opt.def_cipher_algo;
	    }

            efx->cfx.dek->use_mdc = use_mdc(efx->pk_list,efx->cfx.dek->algo);

	    make_session_key( efx->cfx.dek );
	    if( DBG_CIPHER )
		log_hexdump("DEK is: ",
			     efx->cfx.dek->key, efx->cfx.dek->keylen );

	    rc = write_pubkey_enc_from_list( efx->pk_list, efx->cfx.dek, a );
	    if( rc )
		return rc;

	    if(efx->symkey_s2k && efx->symkey_dek)
	      {
		rc=write_symkey_enc(efx->symkey_s2k,efx->symkey_dek,
				    efx->cfx.dek,a);
		if(rc)
		  return rc;
	      }

	    iobuf_push_filter( a, cipher_filter, &efx->cfx );

	    efx->header_okay = 1;
	}
	rc = iobuf_write( a, buf, size );

    }
    else if( control == IOBUFCTRL_FREE )
      {
	xfree(efx->symkey_dek);
	xfree(efx->symkey_s2k);
      }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "encrypt_filter";
    }
    return rc;
}


/****************
 * Write pubkey-enc packets from the list of PKs to OUT.
 */
static int
write_pubkey_enc_from_list( PK_LIST pk_list, DEK *dek, IOBUF out )
{
    PACKET pkt;
    PKT_public_key *pk;
    PKT_pubkey_enc  *enc;
    int rc;

    for( ; pk_list; pk_list = pk_list->next ) {
	MPI frame;

	pk = pk_list->pk;

	print_pubkey_algo_note( pk->pubkey_algo );
	enc = xmalloc_clear( sizeof *enc );
	enc->pubkey_algo = pk->pubkey_algo;
	keyid_from_pk( pk, enc->keyid );
	enc->throw_keyid = (opt.throw_keyid || (pk_list->flags&1));

	if(opt.throw_keyid && (PGP2 || PGP6 || PGP7 || PGP8))
	  {
	    log_info(_("you may not use %s while in %s mode\n"),
		     "--throw-keyid",compliance_option_string());
	    compliance_failure();
	  }

	/* Okay, what's going on: We have the session key somewhere in
	 * the structure DEK and want to encode this session key in
	 * an integer value of n bits.	pubkey_nbits gives us the
	 * number of bits we have to use.  We then encode the session
	 * key in some way and we get it back in the big intger value
	 * FRAME.  Then we use FRAME, the public key PK->PKEY and the
	 * algorithm number PK->PUBKEY_ALGO and pass it to pubkey_encrypt
	 * which returns the encrypted value in the array ENC->DATA.
	 * This array has a size which depends on the used algorithm
	 * (e.g. 2 for Elgamal).  We don't need frame anymore because we
	 * have everything now in enc->data which is the passed to
	 * build_packet()
	 */
	frame = encode_session_key( dek, pubkey_nbits( pk->pubkey_algo,
							  pk->pkey ) );
	rc = pubkey_encrypt( pk->pubkey_algo, enc->data, frame, pk->pkey );
	mpi_free( frame );
	if( rc )
	    log_error("pubkey_encrypt failed: %s\n", g10_errstr(rc) );
	else {
	    if( opt.verbose ) {
		char *ustr = get_user_id_string_native (enc->keyid);
		log_info(_("%s/%s encrypted for: \"%s\"\n"),
		    pubkey_algo_to_string(enc->pubkey_algo),
		    cipher_algo_to_string(dek->algo), ustr );
		xfree(ustr);
	    }
	    /* and write it */
	    init_packet(&pkt);
	    pkt.pkttype = PKT_PUBKEY_ENC;
	    pkt.pkt.pubkey_enc = enc;
	    rc = build_packet( out, &pkt );
	    if( rc )
	       log_error("build_packet(pubkey_enc) failed: %s\n", g10_errstr(rc));
	}
	free_pubkey_enc(enc);
	if( rc )
	    return rc;
    }
    return 0;
}

void
encode_crypt_files(int nfiles, char **files, STRLIST remusr)
{
  int rc = 0;

  if (opt.outfile)
    {
      log_error(_("--output doesn't work for this command\n"));
      return;        
    }
    
  if (!nfiles)
    {
      char line[2048];
      unsigned int lno = 0;
      while ( fgets(line, DIM(line), stdin) )
        {
          lno++;
          if (!*line || line[strlen(line)-1] != '\n')
            {
              log_error("input line %u too long or missing LF\n", lno);
              return;
            }
          line[strlen(line)-1] = '\0';
          print_file_status(STATUS_FILE_START, line, 2);
          if ( (rc = encode_crypt(line, remusr, 0)) )
            log_error("encryption of `%s' failed: %s\n",
                      print_fname_stdin(line), g10_errstr(rc) );
          write_status( STATUS_FILE_DONE );
          iobuf_ioctl( NULL, 2, 0, NULL); /* Invalidate entire cache. */
        }
    }
  else
    {
      while (nfiles--)
        {
          print_file_status(STATUS_FILE_START, *files, 2);
          if ( (rc = encode_crypt(*files, remusr, 0)) )
            log_error("encryption of `%s' failed: %s\n",
                      print_fname_stdin(*files), g10_errstr(rc) );
          write_status( STATUS_FILE_DONE );
          iobuf_ioctl( NULL, 2, 0, NULL); /* Invalidate entire cache. */
          files++;
        }
    }
}
