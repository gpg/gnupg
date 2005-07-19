/* export.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
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
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "i18n.h"
#include "trustdb.h"

static int do_export( STRLIST users, int secret, unsigned int options );
static int do_export_stream( IOBUF out, STRLIST users, int secret,
			     KBNODE *keyblock_out, unsigned int options,
			     int *any );

int
parse_export_options(char *str,unsigned int *options,int noisy)
{
  struct parse_options export_opts[]=
    {
      {"export-local-sigs",EXPORT_LOCAL_SIGS,NULL},
      {"export-attributes",EXPORT_ATTRIBUTES,NULL},
      {"export-sensitive-revkeys",EXPORT_SENSITIVE_REVKEYS,NULL},
      {"export-minimal",EXPORT_MINIMAL|EXPORT_CLEAN_SIGS|EXPORT_CLEAN_UIDS,NULL},
      {"export-clean",EXPORT_CLEAN_SIGS|EXPORT_CLEAN_UIDS,NULL},
      {"export-clean-sigs",EXPORT_CLEAN_SIGS,NULL},
      {"export-clean-uids",EXPORT_CLEAN_UIDS,NULL},

      {"export-reset-subkey-passwd", EXPORT_RESET_SUBKEY_PASSWD, NULL},

      /* Aliases for backward compatibility */
      {"include-local-sigs",EXPORT_LOCAL_SIGS,NULL},
      {"include-attributes",EXPORT_ATTRIBUTES,NULL},
      {"include-sensitive-revkeys",EXPORT_SENSITIVE_REVKEYS,NULL},
      /* dummy */
      {"export-unusable-sigs",0,NULL},
      {NULL,0,NULL}
      /* add tags for include revoked and disabled? */
    };

  return parse_options(str,options,export_opts,noisy);
}

/****************
 * Export the public keys (to standard out or --output).
 * Depending on opt.armor the output is armored.
 * options are defined in main.h.
 * If USERS is NULL, the complete ring will be exported.  */
int
export_pubkeys( STRLIST users, unsigned int options )
{
    return do_export( users, 0, options );
}

/****************
 * Export to an already opened stream; return -1 if no keys have
 * been exported
 */
int
export_pubkeys_stream( IOBUF out, STRLIST users,
		       KBNODE *keyblock_out, unsigned int options )
{
    int any, rc;

    rc = do_export_stream( out, users, 0, keyblock_out, options, &any );
    if( !rc && !any )
	rc = -1;
    return rc;
}

int
export_seckeys( STRLIST users )
{
    return do_export( users, 1, 0 );
}

int
export_secsubkeys( STRLIST users )
{
    return do_export( users, 2, 0 );
}

static int
do_export( STRLIST users, int secret, unsigned int options )
{
    IOBUF out = NULL;
    int any, rc;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;

    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);

    rc = open_outfile( NULL, 0, &out );
    if( rc )
	return rc;

    if( opt.armor ) {
	afx.what = secret?5:1;
	iobuf_push_filter( out, armor_filter, &afx );
    }
    if( opt.compress_keys )
      push_compress_filter(out,&zfx,default_compress_algo());

    rc = do_export_stream( out, users, secret, NULL, options, &any );
    if( rc || !any )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    return rc;
}


/* If keyblock_out is non-NULL, AND the exit code is zero, then it
   contains a pointer to the first keyblock found and exported.  No
   other keyblocks are exported.  The caller must free it. */
static int
do_export_stream( IOBUF out, STRLIST users, int secret,
		  KBNODE *keyblock_out, unsigned int options, int *any )
{
    int rc = 0;
    PACKET pkt;
    KBNODE keyblock = NULL;
    KBNODE kbctx, node;
    size_t ndesc, descindex;
    KEYDB_SEARCH_DESC *desc = NULL;
    KEYDB_HANDLE kdbhd;
    STRLIST sl;
    u32 keyid[2];

    *any = 0;
    init_packet( &pkt );
    kdbhd = keydb_new (secret);

    if (!users) {
        ndesc = 1;
        desc = m_alloc_clear ( ndesc * sizeof *desc);
        desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
    }
    else {
        for (ndesc=0, sl=users; sl; sl = sl->next, ndesc++) 
            ;
        desc = m_alloc ( ndesc * sizeof *desc);
        
        for (ndesc=0, sl=users; sl; sl = sl->next) {
	    if (classify_user_id (sl->d, desc+ndesc))
                ndesc++;
            else
                log_error (_("key \"%s\" not found: %s\n"),
                           sl->d, g10_errstr (G10ERR_INV_USER_ID));
        }

        /* it would be nice to see which of the given users did
           actually match one in the keyring.  To implement this we
           need to have a found flag for each entry in desc and to set
           this we must check all those entries after a match to mark
           all matched one - currently we stop at the first match.  To
           do this we need an extra flag to enable this feature so */
    }

#ifdef ENABLE_SELINUX_HACKS
    if (secret) {
        log_error (_("exporting secret keys not allowed\n"));
        rc = G10ERR_GENERAL;
        goto leave;
    }
#endif

    while (!(rc = keydb_search2 (kdbhd, desc, ndesc, &descindex))) {
        int sha1_warned=0,skip_until_subkey=0;
	u32 sk_keyid[2];

	if (!users) 
            desc[0].mode = KEYDB_SEARCH_MODE_NEXT;

        /* read the keyblock */
        rc = keydb_get_keyblock (kdbhd, &keyblock );
	if( rc ) {
            log_error (_("error reading keyblock: %s\n"), g10_errstr(rc) );
	    goto leave;
	}

	if((node=find_kbnode(keyblock,PKT_SECRET_KEY)))
	  {
	    PKT_secret_key *sk=node->pkt->pkt.secret_key;

	    keyid_from_sk(sk,sk_keyid);

	    /* we can't apply GNU mode 1001 on an unprotected key */
	    if( secret == 2 && !sk->is_protected )
	      {
		log_info(_("key %s: not protected - skipped\n"),
			 keystr(sk_keyid));
		continue;
	      }

	    /* no v3 keys with GNU mode 1001 */
	    if( secret == 2 && sk->version == 3 )
	      {
		log_info(_("key %s: PGP 2.x style key - skipped\n"),
			 keystr(sk_keyid));
		continue;
	      }
	  }
	else
	  {
	    /* It's a public key export */
	    if((options&EXPORT_MINIMAL)
	       && (node=find_kbnode(keyblock,PKT_PUBLIC_KEY)))
	      keyid_from_pk(node->pkt->pkt.public_key,keyid);

	    if(options&EXPORT_CLEAN_UIDS)
	      clean_uids_from_key(keyblock,opt.verbose);
	  }

	/* and write it */
	for( kbctx=NULL; (node = walk_kbnode( keyblock, &kbctx, 0 )); ) {
	    if( skip_until_subkey )
	      {
		if(node->pkt->pkttype==PKT_PUBLIC_SUBKEY
		   || node->pkt->pkttype==PKT_SECRET_SUBKEY)
		  skip_until_subkey=0;
		else
		  continue;
	      }

	    /* We used to use comment packets, but not any longer.  In
	       case we still have comments on a key, strip them here
	       before we call build_packet(). */
	    if( node->pkt->pkttype == PKT_COMMENT )
	      continue;

            /* make sure that ring_trust packets never get exported */
            if (node->pkt->pkttype == PKT_RING_TRUST)
              continue;

	    /* If exact is set, then we only export what was requested
	       (plus the primary key, if the user didn't specifically
	       request it) */
	    if(desc[descindex].exact
	       && (node->pkt->pkttype==PKT_PUBLIC_SUBKEY
		   || node->pkt->pkttype==PKT_SECRET_SUBKEY))
	      {
		u32 kid[2];
		byte fpr[MAX_FINGERPRINT_LEN];
		size_t fprlen;

		switch(desc[descindex].mode)
		  {
		  case KEYDB_SEARCH_MODE_SHORT_KID:
		  case KEYDB_SEARCH_MODE_LONG_KID:
		    if(node->pkt->pkttype==PKT_PUBLIC_SUBKEY)
		      keyid_from_pk(node->pkt->pkt.public_key,kid);
		    else
		      keyid_from_sk(node->pkt->pkt.secret_key,kid);
		    break;

		  case KEYDB_SEARCH_MODE_FPR16:
		  case KEYDB_SEARCH_MODE_FPR20:
		  case KEYDB_SEARCH_MODE_FPR:
		    if(node->pkt->pkttype==PKT_PUBLIC_SUBKEY)
		      fingerprint_from_pk(node->pkt->pkt.public_key,
					  fpr,&fprlen);
		    else
		      fingerprint_from_sk(node->pkt->pkt.secret_key,
					  fpr,&fprlen);
		    break;

		  default:
		    break;
		  }

		switch(desc[descindex].mode)
		  {
		  case KEYDB_SEARCH_MODE_SHORT_KID:
		    if (desc[descindex].u.kid[1] != kid[1])
		      skip_until_subkey=1;
		    break;
		  case KEYDB_SEARCH_MODE_LONG_KID:
		    if (desc[descindex].u.kid[0] != kid[0]
			|| desc[descindex].u.kid[1] != kid[1])
		      skip_until_subkey=1;
		    break;
		  case KEYDB_SEARCH_MODE_FPR16:
		    if (memcmp (desc[descindex].u.fpr, fpr, 16))
		      skip_until_subkey=1;
		    break;
		  case KEYDB_SEARCH_MODE_FPR20:
		  case KEYDB_SEARCH_MODE_FPR:
		    if (memcmp (desc[descindex].u.fpr, fpr, 20))
		      skip_until_subkey=1;
		    break;
		  default:
		    break;
		  }

		if(skip_until_subkey)
		  continue;
	      }

	    if(node->pkt->pkttype==PKT_USER_ID)
	      {
		/* Run clean_sigs_from_uid against each uid if
		   export-clean-sigs is on. */
		if(options&EXPORT_CLEAN_SIGS)
		  clean_sigs_from_uid(keyblock,node,opt.verbose);
	      }
	    else if(node->pkt->pkttype==PKT_SIGNATURE)
	      {
		/* If we have export-minimal turned on, do not include
		   any signature that isn't a selfsig.  Note that this
		   only applies to uid sigs (0x10, 0x11, 0x12, and
		   0x13).  A designated revocation is not stripped. */
		if((options&EXPORT_MINIMAL)
		   && IS_UID_SIG(node->pkt->pkt.signature)
		   && (node->pkt->pkt.signature->keyid[0]!=keyid[0]
		       || node->pkt->pkt.signature->keyid[1]!=keyid[1]))
		  continue;

		/* do not export packets which are marked as not
		   exportable */
		if(!(options&EXPORT_LOCAL_SIGS)
		   && !node->pkt->pkt.signature->flags.exportable)
		  continue; /* not exportable */

		/* Do not export packets with a "sensitive" revocation
		   key unless the user wants us to.  Note that we do
		   export these when issuing the actual revocation
		   (see revoke.c). */
		if(!(options&EXPORT_SENSITIVE_REVKEYS)
		   && node->pkt->pkt.signature->revkey)
		  {
		    int i;

		    for(i=0;i<node->pkt->pkt.signature->numrevkeys;i++)
		      if(node->pkt->pkt.signature->revkey[i]->class & 0x40)
			break;

		    if(i<node->pkt->pkt.signature->numrevkeys)
		      continue;
		  }
	      }

	    /* Don't export attribs? */
	    if( !(options&EXPORT_ATTRIBUTES) &&
		node->pkt->pkttype == PKT_USER_ID &&
		node->pkt->pkt.user_id->attrib_data ) {
	      /* Skip until we get to something that is not an attrib
		 or a signature on an attrib */
	      while(kbctx->next && kbctx->next->pkt->pkttype==PKT_SIGNATURE) {
		kbctx=kbctx->next;
	      }
 
	      continue;
	    }

	    if( secret == 2 && node->pkt->pkttype == PKT_SECRET_KEY )
	      {
		/* We don't want to export the secret parts of the
		 * primary key, this is done by using GNU protection mode 1001
		 */
		int save_mode = node->pkt->pkt.secret_key->protect.s2k.mode;
		node->pkt->pkt.secret_key->protect.s2k.mode = 1001;
		rc = build_packet( out, node->pkt );
		node->pkt->pkt.secret_key->protect.s2k.mode = save_mode;
	      }
	    else if (secret == 2 && node->pkt->pkttype == PKT_SECRET_SUBKEY
                     && (opt.export_options&EXPORT_RESET_SUBKEY_PASSWD))
              {
                /* If the subkey is protected reset the passphrase to
                   export an unprotected subkey.  This feature is
                   useful in cases of a subkey copied to an unattended
                   machine where a passphrase is not required. */
                PKT_secret_key *sk_save, *sk;

                sk_save = node->pkt->pkt.secret_key;
                sk = copy_secret_key (NULL, sk_save);
                node->pkt->pkt.secret_key = sk;

                log_info ("about to export an unprotected subkey\n");
                switch (is_secret_key_protected (sk))
                  {
                  case -1:
                    rc = G10ERR_PUBKEY_ALGO;
                    break;
                  case 0:
                    break;
                  default:
                    if (sk->protect.s2k.mode == 1001)
                      ; /* No secret parts. */
                    else if( sk->protect.s2k.mode == 1002 ) 
                      ; /* Card key stub. */
                    else 
                      {
                        rc = check_secret_key( sk, 0 );
                      }
                    break;
                  }
                if (rc)
                  {
                    node->pkt->pkt.secret_key = sk_save;
                    free_secret_key (sk);
                    /* FIXME: Make translatable after releasing 1.4.2 */
                    log_error ("failed to unprotect the subkey: %s\n",
                               g10_errstr (rc));
                    goto leave;
                  }

		rc = build_packet (out, node->pkt);

                node->pkt->pkt.secret_key = sk_save;
                free_secret_key (sk);
              }
	    else
	      {
		/* Warn the user if the secret key or any of the secret
		   subkeys are protected with SHA1 and we have
		   simple_sk_checksum set. */
		if(!sha1_warned && opt.simple_sk_checksum &&
		   (node->pkt->pkttype==PKT_SECRET_KEY ||
		    node->pkt->pkttype==PKT_SECRET_SUBKEY) &&
		   node->pkt->pkt.secret_key->protect.sha1chk)
		  {
		    /* I hope this warning doesn't confuse people. */
		    log_info(_("WARNING: secret key %s does not have a "
			       "simple SK checksum\n"),keystr(sk_keyid));

		    sha1_warned=1;
		  }

		rc = build_packet( out, node->pkt );
	      }

	    if( rc ) {
		log_error("build_packet(%d) failed: %s\n",
			    node->pkt->pkttype, g10_errstr(rc) );
		rc = G10ERR_WRITE_FILE;
		goto leave;
	    }
	}
	++*any;
	if(keyblock_out)
	  {
	    *keyblock_out=keyblock;
	    break;
	  }
    }
    if( rc == -1 )
	rc = 0;

  leave:
    m_free(desc);
    keydb_release (kdbhd);
    if(rc || keyblock_out==NULL)
      release_kbnode( keyblock );
    if( !*any )
	log_info(_("WARNING: nothing exported\n"));
    return rc;
}
