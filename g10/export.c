/* export.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
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

static int do_export( STRLIST users, int secret, unsigned int options );
static int do_export_stream( IOBUF out, STRLIST users, int secret,
			     KBNODE *keyblock_out, unsigned int options,
			     int *any );

int
parse_export_options(char *str,unsigned int *options)
{
  char *tok;
  int hit=0;
  struct
  {
    char *name;
    unsigned int bit;
  } export_opts[]=
    {
      {"include-non-rfc",EXPORT_INCLUDE_NON_RFC},
      {"include-local-sigs",EXPORT_INCLUDE_LOCAL_SIGS},
      {"include-attributes",EXPORT_INCLUDE_ATTRIBUTES},
      {"include-sensitive-revkeys",EXPORT_INCLUDE_SENSITIVE_REVKEYS},
      {NULL,0}
      /* add tags for include revoked and disabled? */
    };

  while((tok=strsep(&str," ,")))
    {
      int i,rev=0;

      if(ascii_strncasecmp("no-",tok,3)==0)
	{
	  rev=1;
	  tok+=3;
	}

      for(i=0;export_opts[i].name;i++)
	{
	  if(ascii_strcasecmp(export_opts[i].name,tok)==0)
	    {
	      if(rev)
		*options&=~export_opts[i].bit;
	      else
		*options|=export_opts[i].bit;
	      hit=1;
	      break;
	    }
	}

      if(!hit && !export_opts[i].name)
	return 0;
    }

  return hit;
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
    if( opt.compress_keys && opt.compress )
	iobuf_push_filter( out, compress_filter, &zfx );
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
                log_error (_("key `%s' not found: %s\n"),
                           sl->d, g10_errstr (G10ERR_INV_USER_ID));
        }

        /* it would be nice to see which of the given users did
           actually match one in the keyring.  To implement this we
           need to have a found flag for each entry in desc and to set
           this we must check all those entries after a match to mark
           all matched one - currently we stop at the first match.  To
           do this we need an extra flag to enable this feature so */
    }

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

	/* do not export keys which are incompatible with rfc2440 */
	if( !(options&EXPORT_INCLUDE_NON_RFC) &&
	    (node = find_kbnode( keyblock, PKT_PUBLIC_KEY )) ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;
	    if( pk->version == 3 && pk->pubkey_algo > 3 ) {
		log_info(_("key %08lX: not a rfc2440 key - skipped\n"),
			      (ulong)keyid_from_pk( pk, NULL) );
		continue;
	    }
	}

	node=find_kbnode( keyblock, PKT_SECRET_KEY );
	if(node)
	  {
	    PKT_secret_key *sk=node->pkt->pkt.secret_key;

	    keyid_from_sk(sk,sk_keyid);

	    /* we can't apply GNU mode 1001 on an unprotected key */
	    if( secret == 2 && !sk->is_protected )
	      {
		log_info(_("key %08lX: not protected - skipped\n"),
			 (ulong)sk_keyid[1]);
		continue;
	      }

	    /* no v3 keys with GNU mode 1001 */
	    if( secret == 2 && sk->version == 3 )
	      {
		log_info(_("key %08lX: PGP 2.x style key - skipped\n"),
			 (ulong)sk_keyid[1]);
		continue;
	      }
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

	    /* don't export any comment packets but those in the
	     * secret keyring */
	    if( !secret && node->pkt->pkttype == PKT_COMMENT )
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

	    if( node->pkt->pkttype == PKT_SIGNATURE ) {
	      /* do not export packets which are marked as not exportable */
	      if( !(options&EXPORT_INCLUDE_LOCAL_SIGS) &&
		  !node->pkt->pkt.signature->flags.exportable )
		continue; /* not exportable */

	      /* Do not export packets with a "sensitive" revocation
                 key unless the user wants us to.  Note that we do
                 export these when issuing the actual revocation (see
                 revoke.c). */
	      if( !(options&EXPORT_INCLUDE_SENSITIVE_REVKEYS) &&
		  node->pkt->pkt.signature->revkey ) {
		int i;

		for(i=0;i<node->pkt->pkt.signature->numrevkeys;i++)
		  if(node->pkt->pkt.signature->revkey[i]->class & 0x40)
		    break;

		if(i<node->pkt->pkt.signature->numrevkeys)
		  continue;
	      }

	      /* delete our verification cache */
	      delete_sig_subpkt (node->pkt->pkt.signature->unhashed,
				 SIGSUBPKT_PRIV_VERIFY_CACHE);
	    }

	    /* Don't export attribs? */
	    if( !(options&EXPORT_INCLUDE_ATTRIBUTES) &&
		node->pkt->pkttype == PKT_USER_ID &&
		node->pkt->pkt.user_id->attrib_data ) {
	      /* Skip until we get to something that is not an attrib
		 or a signature on an attrib */
	      while(kbctx->next && kbctx->next->pkt->pkttype==PKT_SIGNATURE) {
		kbctx=kbctx->next;
	      }
 
	      continue;
	    }

	    if( secret == 2 && node->pkt->pkttype == PKT_SECRET_KEY ) {
		/* we don't want to export the secret parts of the
		 * primary key, this is done by using GNU protection mode 1001
		 */
		int save_mode = node->pkt->pkt.secret_key->protect.s2k.mode;
		node->pkt->pkt.secret_key->protect.s2k.mode = 1001;
		rc = build_packet( out, node->pkt );
		node->pkt->pkt.secret_key->protect.s2k.mode = save_mode;
	    }
	    else {
	      /* Warn the user if the secret key or any of the secret
                 subkeys are protected with SHA1 and we have
                 simple_sk_checksum set. */
	      if(!sha1_warned && opt.simple_sk_checksum &&
		 (node->pkt->pkttype==PKT_SECRET_KEY ||
		  node->pkt->pkttype==PKT_SECRET_SUBKEY) &&
		 node->pkt->pkt.secret_key->protect.sha1chk)
		{
		  /* I hope this warning doesn't confuse people. */
		  log_info(_("WARNING: secret key %08lX does not have a "
			     "simple SK checksum\n"),(ulong)sk_keyid[1]);

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

