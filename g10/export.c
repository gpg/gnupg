/* export.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005 Free Software Foundation, Inc.
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
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "i18n.h"
#include "trustdb.h"


/* An object to keep track of subkeys. */
struct subkey_list_s
{
  struct subkey_list_s *next;
  u32 kid[2];
};
typedef struct subkey_list_s *subkey_list_t;


static int do_export( STRLIST users, int secret, unsigned int options );
static int do_export_stream( IOBUF out, STRLIST users, int secret,
			     KBNODE *keyblock_out, unsigned int options,
			     int *any );

int
parse_export_options(char *str,unsigned int *options,int noisy)
{
  struct parse_options export_opts[]=
    {
      {"export-local-sigs",EXPORT_LOCAL_SIGS,NULL,
       N_("export signatures that are marked as local-only")},
      {"export-attributes",EXPORT_ATTRIBUTES,NULL,
       N_("export attribute user IDs (generally photo IDs)")},
      {"export-sensitive-revkeys",EXPORT_SENSITIVE_REVKEYS,NULL,
       N_("export revocation keys marked as \"sensitive\"")},
      {"export-reset-subkey-passwd",EXPORT_RESET_SUBKEY_PASSWD,NULL,
       N_("remove the passphrase from exported subkeys")},
      {"export-clean",EXPORT_CLEAN,NULL,
       N_("remove unusable parts from key during export")},
      {"export-minimal",EXPORT_MINIMAL|EXPORT_CLEAN,NULL,
       N_("remove as much as possible from key during export")},
      /* Aliases for backward compatibility */
      {"include-local-sigs",EXPORT_LOCAL_SIGS,NULL,NULL},
      {"include-attributes",EXPORT_ATTRIBUTES,NULL,NULL},
      {"include-sensitive-revkeys",EXPORT_SENSITIVE_REVKEYS,NULL,NULL},
      /* dummy */
      {"export-unusable-sigs",0,NULL,NULL},
      {"export-clean-sigs",0,NULL,NULL},
      {"export-clean-uids",0,NULL,NULL},
      {NULL,0,NULL,NULL}
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



/* Release an entire subkey list. */
static void
release_subkey_list (subkey_list_t list)
{
  while (list)
    {
      subkey_list_t tmp = list->next;;
      xfree (list);
      list = tmp;
    }
}


/* Returns true if NODE is a subkey and contained in LIST. */
static int
subkey_in_list_p (subkey_list_t list, KBNODE node)
{
  if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
      || node->pkt->pkttype == PKT_SECRET_SUBKEY )
    {
      u32 kid[2];

      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        keyid_from_pk (node->pkt->pkt.public_key, kid);
      else
        keyid_from_sk (node->pkt->pkt.secret_key, kid);
      
      for (; list; list = list->next)
        if (list->kid[0] == kid[0] && list->kid[1] == kid[1])
          return 1;
    }
  return 0;
}

/* Allocate a new subkey list item from NODE. */
static subkey_list_t
new_subkey_list_item (KBNODE node)
{
  subkey_list_t list = xcalloc (1, sizeof *list);

  if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
    keyid_from_pk (node->pkt->pkt.public_key, list->kid);
  else if (node->pkt->pkttype == PKT_SECRET_SUBKEY)
    keyid_from_sk (node->pkt->pkt.secret_key, list->kid);

  return list;
}


/* Helper function to check whether the subkey at NODE actually
   matches the description at DESC.  The function returns true if the
   key under question has been specified by an exact specification
   (keyID or fingerprint) and does match the one at NODE.  It is
   assumed that the packet at NODE is either a public or secret
   subkey. */
static int
exact_subkey_match_p (KEYDB_SEARCH_DESC *desc, KBNODE node)
{
  u32 kid[2];
  byte fpr[MAX_FINGERPRINT_LEN];
  size_t fprlen;
  int result = 0;

  switch(desc->mode)
    {
    case KEYDB_SEARCH_MODE_SHORT_KID:
    case KEYDB_SEARCH_MODE_LONG_KID:
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        keyid_from_pk (node->pkt->pkt.public_key, kid);
      else
        keyid_from_sk (node->pkt->pkt.secret_key, kid);
      break;
      
    case KEYDB_SEARCH_MODE_FPR16:
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        fingerprint_from_pk (node->pkt->pkt.public_key, fpr,&fprlen);
      else
        fingerprint_from_sk (node->pkt->pkt.secret_key, fpr,&fprlen);
      break;
      
    default:
      break;
    }
  
  switch(desc->mode)
    {
    case KEYDB_SEARCH_MODE_SHORT_KID:
      if (desc->u.kid[1] == kid[1])
        result = 1;
      break;

    case KEYDB_SEARCH_MODE_LONG_KID:
      if (desc->u.kid[0] == kid[0] && desc->u.kid[1] == kid[1])
        result = 1;
      break;

    case KEYDB_SEARCH_MODE_FPR16:
      if (!memcmp (desc->u.fpr, fpr, 16))
        result = 1;
      break;

    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      if (!memcmp (desc->u.fpr, fpr, 20))
        result = 1;
      break;

    default:
      break;
    }

  return result;
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
    subkey_list_t subkey_list = NULL;  /* Track alreay processed subkeys. */
    KEYDB_HANDLE kdbhd;
    STRLIST sl;

    *any = 0;
    init_packet( &pkt );
    kdbhd = keydb_new (secret);

    if (!users) {
        ndesc = 1;
        desc = xcalloc ( ndesc, sizeof *desc );
        desc[0].mode = KEYDB_SEARCH_MODE_FIRST;
    }
    else {
        for (ndesc=0, sl=users; sl; sl = sl->next, ndesc++) 
            ;
        desc = xmalloc ( ndesc * sizeof *desc);
        
        for (ndesc=0, sl=users; sl; sl = sl->next) {
	    if (classify_user_id (sl->d, desc+ndesc))
                ndesc++;
            else
                log_error (_("key \"%s\" not found: %s\n"),
                           sl->d, g10_errstr (G10ERR_INV_USER_ID));
        }

        /* It would be nice to see which of the given users did
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

        /* Read the keyblock. */
        rc = keydb_get_keyblock (kdbhd, &keyblock );
	if( rc ) {
            log_error (_("error reading keyblock: %s\n"), g10_errstr(rc) );
	    goto leave;
	}

	if((node=find_kbnode(keyblock,PKT_SECRET_KEY)))
	  {
	    PKT_secret_key *sk=node->pkt->pkt.secret_key;

	    keyid_from_sk(sk,sk_keyid);

	    /* We can't apply GNU mode 1001 on an unprotected key. */
	    if( secret == 2 && !sk->is_protected )
	      {
		log_info(_("key %s: not protected - skipped\n"),
			 keystr(sk_keyid));
		continue;
	      }

	    /* No v3 keys with GNU mode 1001. */
	    if( secret == 2 && sk->version == 3 )
	      {
		log_info(_("key %s: PGP 2.x style key - skipped\n"),
			 keystr(sk_keyid));
		continue;
	      }

            /* It does not make sense to export a key with a primary
               key on card using a non-key stub.  We simply skip those
               keys when used with --export-secret-subkeys. */
            if (secret == 2 && sk->is_protected
                && sk->protect.s2k.mode == 1002 ) 
              {
		log_info(_("key %s: key material on-card - skipped\n"),
			 keystr(sk_keyid));
		continue;
              }
	  }
	else
	  {
	    /* It's a public key export, so do the cleaning if
	       requested.  Note that both export-clean and
	       export-minimal only apply to UID sigs (0x10, 0x11,
	       0x12, and 0x13).  A designated revocation is never
	       stripped, even with export-minimal set. */

	    if(options&EXPORT_CLEAN)
	      clean_key(keyblock,opt.verbose,options&EXPORT_MINIMAL,NULL,NULL);
	  }

	/* And write it. */
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

            /* Make sure that ring_trust packets never get exported. */
            if (node->pkt->pkttype == PKT_RING_TRUST)
              continue;

	    /* If exact is set, then we only export what was requested
	       (plus the primary key, if the user didn't specifically
	       request it). */
	    if(desc[descindex].exact
	       && (node->pkt->pkttype==PKT_PUBLIC_SUBKEY
		   || node->pkt->pkttype==PKT_SECRET_SUBKEY))
	      {
                if (!exact_subkey_match_p (desc+descindex, node))
                  {
                    /* Before skipping this subkey, check whether any
                       other description wants an exact match on a
                       subkey and include that subkey into the output
                       too.  Need to add this subkey to a list so that
                       it won't get processed a second time.
                   
                       So the first step here is to check that list and
                       skip in any case if the key is in that list.

                       We need this whole mess because the import
                       function is not able to merge secret keys and
                       thus it is useless to output them as two
                       separate keys and have import merge them.  */
                    if (subkey_in_list_p (subkey_list, node))  
                      skip_until_subkey = 1; /* Already processed this one. */
                    else
                      {
                        size_t j;

                        for (j=0; j < ndesc; j++)
                          if (j != descindex && desc[j].exact
                              && exact_subkey_match_p (desc+j, node))
                            break;
                        if (!(j < ndesc))
                          skip_until_subkey = 1; /* No other one matching. */ 
                      }
                  }

		if(skip_until_subkey)
		  continue;

                /* Mark this one as processed. */
                {
                  subkey_list_t tmp = new_subkey_list_item (node);
                  tmp->next = subkey_list;
                  subkey_list = tmp;
                }
	      }

	    if(node->pkt->pkttype==PKT_SIGNATURE)
	      {
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

                log_info (_("about to export an unprotected subkey\n"));
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
                    log_error (_("failed to unprotect the subkey: %s\n"),
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
    release_subkey_list (subkey_list);
    xfree(desc);
    keydb_release (kdbhd);
    if(rc || keyblock_out==NULL)
      release_kbnode( keyblock );
    if( !*any )
	log_info(_("WARNING: nothing exported\n"));
    return rc;
}
