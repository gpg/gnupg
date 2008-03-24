/* import.c - import a key into our key storage.
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
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"
#include "main.h"
#include "i18n.h"
#include "ttyio.h"
#include "status.h"
#include "keyserver-internal.h"

struct stats_s {
    ulong count;
    ulong no_user_id;
    ulong imported;
    ulong imported_rsa;
    ulong n_uids;
    ulong n_sigs;
    ulong n_subk;
    ulong unchanged;
    ulong n_revoc;
    ulong secret_read;
    ulong secret_imported;
    ulong secret_dups;
    ulong skipped_new_keys;
    ulong not_imported;
    ulong n_sigs_cleaned;
    ulong n_uids_cleaned;
};


static int import( IOBUF inp, const char* fname,struct stats_s *stats,
		   unsigned char **fpr,size_t *fpr_len,unsigned int options );
static int read_block( IOBUF a, PACKET **pending_pkt, KBNODE *ret_root );
static void revocation_present(KBNODE keyblock);
static int import_one(const char *fname, KBNODE keyblock,struct stats_s *stats,
		      unsigned char **fpr,size_t *fpr_len,
		      unsigned int options,int from_sk);
static int import_secret_one( const char *fname, KBNODE keyblock,
                              struct stats_s *stats, unsigned int options);
static int import_revoke_cert( const char *fname, KBNODE node,
                               struct stats_s *stats);
static int chk_self_sigs( const char *fname, KBNODE keyblock,
			  PKT_public_key *pk, u32 *keyid, int *non_self );
static int delete_inv_parts( const char *fname, KBNODE keyblock,
			     u32 *keyid, unsigned int options );
static int merge_blocks( const char *fname, KBNODE keyblock_orig,
			 KBNODE keyblock, u32 *keyid,
			 int *n_uids, int *n_sigs, int *n_subk );
static int append_uid( KBNODE keyblock, KBNODE node, int *n_sigs,
			     const char *fname, u32 *keyid );
static int append_key( KBNODE keyblock, KBNODE node, int *n_sigs,
			     const char *fname, u32 *keyid );
static int merge_sigs( KBNODE dst, KBNODE src, int *n_sigs,
			     const char *fname, u32 *keyid );
static int merge_keysigs( KBNODE dst, KBNODE src, int *n_sigs,
			     const char *fname, u32 *keyid );

int
parse_import_options(char *str,unsigned int *options,int noisy)
{
  struct parse_options import_opts[]=
    {
      {"import-local-sigs",IMPORT_LOCAL_SIGS,NULL,
       N_("import signatures that are marked as local-only")},
      {"repair-pks-subkey-bug",IMPORT_REPAIR_PKS_SUBKEY_BUG,NULL,
       N_("repair damage from the pks keyserver during import")},
      {"fast-import",IMPORT_FAST,NULL,
       N_("do not update the trustdb after import")},
      {"convert-sk-to-pk",IMPORT_SK2PK,NULL,
       N_("create a public key when importing a secret key")},
      {"merge-only",IMPORT_MERGE_ONLY,NULL,
       N_("only accept updates to existing keys")},
      {"import-clean",IMPORT_CLEAN,NULL,
       N_("remove unusable parts from key after import")},
      {"import-minimal",IMPORT_MINIMAL|IMPORT_CLEAN,NULL,
       N_("remove as much as possible from key after import")},
      /* Aliases for backward compatibility */
      {"allow-local-sigs",IMPORT_LOCAL_SIGS,NULL,NULL},
      {"repair-hkp-subkey-bug",IMPORT_REPAIR_PKS_SUBKEY_BUG,NULL,NULL},
      /* dummy */
      {"import-unusable-sigs",0,NULL,NULL},
      {"import-clean-sigs",0,NULL,NULL},
      {"import-clean-uids",0,NULL,NULL},
      {NULL,0,NULL,NULL}
    };

  return parse_options(str,options,import_opts,noisy);
}

void *
import_new_stats_handle (void)
{
    return xmalloc_clear ( sizeof (struct stats_s) );
}

void
import_release_stats_handle (void *p)
{
    xfree (p);
}

/****************
 * Import the public keys from the given filename. Input may be armored.
 * This function rejects all keys which are not validly self signed on at
 * least one userid. Only user ids which are self signed will be imported.
 * Other signatures are not checked.
 *
 * Actually this function does a merge. It works like this:
 *
 *  - get the keyblock
 *  - check self-signatures and remove all userids and their signatures
 *    without/invalid self-signatures.
 *  - reject the keyblock, if we have no valid userid.
 *  - See whether we have this key already in one of our pubrings.
 *    If not, simply add it to the default keyring.
 *  - Compare the key and the self-signatures of the new and the one in
 *    our keyring.  If they are different something weird is going on;
 *    ask what to do.
 *  - See whether we have only non-self-signature on one user id; if not
 *    ask the user what to do.
 *  - compare the signatures: If we already have this signature, check
 *    that they compare okay; if not, issue a warning and ask the user.
 *    (consider looking at the timestamp and use the newest?)
 *  - Simply add the signature.  Can't verify here because we may not have
 *    the signature's public key yet; verification is done when putting it
 *    into the trustdb, which is done automagically as soon as this pubkey
 *    is used.
 *  - Proceed with next signature.
 *
 *  Key revocation certificates have special handling.
 *
 */
static int
import_keys_internal( IOBUF inp, char **fnames, int nnames,
		      void *stats_handle, unsigned char **fpr, size_t *fpr_len,
		      unsigned int options )
{
    int i, rc = 0;
    struct stats_s *stats = stats_handle;

    if (!stats)
        stats = import_new_stats_handle ();

    if (inp) {
        rc = import( inp, "[stream]", stats, fpr, fpr_len, options);
    }
    else {
        if( !fnames && !nnames )
	    nnames = 1;  /* Ohh what a ugly hack to jump into the loop */

	for(i=0; i < nnames; i++ ) {
	    const char *fname = fnames? fnames[i] : NULL;
	    IOBUF inp2 = iobuf_open(fname);
	    if( !fname )
	        fname = "[stdin]";
            if (inp2 && is_secured_file (iobuf_get_fd (inp2)))
              {
                iobuf_close (inp2);
                inp2 = NULL;
                errno = EPERM;
              }
	    if( !inp2 )
	        log_error(_("can't open `%s': %s\n"), fname, strerror(errno) );
	    else
	      {
	        rc = import( inp2, fname, stats, fpr, fpr_len, options );
	        iobuf_close(inp2);
                /* Must invalidate that ugly cache to actually close it. */
                iobuf_ioctl (NULL, 2, 0, (char*)fname);
	        if( rc )
		  log_error("import from `%s' failed: %s\n", fname,
			    g10_errstr(rc) );
	      }
	    if( !fname )
	        break;
	}
    }
    if (!stats_handle) {
        import_print_stats (stats);
        import_release_stats_handle (stats);
    }

    /* If no fast import and the trustdb is dirty (i.e. we added a key
       or userID that had something other than a selfsig, a signature
       that was other than a selfsig, or any revocation), then
       update/check the trustdb if the user specified by setting
       interactive or by not setting no-auto-check-trustdb */

    if(!(options&IMPORT_FAST))
      trustdb_check_or_update();

    return rc;
}

void
import_keys( char **fnames, int nnames,
	     void *stats_handle, unsigned int options )
{
  import_keys_internal(NULL,fnames,nnames,stats_handle,NULL,NULL,options);
}

int
import_keys_stream( IOBUF inp, void *stats_handle,
		    unsigned char **fpr, size_t *fpr_len,unsigned int options )
{
  return import_keys_internal(inp,NULL,0,stats_handle,fpr,fpr_len,options);
}

static int
import( IOBUF inp, const char* fname,struct stats_s *stats,
	unsigned char **fpr,size_t *fpr_len,unsigned int options )
{
    PACKET *pending_pkt = NULL;
    KBNODE keyblock = NULL;
    int rc = 0;

    getkey_disable_caches();

    if( !opt.no_armor ) { /* armored reading is not disabled */
	armor_filter_context_t *afx = new_armor_context ();
	afx->only_keyblocks = 1;
	push_armor_filter (afx, inp);
        release_armor_context (afx);
    }

    while( !(rc = read_block( inp, &pending_pkt, &keyblock) )) {
	if( keyblock->pkt->pkttype == PKT_PUBLIC_KEY )
	    rc = import_one( fname, keyblock, stats, fpr, fpr_len, options, 0);
	else if( keyblock->pkt->pkttype == PKT_SECRET_KEY ) 
                rc = import_secret_one( fname, keyblock, stats, options );
	else if( keyblock->pkt->pkttype == PKT_SIGNATURE
		 && keyblock->pkt->pkt.signature->sig_class == 0x20 )
	    rc = import_revoke_cert( fname, keyblock, stats );
	else {
	    log_info( _("skipping block of type %d\n"),
					    keyblock->pkt->pkttype );
	}
	release_kbnode(keyblock);
        /* fixme: we should increment the not imported counter but this
           does only make sense if we keep on going despite of errors. */
	if( rc )
	    break;
	if( !(++stats->count % 100) && !opt.quiet )
	    log_info(_("%lu keys processed so far\n"), stats->count );
    }
    if( rc == -1 )
	rc = 0;
    else if( rc && rc != G10ERR_INV_KEYRING )
	log_error( _("error reading `%s': %s\n"), fname, g10_errstr(rc));

    return rc;
}


void
import_print_stats (void *hd)
{
    struct stats_s *stats = hd;

    if( !opt.quiet ) {
	log_info(_("Total number processed: %lu\n"), stats->count );
	if( stats->skipped_new_keys )
	    log_info(_("      skipped new keys: %lu\n"),
						stats->skipped_new_keys );
	if( stats->no_user_id )
	    log_info(_("          w/o user IDs: %lu\n"), stats->no_user_id );
	if( stats->imported || stats->imported_rsa ) {
	    log_info(_("              imported: %lu"), stats->imported );
	    if( stats->imported_rsa )
		fprintf(stderr, "  (RSA: %lu)", stats->imported_rsa );
	    putc('\n', stderr);
	}
	if( stats->unchanged )
	    log_info(_("             unchanged: %lu\n"), stats->unchanged );
	if( stats->n_uids )
	    log_info(_("          new user IDs: %lu\n"), stats->n_uids );
	if( stats->n_subk )
	    log_info(_("           new subkeys: %lu\n"), stats->n_subk );
	if( stats->n_sigs )
	    log_info(_("        new signatures: %lu\n"), stats->n_sigs );
	if( stats->n_revoc )
	    log_info(_("   new key revocations: %lu\n"), stats->n_revoc );
	if( stats->secret_read )
	    log_info(_("      secret keys read: %lu\n"), stats->secret_read );
	if( stats->secret_imported )
	    log_info(_("  secret keys imported: %lu\n"), stats->secret_imported );
	if( stats->secret_dups )
	    log_info(_(" secret keys unchanged: %lu\n"), stats->secret_dups );
	if( stats->not_imported )
	    log_info(_("          not imported: %lu\n"), stats->not_imported );
	if( stats->n_sigs_cleaned)
	    log_info(_("    signatures cleaned: %lu\n"),stats->n_sigs_cleaned);
	if( stats->n_uids_cleaned)
	    log_info(_("      user IDs cleaned: %lu\n"),stats->n_uids_cleaned);
    }

    if( is_status_enabled() ) {
	char buf[14*20];
	sprintf(buf, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
		stats->count,
		stats->no_user_id,
		stats->imported,
		stats->imported_rsa,
		stats->unchanged,
		stats->n_uids,
		stats->n_subk,
		stats->n_sigs,
		stats->n_revoc,
		stats->secret_read,
		stats->secret_imported,
		stats->secret_dups,
		stats->skipped_new_keys,
                stats->not_imported );
	write_status_text( STATUS_IMPORT_RES, buf );
    }
}


/****************
 * Read the next keyblock from stream A.
 * PENDING_PKT should be initialzed to NULL
 * and not chnaged form the caller.
 * Retunr: 0 = okay, -1 no more blocks or another errorcode.
 */
static int
read_block( IOBUF a, PACKET **pending_pkt, KBNODE *ret_root )
{
    int rc;
    PACKET *pkt;
    KBNODE root = NULL;
    int in_cert;

    if( *pending_pkt ) {
	root = new_kbnode( *pending_pkt );
	*pending_pkt = NULL;
	in_cert = 1;
    }
    else
	in_cert = 0;
    pkt = xmalloc( sizeof *pkt );
    init_packet(pkt);
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	if( rc ) {  /* ignore errors */
	    if( rc != G10ERR_UNKNOWN_PACKET ) {
		log_error("read_block: read error: %s\n", g10_errstr(rc) );
		rc = G10ERR_INV_KEYRING;
		goto ready;
	    }
	    free_packet( pkt );
	    init_packet(pkt);
	    continue;
	}

	if( !root && pkt->pkttype == PKT_SIGNATURE
		  && pkt->pkt.signature->sig_class == 0x20 ) {
	    /* this is a revocation certificate which is handled
	     * in a special way */
	    root = new_kbnode( pkt );
	    pkt = NULL;
	    goto ready;
	}

	/* make a linked list of all packets */
	switch( pkt->pkttype ) {
	  case PKT_COMPRESSED:
	    if(check_compress_algo(pkt->pkt.compressed->algorithm))
	      {
		rc = G10ERR_COMPR_ALGO;
		goto ready;
	      }
	    else
	      {
		compress_filter_context_t *cfx = xmalloc_clear( sizeof *cfx );
		pkt->pkt.compressed->buf = NULL;
		push_compress_filter2(a,cfx,pkt->pkt.compressed->algorithm,1);
	      }
	    free_packet( pkt );
	    init_packet(pkt);
	    break;

          case PKT_RING_TRUST:
            /* skip those packets */
	    free_packet( pkt );
	    init_packet(pkt);
            break;

	  case PKT_PUBLIC_KEY:
	  case PKT_SECRET_KEY:
	    if( in_cert ) { /* store this packet */
		*pending_pkt = pkt;
		pkt = NULL;
		goto ready;
	    }
	    in_cert = 1;
	  default:
	    if( in_cert ) {
		if( !root )
		    root = new_kbnode( pkt );
		else
		    add_kbnode( root, new_kbnode( pkt ) );
		pkt = xmalloc( sizeof *pkt );
	    }
	    init_packet(pkt);
	    break;
	}
    }
  ready:
    if( rc == -1 && root )
	rc = 0;

    if( rc )
	release_kbnode( root );
    else
	*ret_root = root;
    free_packet( pkt );
    xfree( pkt );
    return rc;
}

/* Walk through the subkeys on a pk to find if we have the PKS
   disease: multiple subkeys with their binding sigs stripped, and the
   sig for the first subkey placed after the last subkey.  That is,
   instead of "pk uid sig sub1 bind1 sub2 bind2 sub3 bind3" we have
   "pk uid sig sub1 sub2 sub3 bind1".  We can't do anything about sub2
   and sub3, as they are already lost, but we can try and rescue sub1
   by reordering the keyblock so that it reads "pk uid sig sub1 bind1
   sub2 sub3".  Returns TRUE if the keyblock was modified. */

static int
fix_pks_corruption(KBNODE keyblock)
{
  int changed=0,keycount=0;
  KBNODE node,last=NULL,sknode=NULL;

  /* First determine if we have the problem at all.  Look for 2 or
     more subkeys in a row, followed by a single binding sig. */
  for(node=keyblock;node;last=node,node=node->next)
    {
      if(node->pkt->pkttype==PKT_PUBLIC_SUBKEY)
	{
	  keycount++;
	  if(!sknode)
	    sknode=node;
	}
      else if(node->pkt->pkttype==PKT_SIGNATURE &&
	      node->pkt->pkt.signature->sig_class==0x18 &&
	      keycount>=2 && node->next==NULL)
	{
	  /* We might have the problem, as this key has two subkeys in
	     a row without any intervening packets. */

	  /* Sanity check */
	  if(last==NULL)
	    break;

	  /* Temporarily attach node to sknode. */
	  node->next=sknode->next;
	  sknode->next=node;
	  last->next=NULL;

	  /* Note we aren't checking whether this binding sig is a
	     selfsig.  This is not necessary here as the subkey and
	     binding sig will be rejected later if that is the
	     case. */
	  if(check_key_signature(keyblock,node,NULL))
	    {
	      /* Not a match, so undo the changes. */
	      sknode->next=node->next;
	      last->next=node;
	      node->next=NULL;
	      break;
	    }
	  else
	    {
	      sknode->flag |= 1; /* Mark it good so we don't need to
                                    check it again */
	      changed=1;
	      break;
	    }
	}
      else
	keycount=0;
    }

  return changed;
}


static void
print_import_ok (PKT_public_key *pk, PKT_secret_key *sk, unsigned int reason)
{
  byte array[MAX_FINGERPRINT_LEN], *s;
  char buf[MAX_FINGERPRINT_LEN*2+30], *p;
  size_t i, n;

  sprintf (buf, "%u ", reason);
  p = buf + strlen (buf);

  if (pk)
    fingerprint_from_pk (pk, array, &n);
  else
    fingerprint_from_sk (sk, array, &n);
  s = array;
  for (i=0; i < n ; i++, s++, p += 2)
    sprintf (p, "%02X", *s);

  write_status_text (STATUS_IMPORT_OK, buf);
}

static void
print_import_check (PKT_public_key * pk, PKT_user_id * id)
{
    char * buf;
    byte fpr[24];
    u32 keyid[2];
    size_t i, pos = 0, n;

    buf = xmalloc (17+41+id->len+32);
    keyid_from_pk (pk, keyid);
    sprintf (buf, "%08X%08X ", keyid[0], keyid[1]);
    pos = 17;
    fingerprint_from_pk (pk, fpr, &n);
    for (i = 0; i < n; i++, pos += 2)
        sprintf (buf+pos, "%02X", fpr[i]);
    strcat (buf, " ");
    pos += 1;
    strcat (buf, id->name);
    write_status_text (STATUS_IMPORT_CHECK, buf);
    xfree (buf);
}

static void
check_prefs_warning(PKT_public_key *pk)
{
  log_info(_("WARNING: key %s contains preferences for unavailable\n"),
            keystr_from_pk(pk));
  /* TRANSLATORS: This string is belongs to the previous one.  They are
     only split up to allow printing of a common prefix. */
  log_info(_("         algorithms on these user IDs:\n"));
}

static void
check_prefs(KBNODE keyblock)
{
  KBNODE node;
  PKT_public_key *pk;
  int problem=0;
  
  merge_keys_and_selfsig(keyblock);
  pk=keyblock->pkt->pkt.public_key;

  for(node=keyblock;node;node=node->next)
    {
      if(node->pkt->pkttype==PKT_USER_ID
	 && node->pkt->pkt.user_id->created
	 && node->pkt->pkt.user_id->prefs)
	{
	  PKT_user_id *uid=node->pkt->pkt.user_id;
	  prefitem_t *prefs=uid->prefs;
	  char *user=utf8_to_native(uid->name,strlen(uid->name),0);

	  for(;prefs->type;prefs++)
	    {
	      char num[10]; /* prefs->value is a byte, so we're over
			       safe here */

	      sprintf(num,"%u",prefs->value);

	      if(prefs->type==PREFTYPE_SYM)
		{
		  if(check_cipher_algo(prefs->value))
		    {
		      const char *algo=cipher_algo_to_string(prefs->value);
		      if(!problem)
			check_prefs_warning(pk);
		      log_info(_("         \"%s\": preference for cipher"
				 " algorithm %s\n"),user,algo?algo:num);
		      problem=1;
		    }
		}
	      else if(prefs->type==PREFTYPE_HASH)
		{
		  if(check_digest_algo(prefs->value))
		    {
		      const char *algo=digest_algo_to_string(prefs->value);
		      if(!problem)
			check_prefs_warning(pk);
		      log_info(_("         \"%s\": preference for digest"
				 " algorithm %s\n"),user,algo?algo:num);
		      problem=1;
		    }
		}
	      else if(prefs->type==PREFTYPE_ZIP)
		{
		  if(check_compress_algo(prefs->value))
		    {
		      const char *algo=compress_algo_to_string(prefs->value);
		      if(!problem)
			check_prefs_warning(pk);
		      log_info(_("         \"%s\": preference for compression"
				 " algorithm %s\n"),user,algo?algo:num);
		      problem=1;
		    }
		}
	    }

	  xfree(user);
	}
    }

  if(problem)
    {
      log_info(_("it is strongly suggested that you update"
		 " your preferences and\n"));
      log_info(_("re-distribute this key to avoid potential algorithm"
		 " mismatch problems\n"));

      if(!opt.batch)
	{
	  STRLIST sl=NULL,locusr=NULL;
	  size_t fprlen=0;
	  byte fpr[MAX_FINGERPRINT_LEN],*p;
	  char username[(MAX_FINGERPRINT_LEN*2)+1];
	  unsigned int i;

	  p=fingerprint_from_pk(pk,fpr,&fprlen);
	  for(i=0;i<fprlen;i++,p++)
	    sprintf(username+2*i,"%02X",*p);
	  add_to_strlist(&locusr,username);

	  append_to_strlist(&sl,"updpref");
	  append_to_strlist(&sl,"save");

	  keyedit_menu( username, locusr, sl, 1, 1 );
	  free_strlist(sl);
	  free_strlist(locusr);
	}
      else if(!opt.quiet)
	log_info(_("you can update your preferences with:"
		   " gpg --edit-key %s updpref save\n"),keystr_from_pk(pk));
    }
}

/****************
 * Try to import one keyblock.	Return an error only in serious cases, but
 * never for an invalid keyblock.  It uses log_error to increase the
 * internal errorcount, so that invalid input can be detected by programs
 * which called g10.
 */
static int
import_one( const char *fname, KBNODE keyblock, struct stats_s *stats,
	    unsigned char **fpr,size_t *fpr_len,unsigned int options,
	    int from_sk )
{
    PKT_public_key *pk;
    PKT_public_key *pk_orig;
    KBNODE node, uidnode;
    KBNODE keyblock_orig = NULL;
    u32 keyid[2];
    int rc = 0;
    int new_key = 0;
    int mod_key = 0;
    int non_self = 0;

    /* get the key and print some info about it */
    node = find_kbnode( keyblock, PKT_PUBLIC_KEY );
    if( !node )
	BUG();

    pk = node->pkt->pkt.public_key;

    keyid_from_pk( pk, keyid );
    uidnode = find_next_kbnode( keyblock, PKT_USER_ID );

    if( opt.verbose && !opt.interactive )
      {
	log_info( "pub  %4u%c/%s %s  ",
		  nbits_from_pk( pk ),
		  pubkey_letter( pk->pubkey_algo ),
		  keystr_from_pk(pk), datestr_from_pk(pk) );
	if( uidnode )
	  print_utf8_string( stderr, uidnode->pkt->pkt.user_id->name,
			     uidnode->pkt->pkt.user_id->len );
	putc('\n', stderr);
      }

    if( !uidnode )
      {
	log_error( _("key %s: no user ID\n"), keystr_from_pk(pk));
	return 0;
      }
    
    if (opt.interactive) {
        if(is_status_enabled())
	  print_import_check (pk, uidnode->pkt->pkt.user_id);
	merge_keys_and_selfsig (keyblock);
        tty_printf ("\n");
        show_basic_key_info (keyblock);
        tty_printf ("\n");
        if (!cpr_get_answer_is_yes ("import.okay",
                                    "Do you want to import this key? (y/N) "))
            return 0;
    }

    collapse_uids(&keyblock);

    /* Clean the key that we're about to import, to cut down on things
       that we have to clean later.  This has no practical impact on
       the end result, but does result in less logging which might
       confuse the user. */
    if(options&IMPORT_CLEAN)
      clean_key(keyblock,opt.verbose,options&IMPORT_MINIMAL,NULL,NULL);

    clear_kbnode_flags( keyblock );

    if((options&IMPORT_REPAIR_PKS_SUBKEY_BUG) && fix_pks_corruption(keyblock)
       && opt.verbose)
      log_info(_("key %s: PKS subkey corruption repaired\n"),
	       keystr_from_pk(pk));

    rc = chk_self_sigs( fname, keyblock , pk, keyid, &non_self );
    if( rc )
	return rc== -1? 0:rc;

    /* If we allow such a thing, mark unsigned uids as valid */
    if( opt.allow_non_selfsigned_uid )
      for( node=keyblock; node; node = node->next )
	if( node->pkt->pkttype == PKT_USER_ID && !(node->flag & 1) )
	  {
	    char *user=utf8_to_native(node->pkt->pkt.user_id->name,
				      node->pkt->pkt.user_id->len,0);
	    node->flag |= 1;
	    log_info( _("key %s: accepted non self-signed user ID \"%s\"\n"),
		      keystr_from_pk(pk),user);
	    xfree(user);
	  }

    if( !delete_inv_parts( fname, keyblock, keyid, options ) ) {
        log_error( _("key %s: no valid user IDs\n"), keystr_from_pk(pk));
	if( !opt.quiet )
	  log_info(_("this may be caused by a missing self-signature\n"));
	stats->no_user_id++;
	return 0;
    }

    /* do we have this key already in one of our pubrings ? */
    pk_orig = xmalloc_clear( sizeof *pk_orig );
    rc = get_pubkey_fast ( pk_orig, keyid );
    if( rc && rc != G10ERR_NO_PUBKEY && rc != G10ERR_UNU_PUBKEY )
      {
	log_error( _("key %s: public key not found: %s\n"),
		   keystr(keyid), g10_errstr(rc));
      }
    else if ( rc && (opt.import_options&IMPORT_MERGE_ONLY) )
      {
	if( opt.verbose )
	  log_info( _("key %s: new key - skipped\n"), keystr(keyid));
	rc = 0;
	stats->skipped_new_keys++;
      }
    else if( rc ) { /* insert this key */
        KEYDB_HANDLE hd = keydb_new (0);

        rc = keydb_locate_writable (hd, NULL);
	if (rc) {
	    log_error (_("no writable keyring found: %s\n"), g10_errstr (rc));
            keydb_release (hd);
	    return G10ERR_GENERAL;
	}
	if( opt.verbose > 1 )
	    log_info (_("writing to `%s'\n"), keydb_get_resource_name (hd) );

	rc = keydb_insert_keyblock (hd, keyblock );
        if (rc)
	   log_error (_("error writing keyring `%s': %s\n"),
		       keydb_get_resource_name (hd), g10_errstr(rc));
	else
	  {
	    /* This should not be possible since we delete the
	       ownertrust when a key is deleted, but it can happen if
	       the keyring and trustdb are out of sync.  It can also
	       be made to happen with the trusted-key command. */

	    clear_ownertrusts (pk);
	    if(non_self)
	      revalidation_mark ();
	  }
        keydb_release (hd);

	/* we are ready */
	if( !opt.quiet )
	  {
	    char *p=get_user_id_native (keyid);
	    log_info( _("key %s: public key \"%s\" imported\n"),
		      keystr(keyid),p);
	    xfree(p);
	  }
	if( is_status_enabled() )
	  {
	    char *us = get_long_user_id_string( keyid );
	    write_status_text( STATUS_IMPORTED, us );
	    xfree(us);
            print_import_ok (pk,NULL, 1);
	  }
	stats->imported++;
	if( is_RSA( pk->pubkey_algo ) )
	    stats->imported_rsa++;
	new_key = 1;
    }
    else { /* merge */
        KEYDB_HANDLE hd;
	int n_uids, n_sigs, n_subk, n_sigs_cleaned, n_uids_cleaned;

	/* Compare the original against the new key; just to be sure nothing
	 * weird is going on */
	if( cmp_public_keys( pk_orig, pk ) )
	  {
	    log_error( _("key %s: doesn't match our copy\n"),keystr(keyid));
	    goto leave;
	  }

	/* now read the original keyblock */
        hd = keydb_new (0);
        {
            byte afp[MAX_FINGERPRINT_LEN];
            size_t an;

            fingerprint_from_pk (pk_orig, afp, &an);
            while (an < MAX_FINGERPRINT_LEN) 
                afp[an++] = 0;
            rc = keydb_search_fpr (hd, afp);
        }
	if( rc )
	  {
	    log_error (_("key %s: can't locate original keyblock: %s\n"),
		       keystr(keyid), g10_errstr(rc));
            keydb_release (hd);
	    goto leave;
	  }
	rc = keydb_get_keyblock (hd, &keyblock_orig );
	if (rc)
	  {
	    log_error (_("key %s: can't read original keyblock: %s\n"),
		       keystr(keyid), g10_errstr(rc));
            keydb_release (hd);
	    goto leave;
	  }

	/* and try to merge the block */
	clear_kbnode_flags( keyblock_orig );
	clear_kbnode_flags( keyblock );
	n_uids = n_sigs = n_subk = n_sigs_cleaned = n_uids_cleaned = 0;
	rc = merge_blocks( fname, keyblock_orig, keyblock,
			   keyid, &n_uids, &n_sigs, &n_subk );
	if( rc )
	  {
            keydb_release (hd);
	    goto leave;
	  }

	if(options&IMPORT_CLEAN)
	  clean_key(keyblock_orig,opt.verbose,options&IMPORT_MINIMAL,
		    &n_uids_cleaned,&n_sigs_cleaned);

	if( n_uids || n_sigs || n_subk || n_sigs_cleaned || n_uids_cleaned) {
	    mod_key = 1;
	    /* keyblock_orig has been updated; write */
	    rc = keydb_update_keyblock (hd, keyblock_orig);
            if (rc)
		log_error (_("error writing keyring `%s': %s\n"),
			     keydb_get_resource_name (hd), g10_errstr(rc) );
	    else if(non_self)
	      revalidation_mark ();

	    /* we are ready */
	    if( !opt.quiet )
	      {
	        char *p=get_user_id_native(keyid);
		if( n_uids == 1 )
		  log_info( _("key %s: \"%s\" 1 new user ID\n"),
			   keystr(keyid),p);
		else if( n_uids )
		  log_info( _("key %s: \"%s\" %d new user IDs\n"),
			    keystr(keyid),p,n_uids);
		if( n_sigs == 1 )
		  log_info( _("key %s: \"%s\" 1 new signature\n"),
			    keystr(keyid), p);
		else if( n_sigs )
		  log_info( _("key %s: \"%s\" %d new signatures\n"),
			    keystr(keyid), p, n_sigs );
		if( n_subk == 1 )
		  log_info( _("key %s: \"%s\" 1 new subkey\n"),
			    keystr(keyid), p);
		else if( n_subk )
		  log_info( _("key %s: \"%s\" %d new subkeys\n"),
			    keystr(keyid), p, n_subk );
		if(n_sigs_cleaned==1)
		  log_info(_("key %s: \"%s\" %d signature cleaned\n"),
			   keystr(keyid),p,n_sigs_cleaned);
		else if(n_sigs_cleaned)
		  log_info(_("key %s: \"%s\" %d signatures cleaned\n"),
			   keystr(keyid),p,n_sigs_cleaned);
		if(n_uids_cleaned==1)
		  log_info(_("key %s: \"%s\" %d user ID cleaned\n"),
			   keystr(keyid),p,n_uids_cleaned);
		else if(n_uids_cleaned)
		  log_info(_("key %s: \"%s\" %d user IDs cleaned\n"),
			   keystr(keyid),p,n_uids_cleaned);
		xfree(p);
	      }

	    stats->n_uids +=n_uids;
	    stats->n_sigs +=n_sigs;
	    stats->n_subk +=n_subk;
	    stats->n_sigs_cleaned +=n_sigs_cleaned;
	    stats->n_uids_cleaned +=n_uids_cleaned;

            if (is_status_enabled ()) 
                 print_import_ok (pk, NULL,
                                  ((n_uids?2:0)|(n_sigs?4:0)|(n_subk?8:0)));
	}
	else
	  {
	    if (is_status_enabled ()) 
	      print_import_ok (pk, NULL, 0);

	    if( !opt.quiet )
	      {
		char *p=get_user_id_native(keyid);
		log_info( _("key %s: \"%s\" not changed\n"),keystr(keyid),p);
		xfree(p);
	      }

	    stats->unchanged++;
	  }

        keydb_release (hd); hd = NULL;
    }

  leave:

    /* Now that the key is definitely incorporated into the keydb, we
       need to check if a designated revocation is present or if the
       prefs are not rational so we can warn the user. */

    if(mod_key)
      {
	revocation_present(keyblock_orig);
	if(!from_sk && seckey_available(keyid)==0)
	  check_prefs(keyblock_orig);
      }
    else if(new_key)
      {
	/* A little explanation for this: we fill in the fingerprint
	   when importing keys as it can be useful to know the
	   fingerprint in certain keyserver-related cases (a keyserver
	   asked for a particular name, but the key doesn't have that
	   name).  However, in cases where we're importing more than
	   one key at a time, we cannot know which key to fingerprint.
	   In these cases, rather than guessing, we do not fingerpring
	   at all, and we must hope the user ID on the keys are
	   useful. */
	if(fpr)
	  {
	    xfree(*fpr);
	    if(stats->imported==1)
	      *fpr=fingerprint_from_pk(pk,NULL,fpr_len);
	    else
	      *fpr=NULL;
	  }

	revocation_present(keyblock);
	if(!from_sk && seckey_available(keyid)==0)
	  check_prefs(keyblock);
      }

    release_kbnode( keyblock_orig );
    free_public_key( pk_orig );

    return rc;
}

/* Walk a secret keyblock and produce a public keyblock out of it. */
static KBNODE
sec_to_pub_keyblock(KBNODE sec_keyblock)
{
  KBNODE secnode,pub_keyblock=NULL,ctx=NULL;

  while((secnode=walk_kbnode(sec_keyblock,&ctx,0)))
    {
      KBNODE pubnode;

      if(secnode->pkt->pkttype==PKT_SECRET_KEY ||
	 secnode->pkt->pkttype==PKT_SECRET_SUBKEY)
	{
	  /* Make a public key.  We only need to convert enough to
	     write the keyblock out. */

	  PKT_secret_key *sk=secnode->pkt->pkt.secret_key;
	  PACKET *pkt=xmalloc_clear(sizeof(PACKET));
	  PKT_public_key *pk=xmalloc_clear(sizeof(PKT_public_key));
	  int n;

	  if(secnode->pkt->pkttype==PKT_SECRET_KEY)
	    pkt->pkttype=PKT_PUBLIC_KEY;
	  else
	    pkt->pkttype=PKT_PUBLIC_SUBKEY;

	  pkt->pkt.public_key=pk;

	  pk->version=sk->version;
	  pk->timestamp=sk->timestamp;
	  pk->expiredate=sk->expiredate;
	  pk->pubkey_algo=sk->pubkey_algo;

	  n=pubkey_get_npkey(pk->pubkey_algo);
	  if(n==0)
	    {
	      /* we can't properly extract the pubkey without knowing
		 the number of MPIs */
	      release_kbnode(pub_keyblock);
	      return NULL;
	    }
	  else
	    {
	      int i;

	      for(i=0;i<n;i++)
		pk->pkey[i]=mpi_copy(sk->skey[i]);
	    }

	  pubnode=new_kbnode(pkt);
	}
      else
	{
	  pubnode=clone_kbnode(secnode);
	}

      if(pub_keyblock==NULL)
	pub_keyblock=pubnode;
      else
	add_kbnode(pub_keyblock,pubnode);
    }

  return pub_keyblock;
}

/****************
 * Ditto for secret keys.  Handling is simpler than for public keys.
 * We allow secret key importing only when allow is true, this is so
 * that a secret key can not be imported accidently and thereby tampering
 * with the trust calculation.
 */
static int
import_secret_one( const char *fname, KBNODE keyblock, 
                   struct stats_s *stats, unsigned int options)
{
    PKT_secret_key *sk;
    KBNODE node, uidnode;
    u32 keyid[2];
    int rc = 0;

    /* get the key and print some info about it */
    node = find_kbnode( keyblock, PKT_SECRET_KEY );
    if( !node )
	BUG();

    sk = node->pkt->pkt.secret_key;
    keyid_from_sk( sk, keyid );
    uidnode = find_next_kbnode( keyblock, PKT_USER_ID );

    if( opt.verbose )
      {
	log_info( "sec  %4u%c/%s %s   ",
		  nbits_from_sk( sk ),
		  pubkey_letter( sk->pubkey_algo ),
		  keystr_from_sk(sk), datestr_from_sk(sk) );
	if( uidnode )
	  print_utf8_string( stderr, uidnode->pkt->pkt.user_id->name,
			     uidnode->pkt->pkt.user_id->len );
	putc('\n', stderr);
      }
    stats->secret_read++;

    if( !uidnode )
      {
	log_error( _("key %s: no user ID\n"), keystr_from_sk(sk));
	return 0;
      }

    if(sk->protect.algo>110)
      {
	log_error(_("key %s: secret key with invalid cipher %d"
		    " - skipped\n"),keystr_from_sk(sk),sk->protect.algo);
	return 0;
      }

#ifdef ENABLE_SELINUX_HACKS
    if (1)
      {
        /* We don't allow to import secret keys because that may be used
           to put a secret key into the keyring and the user might later
           be tricked into signing stuff with that key.  */
        log_error (_("importing secret keys not allowed\n"));
        return 0;
      }
#endif 
    
    clear_kbnode_flags( keyblock );

    /* do we have this key already in one of our secrings ? */
    rc = seckey_available( keyid );
    if( rc == G10ERR_NO_SECKEY && !(opt.import_options&IMPORT_MERGE_ONLY) )
      {
	/* simply insert this key */
        KEYDB_HANDLE hd = keydb_new (1);

	/* get default resource */
        rc = keydb_locate_writable (hd, NULL);
	if (rc) {
	  log_error (_("no default secret keyring: %s\n"), g10_errstr (rc));
	  keydb_release (hd);
	  return G10ERR_GENERAL;
	}
	rc = keydb_insert_keyblock (hd, keyblock );
        if (rc)
	  log_error (_("error writing keyring `%s': %s\n"),
		     keydb_get_resource_name (hd), g10_errstr(rc) );
        keydb_release (hd);
	/* we are ready */
	if( !opt.quiet )
	  log_info( _("key %s: secret key imported\n"), keystr_from_sk(sk));
	stats->secret_imported++;
        if (is_status_enabled ()) 
	  print_import_ok (NULL, sk, 1|16);

	if(options&IMPORT_SK2PK)
	  {
	    /* Try and make a public key out of this. */

	    KBNODE pub_keyblock=sec_to_pub_keyblock(keyblock);
	    if(pub_keyblock)
	      {
		import_one(fname,pub_keyblock,stats,
			   NULL,NULL,opt.import_options,1);
		release_kbnode(pub_keyblock);
	      }
	  }

	/* Now that the key is definitely incorporated into the keydb,
	   if we have the public part of this key, we need to check if
	   the prefs are rational. */
	node=get_pubkeyblock(keyid);
	if(node)
	  {
	    check_prefs(node);
	    release_kbnode(node);
	  }
      }
    else if( !rc )
      { /* we can't merge secret keys */
	log_error( _("key %s: already in secret keyring\n"),
		   keystr_from_sk(sk));
	stats->secret_dups++;
        if (is_status_enabled ()) 
	  print_import_ok (NULL, sk, 16);

	/* TODO: if we ever do merge secret keys, make sure to handle
	   the sec_to_pub_keyblock feature as well. */
      }
    else
      log_error( _("key %s: secret key not found: %s\n"),
		 keystr_from_sk(sk), g10_errstr(rc));

    return rc;
}


/****************
 * Import a revocation certificate; this is a single signature packet.
 */
static int
import_revoke_cert( const char *fname, KBNODE node, struct stats_s *stats )
{
    PKT_public_key *pk=NULL;
    KBNODE onode, keyblock = NULL;
    KEYDB_HANDLE hd = NULL;
    u32 keyid[2];
    int rc = 0;

    assert( !node->next );
    assert( node->pkt->pkttype == PKT_SIGNATURE );
    assert( node->pkt->pkt.signature->sig_class == 0x20 );

    keyid[0] = node->pkt->pkt.signature->keyid[0];
    keyid[1] = node->pkt->pkt.signature->keyid[1];

    pk = xmalloc_clear( sizeof *pk );
    rc = get_pubkey( pk, keyid );
    if( rc == G10ERR_NO_PUBKEY )
      {
	log_error(_("key %s: no public key -"
		    " can't apply revocation certificate\n"), keystr(keyid));
	rc = 0;
	goto leave;
      }
    else if( rc )
      {
	log_error(_("key %s: public key not found: %s\n"),
		  keystr(keyid), g10_errstr(rc));
	goto leave;
      }

    /* read the original keyblock */
    hd = keydb_new (0);
    {
        byte afp[MAX_FINGERPRINT_LEN];
        size_t an;
        
        fingerprint_from_pk (pk, afp, &an);
        while (an < MAX_FINGERPRINT_LEN) 
            afp[an++] = 0;
        rc = keydb_search_fpr (hd, afp);
    }
    if (rc)
      {
	log_error (_("key %s: can't locate original keyblock: %s\n"),
                   keystr(keyid), g10_errstr(rc));
	goto leave;
      }
    rc = keydb_get_keyblock (hd, &keyblock );
    if (rc)
      {
	log_error (_("key %s: can't read original keyblock: %s\n"),
                   keystr(keyid), g10_errstr(rc));
	goto leave;
      }

    /* it is okay, that node is not in keyblock because
     * check_key_signature works fine for sig_class 0x20 in this
     * special case. */
    rc = check_key_signature( keyblock, node, NULL);
    if( rc )
      {
	log_error( _("key %s: invalid revocation certificate"
		     ": %s - rejected\n"), keystr(keyid), g10_errstr(rc));
	goto leave;
      }

    /* check whether we already have this */
    for(onode=keyblock->next; onode; onode=onode->next ) {
	if( onode->pkt->pkttype == PKT_USER_ID )
	    break;
	else if( onode->pkt->pkttype == PKT_SIGNATURE
		 && !cmp_signatures(node->pkt->pkt.signature,
				    onode->pkt->pkt.signature))
	  {
	    rc = 0;
	    goto leave; /* yes, we already know about it */
	  }
    }


    /* insert it */
    insert_kbnode( keyblock, clone_kbnode(node), 0 );

    /* and write the keyblock back */
    rc = keydb_update_keyblock (hd, keyblock );
    if (rc)
	log_error (_("error writing keyring `%s': %s\n"),
                   keydb_get_resource_name (hd), g10_errstr(rc) );
    keydb_release (hd); hd = NULL;
    /* we are ready */
    if( !opt.quiet )
      {
        char *p=get_user_id_native (keyid);
	log_info( _("key %s: \"%s\" revocation certificate imported\n"),
		  keystr(keyid),p);
	xfree(p);
      }
    stats->n_revoc++;

    /* If the key we just revoked was ultimately trusted, remove its
       ultimate trust.  This doesn't stop the user from putting the
       ultimate trust back, but is a reasonable solution for now. */
    if(get_ownertrust(pk)==TRUST_ULTIMATE)
      clear_ownertrusts(pk);

    revalidation_mark ();

  leave:
    keydb_release (hd);
    release_kbnode( keyblock );
    free_public_key( pk );
    return rc;
}


/****************
 * loop over the keyblock and check all self signatures.
 * Mark all user-ids with a self-signature by setting flag bit 0.
 * Mark all user-ids with an invalid self-signature by setting bit 1.
 * This works also for subkeys, here the subkey is marked.  Invalid or
 * extra subkey sigs (binding or revocation) are marked for deletion.
 * non_self is set to true if there are any sigs other than self-sigs
 * in this keyblock.
 */
static int
chk_self_sigs( const char *fname, KBNODE keyblock,
	       PKT_public_key *pk, u32 *keyid, int *non_self )
{
    KBNODE n,knode=NULL;
    PKT_signature *sig;
    int rc;
    u32 bsdate=0,rsdate=0;
    KBNODE bsnode=NULL,rsnode=NULL;

    for( n=keyblock; (n = find_next_kbnode(n, 0)); ) {
      if(n->pkt->pkttype==PKT_PUBLIC_SUBKEY)
	{
	  knode=n;
	  bsdate=0;
	  rsdate=0;
	  bsnode=NULL;
	  rsnode=NULL;
	  continue;
	}
      else if( n->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	sig = n->pkt->pkt.signature;
	if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] ) {

	    /* This just caches the sigs for later use.  That way we
	       import a fully-cached key which speeds things up. */
	    if(!opt.no_sig_cache)
	      check_key_signature(keyblock,n,NULL);

	    if( IS_UID_SIG(sig) || IS_UID_REV(sig) )
	      {
		KBNODE unode = find_prev_kbnode( keyblock, n, PKT_USER_ID );
		if( !unode )
		  {
		    log_error( _("key %s: no user ID for signature\n"),
			       keystr(keyid));
		    return -1;	/* the complete keyblock is invalid */
		  }

		/* If it hasn't been marked valid yet, keep trying */
		if(!(unode->flag&1)) {
		  rc = check_key_signature( keyblock, n, NULL);
		  if( rc )
		    {
		      if( opt.verbose )
			{
			  char *p=utf8_to_native(unode->pkt->pkt.user_id->name,
				      strlen(unode->pkt->pkt.user_id->name),0);
			  log_info( rc == G10ERR_PUBKEY_ALGO ?
				    _("key %s: unsupported public key "
				      "algorithm on user ID \"%s\"\n"):
				    _("key %s: invalid self-signature "
				      "on user ID \"%s\"\n"),
				    keystr(keyid),p);
			  xfree(p);
			}
		    }
		  else
		    unode->flag |= 1; /* mark that signature checked */
		}
	      }
	    else if( sig->sig_class == 0x18 ) {
	      /* Note that this works based solely on the timestamps
		 like the rest of gpg.  If the standard gets
		 revocation targets, this may need to be revised. */

		if( !knode )
		  {
		    if(opt.verbose)
		      log_info( _("key %s: no subkey for key binding\n"),
				keystr(keyid));
		    n->flag |= 4; /* delete this */
		  }
		else
		  {
		    rc = check_key_signature( keyblock, n, NULL);
		    if( rc )
		      {
			if(opt.verbose)
			  log_info(rc == G10ERR_PUBKEY_ALGO ?
				   _("key %s: unsupported public key"
				     " algorithm\n"):
				   _("key %s: invalid subkey binding\n"),
				   keystr(keyid));
			n->flag|=4;
		      }
		    else
		      {
			/* It's valid, so is it newer? */
			if(sig->timestamp>=bsdate) {
			  knode->flag |= 1;  /* the subkey is valid */
			  if(bsnode)
			    {
			      bsnode->flag|=4; /* Delete the last binding
						  sig since this one is
						  newer */
			      if(opt.verbose)
				log_info(_("key %s: removed multiple subkey"
					   " binding\n"),keystr(keyid));
			    }

			  bsnode=n;
			  bsdate=sig->timestamp;
			}
			else
			  n->flag|=4; /* older */
		      }
		  }
	    }
	    else if( sig->sig_class == 0x28 ) {
	      /* We don't actually mark the subkey as revoked right
                 now, so just check that the revocation sig is the
                 most recent valid one.  Note that we don't care if
                 the binding sig is newer than the revocation sig.
                 See the comment in getkey.c:merge_selfsigs_subkey for
                 more */
		if( !knode )
		  {
		    if(opt.verbose)
		      log_info( _("key %s: no subkey for key revocation\n"),
				keystr(keyid));
		    n->flag |= 4; /* delete this */
		  }
		else
		  {
		    rc = check_key_signature( keyblock, n, NULL);
		    if( rc )
		      {
			if(opt.verbose)
			  log_info(rc == G10ERR_PUBKEY_ALGO ?
				   _("key %s: unsupported public"
				     " key algorithm\n"):
				   _("key %s: invalid subkey revocation\n"),
				   keystr(keyid));
			n->flag|=4;
		      }
		    else
		      {
			/* It's valid, so is it newer? */
			if(sig->timestamp>=rsdate)
			  {
			    if(rsnode)
			      {
				rsnode->flag|=4; /* Delete the last revocation
						    sig since this one is
						    newer */
				if(opt.verbose)
				  log_info(_("key %s: removed multiple subkey"
					     " revocation\n"),keystr(keyid));
			      }

			    rsnode=n;
			    rsdate=sig->timestamp;
			  }
			else
			  n->flag|=4; /* older */
		      }
		  }
	    }
	}
	else
	  *non_self=1;
    }

    return 0;
}

/****************
 * delete all parts which are invalid and those signatures whose
 * public key algorithm is not available in this implemenation;
 * but consider RSA as valid, because parse/build_packets knows
 * about it.
 * returns: true if at least one valid user-id is left over.
 */
static int
delete_inv_parts( const char *fname, KBNODE keyblock,
		  u32 *keyid, unsigned int options)
{
    KBNODE node;
    int nvalid=0, uid_seen=0, subkey_seen=0;

    for(node=keyblock->next; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    uid_seen = 1;
	    if( (node->flag & 2) || !(node->flag & 1) ) {
		if( opt.verbose )
		  {
		    char *p=utf8_to_native(node->pkt->pkt.user_id->name,
					   node->pkt->pkt.user_id->len,0);
		    log_info( _("key %s: skipped user ID \"%s\"\n"),
			      keystr(keyid),p);
		    xfree(p);
		  }
		delete_kbnode( node ); /* the user-id */
		/* and all following packets up to the next user-id */
		while( node->next
		       && node->next->pkt->pkttype != PKT_USER_ID
		       && node->next->pkt->pkttype != PKT_PUBLIC_SUBKEY
		       && node->next->pkt->pkttype != PKT_SECRET_SUBKEY ){
		    delete_kbnode( node->next );
		    node = node->next;
		}
	    }
	    else
		nvalid++;
	}
	else if(    node->pkt->pkttype == PKT_PUBLIC_SUBKEY
		 || node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    if( (node->flag & 2) || !(node->flag & 1) ) {
		if( opt.verbose )
		  log_info( _("key %s: skipped subkey\n"),keystr(keyid));

		delete_kbnode( node ); /* the subkey */
		/* and all following signature packets */
		while( node->next
		       && node->next->pkt->pkttype == PKT_SIGNATURE ) {
		    delete_kbnode( node->next );
		    node = node->next;
		}
	    }
	    else
	      subkey_seen = 1;
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE
		 && check_pubkey_algo( node->pkt->pkt.signature->pubkey_algo)
		 && node->pkt->pkt.signature->pubkey_algo != PUBKEY_ALGO_RSA )
	    delete_kbnode( node ); /* build_packet() can't handle this */
	else if( node->pkt->pkttype == PKT_SIGNATURE &&
		 !node->pkt->pkt.signature->flags.exportable &&
		 !(options&IMPORT_LOCAL_SIGS) &&
		 seckey_available( node->pkt->pkt.signature->keyid ) )
	  {
	    /* here we violate the rfc a bit by still allowing
	     * to import non-exportable signature when we have the
	     * the secret key used to create this signature - it
	     * seems that this makes sense */
	    if(opt.verbose)
	      log_info( _("key %s: non exportable signature"
			  " (class 0x%02X) - skipped\n"),
			keystr(keyid), node->pkt->pkt.signature->sig_class );
	    delete_kbnode( node );
	  }
	else if( node->pkt->pkttype == PKT_SIGNATURE
		 && node->pkt->pkt.signature->sig_class == 0x20 )  {
	    if( uid_seen )
	      {
	        if(opt.verbose)
		  log_info( _("key %s: revocation certificate"
			      " at wrong place - skipped\n"),keystr(keyid));
		delete_kbnode( node );
	      }
	    else {
	      /* If the revocation cert is from a different key than
                 the one we're working on don't check it - it's
                 probably from a revocation key and won't be
                 verifiable with this key anyway. */

	      if(node->pkt->pkt.signature->keyid[0]==keyid[0] &&
		 node->pkt->pkt.signature->keyid[1]==keyid[1])
		{
		  int rc = check_key_signature( keyblock, node, NULL);
		  if( rc )
		    {
		      if(opt.verbose)
			log_info( _("key %s: invalid revocation"
				    " certificate: %s - skipped\n"),
				  keystr(keyid), g10_errstr(rc));
		      delete_kbnode( node );
		    }
		}
	    }
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE &&
		 (node->pkt->pkt.signature->sig_class == 0x18 ||
		  node->pkt->pkt.signature->sig_class == 0x28) &&
		 !subkey_seen )
	  {
	    if(opt.verbose)
	      log_info( _("key %s: subkey signature"
			  " in wrong place - skipped\n"), keystr(keyid));
	    delete_kbnode( node );
	  }
	else if( node->pkt->pkttype == PKT_SIGNATURE
		 && !IS_CERT(node->pkt->pkt.signature))
	  {
	    if(opt.verbose)
	      log_info(_("key %s: unexpected signature class (0x%02X) -"
			 " skipped\n"),keystr(keyid),
		       node->pkt->pkt.signature->sig_class);
	    delete_kbnode(node);
	  }
	else if( (node->flag & 4) ) /* marked for deletion */
	  delete_kbnode( node );
    }

    /* note: because keyblock is the public key, it is never marked
     * for deletion and so keyblock cannot change */
    commit_kbnode( &keyblock );
    return nvalid;
}


/****************
 * It may happen that the imported keyblock has duplicated user IDs.
 * We check this here and collapse those user IDs together with their
 * sigs into one.
 * Returns: True if the keyblock has changed.
 */
int
collapse_uids( KBNODE *keyblock )
{
  KBNODE uid1;
  int any=0;

  for(uid1=*keyblock;uid1;uid1=uid1->next)
    {
      KBNODE uid2;

      if(is_deleted_kbnode(uid1))
	continue;

      if(uid1->pkt->pkttype!=PKT_USER_ID)
	continue;

      for(uid2=uid1->next;uid2;uid2=uid2->next)
	{
	  if(is_deleted_kbnode(uid2))
	    continue;

	  if(uid2->pkt->pkttype!=PKT_USER_ID)
	    continue;

	  if(cmp_user_ids(uid1->pkt->pkt.user_id,
			  uid2->pkt->pkt.user_id)==0)
	    {
	      /* We have a duplicated uid */
	      KBNODE sig1,last;

	      any=1;

	      /* Now take uid2's signatures, and attach them to
		 uid1 */
	      for(last=uid2;last->next;last=last->next)
		{
		  if(is_deleted_kbnode(last))
		    continue;

		  if(last->next->pkt->pkttype==PKT_USER_ID
		     || last->next->pkt->pkttype==PKT_PUBLIC_SUBKEY
		     || last->next->pkt->pkttype==PKT_SECRET_SUBKEY)
		    break;
		}

	      /* Snip out uid2 */
	      (find_prev_kbnode(*keyblock,uid2,0))->next=last->next;

	      /* Now put uid2 in place as part of uid1 */
	      last->next=uid1->next;
	      uid1->next=uid2;
	      delete_kbnode(uid2);

	      /* Now dedupe uid1 */
	      for(sig1=uid1->next;sig1;sig1=sig1->next)
		{
		  KBNODE sig2;

		  if(is_deleted_kbnode(sig1))
		    continue;

		  if(sig1->pkt->pkttype==PKT_USER_ID
		     || sig1->pkt->pkttype==PKT_PUBLIC_SUBKEY
		     || sig1->pkt->pkttype==PKT_SECRET_SUBKEY)
		    break;

		  if(sig1->pkt->pkttype!=PKT_SIGNATURE)
		    continue;

		  for(sig2=sig1->next,last=sig1;sig2;last=sig2,sig2=sig2->next)
		    {
		      if(is_deleted_kbnode(sig2))
			continue;

		      if(sig2->pkt->pkttype==PKT_USER_ID
			 || sig2->pkt->pkttype==PKT_PUBLIC_SUBKEY
			 || sig2->pkt->pkttype==PKT_SECRET_SUBKEY)
			break;

		      if(sig2->pkt->pkttype!=PKT_SIGNATURE)
			continue;

		      if(cmp_signatures(sig1->pkt->pkt.signature,
					sig2->pkt->pkt.signature)==0)
			{
			  /* We have a match, so delete the second
			     signature */
			  delete_kbnode(sig2);
			  sig2=last;
			}
		    }
		}
	    }
	}
    }

  commit_kbnode(keyblock);

  if(any && !opt.quiet)
    {
      const char *key="???";

      if( (uid1=find_kbnode( *keyblock, PKT_PUBLIC_KEY )) )
	key=keystr_from_pk(uid1->pkt->pkt.public_key);
      else if( (uid1 = find_kbnode( *keyblock, PKT_SECRET_KEY )) )
	key=keystr_from_sk(uid1->pkt->pkt.secret_key);

      log_info(_("key %s: duplicated user ID detected - merged\n"),key);
    }

  return any;
}

/* Check for a 0x20 revocation from a revocation key that is not
   present.  This may be called without the benefit of merge_xxxx so
   you can't rely on pk->revkey and friends. */
static void
revocation_present(KBNODE keyblock)
{
  KBNODE onode,inode;
  PKT_public_key *pk=keyblock->pkt->pkt.public_key;

  for(onode=keyblock->next;onode;onode=onode->next)
    {
      /* If we reach user IDs, we're done. */
      if(onode->pkt->pkttype==PKT_USER_ID)
	break;

      if(onode->pkt->pkttype==PKT_SIGNATURE &&
	 onode->pkt->pkt.signature->sig_class==0x1F &&
	 onode->pkt->pkt.signature->revkey)
	{
	  int idx;
	  PKT_signature *sig=onode->pkt->pkt.signature;

	  for(idx=0;idx<sig->numrevkeys;idx++)
	    {
	      u32 keyid[2];

	      keyid_from_fingerprint(sig->revkey[idx]->fpr,
				     MAX_FINGERPRINT_LEN,keyid);

	      for(inode=keyblock->next;inode;inode=inode->next)
		{
		  /* If we reach user IDs, we're done. */
		  if(inode->pkt->pkttype==PKT_USER_ID)
		    break;

		  if(inode->pkt->pkttype==PKT_SIGNATURE &&
		     inode->pkt->pkt.signature->sig_class==0x20 &&
		     inode->pkt->pkt.signature->keyid[0]==keyid[0] &&
		     inode->pkt->pkt.signature->keyid[1]==keyid[1])
		    {
		      /* Okay, we have a revocation key, and a
                         revocation issued by it.  Do we have the key
                         itself? */
		      int rc;

		      rc=get_pubkey_byfprint_fast (NULL,sig->revkey[idx]->fpr,
                                                   MAX_FINGERPRINT_LEN);
		      if(rc==G10ERR_NO_PUBKEY || rc==G10ERR_UNU_PUBKEY)
			{
			  char *tempkeystr=xstrdup(keystr_from_pk(pk));

			  /* No, so try and get it */
			  if(opt.keyserver
			     && (opt.keyserver_options.options
				 & KEYSERVER_AUTO_KEY_RETRIEVE))
			    {
			      log_info(_("WARNING: key %s may be revoked:"
					 " fetching revocation key %s\n"),
				       tempkeystr,keystr(keyid));
			      keyserver_import_fprint(sig->revkey[idx]->fpr,
						      MAX_FINGERPRINT_LEN,
						      opt.keyserver);

			      /* Do we have it now? */
			      rc=get_pubkey_byfprint_fast (NULL,
						     sig->revkey[idx]->fpr,
						     MAX_FINGERPRINT_LEN);
			    }

			  if(rc==G10ERR_NO_PUBKEY || rc==G10ERR_UNU_PUBKEY)
			    log_info(_("WARNING: key %s may be revoked:"
				       " revocation key %s not present.\n"),
				     tempkeystr,keystr(keyid));

			  xfree(tempkeystr);
			}
		    }
		}
	    }
	}
    }
}

/****************
 * compare and merge the blocks
 *
 * o compare the signatures: If we already have this signature, check
 *   that they compare okay; if not, issue a warning and ask the user.
 * o Simply add the signature.	Can't verify here because we may not have
 *   the signature's public key yet; verification is done when putting it
 *   into the trustdb, which is done automagically as soon as this pubkey
 *   is used.
 * Note: We indicate newly inserted packets with flag bit 0
 */
static int
merge_blocks( const char *fname, KBNODE keyblock_orig, KBNODE keyblock,
	      u32 *keyid, int *n_uids, int *n_sigs, int *n_subk )
{
    KBNODE onode, node;
    int rc, found;

    /* 1st: handle revocation certificates */
    for(node=keyblock->next; node; node=node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID )
	    break;
	else if( node->pkt->pkttype == PKT_SIGNATURE
		 && node->pkt->pkt.signature->sig_class == 0x20 )  {
	    /* check whether we already have this */
	    found = 0;
	    for(onode=keyblock_orig->next; onode; onode=onode->next ) {
		if( onode->pkt->pkttype == PKT_USER_ID )
		    break;
		else if( onode->pkt->pkttype == PKT_SIGNATURE
			 && onode->pkt->pkt.signature->sig_class == 0x20
			 && !cmp_signatures(onode->pkt->pkt.signature,
					    node->pkt->pkt.signature))
		  {
		    found = 1;
		    break;
		  }
	    }
	    if( !found ) {
		KBNODE n2 = clone_kbnode(node);
		insert_kbnode( keyblock_orig, n2, 0 );
		n2->flag |= 1;
                ++*n_sigs;
		if(!opt.quiet)
		  {
		    char *p=get_user_id_native (keyid);
		    log_info(_("key %s: \"%s\" revocation"
			       " certificate added\n"), keystr(keyid),p);
		    xfree(p);
		  }
	    }
	}
    }

    /* 2nd: merge in any direct key (0x1F) sigs */
    for(node=keyblock->next; node; node=node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID )
	    break;
	else if( node->pkt->pkttype == PKT_SIGNATURE
		 && node->pkt->pkt.signature->sig_class == 0x1F )  {
	    /* check whether we already have this */
	    found = 0;
	    for(onode=keyblock_orig->next; onode; onode=onode->next ) {
		if( onode->pkt->pkttype == PKT_USER_ID )
		    break;
		else if( onode->pkt->pkttype == PKT_SIGNATURE
			 && onode->pkt->pkt.signature->sig_class == 0x1F
			 && !cmp_signatures(onode->pkt->pkt.signature,
					    node->pkt->pkt.signature)) {
		    found = 1;
		    break;
		}
	    }
	    if( !found )
	      {
		KBNODE n2 = clone_kbnode(node);
		insert_kbnode( keyblock_orig, n2, 0 );
		n2->flag |= 1;
                ++*n_sigs;
		if(!opt.quiet)
		  log_info( _("key %s: direct key signature added\n"),
			    keystr(keyid));
	      }
	}
    }

    /* 3rd: try to merge new certificates in */
    for(onode=keyblock_orig->next; onode; onode=onode->next ) {
	if( !(onode->flag & 1) && onode->pkt->pkttype == PKT_USER_ID) {
	    /* find the user id in the imported keyblock */
	    for(node=keyblock->next; node; node=node->next )
		if( node->pkt->pkttype == PKT_USER_ID
		    && !cmp_user_ids( onode->pkt->pkt.user_id,
					  node->pkt->pkt.user_id ) )
		    break;
	    if( node ) { /* found: merge */
		rc = merge_sigs( onode, node, n_sigs, fname, keyid );
		if( rc )
		    return rc;
	    }
	}
    }

    /* 4th: add new user-ids */
    for(node=keyblock->next; node; node=node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID) {
	    /* do we have this in the original keyblock */
	    for(onode=keyblock_orig->next; onode; onode=onode->next )
		if( onode->pkt->pkttype == PKT_USER_ID
		    && !cmp_user_ids( onode->pkt->pkt.user_id,
				      node->pkt->pkt.user_id ) )
		    break;
	    if( !onode ) { /* this is a new user id: append */
		rc = append_uid( keyblock_orig, node, n_sigs, fname, keyid);
		if( rc )
		    return rc;
		++*n_uids;
	    }
	}
    }

    /* 5th: add new subkeys */
    for(node=keyblock->next; node; node=node->next ) {
	onode = NULL;
	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    /* do we have this in the original keyblock? */
	    for(onode=keyblock_orig->next; onode; onode=onode->next )
		if( onode->pkt->pkttype == PKT_PUBLIC_SUBKEY
		    && !cmp_public_keys( onode->pkt->pkt.public_key,
					 node->pkt->pkt.public_key ) )
		    break;
	    if( !onode ) { /* this is a new subkey: append */
		rc = append_key( keyblock_orig, node, n_sigs, fname, keyid);
		if( rc )
		    return rc;
		++*n_subk;
	    }
	}
	else if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    /* do we have this in the original keyblock? */
	    for(onode=keyblock_orig->next; onode; onode=onode->next )
		if( onode->pkt->pkttype == PKT_SECRET_SUBKEY
		    && !cmp_secret_keys( onode->pkt->pkt.secret_key,
					 node->pkt->pkt.secret_key ) )
		    break;
	    if( !onode ) { /* this is a new subkey: append */
		rc = append_key( keyblock_orig, node, n_sigs, fname, keyid);
		if( rc )
		    return rc;
		++*n_subk;
	    }
	}
    }

    /* 6th: merge subkey certificates */
    for(onode=keyblock_orig->next; onode; onode=onode->next ) {
	if( !(onode->flag & 1)
	    &&	(   onode->pkt->pkttype == PKT_PUBLIC_SUBKEY
		 || onode->pkt->pkttype == PKT_SECRET_SUBKEY) ) {
	    /* find the subkey in the imported keyblock */
	    for(node=keyblock->next; node; node=node->next ) {
		if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
		    && !cmp_public_keys( onode->pkt->pkt.public_key,
					  node->pkt->pkt.public_key ) )
		    break;
		else if( node->pkt->pkttype == PKT_SECRET_SUBKEY
		    && !cmp_secret_keys( onode->pkt->pkt.secret_key,
					  node->pkt->pkt.secret_key ) )
		    break;
	    }
	    if( node ) { /* found: merge */
		rc = merge_keysigs( onode, node, n_sigs, fname, keyid );
		if( rc )
		    return rc;
	    }
	}
    }


    return 0;
}


/****************
 * append the userid starting with NODE and all signatures to KEYBLOCK.
 */
static int
append_uid( KBNODE keyblock, KBNODE node, int *n_sigs,
					  const char *fname, u32 *keyid )
{
    KBNODE n, n_where=NULL;

    assert(node->pkt->pkttype == PKT_USER_ID );

    /* find the position */
    for( n = keyblock; n; n_where = n, n = n->next ) {
	if( n->pkt->pkttype == PKT_PUBLIC_SUBKEY
	    || n->pkt->pkttype == PKT_SECRET_SUBKEY )
	    break;
    }
    if( !n )
	n_where = NULL;

    /* and append/insert */
    while( node ) {
	/* we add a clone to the original keyblock, because this
	 * one is released first */
	n = clone_kbnode(node);
	if( n_where ) {
	    insert_kbnode( n_where, n, 0 );
	    n_where = n;
	}
	else
	    add_kbnode( keyblock, n );
	n->flag |= 1;
	node->flag |= 1;
	if( n->pkt->pkttype == PKT_SIGNATURE )
	    ++*n_sigs;

	node = node->next;
	if( node && node->pkt->pkttype != PKT_SIGNATURE )
	    break;
    }

    return 0;
}


/****************
 * Merge the sigs from SRC onto DST. SRC and DST are both a PKT_USER_ID.
 * (how should we handle comment packets here?)
 */
static int
merge_sigs( KBNODE dst, KBNODE src, int *n_sigs,
				    const char *fname, u32 *keyid )
{
    KBNODE n, n2;
    int found=0;

    assert(dst->pkt->pkttype == PKT_USER_ID );
    assert(src->pkt->pkttype == PKT_USER_ID );

    for(n=src->next; n && n->pkt->pkttype != PKT_USER_ID; n = n->next ) {
	if( n->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	if( n->pkt->pkt.signature->sig_class == 0x18
	    || n->pkt->pkt.signature->sig_class == 0x28 )
	    continue; /* skip signatures which are only valid on subkeys */
	found = 0;
	for(n2=dst->next; n2 && n2->pkt->pkttype != PKT_USER_ID; n2 = n2->next)
	  if(!cmp_signatures(n->pkt->pkt.signature,n2->pkt->pkt.signature))
	    {
	      found++;
	      break;
	    }
	if( !found ) {
	    /* This signature is new or newer, append N to DST.
	     * We add a clone to the original keyblock, because this
	     * one is released first */
	    n2 = clone_kbnode(n);
	    insert_kbnode( dst, n2, PKT_SIGNATURE );
	    n2->flag |= 1;
	    n->flag |= 1;
	    ++*n_sigs;
	}
    }

    return 0;
}

/****************
 * Merge the sigs from SRC onto DST. SRC and DST are both a PKT_xxx_SUBKEY.
 */
static int
merge_keysigs( KBNODE dst, KBNODE src, int *n_sigs,
				    const char *fname, u32 *keyid )
{
    KBNODE n, n2;
    int found=0;

    assert(   dst->pkt->pkttype == PKT_PUBLIC_SUBKEY
	   || dst->pkt->pkttype == PKT_SECRET_SUBKEY );

    for(n=src->next; n ; n = n->next ) {
	if( n->pkt->pkttype == PKT_PUBLIC_SUBKEY
	    || n->pkt->pkttype == PKT_PUBLIC_KEY )
	    break;
	if( n->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	found = 0;
	for(n2=dst->next; n2; n2 = n2->next){
	    if( n2->pkt->pkttype == PKT_PUBLIC_SUBKEY
		|| n2->pkt->pkttype == PKT_PUBLIC_KEY )
		break;
	    if( n2->pkt->pkttype == PKT_SIGNATURE
		&& n->pkt->pkt.signature->keyid[0]
		   == n2->pkt->pkt.signature->keyid[0]
		&& n->pkt->pkt.signature->keyid[1]
		   == n2->pkt->pkt.signature->keyid[1]
		&& n->pkt->pkt.signature->timestamp
		   <= n2->pkt->pkt.signature->timestamp
		&& n->pkt->pkt.signature->sig_class
		   == n2->pkt->pkt.signature->sig_class ) {
		found++;
		break;
	    }
	}
	if( !found ) {
	    /* This signature is new or newer, append N to DST.
	     * We add a clone to the original keyblock, because this
	     * one is released first */
	    n2 = clone_kbnode(n);
	    insert_kbnode( dst, n2, PKT_SIGNATURE );
	    n2->flag |= 1;
	    n->flag |= 1;
	    ++*n_sigs;
	}
    }

    return 0;
}

/****************
 * append the subkey starting with NODE and all signatures to KEYBLOCK.
 * Mark all new and copied packets by setting flag bit 0.
 */
static int
append_key( KBNODE keyblock, KBNODE node, int *n_sigs,
					  const char *fname, u32 *keyid )
{
    KBNODE n;

    assert( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	   || node->pkt->pkttype == PKT_SECRET_SUBKEY );

    while(  node ) {
	/* we add a clone to the original keyblock, because this
	 * one is released first */
	n = clone_kbnode(node);
	add_kbnode( keyblock, n );
	n->flag |= 1;
	node->flag |= 1;
	if( n->pkt->pkttype == PKT_SIGNATURE )
	    ++*n_sigs;

	node = node->next;
	if( node && node->pkt->pkttype != PKT_SIGNATURE )
	    break;
    }

    return 0;
}



/* Walk a public keyblock and produce a secret keyblock out of it.
   Instead of inserting the secret key parameters (which we don't
   have), we insert a stub.  */
static KBNODE
pub_to_sec_keyblock (KBNODE pub_keyblock)
{
  KBNODE pubnode, secnode;
  KBNODE sec_keyblock = NULL;
  KBNODE walkctx = NULL;

  while((pubnode = walk_kbnode (pub_keyblock,&walkctx,0)))
    {
      if (pubnode->pkt->pkttype == PKT_PUBLIC_KEY
          || pubnode->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  /* Make a secret key.  We only need to convert enough to
	     write the keyblock out. */
	  PKT_public_key *pk = pubnode->pkt->pkt.public_key;
	  PACKET *pkt = xmalloc_clear (sizeof *pkt);
	  PKT_secret_key *sk = xmalloc_clear (sizeof *sk);
          int i, n;
          
          if (pubnode->pkt->pkttype == PKT_PUBLIC_KEY)
	    pkt->pkttype = PKT_SECRET_KEY;
	  else
	    pkt->pkttype = PKT_SECRET_SUBKEY;
          
	  pkt->pkt.secret_key = sk;

          copy_public_parts_to_secret_key ( pk, sk );
	  sk->version     = pk->version;
	  sk->timestamp   = pk->timestamp;
        
          n = pubkey_get_npkey (pk->pubkey_algo);
          if (!n)
            n = 1; /* Unknown number of parameters, however the data
                      is stored in the first mpi. */
          for (i=0; i < n; i++ )
            sk->skey[i] = mpi_copy (pk->pkey[i]);
  
          sk->is_protected = 1;
          sk->protect.s2k.mode = 1001;
  
  	  secnode = new_kbnode (pkt);
        }
      else
	{
	  secnode = clone_kbnode (pubnode);
	}
      
      if(!sec_keyblock)
	sec_keyblock = secnode;
      else
	add_kbnode (sec_keyblock, secnode);
    }

  return sec_keyblock;
}


/* Walk over the secret keyring SEC_KEYBLOCK and update any simple
   stub keys with the serial number SNNUM of the card if one of the
   fingerprints FPR1, FPR2 or FPR3 match.  Print a note if the key is
   a duplicate (may happen in case of backed uped keys). 
   
   Returns: True if anything changed.
*/
static int
update_sec_keyblock_with_cardinfo (KBNODE sec_keyblock, 
                                   const unsigned char *fpr1,
                                   const unsigned char *fpr2,
                                   const unsigned char *fpr3,
                                   const char *serialnostr)
{
  KBNODE node;
  KBNODE walkctx = NULL;
  PKT_secret_key *sk;
  byte array[MAX_FINGERPRINT_LEN];
  size_t n;
  int result = 0;
  const char *s;

  while((node = walk_kbnode (sec_keyblock, &walkctx, 0)))
    {
      if (node->pkt->pkttype != PKT_SECRET_KEY
          && node->pkt->pkttype != PKT_SECRET_SUBKEY)
        continue;
      sk = node->pkt->pkt.secret_key;
      
      fingerprint_from_sk (sk, array, &n);
      if (n != 20)
        continue; /* Can't be a card key.  */
      if ( !((fpr1 && !memcmp (array, fpr1, 20))
             || (fpr2 && !memcmp (array, fpr2, 20))
             || (fpr3 && !memcmp (array, fpr3, 20))) )
        continue;  /* No match.  */

      if (sk->is_protected == 1 && sk->protect.s2k.mode == 1001)
        {
          /* Standard case: migrate that stub to a key stub.  */
          sk->protect.s2k.mode = 1002;
          s = serialnostr;
          for (sk->protect.ivlen=0; sk->protect.ivlen < 16 && *s && s[1];
               sk->protect.ivlen++, s += 2)
            sk->protect.iv[sk->protect.ivlen] = xtoi_2 (s);
          result = 1;
        }
      else if (sk->is_protected == 1 && sk->protect.s2k.mode == 1002)
        {
          s = serialnostr;
          for (sk->protect.ivlen=0; sk->protect.ivlen < 16 && *s && s[1];
               sk->protect.ivlen++, s += 2)
            if (sk->protect.iv[sk->protect.ivlen] != xtoi_2 (s))
              {
                log_info (_("NOTE: a key's S/N does not "
                            "match the card's one\n"));
                break;
              }
        }
      else
        {
          if (node->pkt->pkttype != PKT_SECRET_KEY)
            log_info (_("NOTE: primary key is online and stored on card\n"));
          else
            log_info (_("NOTE: secondary key is online and stored on card\n"));
        }
    }

  return result;
}



/* Check whether a secret key stub exists for the public key PK.  If
   not create such a stub key and store it into the secring.  If it
   exists, add appropriate subkey stubs and update the secring.
   Return 0 if the key could be created. */
int
auto_create_card_key_stub ( const char *serialnostr, 
                            const unsigned char *fpr1,
                            const unsigned char *fpr2,
                            const unsigned char *fpr3)
{
  KBNODE pub_keyblock;
  KBNODE sec_keyblock;
  KEYDB_HANDLE hd;
  int rc;

  /* We only want to do this for an OpenPGP card.  */
  if (!serialnostr || strncmp (serialnostr, "D27600012401", 12) 
      || strlen (serialnostr) != 32 )
    return G10ERR_GENERAL;

  /* First get the public keyring from any of the provided fingerprints. */
  if ( (fpr1 && !get_keyblock_byfprint (&pub_keyblock, fpr1, 20))
       || (fpr2 && !get_keyblock_byfprint (&pub_keyblock, fpr2, 20))
       || (fpr3 && !get_keyblock_byfprint (&pub_keyblock, fpr3, 20)))
    ;
  else
    return G10ERR_GENERAL;
 
  hd = keydb_new (1);

  /* Now check whether there is a secret keyring.  */
  {
    PKT_public_key *pk = pub_keyblock->pkt->pkt.public_key;
    byte afp[MAX_FINGERPRINT_LEN];
    size_t an;

    fingerprint_from_pk (pk, afp, &an);
    if (an < MAX_FINGERPRINT_LEN)
      memset (afp+an, 0, MAX_FINGERPRINT_LEN-an);
    rc = keydb_search_fpr (hd, afp);
  }

  if (!rc)
    {
      rc = keydb_get_keyblock (hd, &sec_keyblock);
      if (rc)
        {
          log_error (_("error reading keyblock: %s\n"), g10_errstr(rc) );
          rc = G10ERR_GENERAL;
        }
      else
        {
          merge_keys_and_selfsig (sec_keyblock);
          
          /* FIXME: We need to add new subkeys first.  */
          if (update_sec_keyblock_with_cardinfo (sec_keyblock,
                                                 fpr1, fpr2, fpr3,
                                                 serialnostr))
            {
              rc = keydb_update_keyblock (hd, sec_keyblock );
              if (rc)
                log_error (_("error writing keyring `%s': %s\n"),
                           keydb_get_resource_name (hd), g10_errstr(rc) );
            }
        }
    }
  else  /* A secret key does not exists - create it.  */
    {
      sec_keyblock = pub_to_sec_keyblock (pub_keyblock);
      update_sec_keyblock_with_cardinfo (sec_keyblock,
                                         fpr1, fpr2, fpr3,
                                         serialnostr);

      rc = keydb_locate_writable (hd, NULL);
      if (rc)
        {
          log_error (_("no default secret keyring: %s\n"), g10_errstr (rc));
          rc = G10ERR_GENERAL;
        }
      else
        {
          rc = keydb_insert_keyblock (hd, sec_keyblock );
          if (rc)
            log_error (_("error writing keyring `%s': %s\n"),
                       keydb_get_resource_name (hd), g10_errstr(rc) );
        }
    }
    
  release_kbnode (sec_keyblock);
  release_kbnode (pub_keyblock);
  keydb_release (hd);
  return rc;
}

