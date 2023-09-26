/* import.c - import a key into our key storage.
 * Copyright (C) 1998-2007, 2010-2011 Free Software Foundation, Inc.
 * Copyright (C) 2014, 2016, 2017, 2019  Werner Koch
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
#include <errno.h>

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "../common/status.h"
#include "keydb.h"
#include "../common/util.h"
#include "trustdb.h"
#include "main.h"
#include "../common/i18n.h"
#include "../common/ttyio.h"
#include "../common/recsel.h"
#include "keyserver-internal.h"
#include "call-agent.h"
#include "../common/membuf.h"
#include "../common/init.h"
#include "../common/mbox-util.h"
#include "key-check.h"
#include "key-clean.h"


struct import_stats_s
{
  ulong count;
  ulong no_user_id;
  ulong imported;
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
  ulong v3keys;   /* Number of V3 keys seen.  */
};


/* Node flag to indicate that a user ID or a subkey has a
 * valid self-signature.  */
#define NODE_GOOD_SELFSIG  1
/* Node flag to indicate that a user ID or subkey has
 * an invalid self-signature.  */
#define NODE_BAD_SELFSIG   2
/* Node flag to indicate that the node shall be deleted.  */
#define NODE_DELETION_MARK 4
/* A node flag used to temporary mark a node. */
#define NODE_FLAG_A  8
/* A flag used by transfer_secret_keys. */
#define NODE_TRANSFER_SECKEY 16


/* An object and a global instance to store selectors created from
 * --import-filter keep-uid=EXPR.
 * --import-filter drop-sig=EXPR.
 *
 * FIXME: We should put this into the CTRL object but that requires a
 * lot more changes right now.  For now we use save and restore
 * function to temporary change them.
 */
/* Definition of the import filters.  */
struct import_filter_s
{
  recsel_expr_t keep_uid;
  recsel_expr_t drop_sig;
};
/* The current instance.  */
struct import_filter_s import_filter;


static int import (ctrl_t ctrl,
                   IOBUF inp, const char* fname, struct import_stats_s *stats,
		   unsigned char **fpr, size_t *fpr_len, unsigned int options,
		   import_screener_t screener, void *screener_arg,
                   int origin, const char *url);
static int read_block (IOBUF a, unsigned int options,
                       PACKET **pending_pkt, kbnode_t *ret_root, int *r_v3keys);
static void revocation_present (ctrl_t ctrl, kbnode_t keyblock);
static gpg_error_t import_one (ctrl_t ctrl,
                       kbnode_t keyblock,
                       struct import_stats_s *stats,
                       unsigned char **fpr, size_t *fpr_len,
                       unsigned int options, int from_sk, int silent,
                       import_screener_t screener, void *screener_arg,
                       int origin, const char *url, int *r_valid);
static gpg_error_t import_matching_seckeys (
                       ctrl_t ctrl, kbnode_t seckeys,
                       const byte *mainfpr, size_t mainfprlen,
                       struct import_stats_s *stats, int batch);
static gpg_error_t import_secret_one (ctrl_t ctrl, kbnode_t keyblock,
                              struct import_stats_s *stats, int batch,
                              unsigned int options, int for_migration,
                              import_screener_t screener, void *screener_arg,
                              kbnode_t *r_secattic);
static int import_revoke_cert (ctrl_t ctrl, kbnode_t node, unsigned int options,
                               struct import_stats_s *stats);
static int chk_self_sigs (ctrl_t ctrl, kbnode_t keyblock, u32 *keyid,
                          int *non_self);
static int delete_inv_parts (ctrl_t ctrl, kbnode_t keyblock,
                             u32 *keyid, unsigned int options,
                             kbnode_t *r_otherrevsigs);
static int any_uid_left (kbnode_t keyblock);
static void remove_all_non_self_sigs (kbnode_t *keyblock, u32 *keyid);
static int merge_blocks (ctrl_t ctrl, unsigned int options,
                         kbnode_t keyblock_orig,
			 kbnode_t keyblock, u32 *keyid,
                         u32 curtime, int origin, const char *url,
			 int *n_uids, int *n_sigs, int *n_subk );
static gpg_error_t append_new_uid (unsigned int options,
                                   kbnode_t keyblock, kbnode_t node,
                                   u32 curtime, int origin, const char *url,
                                   int *n_sigs);
static int append_key (kbnode_t keyblock, kbnode_t node, int *n_sigs);
static int merge_sigs (kbnode_t dst, kbnode_t src, int *n_sigs);
static int merge_keysigs (kbnode_t dst, kbnode_t src, int *n_sigs);



static void
release_import_filter (import_filter_t filt)
{
  recsel_release (filt->keep_uid);
  filt->keep_uid = NULL;
  recsel_release (filt->drop_sig);
  filt->drop_sig = NULL;
}

static void
cleanup_import_globals (void)
{
  release_import_filter (&import_filter);
}


int
parse_import_options(char *str,unsigned int *options,int noisy)
{
  struct parse_options import_opts[]=
    {
      {"import-local-sigs",IMPORT_LOCAL_SIGS,NULL,
       N_("import signatures that are marked as local-only")},

      {"repair-pks-subkey-bug",IMPORT_REPAIR_PKS_SUBKEY_BUG,NULL,
       N_("repair damage from the pks keyserver during import")},

      {"keep-ownertrust", IMPORT_KEEP_OWNERTTRUST, NULL,
       N_("do not clear the ownertrust values during import")},

      {"fast-import",IMPORT_FAST,NULL,
       N_("do not update the trustdb after import")},

      {"import-show",IMPORT_SHOW,NULL,
       N_("show key during import")},

      {"merge-only",IMPORT_MERGE_ONLY,NULL,
       N_("only accept updates to existing keys")},

      {"import-clean",IMPORT_CLEAN,NULL,
       N_("remove unusable parts from key after import")},

      {"import-minimal",IMPORT_MINIMAL|IMPORT_CLEAN,NULL,
       N_("remove as much as possible from key after import")},

      {"self-sigs-only", IMPORT_SELF_SIGS_ONLY, NULL,
       N_("ignore key-signatures which are not self-signatures")},

      {"import-export", IMPORT_EXPORT, NULL,
       N_("run import filters and export key immediately")},

      {"restore", IMPORT_RESTORE, NULL,
       N_("assume the GnuPG key backup format")},
      {"import-restore", IMPORT_RESTORE, NULL, NULL},

      {"repair-keys", IMPORT_REPAIR_KEYS, NULL,
       N_("repair keys on import")},

      /* No description to avoid string change: Fixme for 2.3 */
      {"show-only", (IMPORT_SHOW | IMPORT_DRY_RUN), NULL,
       NULL},

      /* Aliases for backward compatibility */
      {"allow-local-sigs",IMPORT_LOCAL_SIGS,NULL,NULL},
      {"repair-hkp-subkey-bug",IMPORT_REPAIR_PKS_SUBKEY_BUG,NULL,NULL},
      /* dummy */
      {"import-unusable-sigs",0,NULL,NULL},
      {"import-clean-sigs",0,NULL,NULL},
      {"import-clean-uids",0,NULL,NULL},
      {"convert-sk-to-pk",0, NULL,NULL}, /* Not anymore needed due to
                                            the new design.  */
      {NULL,0,NULL,NULL}
    };
  int rc;
  int saved_self_sigs_only;

  /* We need to set a flag indicating wether the user has set
   * IMPORT_SELF_SIGS_ONLY or it came from the default.  */
  saved_self_sigs_only = (*options & IMPORT_SELF_SIGS_ONLY);
  saved_self_sigs_only &= ~IMPORT_SELF_SIGS_ONLY;

  rc = parse_options (str, options, import_opts, noisy);

  if (rc && (*options & IMPORT_SELF_SIGS_ONLY))
    opt.flags.expl_import_self_sigs_only = 1;
  else
    *options |= saved_self_sigs_only;

  if (rc && (*options & IMPORT_RESTORE))
    {
      /* Alter other options we want or don't want for restore.  */
      *options |= (IMPORT_LOCAL_SIGS | IMPORT_KEEP_OWNERTTRUST);
      *options &= ~(IMPORT_MINIMAL | IMPORT_CLEAN
                    | IMPORT_REPAIR_PKS_SUBKEY_BUG
                    | IMPORT_MERGE_ONLY);
    }
  return rc;
}


/* Parse and set an import filter from string.  STRING has the format
 * "NAME=EXPR" with NAME being the name of the filter.  Spaces before
 * and after NAME are not allowed.  If this function is all called
 * several times all expressions for the same NAME are concatenated.
 * Supported filter names are:
 *
 *  - keep-uid :: If the expression evaluates to true for a certain
 *                user ID packet, that packet and all it dependencies
 *                will be imported.  The expression may use these
 *                variables:
 *
 *                - uid  :: The entire user ID.
 *                - mbox :: The mail box part of the user ID.
 *                - primary :: Evaluate to true for the primary user ID.
 */
gpg_error_t
parse_and_set_import_filter (const char *string)
{
  gpg_error_t err;

  /* Auto register the cleanup function.  */
  register_mem_cleanup_func (cleanup_import_globals);

  if (!strncmp (string, "keep-uid=", 9))
    err = recsel_parse_expr (&import_filter.keep_uid, string+9);
  else if (!strncmp (string, "drop-sig=", 9))
    err = recsel_parse_expr (&import_filter.drop_sig, string+9);
  else
    err = gpg_error (GPG_ERR_INV_NAME);

  return err;
}


/* Save the current import filters, return them, and clear the current
 * filters.  Returns NULL on error and sets ERRNO.  */
import_filter_t
save_and_clear_import_filter (void)
{
  import_filter_t filt;

  filt = xtrycalloc (1, sizeof *filt);
  if (!filt)
    return NULL;
  *filt = import_filter;
  memset (&import_filter, 0, sizeof import_filter);

  return filt;
}


/* Release the current import filters and restore them from NEWFILT.
 * Ownership of NEWFILT is moved to this function.  */
void
restore_import_filter (import_filter_t filt)
{
  if (filt)
    {
      release_import_filter (&import_filter);
      import_filter = *filt;
      xfree (filt);
    }
}


import_stats_t
import_new_stats_handle (void)
{
  return xmalloc_clear ( sizeof (struct import_stats_s) );
}


void
import_release_stats_handle (import_stats_t p)
{
  xfree (p);
}


/* Read a key from a file.  Only the first key in the file is
 * considered and stored at R_KEYBLOCK.  FNAME is the name of the
 * file.
 */
gpg_error_t
read_key_from_file_or_buffer (ctrl_t ctrl, const char *fname,
                              const void *buffer, size_t buflen,
                              kbnode_t *r_keyblock)
{
  gpg_error_t err;
  iobuf_t inp;
  PACKET *pending_pkt = NULL;
  kbnode_t keyblock = NULL;
  u32 keyid[2];
  int v3keys;   /* Dummy */
  int non_self; /* Dummy */

  (void)ctrl;

  *r_keyblock = NULL;

  log_assert (!!fname ^ !!buffer);

  if (fname)
    {
      inp = iobuf_open (fname);
      if (!inp)
        err = gpg_error_from_syserror ();
      else if (is_secured_file (iobuf_get_fd (inp)))
        {
          iobuf_close (inp);
          inp = NULL;
          err = gpg_error (GPG_ERR_EPERM);
        }
      else
        err = 0;
      if (err)
        {
          log_error (_("can't open '%s': %s\n"),
                     iobuf_is_pipe_filename (fname)? "[stdin]": fname,
                     gpg_strerror (err));
          if (gpg_err_code (err) == GPG_ERR_ENOENT)
            err = gpg_error (GPG_ERR_NO_PUBKEY);
          goto leave;
        }

      /* Push the armor filter.  */
      {
        armor_filter_context_t *afx;
        afx = new_armor_context ();
        afx->only_keyblocks = 1;
        push_armor_filter (afx, inp);
        release_armor_context (afx);
      }

    }
  else  /* Read from buffer (No armor expected).  */
    {
      inp = iobuf_temp_with_content (buffer, buflen);
    }

  /* Read the first non-v3 keyblock.  */
  while (!(err = read_block (inp, 0, &pending_pkt, &keyblock, &v3keys)))
    {
      if (keyblock->pkt->pkttype == PKT_PUBLIC_KEY)
        break;
      log_info (_("skipping block of type %d\n"), keyblock->pkt->pkttype);
      release_kbnode (keyblock);
      keyblock = NULL;
    }
  if (err)
    {
      if (gpg_err_code (err) != GPG_ERR_INV_KEYRING)
        log_error (_("error reading '%s': %s\n"),
                   fname? (iobuf_is_pipe_filename (fname)? "[stdin]": fname)
                   /* */ : "[buffer]",
                   gpg_strerror (err));
      goto leave;
    }

  keyid_from_pk (keyblock->pkt->pkt.public_key, keyid);

  if (!find_next_kbnode (keyblock, PKT_USER_ID))
    {
      err = gpg_error (GPG_ERR_NO_USER_ID);
      goto leave;
    }

  collapse_uids (&keyblock);

  clear_kbnode_flags (keyblock);
  if (chk_self_sigs (ctrl, keyblock, keyid, &non_self))
    {
      err = gpg_error (GPG_ERR_INV_KEYRING);
      goto leave;
    }

  if (!delete_inv_parts (ctrl, keyblock, keyid, 0, NULL) )
    {
      err = gpg_error (GPG_ERR_NO_USER_ID);
      goto leave;
    }

  *r_keyblock = keyblock;
  keyblock = NULL;

 leave:
  if (inp)
    {
      iobuf_close (inp);
      /* Must invalidate that ugly cache to actually close the file. */
      if (fname)
        iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)fname);
    }
  release_kbnode (keyblock);
  /* FIXME: Do we need to free PENDING_PKT ? */
  return err;
}


/* Import an already checked public key which was included in a
 * signature and the signature verified out using this key.  */
gpg_error_t
import_included_key_block (ctrl_t ctrl, kbnode_t keyblock)
{
  gpg_error_t err;
  struct import_stats_s *stats;
  import_filter_t save_filt;
  int save_armor = opt.armor;

  opt.armor = 0;
  stats = import_new_stats_handle ();
  save_filt = save_and_clear_import_filter ();
  if (!save_filt)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* FIXME: Should we introduce a dedicated KEYORG ? */
  err = import_one (ctrl, keyblock,
                    stats, NULL, 0, 0, 0, 0,
                    NULL, NULL, KEYORG_UNKNOWN, NULL, NULL);

 leave:
  restore_import_filter (save_filt);
  import_release_stats_handle (stats);
  opt.armor = save_armor;
  return err;
}



/*
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
 */
static gpg_error_t
import_keys_internal (ctrl_t ctrl, iobuf_t inp, char **fnames, int nnames,
		      import_stats_t stats_handle,
                      unsigned char **fpr, size_t *fpr_len,
		      unsigned int options,
                      import_screener_t screener, void *screener_arg,
                      int origin, const char *url)
{
  int i;
  gpg_error_t err = 0;
  struct import_stats_s *stats = stats_handle;

  if (!stats)
    stats = import_new_stats_handle ();

  if (inp)
    {
      err = import (ctrl, inp, "[stream]", stats, fpr, fpr_len, options,
                    screener, screener_arg, origin, url);
    }
  else
    {
      if (!fnames && !nnames)
        nnames = 1;  /* Ohh what a ugly hack to jump into the loop */

      for (i=0; i < nnames; i++)
        {
          const char *fname = fnames? fnames[i] : NULL;
          IOBUF inp2 = iobuf_open(fname);

          if (!fname)
            fname = "[stdin]";
          if (inp2 && is_secured_file (iobuf_get_fd (inp2)))
            {
              iobuf_close (inp2);
              inp2 = NULL;
              gpg_err_set_errno (EPERM);
            }
          if (!inp2)
            log_error (_("can't open '%s': %s\n"), fname, strerror (errno));
          else
            {
              err = import (ctrl, inp2, fname, stats, fpr, fpr_len, options,
                           screener, screener_arg, origin, url);
              iobuf_close (inp2);
              /* Must invalidate that ugly cache to actually close it. */
              iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)fname);
              if (err)
                log_error ("import from '%s' failed: %s\n",
                           fname, gpg_strerror (err) );
            }
          if (!fname)
            break;
	}
    }

  if (!stats_handle)
    {
      if ((options & (IMPORT_SHOW | IMPORT_DRY_RUN))
          != (IMPORT_SHOW | IMPORT_DRY_RUN))
        import_print_stats (stats);
      import_release_stats_handle (stats);
    }

  /* If no fast import and the trustdb is dirty (i.e. we added a key
     or userID that had something other than a selfsig, a signature
     that was other than a selfsig, or any revocation), then
     update/check the trustdb if the user specified by setting
     interactive or by not setting no-auto-check-trustdb */

  if (!(options & IMPORT_FAST))
    check_or_update_trustdb (ctrl);

  return err;
}


void
import_keys (ctrl_t ctrl, char **fnames, int nnames,
	     import_stats_t stats_handle, unsigned int options,
             int origin, const char *url)
{
  import_keys_internal (ctrl, NULL, fnames, nnames, stats_handle,
                        NULL, NULL, options, NULL, NULL, origin, url);
}


gpg_error_t
import_keys_es_stream (ctrl_t ctrl, estream_t fp,
                       import_stats_t stats_handle,
                       unsigned char **fpr, size_t *fpr_len,
                       unsigned int options,
                       import_screener_t screener, void *screener_arg,
                       int origin, const char *url)
{
  gpg_error_t err;
  iobuf_t inp;

  inp = iobuf_esopen (fp, "rb", 1);
  if (!inp)
    {
      err = gpg_error_from_syserror ();
      log_error ("iobuf_esopen failed: %s\n", gpg_strerror (err));
      return err;
    }

  err = import_keys_internal (ctrl, inp, NULL, 0, stats_handle,
                             fpr, fpr_len, options,
                             screener, screener_arg, origin, url);

  iobuf_close (inp);
  return err;
}


static int
import (ctrl_t ctrl, IOBUF inp, const char* fname,struct import_stats_s *stats,
	unsigned char **fpr,size_t *fpr_len, unsigned int options,
	import_screener_t screener, void *screener_arg,
        int origin, const char *url)
{
  PACKET *pending_pkt = NULL;
  kbnode_t keyblock = NULL;  /* Need to initialize because gcc can't
                                grasp the return semantics of
                                read_block. */
  kbnode_t secattic = NULL;  /* Kludge for PGP desktop percularity */
  int rc = 0;
  int v3keys;

  getkey_disable_caches ();

  if (!opt.no_armor) /* Armored reading is not disabled.  */
    {
      armor_filter_context_t *afx;

      afx = new_armor_context ();
      afx->only_keyblocks = 1;
      push_armor_filter (afx, inp);
      release_armor_context (afx);
    }

  while (!(rc = read_block (inp, options, &pending_pkt, &keyblock, &v3keys)))
    {
      stats->v3keys += v3keys;
      if (keyblock->pkt->pkttype == PKT_PUBLIC_KEY)
        {
          rc = import_one (ctrl, keyblock,
                           stats, fpr, fpr_len, options, 0, 0,
                           screener, screener_arg, origin, url, NULL);
          if (secattic)
            {
              byte tmpfpr[MAX_FINGERPRINT_LEN];
              size_t tmpfprlen;

              if (!rc && !(opt.dry_run || (options & IMPORT_DRY_RUN)))
                {
                  /* Kudge for PGP desktop - see below.  */
                  fingerprint_from_pk (keyblock->pkt->pkt.public_key,
                                       tmpfpr, &tmpfprlen);
                  rc = import_matching_seckeys (ctrl, secattic,
                                                tmpfpr, tmpfprlen,
                                                stats, opt.batch);
                }
              release_kbnode (secattic);
              secattic = NULL;
            }
        }
      else if (keyblock->pkt->pkttype == PKT_SECRET_KEY)
        {
          release_kbnode (secattic);
          secattic = NULL;
          rc = import_secret_one (ctrl, keyblock, stats,
                                  opt.batch, options, 0,
                                  screener, screener_arg, &secattic);
          keyblock = NULL;  /* Ownership was transferred.  */
          if (secattic)
            {
              if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY)
                rc = 0; /* Try import after the next pubkey.  */

              /* The attic is a workaround for the peculiar PGP
               * Desktop method of exporting a secret key: The
               * exported file is the concatenation of two armored
               * keyblocks; first the private one and then the public
               * one.  The strange thing is that the secret one has no
               * binding signatures at all and thus we have not
               * imported it.  The attic stores that secret keys and
               * we try to import it once after the very next public
               * keyblock.  */
            }
        }
      else if (keyblock->pkt->pkttype == PKT_SIGNATURE
               && IS_KEY_REV (keyblock->pkt->pkt.signature) )
        {
          release_kbnode (secattic);
          secattic = NULL;
          rc = import_revoke_cert (ctrl, keyblock, options, stats);
        }
      else
        {
          release_kbnode (secattic);
          secattic = NULL;
          log_info (_("skipping block of type %d\n"), keyblock->pkt->pkttype);
	}
      release_kbnode (keyblock);

      /* fixme: we should increment the not imported counter but
         this does only make sense if we keep on going despite of
         errors.  For now we do this only if the imported key is too
         large. */
      if (gpg_err_code (rc) == GPG_ERR_TOO_LARGE
            && gpg_err_source (rc) == GPG_ERR_SOURCE_KEYBOX)
        {
          stats->not_imported++;
        }
      else if (rc)
        break;

      if (!(++stats->count % 100) && !opt.quiet)
        log_info (_("%lu keys processed so far\n"), stats->count );

      if (origin == KEYORG_WKD && stats->count >= 5)
        {
          /* We limit the number of keys _received_ from the WKD to 5.
           * In fact there should be only one key but some sites want
           * to store a few expired keys there also.  gpg's key
           * selection will later figure out which key to use.  Note
           * that for WKD we always return the fingerprint of the
           * first imported key.  */
          log_info ("import from WKD stopped after %d keys\n", 5);
          break;
        }
    }
  stats->v3keys += v3keys;
  if (rc == -1)
    rc = 0;
  else if (rc && gpg_err_code (rc) != GPG_ERR_INV_KEYRING)
    log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (rc));

  release_kbnode (secattic);
  return rc;
}


/* Helper to migrate secring.gpg to GnuPG 2.1.  */
gpg_error_t
import_old_secring (ctrl_t ctrl, const char *fname)
{
  gpg_error_t err;
  iobuf_t inp;
  PACKET *pending_pkt = NULL;
  kbnode_t keyblock = NULL;  /* Need to initialize because gcc can't
                                grasp the return semantics of
                                read_block. */
  struct import_stats_s *stats;
  int v3keys;

  inp = iobuf_open (fname);
  if (inp && is_secured_file (iobuf_get_fd (inp)))
    {
      iobuf_close (inp);
      inp = NULL;
      gpg_err_set_errno (EPERM);
    }
  if (!inp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("can't open '%s': %s\n"), fname, gpg_strerror (err));
      return err;
    }

  getkey_disable_caches();
  stats = import_new_stats_handle ();
  while (!(err = read_block (inp, 0, &pending_pkt, &keyblock, &v3keys)))
    {
      if (keyblock->pkt->pkttype == PKT_SECRET_KEY)
        {
          err = import_secret_one (ctrl, keyblock, stats, 1, 0, 1,
                                   NULL, NULL, NULL);
          keyblock = NULL; /* Ownership was transferred.  */
        }
      release_kbnode (keyblock);
      if (err)
        break;
    }
  import_release_stats_handle (stats);
  if (err == -1)
    err = 0;
  else if (err && gpg_err_code (err) != GPG_ERR_INV_KEYRING)
    log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (err));
  else if (err)
    log_error ("import from '%s' failed: %s\n", fname, gpg_strerror (err));

  iobuf_close (inp);
  iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)fname);

  return err;
}


void
import_print_stats (import_stats_t stats)
{
  if (!opt.quiet)
    {
      log_info(_("Total number processed: %lu\n"),
               stats->count + stats->v3keys);
      if (stats->v3keys)
        log_info(_("    skipped PGP-2 keys: %lu\n"), stats->v3keys);
      if (stats->skipped_new_keys )
        log_info(_("      skipped new keys: %lu\n"),
                 stats->skipped_new_keys );
      if (stats->no_user_id )
        log_info(_("          w/o user IDs: %lu\n"), stats->no_user_id );
      if (stats->imported)
        {
          log_info(_("              imported: %lu"), stats->imported );
          log_printf ("\n");
        }
      if (stats->unchanged )
        log_info(_("             unchanged: %lu\n"), stats->unchanged );
      if (stats->n_uids )
        log_info(_("          new user IDs: %lu\n"), stats->n_uids );
      if (stats->n_subk )
        log_info(_("           new subkeys: %lu\n"), stats->n_subk );
      if (stats->n_sigs )
        log_info(_("        new signatures: %lu\n"), stats->n_sigs );
      if (stats->n_revoc )
        log_info(_("   new key revocations: %lu\n"), stats->n_revoc );
      if (stats->secret_read )
        log_info(_("      secret keys read: %lu\n"), stats->secret_read );
      if (stats->secret_imported )
        log_info(_("  secret keys imported: %lu\n"), stats->secret_imported );
      if (stats->secret_dups )
        log_info(_(" secret keys unchanged: %lu\n"), stats->secret_dups );
      if (stats->not_imported )
        log_info(_("          not imported: %lu\n"), stats->not_imported );
      if (stats->n_sigs_cleaned)
        log_info(_("    signatures cleaned: %lu\n"),stats->n_sigs_cleaned);
      if (stats->n_uids_cleaned)
        log_info(_("      user IDs cleaned: %lu\n"),stats->n_uids_cleaned);
    }

  if (is_status_enabled ())
    {
      char buf[15*20];

      snprintf (buf, sizeof buf,
                "%lu %lu %lu 0 %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
		stats->count + stats->v3keys,
		stats->no_user_id,
		stats->imported,
		stats->unchanged,
		stats->n_uids,
		stats->n_subk,
		stats->n_sigs,
		stats->n_revoc,
		stats->secret_read,
		stats->secret_imported,
		stats->secret_dups,
		stats->skipped_new_keys,
                stats->not_imported,
                stats->v3keys );
      write_status_text (STATUS_IMPORT_RES, buf);
    }
}


/* Return true if PKTTYPE is valid in a keyblock.  */
static int
valid_keyblock_packet (int pkttype)
{
  switch (pkttype)
    {
    case PKT_PUBLIC_KEY:
    case PKT_PUBLIC_SUBKEY:
    case PKT_SECRET_KEY:
    case PKT_SECRET_SUBKEY:
    case PKT_SIGNATURE:
    case PKT_USER_ID:
    case PKT_ATTRIBUTE:
    case PKT_RING_TRUST:
      return 1;
    default:
      return 0;
    }
}


/* Read the next keyblock from stream A.  Meta data (ring trust
 * packets) are only considered if OPTIONS has the IMPORT_RESTORE flag
 * set.  PENDING_PKT should be initialized to NULL and not changed by
 * the caller.
 *
 * Returns 0 for okay, -1 no more blocks, or any other errorcode.  The
 * integer at R_V3KEY counts the number of unsupported v3 keyblocks.
 */
static int
read_block( IOBUF a, unsigned int options,
            PACKET **pending_pkt, kbnode_t *ret_root, int *r_v3keys)
{
  int rc;
  struct parse_packet_ctx_s parsectx;
  PACKET *pkt;
  kbnode_t root = NULL;
  kbnode_t lastnode = NULL;
  int in_cert, in_v3key, skip_sigs;
  u32 keyid[2];
  int got_keyid = 0;
  unsigned int dropped_nonselfsigs = 0;

  *r_v3keys = 0;

  if (*pending_pkt)
    {
      root = lastnode = new_kbnode( *pending_pkt );
      *pending_pkt = NULL;
      log_assert (root->pkt->pkttype == PKT_PUBLIC_KEY
                  || root->pkt->pkttype == PKT_SECRET_KEY);
      in_cert = 1;
      keyid_from_pk (root->pkt->pkt.public_key, keyid);
      got_keyid = 1;
    }
  else
    in_cert = 0;

  pkt = xmalloc (sizeof *pkt);
  init_packet (pkt);
  init_parse_packet (&parsectx, a);
  if (!(options & IMPORT_RESTORE))
    parsectx.skip_meta = 1;
  in_v3key = 0;
  skip_sigs = 0;
  while ((rc=parse_packet (&parsectx, pkt)) != -1)
    {
      if (rc && ((gpg_err_code (rc) == GPG_ERR_LEGACY_KEY
                 || gpg_err_code (rc) == GPG_ERR_UNKNOWN_VERSION)
                 && (pkt->pkttype == PKT_PUBLIC_KEY
                     || pkt->pkttype == PKT_SECRET_KEY)))
        {
          in_v3key = 1;
          if (gpg_err_code (rc) != GPG_ERR_UNKNOWN_VERSION)
            ++*r_v3keys;
          free_packet (pkt, &parsectx);
          init_packet (pkt);
          continue;
        }
      else if (rc ) /* (ignore errors) */
        {
          skip_sigs = 0;
          if (gpg_err_code (rc) == GPG_ERR_UNKNOWN_PACKET)
            ; /* Do not show a diagnostic.  */
          else if (gpg_err_code (rc) == GPG_ERR_INV_PACKET
                   && (pkt->pkttype == PKT_USER_ID
                       || pkt->pkttype == PKT_ATTRIBUTE))
            {
              /* This indicates a too large user id or attribute
               * packet.  We skip this packet and all following
               * signatures.  Sure, this won't allow to repair a
               * garbled keyring in case one of the signatures belong
               * to another user id.  However, this better mitigates
               * DoS using inserted user ids.  */
              skip_sigs = 1;
            }
          else if (gpg_err_code (rc) == GPG_ERR_INV_PACKET
                   && (pkt->pkttype == PKT_OLD_COMMENT
                       || pkt->pkttype == PKT_COMMENT))
            ; /* Ignore too large comment packets.  */
          else
            {
              log_error("read_block: read error: %s\n", gpg_strerror (rc) );
              rc = GPG_ERR_INV_KEYRING;
              goto ready;
            }
          free_packet (pkt, &parsectx);
          init_packet(pkt);
          continue;
	}

      if (skip_sigs)
        {
          if (pkt->pkttype == PKT_SIGNATURE)
            {
              free_packet (pkt, &parsectx);
              init_packet (pkt);
              continue;
            }
          skip_sigs = 0;
        }

      if (in_v3key && !(pkt->pkttype == PKT_PUBLIC_KEY
                        || pkt->pkttype == PKT_SECRET_KEY))
        {
          free_packet (pkt, &parsectx);
          init_packet(pkt);
          continue;
        }
      in_v3key = 0;

      if (!root && pkt->pkttype == PKT_SIGNATURE
          && IS_KEY_REV (pkt->pkt.signature) )
        {
          /* This is a revocation certificate which is handled in a
           * special way.  */
          root = new_kbnode( pkt );
          pkt = NULL;
          goto ready;
        }

      /* Make a linked list of all packets.  */
      switch (pkt->pkttype)
        {
        case PKT_COMPRESSED:
          if (check_compress_algo (pkt->pkt.compressed->algorithm))
            {
              rc = GPG_ERR_COMPR_ALGO;
              goto ready;
            }
          else
            {
              compress_filter_context_t *cfx = xmalloc_clear( sizeof *cfx );
              pkt->pkt.compressed->buf = NULL;
              if (push_compress_filter2 (a, cfx,
                                         pkt->pkt.compressed->algorithm, 1))
                xfree (cfx); /* e.g. in case of compression_algo NONE.  */
            }
          free_packet (pkt, &parsectx);
          init_packet(pkt);
          break;

        case PKT_RING_TRUST:
          /* Skip those packets unless we are in restore mode.  */
          if ((opt.import_options & IMPORT_RESTORE))
            goto x_default;
          free_packet (pkt, &parsectx);
          init_packet(pkt);
          break;

        case PKT_SIGNATURE:
          if (!in_cert)
            goto x_default;
          if (!(options & IMPORT_SELF_SIGS_ONLY))
            goto x_default;
          log_assert (got_keyid);
	  if (pkt->pkt.signature->keyid[0] == keyid[0]
              && pkt->pkt.signature->keyid[1] == keyid[1])
	    { /* This is likely a self-signature.  We import this one.
               * Eventually we should use the ISSUER_FPR to compare
               * self-signatures, but that will work only for v5 keys
               * which are currently not even deployed.
               * Note that we do not do any crypto verify here because
               * that would defeat this very mitigation of DoS by
               * importing a key with a huge amount of faked
               * key-signatures.  A verification will be done later in
               * the processing anyway.  Here we want a cheap an early
               * way to drop non-self-signatures.  */
              goto x_default;
            }
          /* Skip this signature.  */
          dropped_nonselfsigs++;
          free_packet (pkt, &parsectx);
          init_packet(pkt);
          break;

        case PKT_PUBLIC_KEY:
        case PKT_SECRET_KEY:
          if (!got_keyid)
            {
              keyid_from_pk (pkt->pkt.public_key, keyid);
              got_keyid = 1;
            }
          if (in_cert) /* Store this packet.  */
            {
              *pending_pkt = pkt;
              pkt = NULL;
              goto ready;
            }
          in_cert = 1;
          goto x_default;

        default:
        x_default:
          if (in_cert && valid_keyblock_packet (pkt->pkttype))
            {
              if (!root )
                root = lastnode = new_kbnode (pkt);
              else
                {
                  lastnode->next = new_kbnode (pkt);
                  lastnode = lastnode->next;
                }
              pkt = xmalloc (sizeof *pkt);
            }
          else
            free_packet (pkt, &parsectx);
          init_packet(pkt);
          break;
        }
    }

 ready:
  if (rc == -1 && root )
    rc = 0;

  if (rc )
    release_kbnode( root );
  else
    *ret_root = root;
  free_packet (pkt, &parsectx);
  deinit_parse_packet (&parsectx);
  xfree( pkt );
  if (!rc && dropped_nonselfsigs && opt.verbose)
    log_info ("key %s: number of dropped non-self-signatures: %u\n",
              keystr (keyid), dropped_nonselfsigs);

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
fix_pks_corruption (ctrl_t ctrl, kbnode_t keyblock)
{
  int changed = 0;
  int keycount = 0;
  kbnode_t node;
  kbnode_t last = NULL;
  kbnode_t sknode=NULL;

  /* First determine if we have the problem at all.  Look for 2 or
     more subkeys in a row, followed by a single binding sig. */
  for (node=keyblock; node; last=node, node=node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  keycount++;
	  if(!sknode)
	    sknode=node;
	}
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && IS_SUBKEY_SIG (node->pkt->pkt.signature)
               && keycount >= 2
               && !node->next)
	{
	  /* We might have the problem, as this key has two subkeys in
	     a row without any intervening packets. */

	  /* Sanity check */
	  if (!last)
	    break;

	  /* Temporarily attach node to sknode. */
	  node->next = sknode->next;
	  sknode->next = node;
	  last->next = NULL;

	  /* Note we aren't checking whether this binding sig is a
	     selfsig.  This is not necessary here as the subkey and
	     binding sig will be rejected later if that is the
	     case. */
	  if (check_key_signature (ctrl, keyblock,node,NULL))
	    {
	      /* Not a match, so undo the changes. */
	      sknode->next = node->next;
	      last->next = node;
	      node->next = NULL;
	      break;
	    }
	  else
	    {
              /* Mark it good so we don't need to check it again */
	      sknode->flag |= NODE_GOOD_SELFSIG;
	      changed = 1;
	      break;
	    }
	}
      else
	keycount = 0;
    }

  return changed;
}


/* Versions of GnuPG before 1.4.11 and 2.0.16 allowed to import bogus
   direct key signatures.  A side effect of this was that a later
   import of the same good direct key signatures was not possible
   because the cmp_signature check in merge_blocks considered them
   equal.  Although direct key signatures are now checked during
   import, there might still be bogus signatures sitting in a keyring.
   We need to detect and delete them before doing a merge.  This
   function returns the number of removed sigs.  */
static int
fix_bad_direct_key_sigs (ctrl_t ctrl, kbnode_t keyblock, u32 *keyid)
{
  gpg_error_t err;
  kbnode_t node;
  int count = 0;

  for (node = keyblock->next; node; node=node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        break;
      if (node->pkt->pkttype == PKT_SIGNATURE
          && IS_KEY_SIG (node->pkt->pkt.signature))
        {
          err = check_key_signature (ctrl, keyblock, node, NULL);
          if (err && gpg_err_code (err) != GPG_ERR_PUBKEY_ALGO )
            {
              /* If we don't know the error, we can't decide; this is
                 not a problem because cmp_signature can't compare the
                 signature either.  */
              log_info ("key %s: invalid direct key signature removed\n",
                        keystr (keyid));
              delete_kbnode (node);
              count++;
            }
        }
    }

  return count;
}


static void
print_import_ok (PKT_public_key *pk, unsigned int reason)
{
  byte array[MAX_FINGERPRINT_LEN], *s;
  char buf[MAX_FINGERPRINT_LEN*2+30], *p;
  size_t i, n;

  snprintf (buf, sizeof buf, "%u ", reason);
  p = buf + strlen (buf);

  fingerprint_from_pk (pk, array, &n);
  s = array;
  for (i=0; i < n ; i++, s++, p += 2)
    sprintf (p, "%02X", *s);

  write_status_text (STATUS_IMPORT_OK, buf);
}


static void
print_import_check (PKT_public_key * pk, PKT_user_id * id)
{
  byte hexfpr[2*MAX_FINGERPRINT_LEN+1];
  u32 keyid[2];

  keyid_from_pk (pk, keyid);
  hexfingerprint (pk, hexfpr, sizeof hexfpr);
  write_status_printf (STATUS_IMPORT_CHECK, "%08X%08X %s %s",
                       keyid[0], keyid[1], hexfpr, id->name);

}


static void
check_prefs_warning(PKT_public_key *pk)
{
  log_info(_("WARNING: key %s contains preferences for unavailable\n"
             "algorithms on these user IDs:\n"), keystr_from_pk(pk));
}


static void
check_prefs (ctrl_t ctrl, kbnode_t keyblock)
{
  kbnode_t node;
  PKT_public_key *pk;
  int problem=0;

  merge_keys_and_selfsig (ctrl, keyblock);
  pk=keyblock->pkt->pkt.public_key;

  for(node=keyblock;node;node=node->next)
    {
      if(node->pkt->pkttype==PKT_USER_ID
	 && node->pkt->pkt.user_id->created
	 && node->pkt->pkt.user_id->prefs)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  prefitem_t *prefs = uid->prefs;
	  char *user = utf8_to_native(uid->name,strlen(uid->name),0);

	  for(;prefs->type;prefs++)
	    {
	      char num[10]; /* prefs->value is a byte, so we're over
			       safe here */

	      sprintf(num,"%u",prefs->value);

	      if(prefs->type==PREFTYPE_SYM)
		{
		  if (openpgp_cipher_test_algo (prefs->value))
		    {
		      const char *algo =
                        (openpgp_cipher_test_algo (prefs->value)
                         ? num
                         : openpgp_cipher_algo_name (prefs->value));
		      if(!problem)
			check_prefs_warning(pk);
		      log_info(_("         \"%s\": preference for cipher"
				 " algorithm %s\n"), user, algo);
		      problem=1;
		    }
		}
	      else if(prefs->type==PREFTYPE_HASH)
		{
		  if(openpgp_md_test_algo(prefs->value))
		    {
		      const char *algo =
                        (gcry_md_test_algo (prefs->value)
                         ? num
                         : gcry_md_algo_name (prefs->value));
		      if(!problem)
			check_prefs_warning(pk);
		      log_info(_("         \"%s\": preference for digest"
				 " algorithm %s\n"), user, algo);
		      problem=1;
		    }
		}
	      else if(prefs->type==PREFTYPE_ZIP)
		{
		  if(check_compress_algo (prefs->value))
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
	  strlist_t sl = NULL;
          strlist_t locusr = NULL;
	  size_t fprlen=0;
	  byte fpr[MAX_FINGERPRINT_LEN], *p;
	  char username[(MAX_FINGERPRINT_LEN*2)+1];
	  unsigned int i;

	  p = fingerprint_from_pk (pk,fpr,&fprlen);
	  for(i=0;i<fprlen;i++,p++)
	    sprintf(username+2*i,"%02X",*p);
	  add_to_strlist(&locusr,username);

	  append_to_strlist(&sl,"updpref");
	  append_to_strlist(&sl,"save");

	  keyedit_menu (ctrl, username, locusr, sl, 1, 1 );
	  free_strlist(sl);
	  free_strlist(locusr);
	}
      else if(!opt.quiet)
	log_info(_("you can update your preferences with:"
		   " gpg --edit-key %s updpref save\n"),keystr_from_pk(pk));
    }
}


/* Helper for apply_*_filter in import.c and export.c.  */
const char *
impex_filter_getval (void *cookie, const char *propname)
{
  /* FIXME: Malloc our static buffers and access them via PARM.  */
  struct impex_filter_parm_s *parm = cookie;
  ctrl_t ctrl = parm->ctrl;
  kbnode_t node = parm->node;
  static char numbuf[20];
  const char *result;

  log_assert (ctrl && ctrl->magic == SERVER_CONTROL_MAGIC);

  if (node->pkt->pkttype == PKT_USER_ID
      || node->pkt->pkttype == PKT_ATTRIBUTE)
    {
      PKT_user_id *uid = node->pkt->pkt.user_id;

      if (!strcmp (propname, "uid"))
        result = uid->name;
      else if (!strcmp (propname, "mbox"))
        {
          if (!uid->mbox)
            {
              uid->mbox = mailbox_from_userid (uid->name);
            }
          result = uid->mbox;
        }
      else if (!strcmp (propname, "primary"))
        {
          result = uid->flags.primary? "1":"0";
        }
      else if (!strcmp (propname, "expired"))
        {
          result = uid->flags.expired? "1":"0";
        }
      else if (!strcmp (propname, "revoked"))
        {
          result = uid->flags.revoked? "1":"0";
        }
      else
        result = NULL;
    }
  else if (node->pkt->pkttype == PKT_SIGNATURE)
    {
      PKT_signature *sig = node->pkt->pkt.signature;

      if (!strcmp (propname, "sig_created"))
        {
          snprintf (numbuf, sizeof numbuf, "%lu", (ulong)sig->timestamp);
          result = numbuf;
        }
      else if (!strcmp (propname, "sig_created_d"))
        {
          result = datestr_from_sig (sig);
        }
      else if (!strcmp (propname, "sig_algo"))
        {
          snprintf (numbuf, sizeof numbuf, "%d", sig->pubkey_algo);
          result = numbuf;
        }
      else if (!strcmp (propname, "sig_digest_algo"))
        {
          snprintf (numbuf, sizeof numbuf, "%d", sig->digest_algo);
          result = numbuf;
        }
      else if (!strcmp (propname, "expired"))
        {
          result = sig->flags.expired? "1":"0";
        }
      else
        result = NULL;
    }
  else if (node->pkt->pkttype == PKT_PUBLIC_KEY
           || node->pkt->pkttype == PKT_SECRET_KEY
           || node->pkt->pkttype == PKT_PUBLIC_SUBKEY
           || node->pkt->pkttype == PKT_SECRET_SUBKEY)
    {
      PKT_public_key *pk = node->pkt->pkt.public_key;

      if (!strcmp (propname, "secret"))
        {
          result = (node->pkt->pkttype == PKT_SECRET_KEY
                    || node->pkt->pkttype == PKT_SECRET_SUBKEY)? "1":"0";
        }
      else if (!strcmp (propname, "key_algo"))
        {
          snprintf (numbuf, sizeof numbuf, "%d", pk->pubkey_algo);
          result = numbuf;
        }
      else if (!strcmp (propname, "key_created"))
        {
          snprintf (numbuf, sizeof numbuf, "%lu", (ulong)pk->timestamp);
          result = numbuf;
        }
      else if (!strcmp (propname, "key_created_d"))
        {
          result = datestr_from_pk (pk);
        }
      else if (!strcmp (propname, "expired"))
        {
          result = pk->has_expired? "1":"0";
        }
      else if (!strcmp (propname, "revoked"))
        {
          result = pk->flags.revoked? "1":"0";
        }
      else if (!strcmp (propname, "disabled"))
        {
          result = pk_is_disabled (pk)? "1":"0";
        }
      else if (!strcmp (propname, "usage"))
        {
          snprintf (numbuf, sizeof numbuf, "%s%s%s%s%s",
                    (pk->pubkey_usage & PUBKEY_USAGE_ENC)?"e":"",
                    (pk->pubkey_usage & PUBKEY_USAGE_SIG)?"s":"",
                    (pk->pubkey_usage & PUBKEY_USAGE_CERT)?"c":"",
                    (pk->pubkey_usage & PUBKEY_USAGE_AUTH)?"a":"",
                    (pk->pubkey_usage & PUBKEY_USAGE_UNKNOWN)?"?":"");
          result = numbuf;
        }
      else if (!strcmp (propname, "fpr"))
        {
          hexfingerprint (pk, parm->hexfpr, sizeof parm->hexfpr);
          result = parm->hexfpr;
        }
      else
        result = NULL;
    }
  else
    result = NULL;

  return result;
}


/*
 * Apply the keep-uid filter to the keyblock.  The deleted nodes are
 * marked and thus the caller should call commit_kbnode afterwards.
 * KEYBLOCK must not have any blocks marked as deleted.
 */
static void
apply_keep_uid_filter (ctrl_t ctrl, kbnode_t keyblock, recsel_expr_t selector)
{
  kbnode_t node;
  struct impex_filter_parm_s parm;

  parm.ctrl = ctrl;

  for (node = keyblock->next; node; node = node->next )
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          parm.node = node;
          if (!recsel_select (selector, impex_filter_getval, &parm))
            {

              /* log_debug ("keep-uid: deleting '%s'\n", */
              /*            node->pkt->pkt.user_id->name); */
              /* The UID packet and all following packets up to the
               * next UID or a subkey.  */
              delete_kbnode (node);
              for (; node->next
                     && node->next->pkt->pkttype != PKT_USER_ID
                     && node->next->pkt->pkttype != PKT_PUBLIC_SUBKEY
                     && node->next->pkt->pkttype != PKT_SECRET_SUBKEY ;
                   node = node->next)
                delete_kbnode (node->next);
	    }
          /* else */
          /*   log_debug ("keep-uid: keeping '%s'\n", */
          /*              node->pkt->pkt.user_id->name); */
        }
    }
}


/*
 * Apply the drop-sig filter to the keyblock.  The deleted nodes are
 * marked and thus the caller should call commit_kbnode afterwards.
 * KEYBLOCK must not have any blocks marked as deleted.
 */
static void
apply_drop_sig_filter (ctrl_t ctrl, kbnode_t keyblock, recsel_expr_t selector)
{
  kbnode_t node;
  int active = 0;
  u32 main_keyid[2];
  PKT_signature *sig;
  struct impex_filter_parm_s parm;

  parm.ctrl = ctrl;

  keyid_from_pk (keyblock->pkt->pkt.public_key, main_keyid);

  /* Loop over all signatures for user id and attribute packets which
   * are not self signatures.  */
  for (node = keyblock->next; node; node = node->next )
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || node->pkt->pkttype == PKT_SECRET_SUBKEY)
        break; /* ready.  */
      if (node->pkt->pkttype == PKT_USER_ID
          || node->pkt->pkttype == PKT_ATTRIBUTE)
        active = 1;
      if (!active)
        continue;
      if (node->pkt->pkttype != PKT_SIGNATURE)
        continue;

      sig = node->pkt->pkt.signature;
      if (main_keyid[0] == sig->keyid[0] || main_keyid[1] == sig->keyid[1])
        continue;  /* Skip self-signatures.  */

      if (IS_UID_SIG(sig) || IS_UID_REV(sig))
        {
          parm.node = node;
          if (recsel_select (selector, impex_filter_getval, &parm))
            delete_kbnode (node);
        }
    }
}


/* Insert a key origin into a public key packet.  */
static gpg_error_t
insert_key_origin_pk (PKT_public_key *pk, u32 curtime,
                      int origin, const char *url)
{
  if (origin == KEYORG_WKD || origin == KEYORG_DANE)
    {
      /* For WKD and DANE we insert origin information also for the
       * key but we don't record the URL because we have have no use
       * for that: An update using a keyserver has higher precedence
       * and will thus update this origin info.  For refresh using WKD
       * or DANE we need to go via the User ID anyway.  Recall that we
       * are only inserting a new key. */
      pk->keyorg = origin;
      pk->keyupdate = curtime;
    }
  else if (origin == KEYORG_KS && url)
    {
      /* If the key was retrieved from a keyserver using a fingerprint
       * request we add the meta information.  Note that the use of a
       * fingerprint needs to be enforced by the caller of the import
       * function.  This is commonly triggered by verifying a modern
       * signature which has an Issuer Fingerprint signature
       * subpacket.  */
      pk->keyorg = origin;
      pk->keyupdate = curtime;
      xfree (pk->updateurl);
      pk->updateurl = xtrystrdup (url);
      if (!pk->updateurl)
        return gpg_error_from_syserror ();
    }
  else if (origin == KEYORG_FILE)
    {
      pk->keyorg = origin;
      pk->keyupdate = curtime;
    }
  else if (origin == KEYORG_URL)
    {
      pk->keyorg = origin;
      pk->keyupdate = curtime;
      if (url)
        {
          xfree (pk->updateurl);
          pk->updateurl = xtrystrdup (url);
          if (!pk->updateurl)
            return gpg_error_from_syserror ();
        }
    }

  return 0;
}


/* Insert a key origin into a user id packet.  */
static gpg_error_t
insert_key_origin_uid (PKT_user_id *uid, u32 curtime,
                       int origin, const char *url)

{
  if (origin == KEYORG_WKD || origin == KEYORG_DANE)
    {
      /* We insert origin information on a UID only when we received
       * them via the Web Key Directory or a DANE record.  The key we
       * receive here from the WKD has been filtered to contain only
       * the user ID as looked up in the WKD.  For a DANE origin we
       * this should also be the case.  Thus we will see here only one
       * user id.  */
      uid->keyorg = origin;
      uid->keyupdate = curtime;
      if (url)
        {
          xfree (uid->updateurl);
          uid->updateurl = xtrystrdup (url);
          if (!uid->updateurl)
            return gpg_error_from_syserror ();
        }
    }
  else if (origin == KEYORG_KS && url)
    {
      /* If the key was retrieved from a keyserver using a fingerprint
       * request we mark that also in the user ID.  However we do not
       * store the keyserver URL in the UID.  A later update (merge)
       * from a more trusted source will replace this info.  */
      uid->keyorg = origin;
      uid->keyupdate = curtime;
    }
  else if (origin == KEYORG_FILE)
    {
      uid->keyorg = origin;
      uid->keyupdate = curtime;
    }
  else if (origin == KEYORG_URL)
    {
      uid->keyorg = origin;
      uid->keyupdate = curtime;
    }

  return 0;
}


/* Apply meta data to KEYBLOCK.  This sets the origin of the key to
 * ORIGIN and the updateurl to URL.  Note that this function is only
 * used for a new key, that is not when we are merging keys.  */
static gpg_error_t
insert_key_origin (kbnode_t keyblock, int origin, const char *url)
{
  gpg_error_t err;
  kbnode_t node;
  u32 curtime = make_timestamp ();

  for (node = keyblock; node; node = node->next)
    {
      if (is_deleted_kbnode (node))
        ;
      else if (node->pkt->pkttype == PKT_PUBLIC_KEY)
        {
          err = insert_key_origin_pk (node->pkt->pkt.public_key, curtime,
                                      origin, url);
          if (err)
            return err;
        }
      else if (node->pkt->pkttype == PKT_USER_ID)
        {
          err = insert_key_origin_uid (node->pkt->pkt.user_id, curtime,
                                       origin, url);
          if (err)
            return err;
        }
    }

  return 0;
}


/* Update meta data on KEYBLOCK.  This updates the key origin on the
 * public key according to ORIGIN and URL.  The UIDs are already
 * updated when this function is called.  */
static gpg_error_t
update_key_origin (kbnode_t keyblock, u32 curtime, int origin, const char *url)
{
  PKT_public_key *pk;

  log_assert (keyblock->pkt->pkttype == PKT_PUBLIC_KEY);
  pk = keyblock->pkt->pkt.public_key;

  if (pk->keyupdate > curtime)
    ; /* Don't do it for a time warp.  */
  else if (origin == KEYORG_WKD || origin == KEYORG_DANE)
    {
      /* We only update the origin info if they either have never been
       * set or are the origin was the same as the new one.  If this
       * is WKD we also update the UID to show from which user id this
       * was updated.  */
      if (!pk->keyorg || pk->keyorg == KEYORG_WKD || pk->keyorg == KEYORG_DANE)
        {
          pk->keyorg = origin;
          pk->keyupdate = curtime;
          xfree (pk->updateurl);
          pk->updateurl = NULL;
          if (origin == KEYORG_WKD && url)
            {
              pk->updateurl = xtrystrdup (url);
              if (!pk->updateurl)
                return gpg_error_from_syserror ();
            }
        }
    }
  else if (origin == KEYORG_KS)
    {
      /* All updates from a keyserver are considered to have the
       * freshed key.  Thus we always set the new key origin.  */
      pk->keyorg = origin;
      pk->keyupdate = curtime;
      xfree (pk->updateurl);
      pk->updateurl = NULL;
      if (url)
        {
          pk->updateurl = xtrystrdup (url);
          if (!pk->updateurl)
            return gpg_error_from_syserror ();
        }
    }
  else if (origin == KEYORG_FILE)
    {
      /* Updates from a file are considered to be fresh.  */
      pk->keyorg = origin;
      pk->keyupdate = curtime;
      xfree (pk->updateurl);
      pk->updateurl = NULL;
    }
  else if (origin == KEYORG_URL)
    {
      /* Updates from a URL are considered to be fresh.  */
      pk->keyorg = origin;
      pk->keyupdate = curtime;
      xfree (pk->updateurl);
      pk->updateurl = NULL;
      if (url)
        {
          pk->updateurl = xtrystrdup (url);
          if (!pk->updateurl)
            return gpg_error_from_syserror ();
        }
    }

  return 0;
}


/*
 * Try to import one keyblock. Return an error only in serious cases,
 * but never for an invalid keyblock.  It uses log_error to increase
 * the internal errorcount, so that invalid input can be detected by
 * programs which called gpg.  If SILENT is no messages are printed -
 * even most error messages are suppressed.  ORIGIN is the origin of
 * the key (0 for unknown) and URL the corresponding URL.  FROM_SK
 * indicates that the key has been made from a secret key.  If R_SAVED
 * is not NULL a boolean will be stored indicating whether the
 * keyblock has valid parts.  Unless OTHERREVSIGS is NULL it is
 * updated with encountered new revocation signatures.
 */
static gpg_error_t
import_one_real (ctrl_t ctrl,
                 kbnode_t keyblock, struct import_stats_s *stats,
                 unsigned char **fpr, size_t *fpr_len, unsigned int options,
                 int from_sk, int silent,
                 import_screener_t screener, void *screener_arg,
                 int origin, const char *url, int *r_valid,
                 kbnode_t *otherrevsigs)
{
  gpg_error_t err = 0;
  PKT_public_key *pk;
  kbnode_t node, uidnode;
  kbnode_t keyblock_orig = NULL;
  byte fpr2[MAX_FINGERPRINT_LEN];
  size_t fpr2len;
  u32 keyid[2];
  int new_key = 0;
  int mod_key = 0;
  int same_key = 0;
  int non_self = 0;
  size_t an;
  char pkstrbuf[PUBKEY_STRING_SIZE];
  int merge_keys_done = 0;
  int any_filter = 0;
  KEYDB_HANDLE hd = NULL;

  if (r_valid)
    *r_valid = 0;

  /* If show-only is active we don't won't any extra output.  */
  if ((options & (IMPORT_SHOW | IMPORT_DRY_RUN)))
    silent = 1;

  /* Get the key and print some info about it. */
  node = find_kbnode( keyblock, PKT_PUBLIC_KEY );
  if (!node )
    BUG();

  pk = node->pkt->pkt.public_key;

  fingerprint_from_pk (pk, fpr2, &fpr2len);
  for (an = fpr2len; an < MAX_FINGERPRINT_LEN; an++)
    fpr2[an] = 0;
  keyid_from_pk( pk, keyid );
  uidnode = find_next_kbnode( keyblock, PKT_USER_ID );

  if (opt.verbose && !opt.interactive && !silent && !from_sk)
    {
      /* Note that we do not print this info in FROM_SK mode
       * because import_secret_one already printed that.  */
      log_info ("pub  %s/%s %s  ",
                pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
                keystr_from_pk(pk), datestr_from_pk(pk) );
      if (uidnode)
        print_utf8_buffer (log_get_stream (),
                           uidnode->pkt->pkt.user_id->name,
                           uidnode->pkt->pkt.user_id->len );
      log_printf ("\n");
    }


  if (!uidnode )
    {
      if (!silent)
        log_error( _("key %s: no user ID\n"), keystr_from_pk(pk));
      return 0;
    }

  if (screener && screener (keyblock, screener_arg))
    {
      log_error (_("key %s: %s\n"), keystr_from_pk (pk),
                 _("rejected by import screener"));
      return 0;
    }

  if (opt.interactive && !silent)
    {
      if (is_status_enabled())
        print_import_check (pk, uidnode->pkt->pkt.user_id);
      merge_keys_and_selfsig (ctrl, keyblock);
      tty_printf ("\n");
      show_basic_key_info (ctrl, keyblock, from_sk);
      tty_printf ("\n");
      if (!cpr_get_answer_is_yes ("import.okay",
                                  "Do you want to import this key? (y/N) "))
        return 0;
    }

  /* Remove all non-self-sigs if requested.  Noe that this is a NOP if
   * that option has been globally set but we may also be called
   * latter with the already parsed keyblock and a locally changed
   * option.  This is why we need to remove them here as well.  */
  if ((options & IMPORT_SELF_SIGS_ONLY))
    remove_all_non_self_sigs (&keyblock, keyid);

  collapse_uids(&keyblock);

  /* Clean the key that we're about to import, to cut down on things
     that we have to clean later.  This has no practical impact on the
     end result, but does result in less logging which might confuse
     the user. */
  if ((options & IMPORT_CLEAN))
    {
      merge_keys_and_selfsig (ctrl, keyblock);
      clean_all_uids (ctrl, keyblock,
                      opt.verbose, (options&IMPORT_MINIMAL), NULL, NULL);
      clean_all_subkeys (ctrl, keyblock, opt.verbose, KEY_CLEAN_NONE,
                         NULL, NULL);
    }

  clear_kbnode_flags( keyblock );

  if ((options&IMPORT_REPAIR_PKS_SUBKEY_BUG)
      && fix_pks_corruption (ctrl, keyblock)
      && opt.verbose)
    log_info (_("key %s: PKS subkey corruption repaired\n"),
              keystr_from_pk(pk));

  if ((options & IMPORT_REPAIR_KEYS))
    key_check_all_keysigs (ctrl, 1, keyblock, 0, 0);

  if (chk_self_sigs (ctrl, keyblock, keyid, &non_self))
    return 0;  /* Invalid keyblock - error already printed.  */

  /* If we allow such a thing, mark unsigned uids as valid */
  if (opt.allow_non_selfsigned_uid)
    {
      for (node=keyblock; node; node = node->next )
        if (node->pkt->pkttype == PKT_USER_ID
            && !(node->flag & NODE_GOOD_SELFSIG)
            && !(node->flag & NODE_BAD_SELFSIG) )
          {
            char *user=utf8_to_native(node->pkt->pkt.user_id->name,
                                      node->pkt->pkt.user_id->len,0);
            /* Fake a good signature status for the user id.  */
            node->flag |= NODE_GOOD_SELFSIG;
            log_info( _("key %s: accepted non self-signed user ID \"%s\"\n"),
                      keystr_from_pk(pk),user);
            xfree(user);
	  }
    }

  /* Delete invalid parts and bail out if there are no user ids left.  */
  if (!delete_inv_parts (ctrl, keyblock, keyid, options, otherrevsigs))
    {
      if (!silent)
        {
          log_error( _("key %s: no valid user IDs\n"), keystr_from_pk(pk));
          if (!opt.quiet )
            log_info(_("this may be caused by a missing self-signature\n"));
        }
      stats->no_user_id++;
      return 0;
    }

  /* Get rid of deleted nodes.  */
  commit_kbnode (&keyblock);

  /* Apply import filter.  */
  if (import_filter.keep_uid)
    {
      apply_keep_uid_filter (ctrl, keyblock, import_filter.keep_uid);
      commit_kbnode (&keyblock);
      any_filter = 1;
    }
  if (import_filter.drop_sig)
    {
      apply_drop_sig_filter (ctrl, keyblock, import_filter.drop_sig);
      commit_kbnode (&keyblock);
      any_filter = 1;
    }

  /* If we ran any filter we need to check that at least one user id
   * is left in the keyring.  Note that we do not use log_error in
   * this case. */
  if (any_filter && !any_uid_left (keyblock))
    {
      if (!opt.quiet )
        log_info ( _("key %s: no valid user IDs\n"), keystr_from_pk (pk));
      stats->no_user_id++;
      return 0;
    }

  /* The keyblock is valid and ready for real import.  */
  if (r_valid)
    *r_valid = 1;

  /* Show the key in the form it is merged or inserted.  We skip this
   * if "import-export" is also active without --armor or the output
   * file has explicily been given. */
  if ((options & IMPORT_SHOW)
      && !((options & IMPORT_EXPORT) && !opt.armor && !opt.outfile))
    {
      merge_keys_and_selfsig (ctrl, keyblock);
      merge_keys_done = 1;
      /* Note that we do not want to show the validity because the key
       * has not yet imported.  */
      list_keyblock_direct (ctrl, keyblock, from_sk, 0,
                            opt.fingerprint || opt.with_fingerprint, 1);
      es_fflush (es_stdout);
    }

  /* Write the keyblock to the output and do not actually import.  */
  if ((options & IMPORT_EXPORT))
    {
      if (!merge_keys_done)
        {
          merge_keys_and_selfsig (ctrl, keyblock);
          merge_keys_done = 1;
        }
      err = write_keyblock_to_output (keyblock, opt.armor, opt.export_options);
      goto leave;
    }

  if (opt.dry_run || (options & IMPORT_DRY_RUN))
    goto leave;

  /* Do we have this key already in one of our pubrings ? */
  err = get_keyblock_byfprint_fast (&keyblock_orig, &hd,
                                    fpr2, fpr2len, 1/*locked*/);
  if ((err
       && gpg_err_code (err) != GPG_ERR_NO_PUBKEY
       && gpg_err_code (err) != GPG_ERR_UNUSABLE_PUBKEY)
      || !hd)
    {
      /* The !hd above is to catch a misbehaving function which
       * returns NO_PUBKEY for failing to allocate a handle.  */
      if (!silent)
        log_error (_("key %s: public key not found: %s\n"),
                   keystr(keyid), gpg_strerror (err));
    }
  else if (err && (opt.import_options&IMPORT_MERGE_ONLY) )
    {
      if (opt.verbose && !silent )
        log_info( _("key %s: new key - skipped\n"), keystr(keyid));
      err = 0;
      stats->skipped_new_keys++;
    }
  else if (err)  /* Insert this key. */
    {
      /* Note: ERR can only be NO_PUBKEY or UNUSABLE_PUBKEY.  */
      int n_sigs_cleaned, n_uids_cleaned;

      err = keydb_locate_writable (hd);
      if (err)
        {
          log_error (_("no writable keyring found: %s\n"), gpg_strerror (err));
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
	}
      if (opt.verbose > 1 )
        log_info (_("writing to '%s'\n"), keydb_get_resource_name (hd) );

      if ((options & IMPORT_CLEAN))
        {
          merge_keys_and_selfsig (ctrl, keyblock);
          clean_all_uids (ctrl, keyblock, opt.verbose, (options&IMPORT_MINIMAL),
                          &n_uids_cleaned,&n_sigs_cleaned);
          clean_all_subkeys (ctrl, keyblock, opt.verbose, KEY_CLEAN_NONE,
                             NULL, NULL);
        }

      /* Unless we are in restore mode apply meta data to the
       * keyblock.  Note that this will never change the first packet
       * and thus the address of KEYBLOCK won't change.  */
      if ( !(options & IMPORT_RESTORE) )
        {
          err = insert_key_origin (keyblock, origin, url);
          if (err)
            {
              log_error ("insert_key_origin failed: %s\n", gpg_strerror (err));
              err = gpg_error (GPG_ERR_GENERAL);
              goto leave;
            }
        }

      err = keydb_insert_keyblock (hd, keyblock );
      if (err)
        log_error (_("error writing keyring '%s': %s\n"),
                   keydb_get_resource_name (hd), gpg_strerror (err));
      else if (!(opt.import_options & IMPORT_KEEP_OWNERTTRUST))
        {
          /* This should not be possible since we delete the
             ownertrust when a key is deleted, but it can happen if
             the keyring and trustdb are out of sync.  It can also
             be made to happen with the trusted-key command and by
             importing and locally exported key. */

          clear_ownertrusts (ctrl, pk);
          if (non_self)
            revalidation_mark (ctrl);
        }

      /* Release the handle and thus unlock the keyring asap.  */
      keydb_release (hd);
      hd = NULL;

      /* We are ready.  */
      if (!err && !opt.quiet && !silent)
        {
          char *p = get_user_id_byfpr_native (ctrl, fpr2);
          log_info (_("key %s: public key \"%s\" imported\n"),
                    keystr(keyid), p);
          xfree(p);
        }
      if (!err && is_status_enabled())
        {
          char *us = get_long_user_id_string (ctrl, keyid);
          write_status_text( STATUS_IMPORTED, us );
          xfree(us);
          print_import_ok (pk, 1);
        }
      if (!err)
        {
          stats->imported++;
          new_key = 1;
        }
    }
  else /* Key already exists - merge.  */
    {
      int n_uids, n_sigs, n_subk, n_sigs_cleaned, n_uids_cleaned;
      u32 curtime = make_timestamp ();

      /* Compare the original against the new key; just to be sure nothing
       * weird is going on */
      if (cmp_public_keys (keyblock_orig->pkt->pkt.public_key, pk))
        {
          if (!silent)
            log_error( _("key %s: doesn't match our copy\n"),keystr(keyid));
          goto leave;
        }

      /* Make sure the original direct key sigs are all sane.  */
      n_sigs_cleaned = fix_bad_direct_key_sigs (ctrl, keyblock_orig, keyid);
      if (n_sigs_cleaned)
        commit_kbnode (&keyblock_orig);

      /* Try to merge KEYBLOCK into KEYBLOCK_ORIG.  */
      clear_kbnode_flags( keyblock_orig );
      clear_kbnode_flags( keyblock );
      n_uids = n_sigs = n_subk = n_uids_cleaned = 0;
      err = merge_blocks (ctrl, options, keyblock_orig, keyblock, keyid,
                          curtime, origin, url,
                          &n_uids, &n_sigs, &n_subk );
      if (err)
        goto leave;

      /* Clean the final keyblock again if requested.  we can't do
       * this if only self-signatures are imported; see bug #4628.  */
      if ((options & IMPORT_CLEAN)
          && !(options & IMPORT_SELF_SIGS_ONLY))
        {
          merge_keys_and_selfsig (ctrl, keyblock_orig);
          clean_all_uids (ctrl, keyblock_orig, opt.verbose,
                          (options&IMPORT_MINIMAL),
                          &n_uids_cleaned,&n_sigs_cleaned);
          clean_all_subkeys (ctrl, keyblock_orig, opt.verbose, KEY_CLEAN_NONE,
                             NULL, NULL);
        }

      if (n_uids || n_sigs || n_subk || n_sigs_cleaned || n_uids_cleaned)
        {
          /* Unless we are in restore mode apply meta data to the
           * keyblock.  Note that this will never change the first packet
           * and thus the address of KEYBLOCK won't change.  */
          if ( !(options & IMPORT_RESTORE) )
            {
              err = update_key_origin (keyblock_orig, curtime, origin, url);
              if (err)
                {
                  log_error ("update_key_origin failed: %s\n",
                             gpg_strerror (err));
                  goto leave;
                }
            }

          mod_key = 1;
          /* KEYBLOCK_ORIG has been updated; write */
          err = keydb_update_keyblock (ctrl, hd, keyblock_orig);
          if (err)
            log_error (_("error writing keyring '%s': %s\n"),
                       keydb_get_resource_name (hd), gpg_strerror (err));
          else if (non_self)
            revalidation_mark (ctrl);

          /* Release the handle and thus unlock the keyring asap.  */
          keydb_release (hd);
          hd = NULL;

          /* We are ready.  Print and update stats if we got no error.
           * An error here comes from writing the keyblock and thus
           * very likely means that no update happened.  */
          if (!err && !opt.quiet && !silent)
            {
              char *p = get_user_id_byfpr_native (ctrl, fpr2);
              if (n_uids == 1 )
                log_info( _("key %s: \"%s\" 1 new user ID\n"),
                          keystr(keyid),p);
              else if (n_uids )
                log_info( _("key %s: \"%s\" %d new user IDs\n"),
                          keystr(keyid),p,n_uids);
              if (n_sigs == 1 )
                log_info( _("key %s: \"%s\" 1 new signature\n"),
                          keystr(keyid), p);
              else if (n_sigs )
                log_info( _("key %s: \"%s\" %d new signatures\n"),
                          keystr(keyid), p, n_sigs );
              if (n_subk == 1 )
                log_info( _("key %s: \"%s\" 1 new subkey\n"),
                          keystr(keyid), p);
              else if (n_subk )
                log_info( _("key %s: \"%s\" %d new subkeys\n"),
                          keystr(keyid), p, n_subk );
              if (n_sigs_cleaned==1)
                log_info(_("key %s: \"%s\" %d signature cleaned\n"),
                         keystr(keyid),p,n_sigs_cleaned);
              else if (n_sigs_cleaned)
                log_info(_("key %s: \"%s\" %d signatures cleaned\n"),
                         keystr(keyid),p,n_sigs_cleaned);
              if (n_uids_cleaned==1)
                log_info(_("key %s: \"%s\" %d user ID cleaned\n"),
                         keystr(keyid),p,n_uids_cleaned);
              else if (n_uids_cleaned)
                log_info(_("key %s: \"%s\" %d user IDs cleaned\n"),
                         keystr(keyid),p,n_uids_cleaned);
              xfree(p);
            }

          if (!err)
            {
              stats->n_uids +=n_uids;
              stats->n_sigs +=n_sigs;
              stats->n_subk +=n_subk;
              stats->n_sigs_cleaned +=n_sigs_cleaned;
              stats->n_uids_cleaned +=n_uids_cleaned;

              if (is_status_enabled () && !silent)
                print_import_ok (pk, ((n_uids?2:0)|(n_sigs?4:0)|(n_subk?8:0)));
            }
	}
      else
        {
          /* Release the handle and thus unlock the keyring asap.  */
          keydb_release (hd);
          hd = NULL;

          /* FIXME: We do not track the time we last checked a key for
           * updates.  To do this we would need to rewrite even the
           * keys which have no changes.  Adding this would be useful
           * for the automatic update of expired keys via the WKD in
           * case the WKD still carries the expired key.  See
           * get_best_pubkey_byname.  */
          same_key = 1;
          if (is_status_enabled ())
            print_import_ok (pk, 0);

          if (!opt.quiet && !silent)
            {
              char *p = get_user_id_byfpr_native (ctrl, fpr2);
              log_info( _("key %s: \"%s\" not changed\n"),keystr(keyid),p);
              xfree(p);
            }

          stats->unchanged++;
        }
    }

 leave:
  keydb_release (hd);
  if (mod_key || new_key || same_key)
    {
      /* A little explanation for this: we fill in the fingerprint
         when importing keys as it can be useful to know the
         fingerprint in certain keyserver-related cases (a keyserver
         asked for a particular name, but the key doesn't have that
         name).  However, in cases where we're importing more than
         one key at a time, we cannot know which key to fingerprint.
         In these cases, rather than guessing, we do not
         fingerprinting at all, and we must hope the user ID on the
         keys are useful.  Note that we need to do this for new
         keys, merged keys and even for unchanged keys.  This is
         required because for example the --auto-key-locate feature
         may import an already imported key and needs to know the
         fingerprint of the key in all cases.  */
      if (fpr)
        {
          /* Note that we need to compare against 0 here because
             COUNT gets only incremented after returning from this
             function.  */
          if (!stats->count)
            {
              xfree (*fpr);
              *fpr = fingerprint_from_pk (pk, NULL, fpr_len);
            }
          else if (origin != KEYORG_WKD)
            {
              xfree (*fpr);
              *fpr = NULL;
            }
        }
    }

  /* Now that the key is definitely incorporated into the keydb, we
     need to check if a designated revocation is present or if the
     prefs are not rational so we can warn the user. */

  if (mod_key)
    {
      revocation_present (ctrl, keyblock_orig);
      if (!from_sk && have_secret_key_with_kid (keyid))
        check_prefs (ctrl, keyblock_orig);
    }
  else if (new_key)
    {
      revocation_present (ctrl, keyblock);
      if (!from_sk && have_secret_key_with_kid (keyid))
        check_prefs (ctrl, keyblock);
    }

  release_kbnode( keyblock_orig );

  return err;
}


/* Wrapper around import_one_real to retry the import in some cases.  */
static gpg_error_t
import_one (ctrl_t ctrl,
            kbnode_t keyblock, struct import_stats_s *stats,
	    unsigned char **fpr, size_t *fpr_len, unsigned int options,
	    int from_sk, int silent,
            import_screener_t screener, void *screener_arg,
            int origin, const char *url, int *r_valid)
{
  gpg_error_t err;
  kbnode_t otherrevsigs = NULL;
  kbnode_t node;

  err = import_one_real (ctrl, keyblock, stats, fpr, fpr_len, options,
                         from_sk, silent, screener, screener_arg,
                         origin, url, r_valid, &otherrevsigs);
  if (gpg_err_code (err) == GPG_ERR_TOO_LARGE
      && gpg_err_source (err) == GPG_ERR_SOURCE_KEYBOX
      && ((options & (IMPORT_SELF_SIGS_ONLY | IMPORT_CLEAN))
          != (IMPORT_SELF_SIGS_ONLY | IMPORT_CLEAN)))
    {
      /* We hit the maximum image length.  Ask the wrapper to do
       * everything again but this time with some extra options.  */
      u32 keyid[2];

      keyid_from_pk (keyblock->pkt->pkt.public_key, keyid);
      log_info ("key %s: keyblock too large, retrying with self-sigs-only\n",
                keystr (keyid));
      options |= IMPORT_SELF_SIGS_ONLY | IMPORT_CLEAN;
      err = import_one_real (ctrl, keyblock, stats, fpr, fpr_len, options,
                             from_sk, silent, screener, screener_arg,
                             origin, url, r_valid, &otherrevsigs);
    }

  /* Finally try to import other revocation certificates.  For example
   * those of a former key appended to the current key.  */
  if (!err)
    {
      for (node = otherrevsigs; node; node = node->next)
        import_revoke_cert (ctrl, node, options, stats);
    }
  release_kbnode (otherrevsigs);
  return err;
}


/* Transfer all the secret keys in SEC_KEYBLOCK to the gpg-agent.  The
 * function prints diagnostics and returns an error code.  If BATCH is
 * true the secret keys are stored by gpg-agent in the transfer format
 * (i.e. no re-protection and aksing for passphrases). If ONLY_MARKED
 * is set, only those nodes with flag NODE_TRANSFER_SECKEY are
 * processed.  */
gpg_error_t
transfer_secret_keys (ctrl_t ctrl, struct import_stats_s *stats,
                      kbnode_t sec_keyblock, int batch, int force,
                      int only_marked)
{
  gpg_error_t err = 0;
  void *kek = NULL;
  size_t keklen;
  kbnode_t ctx = NULL;
  kbnode_t node;
  PKT_public_key *main_pk, *pk;
  struct seckey_info *ski;
  int nskey;
  membuf_t mbuf;
  int i, j;
  void *format_args[2*PUBKEY_MAX_NSKEY];
  gcry_sexp_t skey, prot, tmpsexp;
  gcry_sexp_t curve = NULL;
  unsigned char *transferkey = NULL;
  size_t transferkeylen;
  gcry_cipher_hd_t cipherhd = NULL;
  unsigned char *wrappedkey = NULL;
  size_t wrappedkeylen;
  char *cache_nonce = NULL;
  int stub_key_skipped = 0;

  /* Get the current KEK.  */
  err = agent_keywrap_key (ctrl, 0, &kek, &keklen);
  if (err)
    {
      log_error ("error getting the KEK: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Prepare a cipher context.  */
  err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (!err)
    err = gcry_cipher_setkey (cipherhd, kek, keklen);
  if (err)
    goto leave;
  xfree (kek);
  kek = NULL;

  /* Note: We need to use walk_kbnode so that we skip nodes which are
   * marked as deleted.  */
  main_pk = NULL;
  while ((node = walk_kbnode (sec_keyblock, &ctx, 0)))
    {
      if (node->pkt->pkttype != PKT_SECRET_KEY
          && node->pkt->pkttype != PKT_SECRET_SUBKEY)
        continue;
      if (only_marked && !(node->flag & NODE_TRANSFER_SECKEY))
        continue;
      pk = node->pkt->pkt.public_key;
      if (!main_pk)
        main_pk = pk;

      /* Make sure the keyids are available.  */
      keyid_from_pk (pk, NULL);
      if (node->pkt->pkttype == PKT_SECRET_KEY)
        {
          pk->main_keyid[0] = pk->keyid[0];
          pk->main_keyid[1] = pk->keyid[1];
        }
      else
        {
          pk->main_keyid[0] = main_pk->keyid[0];
          pk->main_keyid[1] = main_pk->keyid[1];
        }


      ski = pk->seckey_info;
      if (!ski)
        BUG ();

      if (stats)
        {
          stats->count++;
          stats->secret_read++;
        }

      /* We ignore stub keys.  The way we handle them in other parts
         of the code is by asking the agent whether any secret key is
         available for a given keyblock and then concluding that we
         have a secret key; all secret (sub)keys of the keyblock the
         agent does not know of are then stub keys.  This works also
         for card stub keys.  The learn command or the card-status
         command may be used to check with the agent whether a card
         has been inserted and a stub key is in turn generated by the
         agent.  */
      if (ski->s2k.mode == 1001 || ski->s2k.mode == 1002)
        {
          stub_key_skipped = 1;
          continue;
        }

      /* Convert our internal secret key object into an S-expression.  */
      nskey = pubkey_get_nskey (pk->pubkey_algo);
      if (!nskey || nskey > PUBKEY_MAX_NSKEY)
        {
          err = gpg_error (GPG_ERR_BAD_SECKEY);
          log_error ("internal error: %s\n", gpg_strerror (err));
          goto leave;
        }

      init_membuf (&mbuf, 50);
      put_membuf_str (&mbuf, "(skey");
      if (pk->pubkey_algo == PUBKEY_ALGO_ECDSA
          || pk->pubkey_algo == PUBKEY_ALGO_EDDSA
          || pk->pubkey_algo == PUBKEY_ALGO_ECDH)
        {
          /* The ECC case.  */
          char *curvestr = openpgp_oid_to_str (pk->pkey[0]);
          if (!curvestr)
            err = gpg_error_from_syserror ();
          else
            {
              const char *curvename = openpgp_oid_to_curve (curvestr, 1);
              gcry_sexp_release (curve);
              err = gcry_sexp_build (&curve, NULL, "(curve %s)",
                                     curvename?curvename:curvestr);
              xfree (curvestr);
              if (!err)
                {
                  j = 0;
                  /* Append the public key element Q.  */
                  put_membuf_str (&mbuf, " _ %m");
                  format_args[j++] = pk->pkey + 1;

                  /* Append the secret key element D.  For ECDH we
                     skip PKEY[2] because this holds the KEK which is
                     not needed by gpg-agent.  */
                  i = pk->pubkey_algo == PUBKEY_ALGO_ECDH? 3 : 2;
                  if (gcry_mpi_get_flag (pk->pkey[i], GCRYMPI_FLAG_USER1))
                    put_membuf_str (&mbuf, " e %m");
                  else
                    put_membuf_str (&mbuf, " _ %m");
                  format_args[j++] = pk->pkey + i;
                }
            }
        }
      else
        {
          /* Standard case for the old (non-ECC) algorithms.  */
          for (i=j=0; i < nskey; i++)
            {
              if (!pk->pkey[i])
                continue; /* Protected keys only have NPKEY+1 elements.  */

              if (gcry_mpi_get_flag (pk->pkey[i], GCRYMPI_FLAG_USER1))
                put_membuf_str (&mbuf, " e %m");
              else
                put_membuf_str (&mbuf, " _ %m");
              format_args[j++] = pk->pkey + i;
            }
        }
      put_membuf_str (&mbuf, ")");
      put_membuf (&mbuf, "", 1);
      if (err)
        xfree (get_membuf (&mbuf, NULL));
      else
        {
          char *format = get_membuf (&mbuf, NULL);
          if (!format)
            err = gpg_error_from_syserror ();
          else
            err = gcry_sexp_build_array (&skey, NULL, format, format_args);
          xfree (format);
        }
      if (err)
        {
          log_error ("error building skey array: %s\n", gpg_strerror (err));
          goto leave;
        }

      if (ski->is_protected)
        {
          char countbuf[35];

          /* Note that the IVLEN may be zero if we are working on a
             dummy key.  We can't express that in an S-expression and
             thus we send dummy data for the IV.  */
          snprintf (countbuf, sizeof countbuf, "%lu",
                    (unsigned long)ski->s2k.count);
          err = gcry_sexp_build
            (&prot, NULL,
             " (protection %s %s %b %d %s %b %s)\n",
             ski->sha1chk? "sha1":"sum",
             openpgp_cipher_algo_name (ski->algo),
             ski->ivlen? (int)ski->ivlen:1,
             ski->ivlen? ski->iv: (const unsigned char*)"X",
             ski->s2k.mode,
             openpgp_md_algo_name (ski->s2k.hash_algo),
             (int)sizeof (ski->s2k.salt), ski->s2k.salt,
             countbuf);
        }
      else
        err = gcry_sexp_build (&prot, NULL, " (protection none)\n");

      tmpsexp = NULL;
      xfree (transferkey);
      transferkey = NULL;
      if (!err)
        err = gcry_sexp_build (&tmpsexp, NULL,
                               "(openpgp-private-key\n"
                               " (version %d)\n"
                               " (algo %s)\n"
                               " %S%S\n"
                               " (csum %d)\n"
                               " %S)\n",
                               pk->version,
                               openpgp_pk_algo_name (pk->pubkey_algo),
                               curve, skey,
                               (int)(unsigned long)ski->csum, prot);
      gcry_sexp_release (skey);
      gcry_sexp_release (prot);
      if (!err)
        err = make_canon_sexp_pad (tmpsexp, 1, &transferkey, &transferkeylen);
      gcry_sexp_release (tmpsexp);
      if (err)
        {
          log_error ("error building transfer key: %s\n", gpg_strerror (err));
          goto leave;
        }

      /* Wrap the key.  */
      wrappedkeylen = transferkeylen + 8;
      xfree (wrappedkey);
      wrappedkey = xtrymalloc (wrappedkeylen);
      if (!wrappedkey)
        err = gpg_error_from_syserror ();
      else
        err = gcry_cipher_encrypt (cipherhd, wrappedkey, wrappedkeylen,
                                   transferkey, transferkeylen);
      if (err)
        goto leave;
      xfree (transferkey);
      transferkey = NULL;

      /* Send the wrapped key to the agent.  */
      {
        char *desc = gpg_format_keydesc (ctrl, pk, FORMAT_KEYDESC_IMPORT, 1);
        err = agent_import_key (ctrl, desc, &cache_nonce,
                                wrappedkey, wrappedkeylen, batch, force,
				pk->keyid, pk->main_keyid, pk->pubkey_algo,
                                pk->timestamp);
        xfree (desc);
      }
      if (!err)
        {
          if (opt.verbose)
            log_info (_("key %s: secret key imported\n"),
                      keystr_from_pk_with_sub (main_pk, pk));
          if (stats)
            stats->secret_imported++;
        }
      else if ( gpg_err_code (err) == GPG_ERR_EEXIST )
        {
          if (opt.verbose)
            log_info (_("key %s: secret key already exists\n"),
                      keystr_from_pk_with_sub (main_pk, pk));
          err = 0;
          if (stats)
            stats->secret_dups++;
        }
      else
        {
          log_error (_("key %s: error sending to agent: %s\n"),
                     keystr_from_pk_with_sub (main_pk, pk),
                     gpg_strerror (err));
          if (gpg_err_code (err) == GPG_ERR_CANCELED
              || gpg_err_code (err) == GPG_ERR_FULLY_CANCELED)
            break; /* Don't try the other subkeys.  */
        }
    }

  if (!err && stub_key_skipped)
    /* We need to notify user how to migrate stub keys.  */
    err = gpg_error (GPG_ERR_NOT_PROCESSED);

 leave:
  gcry_sexp_release (curve);
  xfree (cache_nonce);
  xfree (wrappedkey);
  xfree (transferkey);
  gcry_cipher_close (cipherhd);
  xfree (kek);
  return err;
}


/* Walk a secret keyblock and produce a public keyblock out of it.
 * Returns a new node or NULL on error.  Modifies the tag field of the
 * nodes.  */
static kbnode_t
sec_to_pub_keyblock (kbnode_t sec_keyblock)
{
  kbnode_t pub_keyblock = NULL;
  kbnode_t ctx = NULL;
  kbnode_t secnode, pubnode;
  kbnode_t lastnode = NULL;
  unsigned int tag = 0;

  /* Set a tag to all nodes.  */
  for (secnode = sec_keyblock; secnode; secnode = secnode->next)
    secnode->tag = ++tag;

  /* Copy.  */
  while ((secnode = walk_kbnode (sec_keyblock, &ctx, 0)))
    {
      if (secnode->pkt->pkttype == PKT_SECRET_KEY
          || secnode->pkt->pkttype == PKT_SECRET_SUBKEY)
	{
	  /* Make a public key.  */
	  PACKET *pkt;
          PKT_public_key *pk;

	  pkt = xtrycalloc (1, sizeof *pkt);
          pk = pkt? copy_public_key (NULL, secnode->pkt->pkt.public_key): NULL;
          if (!pk)
            {
              xfree (pkt);
	      release_kbnode (pub_keyblock);
              return NULL;
            }
	  if (secnode->pkt->pkttype == PKT_SECRET_KEY)
	    pkt->pkttype = PKT_PUBLIC_KEY;
	  else
	    pkt->pkttype = PKT_PUBLIC_SUBKEY;
	  pkt->pkt.public_key = pk;

	  pubnode = new_kbnode (pkt);
	}
      else
	{
	  pubnode = clone_kbnode (secnode);
	}
      pubnode->tag = secnode->tag;

      if (!pub_keyblock)
        pub_keyblock = lastnode = pubnode;
      else
        {
          lastnode->next = pubnode;
          lastnode = pubnode;
        }
    }

  return pub_keyblock;
}


/* Delete all notes in the keyblock at R_KEYBLOCK which are not in
 * PUB_KEYBLOCK.  Modifies the tags of both keyblock's nodes.  */
static gpg_error_t
resync_sec_with_pub_keyblock (kbnode_t *r_keyblock, kbnode_t pub_keyblock,
                              kbnode_t *r_removedsecs)
{
  kbnode_t sec_keyblock = *r_keyblock;
  kbnode_t node, prevnode;
  unsigned int *taglist;
  unsigned int ntaglist, n;
  kbnode_t attic = NULL;
  kbnode_t *attic_head = &attic;

  /* Collect all tags in an array for faster searching.  */
  for (ntaglist = 0, node = pub_keyblock; node; node = node->next)
    ntaglist++;
  taglist = xtrycalloc (ntaglist, sizeof *taglist);
  if (!taglist)
    return gpg_error_from_syserror ();
  for (ntaglist = 0, node = pub_keyblock; node; node = node->next)
    taglist[ntaglist++] = node->tag;

  /* Walks over the secret keyblock and delete all nodes which are not
   * in the tag list.  Those nodes have been deleted in the
   * pub_keyblock.  Sequential search is a bit lazy and could be
   * optimized by sorting and bsearch; however secret keyrings are
   * short and there are easier ways to DoS the import.  */
 again:
  for (prevnode=NULL, node=sec_keyblock; node; prevnode=node, node=node->next)
    {
      for (n=0; n < ntaglist; n++)
        if (taglist[n] == node->tag)
          break;
      if (n == ntaglist)  /* Not in public keyblock.  */
        {
          if (node->pkt->pkttype == PKT_SECRET_KEY
              || node->pkt->pkttype == PKT_SECRET_SUBKEY)
            {
              if (!prevnode)
                sec_keyblock = node->next;
              else
                prevnode->next = node->next;
              node->next = NULL;
              *attic_head = node;
              attic_head = &node->next;
              goto again;  /* That's lame; I know.  */
            }
          else
            delete_kbnode (node);
        }
    }

  xfree (taglist);

  /* Commit the as deleted marked nodes and return the possibly
   * modified keyblock and a list of removed secret key nodes.  */
  commit_kbnode (&sec_keyblock);
  *r_keyblock = sec_keyblock;
  *r_removedsecs = attic;
  return 0;
}


/* Helper for import_secret_one.  */
static gpg_error_t
do_transfer (ctrl_t ctrl, kbnode_t keyblock, PKT_public_key *pk,
             struct import_stats_s *stats, int batch, int only_marked)

{
  gpg_error_t err;
  struct import_stats_s subkey_stats = {0};
  int force = 0;
  int already_exist = agent_probe_secret_key (ctrl, pk);

  if (already_exist == 2)
    {
      if (!opt.quiet)
        log_info (_("key %s: card reference is overridden by key material\n"),
                  keystr_from_pk (pk));
      force = 1;
    }

  err = transfer_secret_keys (ctrl, &subkey_stats, keyblock,
                              batch, force, only_marked);
  if (gpg_err_code (err) == GPG_ERR_NOT_PROCESSED)
    {
      /* TRANSLATORS: For a smartcard, each private key on host has a
       * reference (stub) to a smartcard and actual private key data
       * is stored on the card.  A single smartcard can have up to
       * three private key data.  Importing private key stub is always
       * skipped in 2.1, and it returns GPG_ERR_NOT_PROCESSED.
       * Instead, user should be suggested to run 'gpg --card-status',
       * then, references to a card will be automatically created
       * again.  */
      log_info (_("To migrate '%s', with each smartcard, "
                  "run: %s\n"), "secring.gpg", "gpg --card-status");
      err = 0;
    }

  if (!err)
    {
      int status = 16;

      if (!opt.quiet)
        log_info (_("key %s: secret key imported\n"), keystr_from_pk (pk));
      if (subkey_stats.secret_imported)
        {
          status |= 1;
          stats->secret_imported += 1;
        }
      if (subkey_stats.secret_dups)
        stats->secret_dups += 1;

      if (is_status_enabled ())
        print_import_ok (pk, status);
    }

  return err;
}


/* If the secret keys (main or subkey) in SECKEYS have a corresponding
 * public key in the public key described by (FPR,FPRLEN) import these
 * parts.
 */
static gpg_error_t
import_matching_seckeys (ctrl_t ctrl, kbnode_t seckeys,
                         const byte *mainfpr, size_t mainfprlen,
                         struct import_stats_s *stats, int batch)
{
  gpg_error_t err;
  kbnode_t pub_keyblock = NULL;
  kbnode_t node;
  struct { byte fpr[MAX_FINGERPRINT_LEN]; size_t fprlen; } *fprlist = NULL;
  size_t n, nfprlist;
  byte fpr[MAX_FINGERPRINT_LEN];
  size_t fprlen;
  PKT_public_key *pk;

  /* Get the entire public key block from our keystore and put all its
   * fingerprints into an array.  */
  err = get_pubkey_byfprint (ctrl, NULL, &pub_keyblock, mainfpr, mainfprlen);
  if (err)
    goto leave;
  log_assert (pub_keyblock && pub_keyblock->pkt->pkttype == PKT_PUBLIC_KEY);
  pk = pub_keyblock->pkt->pkt.public_key;

  for (nfprlist = 0, node = pub_keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_PUBLIC_KEY
        || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
      nfprlist++;
  log_assert (nfprlist);
  fprlist = xtrycalloc (nfprlist, sizeof *fprlist);
  if (!fprlist)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  for (n = 0, node = pub_keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_PUBLIC_KEY
        || node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
      {
        fingerprint_from_pk (node->pkt->pkt.public_key,
                             fprlist[n].fpr, &fprlist[n].fprlen);
        n++;
      }
  log_assert (n == nfprlist);

  /* for (n=0; n < nfprlist; n++) */
  /*   log_printhex (fprlist[n].fpr, fprlist[n].fprlen, "pubkey %zu:", n); */

  /* Mark all secret keys which have a matching public key part in
   * PUB_KEYBLOCK.  */
  for (node = seckeys; node; node = node->next)
    {
      if (node->pkt->pkttype != PKT_SECRET_KEY
          && node->pkt->pkttype != PKT_SECRET_SUBKEY)
        continue; /* Should not happen.  */
      fingerprint_from_pk (node->pkt->pkt.public_key, fpr, &fprlen);
      node->flag &= ~NODE_TRANSFER_SECKEY;
      for (n=0; n < nfprlist; n++)
        if (fprlist[n].fprlen == fprlen && !memcmp (fprlist[n].fpr,fpr,fprlen))
          {
            node->flag |= NODE_TRANSFER_SECKEY;
            /* log_debug ("found matching seckey\n"); */
            break;
          }
    }

  /* Transfer all marked keys.  */
  err = do_transfer (ctrl, seckeys, pk, stats, batch, 1);

 leave:
  xfree (fprlist);
  release_kbnode (pub_keyblock);
  return err;
}


/* Import function for a single secret keyblock.  Handling is simpler
 * than for public keys.  We allow secret key importing only when
 * allow is true, this is so that a secret key can not be imported
 * accidentally and thereby tampering with the trust calculation.
 *
 * Ownership of KEYBLOCK is transferred to this function!
 *
 * If R_SECATTIC is not null the last special sec_keyblock is stored
 * there.
 */
static gpg_error_t
import_secret_one (ctrl_t ctrl, kbnode_t keyblock,
                   struct import_stats_s *stats, int batch,
                   unsigned int options, int for_migration,
                   import_screener_t screener, void *screener_arg,
                   kbnode_t *r_secattic)
{
  PKT_public_key *pk;
  struct seckey_info *ski;
  kbnode_t node, uidnode;
  u32 keyid[2];
  gpg_error_t err = 0;
  int nr_prev;
  kbnode_t pub_keyblock;
  kbnode_t attic = NULL;
  byte fpr[MAX_FINGERPRINT_LEN];
  size_t fprlen;
  char pkstrbuf[PUBKEY_STRING_SIZE];

  /* Get the key and print some info about it */
  node = find_kbnode (keyblock, PKT_SECRET_KEY);
  if (!node)
    BUG ();

  pk = node->pkt->pkt.public_key;

  fingerprint_from_pk (pk, fpr, &fprlen);
  keyid_from_pk (pk, keyid);
  uidnode = find_next_kbnode (keyblock, PKT_USER_ID);

  if (screener && screener (keyblock, screener_arg))
    {
      log_error (_("secret key %s: %s\n"), keystr_from_pk (pk),
                 _("rejected by import screener"));
      release_kbnode (keyblock);
      return 0;
  }

  if (opt.verbose && !for_migration)
    {
      log_info ("sec  %s/%s %s  ",
                pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
                keystr_from_pk (pk), datestr_from_pk (pk));
      if (uidnode)
        print_utf8_buffer (log_get_stream (), uidnode->pkt->pkt.user_id->name,
                           uidnode->pkt->pkt.user_id->len);
      log_printf ("\n");
    }
  stats->secret_read++;

  if ((options & IMPORT_NO_SECKEY))
    {
      if (!for_migration)
        log_error (_("importing secret keys not allowed\n"));
      release_kbnode (keyblock);
      return 0;
    }

  if (!uidnode)
    {
      if (!for_migration)
        log_error( _("key %s: no user ID\n"), keystr_from_pk (pk));
      release_kbnode (keyblock);
      return 0;
    }

  ski = pk->seckey_info;
  if (!ski)
    {
      /* Actually an internal error.  */
      log_error ("key %s: secret key info missing\n", keystr_from_pk (pk));
      release_kbnode (keyblock);
      return 0;
    }

  /* A quick check to not import keys with an invalid protection
     cipher algorithm (only checks the primary key, though).  */
  if (ski->algo > 110)
    {
      if (!for_migration)
        log_error (_("key %s: secret key with invalid cipher %d"
                     " - skipped\n"), keystr_from_pk (pk), ski->algo);
      release_kbnode (keyblock);
      return 0;
    }

#ifdef ENABLE_SELINUX_HACKS
  if (1)
    {
      /* We don't allow importing secret keys because that may be used
         to put a secret key into the keyring and the user might later
         be tricked into signing stuff with that key.  */
      log_error (_("importing secret keys not allowed\n"));
      release_kbnode (keyblock);
      return 0;
    }
#endif

  clear_kbnode_flags (keyblock);

  nr_prev = stats->skipped_new_keys;

  /* Make a public key out of the key. */
  pub_keyblock = sec_to_pub_keyblock (keyblock);
  if (!pub_keyblock)
    {
      err = gpg_error_from_syserror ();
      log_error ("key %s: failed to create public key from secret key\n",
                 keystr_from_pk (pk));
    }
  else
    {
      int valid;

      /* Note that this outputs an IMPORT_OK status message for the
	 public key block, and below we will output another one for
	 the secret keys.  FIXME?  */
      import_one (ctrl, pub_keyblock, stats,
		  NULL, NULL, options, 1, for_migration,
                  screener, screener_arg, 0, NULL, &valid);

      /* The secret keyblock may not have nodes which are deleted in
       * the public keyblock.  Otherwise we would import just the
       * secret key without having the public key.  That would be
       * surprising and clutters our private-keys-v1.d.  */
      err = resync_sec_with_pub_keyblock (&keyblock, pub_keyblock, &attic);
      if (err)
        goto leave;

      if (!valid)
        {
          /* If the block was not valid the primary key is left in the
           * original keyblock because we require that for the first
           * node.   Move it to ATTIC.  */
          if (keyblock && keyblock->pkt->pkttype == PKT_SECRET_KEY)
            {
              node = keyblock;
              keyblock = node->next;
              node->next = NULL;
              if (attic)
                {
                  node->next = attic;
                  attic = node;
                }
              else
                attic = node;
            }

          /* Try to import the secret key iff we have a public key.  */
          if (attic && !(opt.dry_run || (options & IMPORT_DRY_RUN)))
            err = import_matching_seckeys (ctrl, attic, fpr, fprlen,
                                           stats, batch);
          else
            err = gpg_error (GPG_ERR_NO_SECKEY);
          goto leave;
        }

      /* log_debug ("attic is:\n"); */
      /* dump_kbnode (attic); */

      /* Proceed with the valid parts of PUBKEYBLOCK. */

      /* At least we cancel the secret key import when the public key
	 import was skipped due to MERGE_ONLY option and a new
	 key.  */
      if (!(opt.dry_run || (options & IMPORT_DRY_RUN))
          && stats->skipped_new_keys <= nr_prev)
	{
          /* Read the keyblock again to get the effects of a merge for
           * the public key.  */
          err = get_pubkey_byfprint (ctrl, NULL, &node, fpr, fprlen);
          if (err || !node)
            log_error ("key %s: failed to re-lookup public key: %s\n",
                       keystr_from_pk (pk), gpg_strerror (err));
          else
            {
              err = do_transfer (ctrl, keyblock, pk, stats, batch, 0);
              if (!err)
                check_prefs (ctrl, node);
              release_kbnode (node);

              if (!err && attic)
                {
                  /* Try to import invalid subkeys.  This can be the
                   * case if the primary secret key was imported due
                   * to --allow-non-selfsigned-uid.  */
                  err = import_matching_seckeys (ctrl, attic, fpr, fprlen,
                                                 stats, batch);
                }

            }
        }
    }

 leave:
  release_kbnode (keyblock);
  release_kbnode (pub_keyblock);
  if (r_secattic)
    *r_secattic = attic;
  else
    release_kbnode (attic);
  return err;
}



/* Return the recocation reason from signature SIG.  If no revocation
 * reason is availabale 0 is returned, in other cases the reason
 * (0..255).  If R_REASON is not NULL a malloced textual
 * representation of the code is stored there.  If R_COMMENT is not
 * NULL the comment from the reason is stored there and its length at
 * R_COMMENTLEN.  Note that the value at R_COMMENT is not filtered but
 * user supplied data in UTF8; thus it needs to be escaped for display
 * purposes.  Both return values are either NULL or a malloced
 * string/buffer.  */
int
get_revocation_reason (PKT_signature *sig, char **r_reason,
                       char **r_comment, size_t *r_commentlen)
{
  int reason_seq = 0;
  size_t reason_n;
  const byte *reason_p;
  char reason_code_buf[20];
  const char *reason_text = NULL;
  int reason_code = 0;

  if (r_reason)
    *r_reason = NULL;
  if (r_comment)
    *r_comment = NULL;

  /* Skip over empty reason packets.  */
  while ((reason_p = enum_sig_subpkt (sig->hashed, SIGSUBPKT_REVOC_REASON,
                                      &reason_n, &reason_seq, NULL))
         && !reason_n)
    ;
  if (reason_p)
    {
      reason_code = *reason_p;
      reason_n--; reason_p++;
      switch (reason_code)
        {
        case 0x00: reason_text = _("No reason specified"); break;
        case 0x01: reason_text = _("Key is superseded");   break;
        case 0x02: reason_text = _("Key has been compromised"); break;
        case 0x03: reason_text = _("Key is no longer used"); break;
        case 0x20: reason_text = _("User ID is no longer valid"); break;
        default:
          snprintf (reason_code_buf, sizeof reason_code_buf,
                    "code=%02x", reason_code);
          reason_text = reason_code_buf;
          break;
        }

      if (r_reason)
        *r_reason = xstrdup (reason_text);

      if (r_comment && reason_n)
        {
          *r_comment = xmalloc (reason_n);
          memcpy (*r_comment, reason_p, reason_n);
          *r_commentlen = reason_n;
        }
    }

  return reason_code;
}


/* List the recocation signature as a "rvs" record.  SIGRC shows the
 * character from the signature verification or 0 if no public key was
 * found.  */
static void
list_standalone_revocation (ctrl_t ctrl, PKT_signature *sig, int sigrc)
{
  char *siguid = NULL;
  size_t siguidlen = 0;
  char *issuer_fpr = NULL;
  int reason_code = 0;
  char *reason_text = NULL;
  char *reason_comment = NULL;
  size_t reason_commentlen;

  if (sigrc != '%' && sigrc != '?' && !opt.fast_list_mode)
    {
      int nouid;
      siguid = get_user_id (ctrl, sig->keyid, &siguidlen, &nouid);
      if (nouid)
        sigrc = '?';
    }

  reason_code = get_revocation_reason (sig, &reason_text,
                                       &reason_comment, &reason_commentlen);

  if (opt.with_colons)
    {
      es_fputs ("rvs:", es_stdout);
      if (sigrc)
        es_putc (sigrc, es_stdout);
      es_fprintf (es_stdout, "::%d:%08lX%08lX:%s:%s:::",
                  sig->pubkey_algo,
                  (ulong) sig->keyid[0], (ulong) sig->keyid[1],
                  colon_datestr_from_sig (sig),
                  colon_expirestr_from_sig (sig));

      if (siguid)
        es_write_sanitized (es_stdout, siguid, siguidlen, ":", NULL);

      es_fprintf (es_stdout, ":%02x%c", sig->sig_class,
                  sig->flags.exportable ? 'x' : 'l');
      if (reason_text)
        es_fprintf (es_stdout, ",%02x", reason_code);
      es_fputs ("::", es_stdout);

      if ((issuer_fpr = issuer_fpr_string (sig)))
        es_fputs (issuer_fpr, es_stdout);

      es_fprintf (es_stdout, ":::%d:", sig->digest_algo);

      if (reason_comment)
        {
          es_fputs ("::::", es_stdout);
          es_write_sanitized (es_stdout, reason_comment, reason_commentlen,
                              ":", NULL);
          es_putc (':', es_stdout);
        }
      es_putc ('\n', es_stdout);

      if (opt.show_subpackets)
        print_subpackets_colon (sig);
    }
  else /* Human readable. */
    {
      es_fputs ("rvs", es_stdout);
      es_fprintf (es_stdout, "%c%c %c%c%c%c%c%c %s %s",
		  sigrc, (sig->sig_class - 0x10 > 0 &&
			  sig->sig_class - 0x10 <
			  4) ? '0' + sig->sig_class - 0x10 : ' ',
		  sig->flags.exportable ? ' ' : 'L',
		  sig->flags.revocable ? ' ' : 'R',
		  sig->flags.policy_url ? 'P' : ' ',
		  sig->flags.notation ? 'N' : ' ',
		  sig->flags.expired ? 'X' : ' ',
		  (sig->trust_depth > 9) ? 'T' : (sig->trust_depth >
						  0) ? '0' +
		  sig->trust_depth : ' ', keystr (sig->keyid),
		  datestr_from_sig (sig));
      if (siguid)
        {
          es_fprintf (es_stdout, "  ");
          print_utf8_buffer (es_stdout, siguid, siguidlen);
        }
      es_putc ('\n', es_stdout);

      if (sig->flags.policy_url
          && (opt.list_options & LIST_SHOW_POLICY_URLS))
        show_policy_url (sig, 3, 0);

      if (sig->flags.notation && (opt.list_options & LIST_SHOW_NOTATIONS))
        show_notation (sig, 3, 0,
                       ((opt.list_options & LIST_SHOW_STD_NOTATIONS) ? 1 : 0)
                       +
                       ((opt.list_options & LIST_SHOW_USER_NOTATIONS) ? 2 : 0));

      if (sig->flags.pref_ks
          && (opt.list_options & LIST_SHOW_KEYSERVER_URLS))
        show_keyserver_url (sig, 3, 0);

      if (reason_text)
        {
          es_fprintf (es_stdout, "      %s%s\n",
                      _("reason for revocation: "), reason_text);
          if (reason_comment)
            {
              const byte *s, *s_lf;
              size_t n, n_lf;

              s = reason_comment;
              n = reason_commentlen;
              s_lf = NULL;
              do
                {
                  /* We don't want any empty lines, so we skip them.  */
                  for (;n && *s == '\n'; s++, n--)
                    ;
                  if (n)
                    {
                      s_lf = memchr (s, '\n', n);
                      n_lf = s_lf? s_lf - s : n;
                      es_fprintf (es_stdout, "         %s",
                                  _("revocation comment: "));
                      es_write_sanitized (es_stdout, s, n_lf, NULL, NULL);
                      es_putc ('\n', es_stdout);
                      s += n_lf; n -= n_lf;
                    }
                } while (s_lf);
            }
        }
    }

  es_fflush (es_stdout);

  xfree (reason_text);
  xfree (reason_comment);
  xfree (siguid);
  xfree (issuer_fpr);
}


/* Import a revocation certificate; only the first packet in the
 * NODE-list is considered.  */
static int
import_revoke_cert (ctrl_t ctrl, kbnode_t node, unsigned int options,
                    struct import_stats_s *stats)
{
  PKT_public_key *pk = NULL;
  kbnode_t onode;
  kbnode_t keyblock = NULL;
  KEYDB_HANDLE hd = NULL;
  u32 keyid[2];
  int rc = 0;
  int sigrc = 0;
  int silent;

  /* No error output for --show-keys.  */
  silent = (options & (IMPORT_SHOW | IMPORT_DRY_RUN));

  log_assert (node->pkt->pkttype == PKT_SIGNATURE );
  log_assert (IS_KEY_REV (node->pkt->pkt.signature));

  /* FIXME: We can do better here by using the issuer fingerprint if
   * available.  We should also make use of get_keyblock_byfprint_fast.  */

  keyid[0] = node->pkt->pkt.signature->keyid[0];
  keyid[1] = node->pkt->pkt.signature->keyid[1];

  pk = xmalloc_clear( sizeof *pk );
  rc = get_pubkey (ctrl, pk, keyid );
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY )
    {
      if (!silent)
        log_error (_("key %s: no public key -"
                     " can't apply revocation certificate\n"), keystr(keyid));
      rc = 0;
      goto leave;
    }
  else if (rc )
    {
      log_error (_("key %s: public key not found: %s\n"),
                 keystr(keyid), gpg_strerror (rc));
      goto leave;
    }

  /* Read the original keyblock. */
  hd = keydb_new ();
  if (!hd)
    {
      rc = gpg_error_from_syserror ();
      goto leave;
    }

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
                 keystr(keyid), gpg_strerror (rc));
      goto leave;
    }
  rc = keydb_get_keyblock (hd, &keyblock );
  if (rc)
    {
      log_error (_("key %s: can't read original keyblock: %s\n"),
                 keystr(keyid), gpg_strerror (rc));
      goto leave;
    }

  /* it is okay, that node is not in keyblock because
   * check_key_signature works fine for sig_class 0x20 (KEY_REV) in
   * this special case.  SIGRC is only used for IMPORT_SHOW.  */
  rc = check_key_signature (ctrl, keyblock, node, NULL);
  switch (gpg_err_code (rc))
    {
    case 0:                       sigrc = '!'; break;
    case GPG_ERR_BAD_SIGNATURE:   sigrc = '-'; break;
    case GPG_ERR_NO_PUBKEY:       sigrc = '?'; break;
    case GPG_ERR_UNUSABLE_PUBKEY: sigrc = '?'; break;
    default:                      sigrc = '%'; break;
    }
  if (rc )
    {
      if (!silent)
        log_error (_("key %s: invalid revocation certificate"
                     ": %s - rejected\n"), keystr(keyid), gpg_strerror (rc));
      goto leave;
    }

  /* check whether we already have this */
  for(onode=keyblock->next; onode; onode=onode->next ) {
    if (onode->pkt->pkttype == PKT_USER_ID )
      break;
    else if (onode->pkt->pkttype == PKT_SIGNATURE
             && !cmp_signatures(node->pkt->pkt.signature,
                                onode->pkt->pkt.signature))
      {
        rc = 0;
        goto leave; /* yes, we already know about it */
      }
  }

  /* insert it */
  insert_kbnode( keyblock, clone_kbnode(node), 0 );

  /* and write the keyblock back unless in dry run mode.  */
  if (!(opt.dry_run || (options & IMPORT_DRY_RUN)))
    {
      rc = keydb_update_keyblock (ctrl, hd, keyblock );
      if (rc)
        log_error (_("error writing keyring '%s': %s\n"),
                   keydb_get_resource_name (hd), gpg_strerror (rc) );
      keydb_release (hd);
      hd = NULL;

      /* we are ready */
      if (!opt.quiet )
        {
          char *p=get_user_id_native (ctrl, keyid);
          log_info( _("key %s: \"%s\" revocation certificate imported\n"),
                    keystr(keyid),p);
          xfree(p);
        }

      /* If the key we just revoked was ultimately trusted, remove its
       * ultimate trust.  This doesn't stop the user from putting the
       * ultimate trust back, but is a reasonable solution for now. */
      if (get_ownertrust (ctrl, pk) == TRUST_ULTIMATE)
        clear_ownertrusts (ctrl, pk);

      revalidation_mark (ctrl);
    }
  stats->n_revoc++;

 leave:
  if ((options & IMPORT_SHOW))
    list_standalone_revocation (ctrl, node->pkt->pkt.signature, sigrc);

  keydb_release (hd);
  release_kbnode( keyblock );
  free_public_key( pk );
  return rc;
}


/* Loop over the KEYBLOCK and check all self signatures.  KEYID is the
 * keyid of the primary key for reporting purposes. On return the
 * following bits in the node flags are set:
 *
 * - NODE_GOOD_SELFSIG  :: User ID or subkey has a self-signature
 * - NODE_BAD_SELFSIG   :: Used ID or subkey has an invalid self-signature
 * - NODE_DELETION_MARK :: This node shall be deleted
 *
 * NON_SELF is set to true if there are any sigs other than self-sigs
 * in this keyblock.
 *
 * Returns 0 on success or -1 (but not an error code) if the keyblock
 * is invalid.
 */
static int
chk_self_sigs (ctrl_t ctrl, kbnode_t keyblock, u32 *keyid, int *non_self)
{
  kbnode_t knode = NULL;   /* The node of the current subkey.  */
  PKT_public_key *subpk = NULL; /* and its packet. */
  kbnode_t bsnode = NULL;  /* Subkey binding signature node.  */
  u32 bsdate = 0;          /* Timestamp of that node.   */
  kbnode_t rsnode = NULL;  /* Subkey recocation signature node.  */
  u32 rsdate = 0;          /* Timestamp of tha node.  */
  PKT_signature *sig;
  int rc;
  kbnode_t n;

  for (n=keyblock; (n = find_next_kbnode (n, 0)); )
    {
      if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  knode = n;
          subpk = knode->pkt->pkt.public_key;
	  bsdate = 0;
	  rsdate = 0;
	  bsnode = NULL;
	  rsnode = NULL;
	  continue;
	}

      if ( n->pkt->pkttype != PKT_SIGNATURE )
        continue;

      sig = n->pkt->pkt.signature;
      if ( keyid[0] != sig->keyid[0] || keyid[1] != sig->keyid[1] )
        {
          *non_self = 1;
          continue;
        }

      /* This just caches the sigs for later use.  That way we
         import a fully-cached key which speeds things up. */
      if (!opt.no_sig_cache)
        check_key_signature (ctrl, keyblock, n, NULL);

      if ( IS_UID_SIG(sig) || IS_UID_REV(sig) )
        {
          kbnode_t unode = find_prev_kbnode( keyblock, n, PKT_USER_ID );
          if ( !unode )
            {
              log_error( _("key %s: no user ID for signature\n"),
                         keystr(keyid));
              return -1;  /* The complete keyblock is invalid.  */
            }

          /* If it hasn't been marked valid yet, keep trying.  */
          if (!(unode->flag & NODE_GOOD_SELFSIG))
            {
              rc = check_key_signature (ctrl, keyblock, n, NULL);
              if ( rc )
                {
                  if ( opt.verbose )
                    {
                      char *p = utf8_to_native
                        (unode->pkt->pkt.user_id->name,
                         strlen (unode->pkt->pkt.user_id->name),0);
                      log_info (gpg_err_code(rc) == GPG_ERR_PUBKEY_ALGO ?
                                _("key %s: unsupported public key "
                                  "algorithm on user ID \"%s\"\n"):
                                _("key %s: invalid self-signature "
                                  "on user ID \"%s\"\n"),
                                keystr (keyid),p);
                      xfree (p);
                    }
                }
              else
                unode->flag |= NODE_GOOD_SELFSIG;
            }
        }
      else if (IS_KEY_SIG (sig))
        {
          rc = check_key_signature (ctrl, keyblock, n, NULL);
          if ( rc )
            {
              if (opt.verbose)
                log_info (gpg_err_code (rc) == GPG_ERR_PUBKEY_ALGO ?
                          _("key %s: unsupported public key algorithm\n"):
                          _("key %s: invalid direct key signature\n"),
                          keystr (keyid));
              n->flag |= NODE_DELETION_MARK;
            }
        }
      else if ( IS_SUBKEY_SIG (sig) )
        {
          /* Note that this works based solely on the timestamps like
             the rest of gpg.  If the standard gets revocation
             targets, this may need to be revised.  */

          if ( !knode )
            {
              if (opt.verbose)
                log_info (_("key %s: no subkey for key binding\n"),
                          keystr (keyid));
              n->flag |= NODE_DELETION_MARK;
            }
          else
            {
              rc = check_key_signature (ctrl, keyblock, n, NULL);
              if ( rc )
                {
                  if (opt.verbose)
                    {
                      keyid_from_pk (subpk, NULL);
                      log_info (gpg_err_code (rc) == GPG_ERR_PUBKEY_ALGO ?
                                _("key %s: unsupported public key"
                                  " algorithm\n"):
                                _("key %s: invalid subkey binding\n"),
                                keystr_with_sub (keyid, subpk->keyid));
                    }
                  n->flag |= NODE_DELETION_MARK;
                }
              else
                {
                  /* It's valid, so is it newer? */
                  if (sig->timestamp >= bsdate)
                    {
                      knode->flag |= NODE_GOOD_SELFSIG; /* Subkey is valid.  */
                      if (bsnode)
                        {
                          /* Delete the last binding sig since this
                             one is newer */
                          bsnode->flag |= NODE_DELETION_MARK;
                          if (opt.verbose)
                            {
                              keyid_from_pk (subpk, NULL);
                              log_info (_("key %s: removed multiple subkey"
                                          " binding\n"),
                                        keystr_with_sub (keyid, subpk->keyid));
                            }
                        }

                      bsnode = n;
                      bsdate = sig->timestamp;
                    }
                  else
                    n->flag |= NODE_DELETION_MARK; /* older */
                }
            }
        }
      else if ( IS_SUBKEY_REV (sig) )
        {
          /* We don't actually mark the subkey as revoked right now,
             so just check that the revocation sig is the most recent
             valid one.  Note that we don't care if the binding sig is
             newer than the revocation sig.  See the comment in
             getkey.c:merge_selfsigs_subkey for more.  */
          if ( !knode )
            {
              if (opt.verbose)
                log_info (_("key %s: no subkey for key revocation\n"),
                          keystr(keyid));
              n->flag |= NODE_DELETION_MARK;
            }
          else
            {
              rc = check_key_signature (ctrl, keyblock, n, NULL);
              if ( rc )
                {
                  if(opt.verbose)
                    log_info (gpg_err_code (rc) == GPG_ERR_PUBKEY_ALGO ?
                              _("key %s: unsupported public"
                                " key algorithm\n"):
                              _("key %s: invalid subkey revocation\n"),
                              keystr(keyid));
                  n->flag |= NODE_DELETION_MARK;
                }
              else
                {
                  /* It's valid, so is it newer? */
                  if (sig->timestamp >= rsdate)
                    {
                      if (rsnode)
                        {
                          /* Delete the last revocation sig since
                             this one is newer.  */
                          rsnode->flag |= NODE_DELETION_MARK;
                          if (opt.verbose)
                            log_info (_("key %s: removed multiple subkey"
                                        " revocation\n"),keystr(keyid));
                        }

                      rsnode = n;
                      rsdate = sig->timestamp;
                    }
                  else
                    n->flag |= NODE_DELETION_MARK; /* older */
                }
            }
        }
    }

  return 0;
}


/* Delete all parts which are invalid and those signatures whose
 * public key algorithm is not available in this implementation; but
 * consider RSA as valid, because parse/build_packets knows about it.
 * If R_OTHERREVSIGS is not NULL, it is used to return a list of
 * revocation certificates which have been deleted from KEYBLOCK but
 * should be handled later.
 *
 * Returns: True if at least one valid user-id is left over.
 */
static int
delete_inv_parts (ctrl_t ctrl, kbnode_t keyblock, u32 *keyid,
                  unsigned int options, kbnode_t *r_otherrevsigs)
{
  kbnode_t node;
  int nvalid=0, uid_seen=0, subkey_seen=0;
  PKT_public_key *pk;

  for (node=keyblock->next; node; node = node->next )
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          uid_seen = 1;
          if ((node->flag & NODE_BAD_SELFSIG)
              || !(node->flag & NODE_GOOD_SELFSIG))
            {
              if (opt.verbose )
                {
                  char *p=utf8_to_native(node->pkt->pkt.user_id->name,
                                         node->pkt->pkt.user_id->len,0);
                  log_info( _("key %s: skipped user ID \"%s\"\n"),
                            keystr(keyid),p);
                  xfree(p);
                }
              delete_kbnode( node ); /* the user-id */
              /* and all following packets up to the next user-id */
              while (node->next
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
      else if (   node->pkt->pkttype == PKT_PUBLIC_SUBKEY
               || node->pkt->pkttype == PKT_SECRET_SUBKEY )
        {
          if ((node->flag & NODE_BAD_SELFSIG)
              || !(node->flag & NODE_GOOD_SELFSIG))
            {
              if (opt.verbose )
                {
                  pk = node->pkt->pkt.public_key;
                  keyid_from_pk (pk, NULL);
                  log_info (_("key %s: skipped subkey\n"),
                            keystr_with_sub (keyid, pk->keyid));
                }

              delete_kbnode( node ); /* the subkey */
              /* and all following signature packets */
              while (node->next
                     && node->next->pkt->pkttype == PKT_SIGNATURE ) {
                delete_kbnode( node->next );
                node = node->next;
              }
	    }
          else
            subkey_seen = 1;
	}
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && openpgp_pk_test_algo (node->pkt->pkt.signature->pubkey_algo)
               && node->pkt->pkt.signature->pubkey_algo != PUBKEY_ALGO_RSA )
        {
          delete_kbnode( node ); /* build_packet() can't handle this */
        }
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && !node->pkt->pkt.signature->flags.exportable
               && !(options&IMPORT_LOCAL_SIGS)
               && !have_secret_key_with_kid (node->pkt->pkt.signature->keyid))
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
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && IS_KEY_REV (node->pkt->pkt.signature))
        {
          if (uid_seen )
            {
              if(opt.verbose)
                log_info( _("key %s: revocation certificate"
                            " at wrong place - skipped\n"),keystr(keyid));
              if (r_otherrevsigs)
                {
                  PACKET *pkt;

                  pkt = xcalloc (1, sizeof *pkt);
                  pkt->pkttype = PKT_SIGNATURE;
                  pkt->pkt.signature = copy_signature
                    (NULL, node->pkt->pkt.signature);
                  *r_otherrevsigs = new_kbnode2 (*r_otherrevsigs, pkt);
                }
              delete_kbnode( node );
            }
          else
            {
	      /* If the revocation cert is from a different key than
                 the one we're working on don't check it - it's
                 probably from a revocation key and won't be
                 verifiable with this key anyway. */

	      if(node->pkt->pkt.signature->keyid[0]==keyid[0]
                 && node->pkt->pkt.signature->keyid[1]==keyid[1])
		{
		  int rc = check_key_signature (ctrl, keyblock, node, NULL);
		  if (rc )
		    {
		      if(opt.verbose)
			log_info( _("key %s: invalid revocation"
				    " certificate: %s - skipped\n"),
				  keystr(keyid), gpg_strerror (rc));
		      delete_kbnode( node );
		    }
		}
              else if (r_otherrevsigs)
                {
                  PACKET *pkt;

                  pkt = xcalloc (1, sizeof *pkt);
                  pkt->pkttype = PKT_SIGNATURE;
                  pkt->pkt.signature = copy_signature
                    (NULL, node->pkt->pkt.signature);
                  *r_otherrevsigs = new_kbnode2 (*r_otherrevsigs, pkt);
                }
	    }
	}
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && (IS_SUBKEY_SIG (node->pkt->pkt.signature)
                   || IS_SUBKEY_REV (node->pkt->pkt.signature))
               && !subkey_seen )
        {
          if(opt.verbose)
            log_info( _("key %s: subkey signature"
                        " in wrong place - skipped\n"), keystr(keyid));
          delete_kbnode( node );
        }
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && !IS_CERT(node->pkt->pkt.signature))
        {
          if(opt.verbose)
            log_info(_("key %s: unexpected signature class (0x%02X) -"
                       " skipped\n"),keystr(keyid),
                     node->pkt->pkt.signature->sig_class);
          delete_kbnode(node);
	  }
      else if ((node->flag & NODE_DELETION_MARK))
        delete_kbnode( node );
    }

  /* note: because keyblock is the public key, it is never marked
   * for deletion and so keyblock cannot change */
  commit_kbnode( &keyblock );
  return nvalid;
}

/* This function returns true if any UID is left in the keyring.  */
static int
any_uid_left (kbnode_t keyblock)
{
  kbnode_t node;

  for (node=keyblock->next; node; node = node->next)
    if (node->pkt->pkttype == PKT_USER_ID)
      return 1;
  return 0;
}


/* Delete all non-self-sigs from KEYBLOCK.
 * Returns: True if the keyblock has changed.  */
static void
remove_all_non_self_sigs (kbnode_t *keyblock, u32 *keyid)
{
  kbnode_t node;
  unsigned int dropped = 0;

  for (node = *keyblock; node; node = node->next)
    {
      if (is_deleted_kbnode (node))
	continue;

      if (node->pkt->pkttype != PKT_SIGNATURE)
	continue;

      if (node->pkt->pkt.signature->keyid[0] == keyid[0]
          && node->pkt->pkt.signature->keyid[1] == keyid[1])
        continue;
      delete_kbnode (node);
      dropped++;
    }

  if (dropped)
    commit_kbnode (keyblock);

  if (dropped && opt.verbose)
    log_info ("key %s: number of dropped non-self-signatures: %u\n",
              keystr (keyid), dropped);
}


/*
 * It may happen that the imported keyblock has duplicated user IDs.
 * We check this here and collapse those user IDs together with their
 * sigs into one.
 * Returns: True if the keyblock has changed.
 */
int
collapse_uids( kbnode_t *keyblock )
{
  kbnode_t uid1;
  int any=0;

  for(uid1=*keyblock;uid1;uid1=uid1->next)
    {
      kbnode_t uid2;

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
	      kbnode_t sig1,last;

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
		  kbnode_t sig2;

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

      if ((uid1 = find_kbnode (*keyblock, PKT_PUBLIC_KEY)) )
	key = keystr_from_pk (uid1->pkt->pkt.public_key);
      else if ((uid1 = find_kbnode( *keyblock, PKT_SECRET_KEY)) )
	key = keystr_from_pk (uid1->pkt->pkt.public_key);

      log_info (_("key %s: duplicated user ID detected - merged\n"), key);
    }

  return any;
}


/* Check for a 0x20 revocation from a revocation key that is not
   present.  This may be called without the benefit of merge_xxxx so
   you can't rely on pk->revkey and friends. */
static void
revocation_present (ctrl_t ctrl, kbnode_t keyblock)
{
  kbnode_t onode, inode;
  PKT_public_key *pk = keyblock->pkt->pkt.public_key;

  for(onode=keyblock->next;onode;onode=onode->next)
    {
      /* If we reach user IDs, we're done. */
      if(onode->pkt->pkttype==PKT_USER_ID)
	break;

      if (onode->pkt->pkttype == PKT_SIGNATURE
          && IS_KEY_SIG (onode->pkt->pkt.signature)
          && onode->pkt->pkt.signature->revkey)
	{
	  int idx;
	  PKT_signature *sig=onode->pkt->pkt.signature;

	  for(idx=0;idx<sig->numrevkeys;idx++)
	    {
	      u32 keyid[2];

	      keyid_from_fingerprint (ctrl, sig->revkey[idx].fpr,
                                      MAX_FINGERPRINT_LEN, keyid);

	      for(inode=keyblock->next;inode;inode=inode->next)
		{
		  /* If we reach user IDs, we're done. */
		  if(inode->pkt->pkttype==PKT_USER_ID)
		    break;

		  if (inode->pkt->pkttype == PKT_SIGNATURE
                      && IS_KEY_REV (inode->pkt->pkt.signature)
                      && inode->pkt->pkt.signature->keyid[0]==keyid[0]
                      && inode->pkt->pkt.signature->keyid[1]==keyid[1])
		    {
		      /* Okay, we have a revocation key, and a
                       * revocation issued by it.  Do we have the key
                       * itself?  */
                      gpg_error_t err;

		      err = get_pubkey_byfprint_fast (NULL,
                                                      sig->revkey[idx].fpr,
                                                      MAX_FINGERPRINT_LEN);
		      if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY
                          || gpg_err_code (err) == GPG_ERR_UNUSABLE_PUBKEY)
			{
			  char *tempkeystr = xstrdup (keystr_from_pk (pk));

			  /* No, so try and get it */
			  if ((opt.keyserver_options.options
                               & KEYSERVER_AUTO_KEY_RETRIEVE)
                              && keyserver_any_configured (ctrl))
			    {
			      log_info(_("WARNING: key %s may be revoked:"
					 " fetching revocation key %s\n"),
				       tempkeystr,keystr(keyid));
			      keyserver_import_fprint (ctrl,
                                                       sig->revkey[idx].fpr,
                                                       MAX_FINGERPRINT_LEN,
                                                       opt.keyserver, 0);

			      /* Do we have it now? */
			      err = get_pubkey_byfprint_fast (NULL,
						     sig->revkey[idx].fpr,
						     MAX_FINGERPRINT_LEN);
			    }

			  if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY
                              || gpg_err_code (err) == GPG_ERR_UNUSABLE_PUBKEY)
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


/*
 * compare and merge the blocks
 *
 * o compare the signatures: If we already have this signature, check
 *   that they compare okay; if not, issue a warning and ask the user.
 * o Simply add the signature.	Can't verify here because we may not have
 *   the signature's public key yet; verification is done when putting it
 *   into the trustdb, which is done automagically as soon as this pubkey
 *   is used.
 * Note: We indicate newly inserted packets with NODE_FLAG_A.
 */
static int
merge_blocks (ctrl_t ctrl, unsigned int options,
              kbnode_t keyblock_orig, kbnode_t keyblock,
              u32 *keyid, u32 curtime, int origin, const char *url,
	      int *n_uids, int *n_sigs, int *n_subk )
{
  kbnode_t onode, node;
  int rc, found;

  /* 1st: handle revocation certificates */
  for (node=keyblock->next; node; node=node->next )
    {
      if (node->pkt->pkttype == PKT_USER_ID )
        break;
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && IS_KEY_REV (node->pkt->pkt.signature))
        {
          /* check whether we already have this */
          found = 0;
          for (onode=keyblock_orig->next; onode; onode=onode->next)
            {
              if (onode->pkt->pkttype == PKT_USER_ID )
                break;
              else if (onode->pkt->pkttype == PKT_SIGNATURE
                       && IS_KEY_REV (onode->pkt->pkt.signature)
                       && !cmp_signatures(onode->pkt->pkt.signature,
                                          node->pkt->pkt.signature))
                {
                  found = 1;
                  break;
                }
	    }
          if (!found)
            {
              kbnode_t n2 = clone_kbnode(node);
              insert_kbnode( keyblock_orig, n2, 0 );
              n2->flag |= NODE_FLAG_A;
              ++*n_sigs;
              if(!opt.quiet)
                {
                  char *p = get_user_id_native (ctrl, keyid);
                  log_info(_("key %s: \"%s\" revocation"
                             " certificate added\n"), keystr(keyid),p);
                  xfree(p);
                }
	    }
	}
    }

  /* 2nd: merge in any direct key (0x1F) sigs */
  for(node=keyblock->next; node; node=node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID )
        break;
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && IS_KEY_SIG (node->pkt->pkt.signature))
        {
          /* check whether we already have this */
          found = 0;
          for (onode=keyblock_orig->next; onode; onode=onode->next)
            {
              if (onode->pkt->pkttype == PKT_USER_ID)
                break;
              else if (onode->pkt->pkttype == PKT_SIGNATURE
                       && IS_KEY_SIG (onode->pkt->pkt.signature)
                       && !cmp_signatures(onode->pkt->pkt.signature,
                                          node->pkt->pkt.signature))
                {
                  found = 1;
                  break;
		}
	    }
          if (!found )
            {
              kbnode_t n2 = clone_kbnode(node);
              insert_kbnode( keyblock_orig, n2, 0 );
              n2->flag |= NODE_FLAG_A;
              ++*n_sigs;
              if(!opt.quiet)
                log_info( _("key %s: direct key signature added\n"),
                          keystr(keyid));
            }
	}
    }

  /* 3rd: try to merge new certificates in */
  for (onode=keyblock_orig->next; onode; onode=onode->next)
    {
      if (!(onode->flag & NODE_FLAG_A) && onode->pkt->pkttype == PKT_USER_ID)
        {
          /* find the user id in the imported keyblock */
          for (node=keyblock->next; node; node=node->next)
            if (node->pkt->pkttype == PKT_USER_ID
                && !cmp_user_ids( onode->pkt->pkt.user_id,
                                  node->pkt->pkt.user_id ) )
              break;
          if (node ) /* found: merge */
            {
              rc = merge_sigs (onode, node, n_sigs);
              if (rc )
                return rc;
	    }
	}
    }

  /* 4th: add new user-ids */
  for (node=keyblock->next; node; node=node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          /* do we have this in the original keyblock */
          for (onode=keyblock_orig->next; onode; onode=onode->next )
            if (onode->pkt->pkttype == PKT_USER_ID
                && !cmp_user_ids( onode->pkt->pkt.user_id,
                                  node->pkt->pkt.user_id ) )
              break;
          if (!onode ) /* this is a new user id: append */
            {
              rc = append_new_uid (options, keyblock_orig, node,
                                   curtime, origin, url, n_sigs);
              if (rc )
                return rc;
              ++*n_uids;
	    }
	}
    }

  /* 5th: add new subkeys */
  for (node=keyblock->next; node; node=node->next)
    {
      onode = NULL;
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          /* do we have this in the original keyblock? */
          for(onode=keyblock_orig->next; onode; onode=onode->next)
            if (onode->pkt->pkttype == PKT_PUBLIC_SUBKEY
                && !cmp_public_keys( onode->pkt->pkt.public_key,
                                     node->pkt->pkt.public_key))
              break;
          if (!onode ) /* This is a new subkey: append.  */
            {
              rc = append_key (keyblock_orig, node, n_sigs);
              if (rc)
                return rc;
              ++*n_subk;
	    }
	}
      else if (node->pkt->pkttype == PKT_SECRET_SUBKEY)
        {
          /* do we have this in the original keyblock? */
          for (onode=keyblock_orig->next; onode; onode=onode->next )
            if (onode->pkt->pkttype == PKT_SECRET_SUBKEY
                && !cmp_public_keys (onode->pkt->pkt.public_key,
                                     node->pkt->pkt.public_key) )
              break;
          if (!onode ) /* This is a new subkey: append.  */
            {
              rc = append_key (keyblock_orig, node, n_sigs);
              if (rc )
                return rc;
              ++*n_subk;
	    }
	}
    }

  /* 6th: merge subkey certificates */
  for (onode=keyblock_orig->next; onode; onode=onode->next)
    {
      if (!(onode->flag & NODE_FLAG_A)
          && (onode->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || onode->pkt->pkttype == PKT_SECRET_SUBKEY))
        {
          /* find the subkey in the imported keyblock */
          for(node=keyblock->next; node; node=node->next)
            {
              if ((node->pkt->pkttype == PKT_PUBLIC_SUBKEY
                   || node->pkt->pkttype == PKT_SECRET_SUBKEY)
                  && !cmp_public_keys( onode->pkt->pkt.public_key,
                                       node->pkt->pkt.public_key ) )
                break;
	    }
          if (node) /* Found: merge.  */
            {
              rc = merge_keysigs( onode, node, n_sigs);
              if (rc )
                return rc;
	    }
	}
    }

  return 0;
}


/* Helper function for merge_blocks.
 *
 * Append the new userid starting with NODE and all signatures to
 * KEYBLOCK.  ORIGIN and URL conveys the usual key origin info.  The
 * integer at N_SIGS is updated with the number of new signatures.
 */
static gpg_error_t
append_new_uid (unsigned int options,
                kbnode_t keyblock, kbnode_t node, u32 curtime,
                int origin, const char *url, int *n_sigs)
{
  gpg_error_t err;
  kbnode_t n;
  kbnode_t n_where = NULL;

  log_assert (node->pkt->pkttype == PKT_USER_ID);

  /* Find the right position for the new user id and its signatures.  */
  for (n = keyblock; n; n_where = n, n = n->next)
    {
      if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || n->pkt->pkttype == PKT_SECRET_SUBKEY )
        break;
    }
  if (!n)
    n_where = NULL;

  /* and append/insert */
  while (node)
    {
      /* we add a clone to the original keyblock, because this
       * one is released first. */
      n = clone_kbnode(node);
      if (n->pkt->pkttype == PKT_USER_ID
          && !(options & IMPORT_RESTORE) )
        {
          err = insert_key_origin_uid (n->pkt->pkt.user_id,
                                       curtime, origin, url);
          if (err)
            return err;
        }

      if (n_where)
        {
          insert_kbnode( n_where, n, 0 );
          n_where = n;
	}
      else
        add_kbnode( keyblock, n );
      n->flag |= NODE_FLAG_A;
      node->flag |= NODE_FLAG_A;
      if (n->pkt->pkttype == PKT_SIGNATURE )
        ++*n_sigs;

      node = node->next;
      if (node && node->pkt->pkttype != PKT_SIGNATURE )
        break;
    }

  return 0;
}


/* Helper function for merge_blocks
 * Merge the sigs from SRC onto DST. SRC and DST are both a PKT_USER_ID.
 * (how should we handle comment packets here?)
 */
static int
merge_sigs (kbnode_t dst, kbnode_t src, int *n_sigs)
{
  kbnode_t n, n2;
  int found = 0;

  log_assert (dst->pkt->pkttype == PKT_USER_ID);
  log_assert (src->pkt->pkttype == PKT_USER_ID);

  for (n=src->next; n && n->pkt->pkttype != PKT_USER_ID; n = n->next)
    {
      if (n->pkt->pkttype != PKT_SIGNATURE )
        continue;
      if (IS_SUBKEY_SIG (n->pkt->pkt.signature)
          || IS_SUBKEY_REV (n->pkt->pkt.signature) )
        continue; /* skip signatures which are only valid on subkeys */

      found = 0;
      for (n2=dst->next; n2 && n2->pkt->pkttype != PKT_USER_ID; n2 = n2->next)
        if (!cmp_signatures(n->pkt->pkt.signature,n2->pkt->pkt.signature))
          {
            found++;
            break;
          }
      if (!found )
        {
          /* This signature is new or newer, append N to DST.
           * We add a clone to the original keyblock, because this
           * one is released first */
          n2 = clone_kbnode(n);
          insert_kbnode( dst, n2, PKT_SIGNATURE );
          n2->flag |= NODE_FLAG_A;
          n->flag |= NODE_FLAG_A;
          ++*n_sigs;
	}
    }

  return 0;
}


/* Helper function for merge_blocks
 * Merge the sigs from SRC onto DST. SRC and DST are both a PKT_xxx_SUBKEY.
 */
static int
merge_keysigs (kbnode_t dst, kbnode_t src, int *n_sigs)
{
  kbnode_t n, n2;
  int found = 0;

  log_assert (dst->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || dst->pkt->pkttype == PKT_SECRET_SUBKEY);

  for (n=src->next; n ; n = n->next)
    {
      if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || n->pkt->pkttype == PKT_PUBLIC_KEY )
        break;
      if (n->pkt->pkttype != PKT_SIGNATURE )
        continue;

      found = 0;
      for (n2=dst->next; n2; n2 = n2->next)
        {
          if (n2->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || n2->pkt->pkttype == PKT_PUBLIC_KEY )
            break;
          if (n2->pkt->pkttype == PKT_SIGNATURE
              && (n->pkt->pkt.signature->keyid[0]
                  == n2->pkt->pkt.signature->keyid[0])
              && (n->pkt->pkt.signature->keyid[1]
                  == n2->pkt->pkt.signature->keyid[1])
              && (n->pkt->pkt.signature->timestamp
                  <= n2->pkt->pkt.signature->timestamp)
              && (n->pkt->pkt.signature->sig_class
                  == n2->pkt->pkt.signature->sig_class))
            {
              found++;
              break;
	    }
	}
      if (!found )
        {
          /* This signature is new or newer, append N to DST.
           * We add a clone to the original keyblock, because this
           * one is released first */
          n2 = clone_kbnode(n);
          insert_kbnode( dst, n2, PKT_SIGNATURE );
          n2->flag |= NODE_FLAG_A;
          n->flag |= NODE_FLAG_A;
          ++*n_sigs;
	}
    }

  return 0;
}


/* Helper function for merge_blocks.
 * Append the subkey starting with NODE and all signatures to KEYBLOCK.
 * Mark all new and copied packets by setting flag bit 0.
 */
static int
append_key (kbnode_t keyblock, kbnode_t node, int *n_sigs)
{
  kbnode_t n;

  log_assert (node->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || node->pkt->pkttype == PKT_SECRET_SUBKEY);

  while (node)
    {
      /* we add a clone to the original keyblock, because this
       * one is released first */
      n = clone_kbnode(node);
      add_kbnode( keyblock, n );
      n->flag |= NODE_FLAG_A;
      node->flag |= NODE_FLAG_A;
      if (n->pkt->pkttype == PKT_SIGNATURE )
        ++*n_sigs;

      node = node->next;
      if (node && node->pkt->pkttype != PKT_SIGNATURE )
        break;
    }

  return 0;
}
