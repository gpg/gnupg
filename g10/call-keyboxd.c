/* call-keyboxd.c - Access to the keyboxd storage server
 * Copyright (C) 2019  g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#include <npth.h>

#include "gpg.h"
#include <assuan.h>
#include "../common/util.h"
#include "../common/membuf.h"
#include "options.h"
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "../common/host2net.h"
#include "../common/exechelp.h"
#include "../common/status.h"
#include "../kbx/kbx-client-util.h"
#include "keydb.h"

#include "keydb-private.h"  /* For struct keydb_handle_s */


/* Data used to keep track of keybox daemon sessions.  This allows us
 * to use several sessions with the keyboxd and also to re-use already
 * established sessions.  Note that gpg.h defines the type
 * keyboxd_local_t for this structure. */
struct keyboxd_local_s
{
  /* Link to other keyboxd contexts which are used simultaneously.  */
  struct keyboxd_local_s *next;

  /* The active Assuan context. */
  assuan_context_t ctx;

  /* The client data helper context.  */
  kbx_client_data_t kcd;

  /* I/O buffer with the last search result or NULL.  Used if
   * D-lines are used to convey the keyblocks. */
  iobuf_t search_result;

  /* This flag set while an operation is running on this context.  */
  unsigned int is_active : 1;

  /* Flag indicating that a search reset is required.  */
  unsigned int need_search_reset : 1;

};


/* Flag indicating that for example bulk import is enabled.  */
static unsigned int in_transaction;




/* Deinitialize all session resources pertaining to the keyboxd.  */
void
gpg_keyboxd_deinit_session_data (ctrl_t ctrl)
{
  keyboxd_local_t kbl;
  gpg_error_t err;

  while ((kbl = ctrl->keyboxd_local))
    {
      ctrl->keyboxd_local = kbl->next;
      if (kbl->is_active)
        log_error ("oops: trying to cleanup an active keyboxd context\n");
      else
        {
          kbx_client_data_release (kbl->kcd);
          kbl->kcd = NULL;
          if (kbl->ctx && in_transaction)
            {
              /* This is our hack to commit the changes done during a
               * bulk import.  If we won't do that the loss of the
               * connection would trigger a rollback in keyboxd.  Note
               * that transactions are not associated with a
               * connection. */
              err = assuan_transact (kbl->ctx, "TRANSACTION commit",
                                     NULL, NULL, NULL, NULL, NULL, NULL);
              if (err)
                log_error ("error committing last transaction: %s\n",
                            gpg_strerror (err));
              in_transaction = 0;
            }
          assuan_release (kbl->ctx);
          kbl->ctx = NULL;
        }
      xfree (kbl);
    }
}


/* Print a warning if the server's version number is less than our
   version number.  Returns an error code on a connection problem.  */
static gpg_error_t
warn_version_mismatch (assuan_context_t ctx, const char *servername)
{
  return warn_server_version_mismatch (ctx, servername, 0,
                                       write_status_strings2, NULL,
                                       !opt.quiet);
}


/* Connect to the keybox daemon and launch it if necessary.  Handle
 * the server's initial greeting and set global options.  Returns a
 * new assuan context or an error.  */
static gpg_error_t
create_new_context (ctrl_t ctrl, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  assuan_context_t ctx;

  *r_ctx = NULL;

  err = start_new_keyboxd (&ctx,
                           GPG_ERR_SOURCE_DEFAULT,
                           opt.keyboxd_program,
                           opt.autostart, opt.verbose, DBG_IPC,
                           NULL, ctrl);
  if (!opt.autostart && gpg_err_code (err) == GPG_ERR_NO_KEYBOXD)
    {
      static int shown;

      if (!shown)
        {
          shown = 1;
          log_info (_("no keyboxd running in this session\n"));
        }
    }
  else if (!err && !(err = warn_version_mismatch (ctx, KEYBOXD_NAME)))
    {
      /* Place to emit global options.  */

      if ((opt.import_options & IMPORT_BULK) && !in_transaction)
        {
          err = assuan_transact (ctx, "TRANSACTION begin",
                                 NULL, NULL, NULL, NULL, NULL, NULL);
          if (err)
            {
              log_error ("error enabling bulk import option: %s\n",
                         gpg_strerror (err));
            }
          else
            in_transaction = 1;
        }

    }

  if (err)
    assuan_release (ctx);
  else
    *r_ctx = ctx;

  return err;
}




/* Get a context for accessing keyboxd.  If no context is available a
 * new one is created and if necessary keyboxd is started.  R_KBL
 * receives a pointer to the local context object.  */
static gpg_error_t
open_context (ctrl_t ctrl, keyboxd_local_t *r_kbl)
{
  gpg_error_t err;
  keyboxd_local_t kbl;

  *r_kbl = NULL;
  for (;;)
    {
      for (kbl = ctrl->keyboxd_local; kbl && kbl->is_active; kbl = kbl->next)
        ;
      if (kbl)
        {
          /* Found an inactive keyboxd session - return that.  */
          log_assert (!kbl->is_active);

          kbl->is_active = 1;
          kbl->need_search_reset = 1;

          *r_kbl = kbl;
          return 0;
        }

      /* None found.  Create a new session and retry.  */
      kbl = xtrycalloc (1, sizeof *kbl);
      if (!kbl)
        return gpg_error_from_syserror ();

      err = create_new_context (ctrl, &kbl->ctx);
      if (err)
        {
          xfree (kbl);
          return err;
        }

      err = kbx_client_data_new (&kbl->kcd, kbl->ctx, 1);
      if (err)
        {
          assuan_release (kbl->ctx);
          xfree (kbl);
          return err;
        }

      /* For thread-saftey we add it to the list and retry; this is
       * easier than to employ a lock.  */
      kbl->next = ctrl->keyboxd_local;
      ctrl->keyboxd_local = kbl;
    }
  /*NOTREACHED*/
}



/* Create a new database handle.  A database handle is similar to a
 * file handle: it contains a local file position.  This is used when
 * searching: subsequent searches resume where the previous search
 * left off.  To rewind the position, use keydb_search_reset().  This
 * function returns NULL on error, sets ERRNO, and prints an error
 * diagnostic.  Depending on --use-keyboxd either the old internal
 * keydb code is used (keydb.c) or, if set, the processing is diverted
 * to the keyboxd. */
/* FIXME: We should change the interface to return a gpg_error_t.  */
KEYDB_HANDLE
keydb_new (ctrl_t ctrl)
{
  gpg_error_t err;
  KEYDB_HANDLE hd;

  if (DBG_CLOCK)
    log_clock ("keydb_new");

  hd = xtrycalloc (1, sizeof *hd);
  if (!hd)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (!opt.use_keyboxd)
    {
      err = internal_keydb_init (hd);
      goto leave;
    }
  hd->use_keyboxd = 1;
  hd->ctrl = ctrl;

  err = open_context (ctrl, &hd->kbl);

 leave:
  if (err)
    {
      int rc;
      log_error (_("error opening key DB: %s\n"), gpg_strerror (err));
      xfree (hd);
      hd = NULL;
      if (!(rc = gpg_err_code_to_errno (err)))
        rc = gpg_err_code_to_errno (GPG_ERR_EIO);
      gpg_err_set_errno (rc);
    }
  return hd;
}


/* Release a keydb handle.  */
void
keydb_release (KEYDB_HANDLE hd)
{
  keyboxd_local_t kbl;

  if (!hd)
    return;

  if (DBG_CLOCK)
    log_clock ("keydb_release");
  if (!hd->use_keyboxd)
    internal_keydb_deinit (hd);
  else
    {
      kbl = hd->kbl;
      if (DBG_CLOCK)
        log_clock ("close_context (found)");
      if (!kbl->is_active)
        log_fatal ("closing inactive keyboxd context %p\n", kbl);
      kbl->is_active = 0;
      hd->kbl = NULL;
      hd->ctrl = NULL;
    }
  xfree (hd);
}


/* Take a lock if we are not using the keyboxd.  */
gpg_error_t
keydb_lock (KEYDB_HANDLE hd)
{
  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!hd->use_keyboxd)
    return internal_keydb_lock (hd);

  return 0;
}


/* Return the keyblock last found by keydb_search() in *RET_KB.
 *
 * On success, the function returns 0 and the caller must free *RET_KB
 * using release_kbnode().  Otherwise, the function returns an error
 * code.
 *
 * The returned keyblock has the kbnode flag bit 0 set for the node
 * with the public key used to locate the keyblock or flag bit 1 set
 * for the user ID node.  */
gpg_error_t
keydb_get_keyblock (KEYDB_HANDLE hd, kbnode_t *ret_kb)
{
  gpg_error_t err;

  *ret_kb = NULL;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (DBG_CLOCK)
    log_clock ("%s enter", __func__);

  if (!hd->use_keyboxd)
    {
      err = internal_keydb_get_keyblock (hd, ret_kb);
      goto leave;
    }

  if (hd->kbl->search_result)
    {
      err = keydb_parse_keyblock (hd->kbl->search_result,
                                  hd->last_ubid_valid? hd->last_pk_no  : 0,
                                  hd->last_ubid_valid? hd->last_uid_no : 0,
                                  ret_kb);
      /* In contrast to the old code we close the iobuf here and thus
       * this function may be called only once to get a keyblock.  */
      iobuf_close (hd->kbl->search_result);
      hd->kbl->search_result = NULL;
    }
  else
    {
      err = gpg_error (GPG_ERR_VALUE_NOT_FOUND);
      goto leave;
    }

 leave:
  if (DBG_CLOCK)
    log_clock ("%s leave%s", __func__, err? " (failed)":"");
  return err;
}


/* Default status callback used to show diagnostics from the keyboxd  */
static gpg_error_t
keydb_default_status_cb (void *opaque, const char *line)
{
  const char *s;

  (void)opaque;

  if ((s = has_leading_keyword (line, "NOTE")))
    log_info (_("Note: %s\n"), s);
  else if ((s = has_leading_keyword (line, "WARNING")))
    log_info (_("WARNING: %s\n"), s);

  return 0;
}



/* Communication object for STORE commands.  */
struct store_parm_s
{
  assuan_context_t ctx;
  const void *data;   /* The key in OpenPGP binary format.  */
  size_t datalen;     /* The length of DATA.  */
};


/* Handle the inquiries from the STORE command.  */
static gpg_error_t
store_inq_cb (void *opaque, const char *line)
{
  struct store_parm_s *parm = opaque;
  gpg_error_t err = 0;

  if (has_leading_keyword (line, "BLOB"))
    {
      if (parm->data)
        err = assuan_send_data (parm->ctx, parm->data, parm->datalen);
    }
  else
    return gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);

  return err;
}


/* Update the keyblock KB (i.e., extract the fingerprint and find the
 * corresponding keyblock in the keyring).
 *
 * This doesn't do anything if --dry-run was specified.
 *
 * Returns 0 on success.  Otherwise, it returns an error code.  Note:
 * if there isn't a keyblock in the keyring corresponding to KB, then
 * this function returns GPG_ERR_VALUE_NOT_FOUND.
 *
 * This function selects the matching record and modifies the current
 * file position to point to the record just after the selected entry.
 * Thus, if you do a subsequent search using HD, you should first do a
 * keydb_search_reset.  Further, if the selected record is important,
 * you should use keydb_push_found_state and keydb_pop_found_state to
 * save and restore it.  */
gpg_error_t
keydb_update_keyblock (ctrl_t ctrl, KEYDB_HANDLE hd, kbnode_t kb)
{
  gpg_error_t err;
  iobuf_t iobuf = NULL;
  struct store_parm_s parm = {NULL};

  log_assert (kb);
  log_assert (kb->pkt->pkttype == PKT_PUBLIC_KEY);

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!hd->use_keyboxd)
    {
      err = internal_keydb_update_keyblock (ctrl, hd, kb);
      goto leave;
    }

  if (opt.dry_run)
    {
      err = 0;
      goto leave;
    }

  err = build_keyblock_image (kb, &iobuf);
  if (err)
    goto leave;

  parm.ctx = hd->kbl->ctx;
  parm.data = iobuf_get_temp_buffer (iobuf);
  parm.datalen = iobuf_get_temp_length (iobuf);
  err = assuan_transact (hd->kbl->ctx, "STORE --update",
                         NULL, NULL,
                         store_inq_cb, &parm,
                         keydb_default_status_cb, hd);


 leave:
  iobuf_close (iobuf);
  return err;
}


/* Insert a keyblock into one of the underlying keyrings or keyboxes.
 *
 * By default, the keyring / keybox from which the last search result
 * came is used.  If there was no previous search result (or
 * keydb_search_reset was called), then the keyring / keybox where the
 * next search would start is used (i.e., the current file position).
 * In keyboxd mode the keyboxd decides where to store it.
 *
 * Note: this doesn't do anything if --dry-run was specified.
 *
 * Returns 0 on success.  Otherwise, it returns an error code.  */
gpg_error_t
keydb_insert_keyblock (KEYDB_HANDLE hd, kbnode_t kb)
{
  gpg_error_t err;
  iobuf_t iobuf = NULL;
  struct store_parm_s parm = {NULL};

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!hd->use_keyboxd)
    {
      err = internal_keydb_insert_keyblock (hd, kb);
      goto leave;
    }

  if (opt.dry_run)
    {
      err = 0;
      goto leave;
    }

  err = build_keyblock_image (kb, &iobuf);
  if (err)
    goto leave;

  parm.ctx = hd->kbl->ctx;
  parm.data = iobuf_get_temp_buffer (iobuf);
  parm.datalen = iobuf_get_temp_length (iobuf);
  err = assuan_transact (hd->kbl->ctx, "STORE --insert",
                         NULL, NULL,
                         store_inq_cb, &parm,
                         keydb_default_status_cb, hd);

 leave:
  iobuf_close (iobuf);
  return err;
}


/* Delete the currently selected keyblock.  If you haven't done a
 * search yet on this database handle (or called keydb_search_reset),
 * then this function returns an error.
 *
 * Returns 0 on success or an error code, if an error occurred.  */
gpg_error_t
keydb_delete_keyblock (KEYDB_HANDLE hd)
{
  gpg_error_t err;
  unsigned char hexubid[UBID_LEN * 2 + 1];
  char line[ASSUAN_LINELENGTH];

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!hd->use_keyboxd)
    {
      err = internal_keydb_delete_keyblock (hd);
      goto leave;
    }

  if (opt.dry_run)
    {
      err = 0;
      goto leave;
    }

  if (!hd->last_ubid_valid)
    {
      err = gpg_error (GPG_ERR_VALUE_NOT_FOUND);
      goto leave;
    }

  bin2hex (hd->last_ubid, UBID_LEN, hexubid);
  snprintf (line, sizeof line, "DELETE %s", hexubid);
  err = assuan_transact (hd->kbl->ctx, line,
                         NULL, NULL,
                         NULL, NULL,
                         keydb_default_status_cb, hd);

 leave:
  return err;
}


/* Clears the current search result and resets the handle's position
 * so that the next search starts at the beginning of the database.
 *
 * Returns 0 on success and an error code if an error occurred.  */
gpg_error_t
keydb_search_reset (KEYDB_HANDLE hd)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (DBG_CLOCK)
    log_clock ("%s", __func__);
  if (DBG_CACHE)
    log_debug ("%s (hd=%p)", __func__, hd);

  if (!hd->use_keyboxd)
    {
      err = internal_keydb_search_reset (hd);
      goto leave;
    }

  /* All we need is to tell search that a reset is pending.  Note that
   * keydb_new sets this flag as well.  To comply with the
   * specification of keydb_delete_keyblock we also need to clear the
   * ubid flag so that after a reset a delete can't be performed.  */
  hd->kbl->need_search_reset = 1;
  hd->last_ubid_valid = 0;
  err = 0;

 leave:
  return err;
}



/* Status callback for SEARCH and NEXT operaions.  */
static gpg_error_t
search_status_cb (void *opaque, const char *line)
{
  KEYDB_HANDLE hd = opaque;
  gpg_error_t err = 0;
  const char *s;
  unsigned int n;

  if ((s = has_leading_keyword (line, "PUBKEY_INFO")))
    {
      if (atoi (s) != PUBKEY_TYPE_OPGP)
        err = gpg_error (GPG_ERR_WRONG_BLOB_TYPE);
      else
        {
          hd->last_ubid_valid = 0;
          while (*s && !spacep (s))
            s++;
          if (!(n=hex2fixedbuf (s, hd->last_ubid, sizeof hd->last_ubid)))
            err = gpg_error (GPG_ERR_INV_VALUE);
          else
            {
              hd->last_ubid_valid = 1;
              hd->last_uid_no = 0;
              hd->last_pk_no = 0;
              s += n;
              while (*s && !spacep (s))
                s++;
              while (spacep (s))
                s++;
              if (*s)
                {
                  hd->last_uid_no = atoi (s);
                  while (*s && !spacep (s))
                    s++;
                  while (spacep (s))
                    s++;
                  if (*s)
                    hd->last_pk_no = atoi (s);
                }
            }
        }
    }
  else
    err = keydb_default_status_cb (opaque, line);

  return err;
}


/* Search the database for keys matching the search description.  If
 * the DB contains any legacy keys, these are silently ignored.
 *
 * DESC is an array of search terms with NDESC entries.  The search
 * terms are or'd together.  That is, the next entry in the DB that
 * matches any of the descriptions will be returned.
 *
 * Note: this function resumes searching where the last search left
 * off (i.e., at the current file position).  If you want to search
 * from the start of the database, then you need to first call
 * keydb_search_reset().
 *
 * If no key matches the search description, returns
 * GPG_ERR_NOT_FOUND.  If there was a match, returns 0.  If an error
 * occurred, returns an error code.
 *
 * The returned key is considered to be selected and the raw data can,
 * for instance, be returned by calling keydb_get_keyblock().  */
gpg_error_t
keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
              size_t ndesc, size_t *descindex)
{
  gpg_error_t err;
  int i;
  char line[ASSUAN_LINELENGTH];
  char *buffer;
  size_t len;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (descindex)
    *descindex = 0; /* Make sure it is always set on return.  */

  if (DBG_CLOCK)
    log_clock ("%s enter", __func__);

  if (DBG_LOOKUP)
    {
      log_debug ("%s: %zu search descriptions:\n", __func__, ndesc);
      for (i = 0; i < ndesc; i ++)
        {
          char *t = keydb_search_desc_dump (&desc[i]);
          log_debug ("%s   %d: %s\n", __func__, i, t);
          xfree (t);
        }
    }

  if (!hd->use_keyboxd)
    {
      err = internal_keydb_search (hd, desc, ndesc, descindex);
      goto leave;
    }

  /* Clear the result objects.  */
  if (hd->kbl->search_result)
    {
      iobuf_close (hd->kbl->search_result);
      hd->kbl->search_result = NULL;
    }

  /* Check whether this is a NEXT search.  */
  if (!hd->kbl->need_search_reset)
    {
      /* No reset requested thus continue the search.  The keyboxd
       * keeps the context of the search and thus the NEXT operates on
       * the last search pattern.  This is how we always used the
       * keydb.c functions.  In theory we were able to modify the
       * search pattern between searches but that is not anymore
       * supported by keyboxd and a cursory check does not show that
       * we actually made used of that misfeature.  */
      snprintf (line, sizeof line, "NEXT");
      goto do_search;
    }

  hd->kbl->need_search_reset = 0;

  if (!ndesc)
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }
  for (i = 0; i < ndesc; i++)
    if (desc->mode == KEYDB_SEARCH_MODE_FIRST)
      {
        /* If any description has mode FIRST, this item trumps all
         * other descriptions.  */
        snprintf (line, sizeof line, "SEARCH --openpgp");
        goto do_search;
      }

  for ( ; ndesc; desc++, ndesc--)
    {
      const char *more = ndesc > 1 ? "--openpgp --more" : "--openpgp";

      switch (desc->mode)
        {
        case KEYDB_SEARCH_MODE_EXACT:
          snprintf (line, sizeof line, "SEARCH %s -- =%s", more, desc->u.name);
          break;

        case KEYDB_SEARCH_MODE_SUBSTR:
          snprintf (line, sizeof line, "SEARCH %s -- *%s", more, desc->u.name);
          break;

        case KEYDB_SEARCH_MODE_MAIL:
          snprintf (line, sizeof line, "SEARCH %s -- <%s",
                    more, desc->u.name+(desc->u.name[0] == '<') );
          break;

        case KEYDB_SEARCH_MODE_MAILSUB:
          snprintf (line, sizeof line, "SEARCH %s -- @%s", more, desc->u.name);
          break;

        case KEYDB_SEARCH_MODE_MAILEND:
          snprintf (line, sizeof line, "SEARCH %s -- .%s", more, desc->u.name);
          break;

        case KEYDB_SEARCH_MODE_WORDS:
          snprintf (line, sizeof line, "SEARCH %s -- +%s", more, desc->u.name);
          break;

        case KEYDB_SEARCH_MODE_SHORT_KID:
          snprintf (line, sizeof line, "SEARCH %s -- 0x%08lX", more,
                    (ulong)desc->u.kid[1]);
          break;

        case KEYDB_SEARCH_MODE_LONG_KID:
          snprintf (line, sizeof line, "SEARCH %s -- 0x%08lX%08lX", more,
                    (ulong)desc->u.kid[0], (ulong)desc->u.kid[1]);
          break;

        case KEYDB_SEARCH_MODE_FPR:
          {
            unsigned char hexfpr[MAX_FINGERPRINT_LEN * 2 + 1];
            log_assert (desc->fprlen <= MAX_FINGERPRINT_LEN);
            bin2hex (desc->u.fpr, desc->fprlen, hexfpr);
            snprintf (line, sizeof line, "SEARCH %s -- 0x%s", more, hexfpr);
          }
          break;

        case KEYDB_SEARCH_MODE_ISSUER:
          snprintf (line, sizeof line, "SEARCH %s -- #/%s", more, desc->u.name);
          break;

        case KEYDB_SEARCH_MODE_ISSUER_SN:
        case KEYDB_SEARCH_MODE_SN:
          snprintf (line, sizeof line, "SEARCH %s -- #%s", more, desc->u.name);
          break;

        case KEYDB_SEARCH_MODE_SUBJECT:
          snprintf (line, sizeof line, "SEARCH %s -- /%s", more, desc->u.name);
          break;

        case KEYDB_SEARCH_MODE_KEYGRIP:
          {
            unsigned char hexgrip[KEYGRIP_LEN * 2 + 1];
            bin2hex (desc->u.grip, KEYGRIP_LEN, hexgrip);
            snprintf (line, sizeof line, "SEARCH %s -- &%s", more, hexgrip);
          }
          break;

        case KEYDB_SEARCH_MODE_UBID:
          {
            unsigned char hexubid[UBID_LEN * 2 + 1];
            bin2hex (desc->u.ubid, UBID_LEN, hexubid);
            snprintf (line, sizeof line, "SEARCH %s -- ^%s", more, hexubid);
          }
          break;

        case KEYDB_SEARCH_MODE_NEXT:
          log_debug ("%s: mode next - we should not get to here!\n", __func__);
          snprintf (line, sizeof line, "NEXT");
          break;

        case KEYDB_SEARCH_MODE_FIRST:
          log_debug ("%s: mode first - we should not get to here!\n", __func__);
          /*fallthru*/
        default:
          err = gpg_error (GPG_ERR_INV_ARG);
          goto leave;
        }

      if (ndesc > 1)
        {
          err = kbx_client_data_simple (hd->kbl->kcd, line);
          if (err)
            goto leave;
        }
    }
  while (ndesc);


 do_search:
  hd->last_ubid_valid = 0;
  err = kbx_client_data_cmd (hd->kbl->kcd, line, search_status_cb, hd);
  if (!err && !(err = kbx_client_data_wait (hd->kbl->kcd, &buffer, &len)))
    {
      hd->kbl->search_result = iobuf_temp_with_content (buffer, len);
      xfree (buffer);
      if (DBG_LOOKUP && hd->last_ubid_valid)
        log_printhex (hd->last_ubid, 20, "found UBID (%d,%d):",
                      hd->last_uid_no, hd->last_pk_no);
    }

 leave:
  if (DBG_CLOCK)
    log_clock ("%s leave (%sfound)", __func__, err? "not ":"");
  return err;
}
