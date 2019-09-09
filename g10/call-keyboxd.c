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

#include "gpg.h"
#include <assuan.h>
#include "../common/util.h"
#include "../common/membuf.h"
#include "options.h"
#include "../common/i18n.h"
#include "../common/asshelp.h"
#include "../common/status.h"
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

  /* This flag set while an operation is running on this context.  */
  unsigned int is_active : 1;

  /* This flag is set to record that the standard per session init has
   * been done.  */
  unsigned int per_session_init_done : 1;
};




/* Deinitialize all session resources pertaining to the keyboxd.  */
void
gpg_keyboxd_deinit_session_data (ctrl_t ctrl)
{
  keyboxd_local_t kbl;

  while ((kbl = ctrl->keyboxd_local))
    {
      ctrl->keyboxd_local = kbl->next;
      if (kbl->is_active)
        log_error ("oops: trying to cleanup an active keyboxd context\n");
      else
        assuan_release (kbl->ctx);
      xfree (kbl);
    }
}


/* Print a warning if the server's version number is less than our
   version number.  Returns an error code on a connection problem.  */
static gpg_error_t
warn_version_mismatch (assuan_context_t ctx, const char *servername)
{
  gpg_error_t err;
  char *serverversion;
  const char *myversion = strusage (13);

  err = get_assuan_server_version (ctx, 0, &serverversion);
  if (err)
    log_error (_("error getting version from '%s': %s\n"),
               servername, gpg_strerror (err));
  else if (compare_version_strings (serverversion, myversion) < 0)
    {
      char *warn;

      warn = xtryasprintf (_("server '%s' is older than us (%s < %s)"),
                           servername, serverversion, myversion);
      if (!warn)
        err = gpg_error_from_syserror ();
      else
        {
          log_info (_("WARNING: %s\n"), warn);
          if (!opt.quiet)
            {
              log_info (_("Note: Outdated servers may lack important"
                          " security fixes.\n"));
              log_info (_("Note: Use the command \"%s\" to restart them.\n"),
                        "gpgconf --kill all");
            }

          write_status_strings (STATUS_WARNING, "server_version_mismatch 0",
                                " ", warn, NULL);
          xfree (warn);
        }
    }
  xfree (serverversion);
  return err;
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
    }

  if (err)
    assuan_release (ctx);
  else
    *r_ctx = ctx;

  return err;
}


/* Get a context for accessing keyboxd.  If no context is available a
 * new one is created and if necessary keyboxd is started.  On success
 * an assuan context is stored at R_CTX.  This context may only be
 * released by means of close_context.  Note that NULL is stored at
 * R_CTX on error.  */
static gpg_error_t
open_context (ctrl_t ctrl, assuan_context_t *r_ctx)
{
  gpg_error_t err;
  keyboxd_local_t kbl;

  *r_ctx = NULL;
  for (;;)
    {
      for (kbl = ctrl->keyboxd_local; kbl && kbl->is_active; kbl = kbl->next)
        ;
      if (kbl)
        {
          /* Found an inactive keyboxd session - return that.  */
          log_assert (!kbl->is_active);

          /* But first do the per session init if not yet done.  */
          if (!kbl->per_session_init_done)
            {
              kbl->per_session_init_done = 1;
            }

          kbl->is_active = 1;

          *r_ctx = kbl->ctx;
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

      /* Although we are not yet using nPth in gpg we better prepare
       * to be nPth thread safe.  Thus we add it to the list and
       * retry; this is easier than to employ a lock.  */
      kbl->next = ctrl->keyboxd_local;
      ctrl->keyboxd_local = kbl;
    }
}


/* Close the assuan context CTX and return it to a pool of unused
 * contexts.  If CTX is NULL, the function does nothing.  */
static void
close_context (ctrl_t ctrl, assuan_context_t ctx)
{
  keyboxd_local_t kbl;

  if (!ctx)
    return;

  for (kbl = ctrl->keyboxd_local; kbl; kbl = kbl->next)
    {
      if (kbl->ctx == ctx)
        {
          if (!kbl->is_active)
            log_fatal ("closing inactive keyboxd context %p\n", ctx);
          kbl->is_active = 0;
          return;
        }
    }
  log_fatal ("closing unknown keyboxd ctx %p\n", ctx);
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
  hd->need_search_reset = 1;

  err = open_context (ctrl, &hd->assuan_context);
  if (err)
    goto leave;

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
  if (!hd)
    return;

  if (!hd->use_keyboxd)
    internal_keydb_deinit (hd);
  else
    {
      close_context (hd->ctrl, hd->assuan_context);
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



/* FIXME: This helper is duplicates code of partse_keyblock_image.  */
static gpg_error_t
keydb_get_keyblock_do_parse (iobuf_t iobuf, int pk_no, int uid_no,
                             kbnode_t *r_keyblock)
{
  gpg_error_t err;
  struct parse_packet_ctx_s parsectx;
  PACKET *pkt;
  kbnode_t keyblock = NULL;
  kbnode_t node, *tail;
  int in_cert, save_mode;
  int pk_count, uid_count;

  *r_keyblock = NULL;

  pkt = xtrymalloc (sizeof *pkt);
  if (!pkt)
    return gpg_error_from_syserror ();
  init_packet (pkt);
  init_parse_packet (&parsectx, iobuf);
  save_mode = set_packet_list_mode (0);
  in_cert = 0;
  tail = NULL;
  pk_count = uid_count = 0;
  while ((err = parse_packet (&parsectx, pkt)) != -1)
    {
      if (gpg_err_code (err) == GPG_ERR_UNKNOWN_PACKET)
        {
          free_packet (pkt, &parsectx);
          init_packet (pkt);
          continue;
	}
      if (err)
        {
          es_fflush (es_stdout);
          log_error ("parse_keyblock_image: read error: %s\n",
                     gpg_strerror (err));
          if (gpg_err_code (err) == GPG_ERR_INV_PACKET)
            {
              free_packet (pkt, &parsectx);
              init_packet (pkt);
              continue;
            }
          err = gpg_error (GPG_ERR_INV_KEYRING);
          break;
        }

      /* Filter allowed packets.  */
      switch (pkt->pkttype)
        {
        case PKT_PUBLIC_KEY:
        case PKT_PUBLIC_SUBKEY:
        case PKT_SECRET_KEY:
        case PKT_SECRET_SUBKEY:
        case PKT_USER_ID:
        case PKT_ATTRIBUTE:
        case PKT_SIGNATURE:
        case PKT_RING_TRUST:
          break; /* Allowed per RFC.  */

        default:
          log_info ("skipped packet of type %d in keybox\n", (int)pkt->pkttype);
          free_packet(pkt, &parsectx);
          init_packet(pkt);
          continue;
        }

      /* Other sanity checks.  */
      if (!in_cert && pkt->pkttype != PKT_PUBLIC_KEY)
        {
          log_error ("parse_keyblock_image: first packet in a keybox blob "
                     "is not a public key packet\n");
          err = gpg_error (GPG_ERR_INV_KEYRING);
          break;
        }
      if (in_cert && (pkt->pkttype == PKT_PUBLIC_KEY
                      || pkt->pkttype == PKT_SECRET_KEY))
        {
          log_error ("parse_keyblock_image: "
                     "multiple keyblocks in a keybox blob\n");
          err = gpg_error (GPG_ERR_INV_KEYRING);
          break;
        }
      in_cert = 1;

      node = new_kbnode (pkt);

      switch (pkt->pkttype)
        {
        case PKT_PUBLIC_KEY:
        case PKT_PUBLIC_SUBKEY:
        case PKT_SECRET_KEY:
        case PKT_SECRET_SUBKEY:
          if (++pk_count == pk_no)
            node->flag |= 1;
          break;

        case PKT_USER_ID:
          if (++uid_count == uid_no)
            node->flag |= 2;
          break;

        default:
          break;
        }

      if (!keyblock)
        keyblock = node;
      else
        *tail = node;
      tail = &node->next;
      pkt = xtrymalloc (sizeof *pkt);
      if (!pkt)
        {
          err = gpg_error_from_syserror ();
          break;
        }
      init_packet (pkt);
    }
  set_packet_list_mode (save_mode);

  if (err == -1 && keyblock)
    err = 0; /* Got the entire keyblock.  */

  if (err)
    release_kbnode (keyblock);
  else
    {
      *r_keyblock = keyblock;
    }
  free_packet (pkt, &parsectx);
  deinit_parse_packet (&parsectx);
  xfree (pkt);
  return err;
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
  int pk_no, uid_no;

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

  if (!hd->search_result)
    {
      err = gpg_error (GPG_ERR_VALUE_NOT_FOUND);
      goto leave;
    }

  pk_no = uid_no = 0;  /*FIXME: Get this from the keyboxd.  */
  err = keydb_get_keyblock_do_parse (hd->search_result, pk_no, uid_no, ret_kb);
  /* In contrast to the old code we close the iobuf here and thus this
   * function may be called only once to get a keyblock.  */
  iobuf_close (hd->search_result);
  hd->search_result = NULL;


 leave:
  if (DBG_CLOCK)
    log_clock ("%s leave%s", __func__, err? " (failed)":"");
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

  log_assert (kb);
  log_assert (kb->pkt->pkttype == PKT_PUBLIC_KEY);

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!hd->use_keyboxd)
    {
      err = internal_keydb_update_keyblock (ctrl, hd, kb);
      goto leave;
    }

  err = GPG_ERR_NOT_IMPLEMENTED;

 leave:
  return err;
}


/* Insert a keyblock into one of the underlying keyrings or keyboxes.
 *
 * Be default, the keyring / keybox from which the last search result
 * came is used.  If there was no previous search result (or
 * keydb_search_reset was called), then the keyring / keybox where the
 * next search would start is used (i.e., the current file position).
 *
 * Note: this doesn't do anything if --dry-run was specified.
 *
 * Returns 0 on success.  Otherwise, it returns an error code.  */
gpg_error_t
keydb_insert_keyblock (KEYDB_HANDLE hd, kbnode_t kb)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!hd->use_keyboxd)
    {
      err = internal_keydb_insert_keyblock (hd, kb);
      goto leave;
    }

  err = GPG_ERR_NOT_IMPLEMENTED;

 leave:
  return err;
}


/* Delete the currently selected keyblock.  If you haven't done a
 * search yet on this database handle (or called keydb_search_reset),
 * then this function returns an error.
 *
 * Returns 0 on success or an error code, if an error occured.  */
gpg_error_t
keydb_delete_keyblock (KEYDB_HANDLE hd)
{
  gpg_error_t err;

  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!hd->use_keyboxd)
    {
      err = internal_keydb_delete_keyblock (hd);
      goto leave;
    }

  err = GPG_ERR_NOT_IMPLEMENTED;

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

  /* All we need todo is to tell search that a reset is pending.  Noet
   * that keydb_new sets this flag as well.  */
  hd->need_search_reset = 1;
  err = 0;

 leave:
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


  if (!hd)
    return gpg_error (GPG_ERR_INV_ARG);

  if (descindex)
    *descindex = 0; /* Make sure it is always set on return.  */

  if (DBG_CLOCK)
    log_clock ("%s enter", __func__);

  if (DBG_LOOKUP)
    {
      log_debug ("%s: %zd search descriptions:\n", __func__, ndesc);
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


  if (hd->search_result)
    {
      iobuf_close (hd->search_result);
      hd->search_result = NULL;
    }

  if (!hd->need_search_reset)
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

  hd->need_search_reset = 0;

  if (!ndesc)
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  /* FIXME: Implement --multi */
  switch (desc->mode)
    {
    case KEYDB_SEARCH_MODE_EXACT:
      snprintf (line, sizeof line, "SEARCH =%s", desc[0].u.name);
      break;

    case KEYDB_SEARCH_MODE_SUBSTR:
      snprintf (line, sizeof line, "SEARCH *%s", desc[0].u.name);
      break;

    case KEYDB_SEARCH_MODE_MAIL:
      snprintf (line, sizeof line, "SEARCH <%s", desc[0].u.name);
      break;

    case KEYDB_SEARCH_MODE_MAILSUB:
      snprintf (line, sizeof line, "SEARCH @%s", desc[0].u.name);
      break;

    case KEYDB_SEARCH_MODE_MAILEND:
      snprintf (line, sizeof line, "SEARCH .%s", desc[0].u.name);
      break;

    case KEYDB_SEARCH_MODE_WORDS:
      snprintf (line, sizeof line, "SEARCH +%s", desc[0].u.name);
      break;

    case KEYDB_SEARCH_MODE_SHORT_KID:
      snprintf (line, sizeof line, "SEARCH 0x%08lX",
                (ulong)desc->u.kid[1]);
      break;

    case KEYDB_SEARCH_MODE_LONG_KID:
      snprintf (line, sizeof line, "SEARCH 0x%08lX%08lX",
                (ulong)desc->u.kid[0], (ulong)desc->u.kid[1]);
      break;

    case KEYDB_SEARCH_MODE_FPR:
      {
        unsigned char hexfpr[MAX_FINGERPRINT_LEN * 2 + 1];
        log_assert (desc[0].fprlen <= MAX_FINGERPRINT_LEN);
        bin2hex (desc[0].u.fpr, desc[0].fprlen, hexfpr);
        snprintf (line, sizeof line, "SEARCH 0x%s", hexfpr);
      }
      break;

    case KEYDB_SEARCH_MODE_ISSUER:
      snprintf (line, sizeof line, "SEARCH #/%s", desc[0].u.name);
      break;

    case KEYDB_SEARCH_MODE_ISSUER_SN:
    case KEYDB_SEARCH_MODE_SN:
      snprintf (line, sizeof line, "SEARCH #%s", desc[0].u.name);
      break;

    case KEYDB_SEARCH_MODE_SUBJECT:
      snprintf (line, sizeof line, "SEARCH /%s", desc[0].u.name);
      break;

    case KEYDB_SEARCH_MODE_KEYGRIP:
      {
        unsigned char hexgrip[KEYGRIP_LEN * 2 + 1];
        bin2hex (desc[0].u.grip, KEYGRIP_LEN, hexgrip);
        snprintf (line, sizeof line, "SEARCH &%s", hexgrip);
      }
      break;

    case KEYDB_SEARCH_MODE_FIRST:
      snprintf (line, sizeof line, "SEARCH");
      break;

    case KEYDB_SEARCH_MODE_NEXT:
      log_debug ("%s: mode next - we should not get to here!\n", __func__);
      snprintf (line, sizeof line, "NEXT");
      break;

    default:
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

 do_search:
  {
    membuf_t data;
    void *buffer;
    size_t len;

    init_membuf (&data, 8192);
    err = assuan_transact (hd->assuan_context, line,
                           put_membuf_cb, &data,
                           NULL, NULL,
                           NULL, NULL);
    if (err)
      {
        xfree (get_membuf (&data, &len));
        goto leave;
      }

    buffer = get_membuf (&data, &len);
    if (!buffer)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }

    /* Fixme: Avoid double allocation.  */
    hd->search_result = iobuf_temp_with_content (buffer, len);
  }


 leave:
  if (DBG_CLOCK)
    log_clock ("%s leave (%sfound)", __func__, err? "not ":"");
  return err;
}
